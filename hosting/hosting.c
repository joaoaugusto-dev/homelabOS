// hosting: hospedagem de aplicações em C. GitHub -> build -> container (podman) ou processo -> Cloudflare Tunnel.
// Build: gcc -O2 -pthread -o hosting hosting.c   |   Config: hosting.conf   |   Teste: ./test.sh
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

/* ---------- config ---------- */
static struct {
    int port, sandbox, behind_proxy;
    char web[PATH_MAX], data[PATH_MAX], dash[64], tunnel[48], git_base[128], cf_api[96];
    char bind[48], admin[32], native[128], cert_domain[128]; // admin: nome do administrador (token da API, domínio do cloudflared); native: quem mais pode rodar comandos no servidor
} cfg = {.port = 8430, .sandbox = 1, .bind = "127.0.0.1", .admin = "admin", .web = "web", .data = "data", .dash = "80,8081", .tunnel = "hosting",
         .git_base = "https://github.com/", .cf_api = "https://api.cloudflare.com/client/v4"};

static void cfg_load(const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) return;
    char l[PATH_MAX + 64];
    while (fgets(l, sizeof l, f)) {
        l[strcspn(l, "\r\n")] = 0;
        char *v = strchr(l, '=');
        if (l[0] == '#' || !v) continue;
        *v++ = 0;
#define S(k, dst) if (!strcmp(l, k)) snprintf(dst, sizeof dst, "%s", v)
        S("web", cfg.web); S("data", cfg.data); S("dash_ports", cfg.dash); S("tunnel", cfg.tunnel);
        S("git_base", cfg.git_base); S("cf_api", cfg.cf_api);
        S("bind", cfg.bind); S("admin", cfg.admin); S("native_users", cfg.native); S("cert_domain", cfg.cert_domain);
        if (!strcmp(l, "port")) cfg.port = atoi(v);
        if (!strcmp(l, "sandbox")) cfg.sandbox = atoi(v);
        if (!strcmp(l, "behind_proxy")) cfg.behind_proxy = atoi(v);
    }
    fclose(f);
}

/* ---------- sha256 + hmac (assinatura do webhook do GitHub) ---------- */
static const uint32_t K[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(uint32_t *h, const uint8_t *p) {
    uint32_t w[64], a, b, c, d, e, f, g, hh;
    for (int i = 0; i < 16; i++) w[i] = p[i*4] << 24 | p[i*4+1] << 16 | p[i*4+2] << 8 | p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i-15], 7) ^ ROR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR(w[i-2], 17) ^ ROR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
static void sha256(const uint8_t *in, size_t n, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha_block(h, in + i);
    uint8_t t[128] = {0};
    size_t r = n - i;
    memcpy(t, in + i, r);
    t[r] = 0x80;
    size_t tl = r < 56 ? 64 : 128;
    uint64_t bits = (uint64_t)n * 8;
    for (int k = 0; k < 8; k++) t[tl - 1 - k] = bits >> (8 * k);
    sha_block(h, t);
    if (tl == 128) sha_block(h, t + 64);
    for (int k = 0; k < 8; k++) { out[k*4] = h[k] >> 24; out[k*4+1] = h[k] >> 16; out[k*4+2] = h[k] >> 8; out[k*4+3] = h[k]; }
}
static void hmac_hex(const char *key, const uint8_t *msg, size_t n, char hex[65]) {
    uint8_t k[64] = {0}, d[32], *buf = malloc(64 + (n > 32 ? n : 32));
    size_t kl = strlen(key);
    if (kl > 64) sha256((const uint8_t *)key, kl, k); else memcpy(k, key, kl);
    for (int i = 0; i < 64; i++) buf[i] = k[i] ^ 0x36;
    memcpy(buf + 64, msg, n);
    sha256(buf, 64 + n, d);
    for (int i = 0; i < 64; i++) buf[i] = k[i] ^ 0x5c;
    memcpy(buf + 64, d, 32);
    sha256(buf, 96, d);
    free(buf);
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", d[i]);
}
static int ct_eq(const char *a, const char *b) { // comparação em tempo constante
    size_t n = strlen(a); int d = n != strlen(b);
    for (size_t i = 0; i < n && !d; i++) d |= a[i] ^ b[i];
    return !d;
}
static void b64(const char *in, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = strlen(in), j = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint8_t)in[i] << 16 | (i + 1 < n ? (uint8_t)in[i+1] << 8 : 0) | (i + 2 < n ? (uint8_t)in[i+2] : 0);
        out[j++] = T[v >> 18 & 63]; out[j++] = T[v >> 12 & 63];
        out[j++] = i + 1 < n ? T[v >> 6 & 63] : '='; out[j++] = i + 2 < n ? T[v & 63] : '=';
    }
    out[j] = 0;
}
static void rand_hex(char *o, int bytes) { // sem entropia boa não existe segredo seguro: aborta em vez de gerar zeros
    uint8_t r[32];
    for (int i = 0; i < bytes;) { ssize_t n = getrandom(r + i, bytes - i, 0); if (n <= 0) { perror("getrandom"); abort(); } i += n; }
    for (int i = 0; i < bytes; i++) sprintf(o + i * 2, "%02x", r[i]);
}

/* ---------- string builder / json ---------- */
typedef struct { char *p; size_t n, cap; } sb;
static void sb_add(sb *b, const char *s, size_t l) {
    if (b->n + l + 1 > b->cap) { b->cap = (b->n + l + 1) * 2 + 256; b->p = realloc(b->p, b->cap); }
    memcpy(b->p + b->n, s, l); b->n += l; b->p[b->n] = 0;
}
static void sb_f(sb *b, const char *fmt, ...) {
    va_list a, a2; va_start(a, fmt); va_copy(a2, a);
    int l = vsnprintf(NULL, 0, fmt, a); va_end(a);
    if (b->n + l + 1 > b->cap) { b->cap = (b->n + l + 1) * 2 + 256; b->p = realloc(b->p, b->cap); }
    vsnprintf(b->p + b->n, l + 1, fmt, a2); va_end(a2); b->n += l;
}
static void sb_str(sb *b, const char *s) {
    sb_add(b, "\"", 1);
    for (; *s; s++) {
        unsigned char ch = *s;
        if (ch == '"' || ch == '\\') { char t[2] = {'\\', ch}; sb_add(b, t, 2); }
        else if (ch == '\n') sb_add(b, "\\n", 2);
        else if (ch < 0x20) sb_f(b, "\\u%04x", ch);
        else sb_add(b, (char *)&ch, 1);
    }
    sb_add(b, "\"", 1);
}
// "chave":"valor" dentro de um JSON de resposta (curl/cloudflared); primeira ocorrência
static int jfind(const char *js, const char *key, char *out, size_t cap) {
    char k[64]; snprintf(k, sizeof k, "\"%s\"", key);
    const char *p = strstr(js, k);
    out[0] = 0;
    if (!p || !(p = strchr(p + strlen(k), ':'))) return 0;
    while (*++p == ' ');
    if (*p != '"') return 0;
    size_t n = 0;
    for (p++; *p && *p != '"' && n + 1 < cap; p++) { if (*p == '\\' && p[1]) p++; out[n++] = *p; }
    out[n] = 0;
    return 1;
}

// início do array de "chave":[...] (tolera espaços) ou NULL; e "chave": true
static const char *jarr(const char *js, const char *key) {
    char k[64]; snprintf(k, sizeof k, "\"%s\"", key);
    const char *p = strstr(js, k);
    if (!p) return NULL;
    p += strlen(k);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '[') return NULL;
    for (p++; *p == ' '; p++);
    return *p == ']' ? NULL : p; // array vazio = nada achado (não deixa o jfind procurar um "id" mais adiante)
}
static int jtrue(const char *js, const char *key) {
    char k[64]; snprintf(k, sizeof k, "\"%s\"", key);
    const char *p = strstr(js, k);
    if (!p) return 0;
    p += strlen(k);
    while (*p == ' ' || *p == ':') p++;
    return !strncmp(p, "true", 4);
}

/* ---------- arquivos / processos ---------- */
static void dpath(char *o, size_t c, const char *fmt, ...) { // caminho dentro de data/
    char t[PATH_MAX]; va_list a; va_start(a, fmt); vsnprintf(t, sizeof t, fmt, a); va_end(a);
    snprintf(o, c, "%s/%s", cfg.data, t);
}
static void mkdirp(const char *p) {
    char t[PATH_MAX]; snprintf(t, sizeof t, "%s", p);
    for (char *s = t + 1; *s; s++) if (*s == '/') { *s = 0; mkdir(t, 0755); *s = '/'; }
    mkdir(t, 0755);
}
static int rm_cb(const char *p, const struct stat *s, int t, struct FTW *f) { (void)s; (void)t; (void)f; return remove(p); }
static void rm_rf(const char *p) { nftw(p, rm_cb, 16, FTW_DEPTH | FTW_PHYS); }
static int slurp(const char *p, char *out, size_t cap) {
    FILE *f = fopen(p, "r");
    if (!f) { out[0] = 0; return -1; }
    size_t n = fread(out, 1, cap - 1, f); out[n] = 0; fclose(f);
    return 0;
}
static void spit(const char *p, const char *s) {
    char t[PATH_MAX + 8]; snprintf(t, sizeof t, "%s.tmp", p);
    FILE *f = fopen(t, "w");
    if (!f) return;
    fputs(s, f); fclose(f); rename(t, p);
}
static int have(const char *bin) {
    const char *path = getenv("PATH");
    char t[PATH_MAX], *dup = strdup(path ? path : "/usr/bin:/bin"), *sv, *d;
    int ok = 0;
    for (d = strtok_r(dup, ":", &sv); d && !ok; d = strtok_r(NULL, ":", &sv)) {
        snprintf(t, sizeof t, "%s/%s", d, bin);
        ok = !access(t, X_OK);
    }
    free(dup);
    return ok;
}

/* Sandbox dos apps nativos e dos builds (Landlock, kernel >= 5.13): só enxergam o sistema (somente leitura), /tmp, /dev e a pasta do
   próprio app. Ficam de fora data/ (token da API, tokens do Cloudflare e do GitHub, senhas de banco), ~/.cloudflared, ~/.ssh e o resto
   do home. Também liga no_new_privs, então sudo/setuid não funcionam dentro do app. Sem Landlock o app roda como antes (e o log avisa). */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
struct ll_attr { uint64_t handled; };
struct ll_rule { uint64_t allowed; int32_t parent_fd; } __attribute__((packed));
static void ll_allow(int rs, const char *path, uint64_t acc) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return; // pasta que não existe nesta distro
    struct ll_rule r = {acc, fd};
    syscall(__NR_landlock_add_rule, rs, 1, &r, 0);
    close(fd);
}
static int ll_abi(void) { return (int)syscall(__NR_landlock_create_ruleset, NULL, 0, 1); }
static void sandbox_enter(const char *appdir) { // roda no filho, antes do exec
    int abi = ll_abi();
    uint64_t all = 0x1fff | (abi >= 2 ? 1ULL << 13 : 0) | (abi >= 3 ? 1ULL << 14 : 0), rd = 1 | 4 | 8; // exec, ler arquivo, ler pasta
    struct ll_attr at = {all};
    int rs = abi >= 1 ? (int)syscall(__NR_landlock_create_ruleset, &at, sizeof at, 0) : -1;
    static const char *ro[] = {"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/opt", "/sys", "/proc", "/run/systemd/resolve", "/var/lib", NULL};
    static const char *rw[] = {"/tmp", "/var/tmp", "/dev", NULL};
    if (rs >= 0) {
        for (int i = 0; ro[i]; i++) ll_allow(rs, ro[i], rd);
        for (int i = 0; rw[i]; i++) ll_allow(rs, rw[i], all);
        ll_allow(rs, appdir, all);
        if (!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) && !syscall(__NR_landlock_restrict_self, rs, 0)) { close(rs); return; }
        close(rs);
    }
    static const char m[] = "[hosting] aviso: sem sandbox (Landlock indisponivel neste kernel); o app roda com os mesmos acessos do servico\n";
    if (write(2, m, sizeof m - 1) < 0) {}
}

typedef struct { const char *cwd; char **env; const char *in; int fd; sb *out; int to; const char *sandbox; } RunOpt;
// Roda um programa e espera. Saída vai para o fd de log ou para o sb. Devolve o código de saída, -1 falha ao iniciar, -2 estourou o tempo.
static int run(char *const *argv, const RunOpt *o) {
    int po[2] = {-1, -1}, pi[2] = {-1, -1};
    if ((o->out && pipe2(po, O_CLOEXEC)) || (o->in && pipe2(pi, O_CLOEXEC))) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (!pid) {
        setsid();
        int nul = open("/dev/null", O_RDWR);
        int out = o->out ? po[1] : o->fd >= 0 ? o->fd : nul;
        dup2(o->in ? pi[0] : nul, 0); dup2(out, 1); dup2(out, 2);
        if (o->cwd && chdir(o->cwd)) _exit(126);
        if (o->sandbox) sandbox_enter(o->sandbox);
        execvpe(argv[0], argv, o->env ? o->env : environ);
        _exit(127);
    }
    if (o->out) close(po[1]);
    if (o->in) { close(pi[0]); if (write(pi[1], o->in, strlen(o->in)) < 0) {} close(pi[1]); }
    time_t dl = time(NULL) + (o->to ? o->to : 600);
    int st = 0, code = -2;
    char buf[4096];
    for (;;) {
        if (o->out) {
            struct pollfd pf = {po[0], POLLIN, 0};
            if (poll(&pf, 1, 100) > 0) {
                ssize_t r = read(po[0], buf, sizeof buf);
                if (r > 0 && o->out->n < (1 << 18)) sb_add(o->out, buf, r);
            }
        } else nanosleep(&(struct timespec){0, 50000000}, NULL);
        if (waitpid(pid, &st, WNOHANG) == pid) { code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st); break; }
        if (time(NULL) > dl) { kill(-pid, SIGKILL); waitpid(pid, &st, 0); break; }
    }
    if (o->out) {
        fcntl(po[0], F_SETFL, O_NONBLOCK);
        ssize_t r;
        while ((r = read(po[0], buf, sizeof buf)) > 0 && o->out->n < (1 << 18)) sb_add(o->out, buf, r);
        close(po[0]);
    }
    return code;
}
// capture: roda e junta stdout+stderr em out
static int capture(char *const *argv, sb *out, const char *in, int to) {
    RunOpt o = {.fd = -1, .out = out, .in = in, .to = to};
    return run(argv, &o);
}
static void quiet(char *const *argv, int to) { sb o = {0}; capture(argv, &o, NULL, to); free(o.p); }
static void trim(char *s) { size_t n = strlen(s); while (n && isspace((unsigned char)s[n-1])) s[--n] = 0; }
static int valid_host(const char *h);
static int valid_token(const char *t) { // tokens do GitHub/Cloudflare: letras, números e _-.~= ; nada que feche aspas ou quebre linha
    size_t n = strlen(t);
    if (!n || n > 120) return 0;
    for (; *t; t++) if (!isalnum((unsigned char)*t) && !strchr("_-.~=", *t)) return 0;
    return 1;
}
static int reg_file(const char *p) { struct stat st; return !lstat(p, &st) && S_ISREG(st.st_mode); } // arquivo comum, nunca link simbólico
// valor entre aspas para um arquivo de configuração do curl (-K): sem controle (nada de nova diretiva) e com \ e " escapados
#define SBS(b, s) sb_add((b), (s), strlen(s))
static void cfq(sb *b, const char *s) {
    sb_add(b, "\"", 1);
    for (; *s; s++) {
        unsigned char ch = *s;
        if (ch < 0x20 || ch == 0x7f) continue;
        if (ch == '"' || ch == '\\') sb_add(b, "\\", 1);
        sb_add(b, (char *)&ch, 1);
    }
    sb_add(b, "\"", 1);
}

/* ---------- modelo ---------- */
// dono: o nome do usuário ou "shared". Privado = só o dono vê e edita; shared = todos os usuários do painel.
static int can(const char *me, const char *owner) { return !strcmp(owner, "shared") || !strcmp(owner, me); }

typedef struct {
    int used;
    char id[32], name[64], owner[16], repo[96], branch[64], token[128], build[400], start[400], runtime[8], host[128], db[40], secret[33], volume[96], env[2048];
    char commit[41], msg[120], rt[8], last[160], upname[100];
    int nat; // 1 = pode rodar comandos nativos no servidor (a última edição foi de quem tem esse direito)
    int port, iport, cport, mem, autodeploy, want, expose; // port = pública (proxy), iport = onde o app de verdade escuta (127.0.0.1)
    time_t deployed;
    // execução, não persiste
    pid_t pid, pgid; time_t started, nextstart, term_at, pg_kill; int fails, restarts, deploying, stop_req, respawn;
} App;
typedef struct { int used; char id[40], name[64], engine[12], owner[16], user[40], pw[33]; time_t created; } Db;
typedef struct { int used; char name[128], owner[16], token[96]; int cert; } Domain;

#define MAXAPP 64
#define MAXDB 64
#define MAXDOM 16
static App apps[MAXAPP];
static Db dbs[MAXDB];
static Domain doms[MAXDOM];
static pthread_mutex_t gmx = PTHREAD_MUTEX_INITIALIZER, build_mx = PTHREAD_MUTEX_INITIALIZER;
static char hook_host[128], tunnel_id[48];
static int tunnel_dirty = 1, tunnel_up;
static struct { int git, podman, cloudflared, psql, mysql, pg_up, my_up; char mybin[12]; } tools;
static volatile sig_atomic_t quit;

static void clean1(char *s) { for (; *s; s++) if (*s == '\r' || *s == '\n') *s = ' '; }
static void slug(const char *in, char *out, size_t cap, char sep) {
    size_t n = 0;
    for (; *in && n + 1 < cap; in++) {
        if (isalnum((unsigned char)*in)) out[n++] = tolower((unsigned char)*in);
        else if (n && out[n-1] != sep) out[n++] = sep;
    }
    while (n && out[n-1] == sep) n--;
    out[n] = 0;
}

static int kvs(const char *l, const char *k, char *d, size_t n) {
    size_t kl = strlen(k);
    if (strncmp(l, k, kl) || l[kl] != '=') return 0;
    snprintf(d, n, "%s", l + kl + 1);
    return 1;
}
static int kvn(const char *l, const char *k, long long *v) {
    char t[32];
    if (!kvs(l, k, t, sizeof t)) return 0;
    *v = atoll(t); return 1;
}

static App *app_find(const char *id) {
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used && !strcmp(apps[i].id, id)) return &apps[i];
    return NULL;
}
static Db *db_find(const char *id) {
    for (int i = 0; i < MAXDB; i++) if (dbs[i].used && !strcmp(dbs[i].id, id)) return &dbs[i];
    return NULL;
}
static void app_dir(char *o, size_t c, const char *id) { dpath(o, c, "apps/%s", id); }

static void app_save(App *a) { // chamar travado
    char p[PATH_MAX], d[PATH_MAX];
    app_dir(d, sizeof d, a->id); mkdirp(d);
    snprintf(p, sizeof p, "%s/app.conf", d);
    sb b = {0};
    sb_f(&b, "name=%s\nowner=%s\nrepo=%s\nbranch=%s\ntoken=%s\nbuild=%s\nstart=%s\nruntime=%s\nhost=%s\ndb=%s\nsecret=%s\nvolume=%s\n", a->name, a->owner, a->repo, a->branch, a->token, a->build, a->start, a->runtime, a->host, a->db, a->secret, a->volume);
    sb_f(&b, "port=%d\niport=%d\ncport=%d\nmem=%d\nautodeploy=%d\nwant=%d\nexpose=%d\ncommit=%s\nmsg=%s\ndeployed=%lld\nrt=%s\nlast=%s\nupname=%s\nnat=%d\n", a->port, a->iport, a->cport, a->mem, a->autodeploy, a->want, a->expose, a->commit, a->msg, (long long)a->deployed, a->rt, a->last, a->upname, a->nat);
    for (char *s = a->env; *s;) { size_t n = strcspn(s, "\n"); sb_add(&b, "env=", 4); sb_add(&b, s, n); sb_add(&b, "\n", 1); s += n + (s[n] ? 1 : 0); }
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600); // guarda token do GitHub: só o dono lê
    if (fd >= 0) { if (write(fd, b.p, b.n) < 0) {} close(fd); }
    free(b.p);
}
static void app_load(const char *id) {
    App *a = NULL;
    for (int i = 0; i < MAXAPP && !a; i++) if (!apps[i].used) a = &apps[i];
    if (!a) return;
    memset(a, 0, sizeof *a);
    a->nat = 1; // app antigo (sem a chave nat) fica como estava
    snprintf(a->id, sizeof a->id, "%s", id);
    char p[PATH_MAX], l[2200];
    dpath(p, sizeof p, "apps/%s/app.conf", id);
    FILE *f = fopen(p, "r");
    if (!f) return;
    long long v;
    while (fgets(l, sizeof l, f)) {
        l[strcspn(l, "\r\n")] = 0;
        if (kvs(l, "name", a->name, sizeof a->name) || kvs(l, "owner", a->owner, sizeof a->owner) || kvs(l, "repo", a->repo, sizeof a->repo) ||
            kvs(l, "branch", a->branch, sizeof a->branch) || kvs(l, "token", a->token, sizeof a->token) || kvs(l, "build", a->build, sizeof a->build) ||
            kvs(l, "start", a->start, sizeof a->start) || kvs(l, "runtime", a->runtime, sizeof a->runtime) || kvs(l, "host", a->host, sizeof a->host) ||
            kvs(l, "db", a->db, sizeof a->db) || kvs(l, "secret", a->secret, sizeof a->secret) || kvs(l, "volume", a->volume, sizeof a->volume) ||
            kvs(l, "commit", a->commit, sizeof a->commit) || kvs(l, "msg", a->msg, sizeof a->msg) || kvs(l, "rt", a->rt, sizeof a->rt) || kvs(l, "last", a->last, sizeof a->last) || kvs(l, "upname", a->upname, sizeof a->upname)) continue;
        if (kvn(l, "port", &v)) a->port = v; else if (kvn(l, "iport", &v)) a->iport = v; else if (kvn(l, "cport", &v)) a->cport = v; else if (kvn(l, "mem", &v)) a->mem = v;
        else if (kvn(l, "nat", &v)) a->nat = v; else if (kvn(l, "expose", &v)) a->expose = v; else if (kvn(l, "autodeploy", &v)) a->autodeploy = v; else if (kvn(l, "want", &v)) a->want = v; else if (kvn(l, "deployed", &v)) a->deployed = v;
        else if (!strncmp(l, "env=", 4) && strlen(a->env) + strlen(l) < sizeof a->env - 2) { strcat(a->env, l + 4); strcat(a->env, "\n"); }
    }
    fclose(f);
    a->used = a->name[0] && a->owner[0];
}
static void db_save(Db *d) {
    char p[PATH_MAX]; dpath(p, sizeof p, "dbs/%s.conf", d->id);
    char b[512]; snprintf(b, sizeof b, "name=%s\nengine=%s\nowner=%s\nuser=%s\npw=%s\ncreated=%lld\n", d->name, d->engine, d->owner, d->user, d->pw, (long long)d->created);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) { if (write(fd, b, strlen(b)) < 0) {} close(fd); }
}
static void db_load_all(void) {
    char dir[PATH_MAX], p[PATH_MAX], l[256]; dpath(dir, sizeof dir, "dbs");
    DIR *d = opendir(dir); if (!d) return;
    struct dirent *de; int n = 0;
    while ((de = readdir(d)) && n < MAXDB) {
        char *dot = strstr(de->d_name, ".conf");
        if (!dot || dot[5] || dot == de->d_name) continue;
        Db *x = &dbs[n]; memset(x, 0, sizeof *x);
        snprintf(x->id, sizeof x->id, "%.*s", (int)(dot - de->d_name), de->d_name);
        snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
        FILE *f = fopen(p, "r"); if (!f) continue;
        long long v;
        while (fgets(l, sizeof l, f)) {
            l[strcspn(l, "\r\n")] = 0;
            if (kvs(l, "name", x->name, sizeof x->name) || kvs(l, "engine", x->engine, sizeof x->engine) || kvs(l, "owner", x->owner, sizeof x->owner) || kvs(l, "user", x->user, sizeof x->user) || kvs(l, "pw", x->pw, sizeof x->pw)) continue;
            if (kvn(l, "created", &v)) x->created = v;
        }
        fclose(f);
        x->used = x->owner[0] != 0; n += x->used;
    }
    closedir(d);
}
static void dom_save(void) { // chamar travado
    sb b = {0};
    for (int i = 0; i < MAXDOM; i++) if (doms[i].used) sb_f(&b, "%s|%s|%d|%s\n", doms[i].name, doms[i].owner, doms[i].cert, doms[i].token);
    char p[PATH_MAX]; dpath(p, sizeof p, "domains.conf");
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) { if (b.n && write(fd, b.p, b.n) < 0) {} close(fd); }
    free(b.p);
}
static void dom_load(void) {
    char p[PATH_MAX], l[400]; dpath(p, sizeof p, "domains.conf");
    FILE *f = fopen(p, "r");
    if (!f) { // primeira execução: cert_domain= (conf) é o domínio do cert.pem do cloudflared, só do administrador
        if (cfg.cert_domain[0] && valid_host(cfg.cert_domain)) {
            snprintf(doms[0].name, sizeof doms[0].name, "%s", cfg.cert_domain); snprintf(doms[0].owner, sizeof doms[0].owner, "%s", cfg.admin);
            doms[0].cert = 1; doms[0].used = 1; dom_save();
        }
        return;
    }
    int n = 0;
    while (fgets(l, sizeof l, f) && n < MAXDOM) {
        l[strcspn(l, "\r\n")] = 0;
        char *a = strchr(l, '|'), *b = a ? strchr(a + 1, '|') : NULL, *c = b ? strchr(b + 1, '|') : NULL;
        if (!c) continue;
        *a = *b = *c = 0;
        snprintf(doms[n].name, sizeof doms[n].name, "%s", l); snprintf(doms[n].owner, sizeof doms[n].owner, "%s", a + 1);
        doms[n].cert = atoi(b + 1); snprintf(doms[n].token, sizeof doms[n].token, "%s", c + 1); doms[n++].used = 1;
    }
    fclose(f);
}
// domínio (cadastrado e acessível a `me`) que termina o host digitado; o mais específico vence
static Domain *dom_for(const char *me, const char *host) {
    Domain *best = NULL; size_t hl = strlen(host);
    for (int i = 0; i < MAXDOM; i++) {
        if (!doms[i].used || !can(me, doms[i].owner)) continue;
        size_t dl = strlen(doms[i].name);
        if (hl >= dl && !strcmp(host + hl - dl, doms[i].name) && (hl == dl || host[hl - dl - 1] == '.') && (!best || dl > strlen(best->name))) best = &doms[i];
    }
    return best;
}
static void settings_save(void) { char p[PATH_MAX], b[200]; dpath(p, sizeof p, "settings.conf"); snprintf(b, sizeof b, "hook_host=%s\n", hook_host); spit(p, b); }

/* ---------- bancos (postgres e mariadb locais, pelo socket unix) ---------- */
/* Administrador dos bancos. Modo seguro: data/pgpass e data/mysql.cnf (0600, criados por deploy/db-admin.sh) guardam a senha de um
   usuário "hosting_admin" que entra por TCP no loopback; como data/ fica fora do alcance do sandbox, os apps nativos não têm como
   usar o banco como administrador. Sem esses arquivos vale o modo ANTIGO: o usuário do serviço entra pelo socket local (peer),
   o que qualquer processo desse mesmo usuário também consegue. */
static int db_creds(const char *engine, char *path, size_t cap) {
    dpath(path, cap, "%s", !strcmp(engine, "postgres") ? "pgpass" : "mysql.cnf");
    return !access(path, R_OK);
}
static int db_run(const char *engine, const char *sql_in, const char *probe, sb *out, int to) { // probe: consulta curta pelo argv (sem segredo); senão o SQL vem no stdin
    char *av[16], cf[PATH_MAX + 32]; int n = 0, creds = db_creds(engine, cf, sizeof cf);
    if (!strcmp(engine, "postgres")) {
        av[n++] = "psql"; av[n++] = "-X";
        if (creds) { av[n++] = "-h"; av[n++] = "127.0.0.1"; av[n++] = "-U"; av[n++] = "hosting_admin"; }
        if (probe) { av[n++] = "-d"; av[n++] = "postgres"; av[n++] = "-Atc"; av[n++] = (char *)probe; }
        else { av[n++] = "-q"; av[n++] = "-v"; av[n++] = "ON_ERROR_STOP=1"; av[n++] = "-d"; av[n++] = "postgres"; av[n++] = "-f"; av[n++] = "-"; }
    } else {
        char opt[PATH_MAX + 40]; snprintf(opt, sizeof opt, "--defaults-extra-file=%s", cf);
        av[n++] = tools.mybin;
        if (creds) av[n++] = opt; // precisa ser o primeiro argumento
        av[n++] = "--batch";
        if (probe) { av[n++] = "-e"; av[n++] = (char *)probe; }
    }
    av[n] = NULL;
    return capture(av, out, sql_in, to);
}
static int db_sql(const char *engine, const char *sql, sb *out) { // o SQL leva a senha do banco: vai pelo stdin, porque o argv qualquer usuário do servidor lê em /proc
    char in[800]; snprintf(in, sizeof in, "%s;\n", sql);
    return db_run(engine, in, NULL, out, 30);
}
static int db_up(const char *engine) { return !strcmp(engine, "postgres") ? tools.pg_up : tools.my_up; }

/* ---------- cloudflare tunnel ---------- */
static void cf_creds(char *o, size_t c, const char *id) { const char *h = getenv("HOME"); snprintf(o, c, "%s/.cloudflared/%s.json", h ? h : "/root", id); }
// garante que o túnel "hosting" existe e guarda o id; err recebe o motivo em caso de falha
static pthread_mutex_t tmx = PTHREAD_MUTEX_INITIALIZER;
static int tunnel_ensure_(char *err, size_t ec);
static int tunnel_ensure(char *err, size_t ec) { pthread_mutex_lock(&tmx); int r = tunnel_ensure_(err, ec); pthread_mutex_unlock(&tmx); return r; }
static int tunnel_ensure_(char *err, size_t ec) {
    if (tunnel_id[0]) return 0;
    if (!tools.cloudflared) { snprintf(err, ec, "cloudflared não está instalado"); return -1; }
    char p[PATH_MAX]; dpath(p, sizeof p, "tunnel.id");
    slurp(p, tunnel_id, sizeof tunnel_id); trim(tunnel_id);
    if (tunnel_id[0]) return 0;
    for (int tr = 0; tr < 2; tr++) {
        sb o = {0};
        char *av[] = {"cloudflared", "tunnel", "list", "--name", cfg.tunnel, "--output", "json", NULL};
        int rc = capture(av, &o, NULL, 30);
        if (rc == 0 && o.p && jfind(o.p, "id", tunnel_id, sizeof tunnel_id)) { spit(p, tunnel_id); free(o.p); return 0; }
        free(o.p);
        if (tr) break;
        sb c = {0};
        char *cr[] = {"cloudflared", "tunnel", "create", cfg.tunnel, NULL};
        rc = capture(cr, &c, NULL, 60);
        if (rc) { snprintf(err, ec, "não consegui criar o túnel: %.120s", c.p ? c.p : "sem resposta"); free(c.p); return -1; }
        free(c.p);
    }
    tunnel_id[0] = 0; snprintf(err, ec, "túnel %s não encontrado", cfg.tunnel);
    return -1;
}
// chamada à API do Cloudflare via curl; a configuração (com o token) vai pelo stdin, não aparece em ps
static int cf_api(const Domain *d, const char *method, const char *path, const char *body, sb *out) {
    sb cfgb = {0};
    char u[400], hv[200]; snprintf(u, sizeof u, "%s%s", cfg.cf_api, path); snprintf(hv, sizeof hv, "Authorization: Bearer %s", d->token);
    SBS(&cfgb, "silent\nshow-error\nmax-time = 25\nurl = "); cfq(&cfgb, u);
    SBS(&cfgb, "\nrequest = "); cfq(&cfgb, method);
    SBS(&cfgb, "\nheader = "); cfq(&cfgb, hv);
    SBS(&cfgb, "\nheader = \"Content-Type: application/json\"\n");
    if (body) { SBS(&cfgb, "data = "); cfq(&cfgb, body); SBS(&cfgb, "\n"); }
    char *av[] = {"curl", "-K", "-", NULL};
    int rc = capture(av, out, cfgb.p, 30);
    free(cfgb.p);
    return rc;
}
static void cf_err(const sb *o, char *err, size_t ec) {
    char m[160];
    if (o->p && jfind(o->p, "message", m, sizeof m)) snprintf(err, ec, "Cloudflare: %s", m);
    else snprintf(err, ec, "Cloudflare não respondeu");
}
// cria (ou atualiza) o CNAME host -> túnel
static int dns_route(const Domain *d, const char *host, char *err, size_t ec) {
    if (tunnel_ensure(err, ec)) return -1;
    if (d->cert) { // domínio do cert.pem: o próprio cloudflared cria o registro
        sb o = {0};
        char *av[] = {"cloudflared", "tunnel", "route", "dns", "--overwrite-dns", tunnel_id, (char *)host, NULL};
        int rc = capture(av, &o, NULL, 60);
        if (rc) snprintf(err, ec, "DNS: %.140s", o.p ? o.p : "falhou");
        free(o.p);
        return rc ? -1 : 0;
    }
    sb o = {0}; char zid[40], pth[200], rid[40], body[400];
    snprintf(pth, sizeof pth, "/zones?name=%s", d->name);
    cf_api(d, "GET", pth, NULL, &o);
    const char *r = o.p ? jarr(o.p, "result") : NULL;
    if (!r || !jfind(r, "id", zid, sizeof zid)) { cf_err(&o, err, ec); free(o.p); return -1; }
    free(o.p); o = (sb){0};
    snprintf(pth, sizeof pth, "/zones/%s/dns_records?type=CNAME&name=%s", zid, host);
    cf_api(d, "GET", pth, NULL, &o);
    r = o.p ? jarr(o.p, "result") : NULL;
    int exists = r && jfind(r, "id", rid, sizeof rid);
    if (exists) { // nunca sobrescreve um registro que não aponta para o nosso túnel (evita tomar um subdomínio que já tem outro dono/destino)
        char ct[160], want[100]; snprintf(want, sizeof want, "%s.cfargotunnel.com", tunnel_id);
        if (!jfind(r, "content", ct, sizeof ct) || strcmp(ct, want)) { free(o.p); snprintf(err, ec, "Esse endereço já existe no Cloudflare e aponta para outro lugar. Remova o registro lá antes de usá-lo aqui."); return -1; }
    }
    free(o.p); o = (sb){0};
    snprintf(body, sizeof body, "{\"type\":\"CNAME\",\"name\":\"%s\",\"content\":\"%s.cfargotunnel.com\",\"proxied\":true,\"ttl\":1}", host, tunnel_id);
    if (exists) snprintf(pth, sizeof pth, "/zones/%s/dns_records/%s", zid, rid); else snprintf(pth, sizeof pth, "/zones/%s/dns_records", zid);
    cf_api(d, exists ? "PUT" : "POST", pth, body, &o);
    int ok = o.p && jtrue(o.p, "success");
    if (!ok) cf_err(&o, err, ec);
    free(o.p);
    return ok ? 0 : -1;
}
static void tunnel_write_cfg(void) { // chamar travado
    char p[PATH_MAX], cr[PATH_MAX]; dpath(p, sizeof p, "tunnel.yml"); cf_creds(cr, sizeof cr, tunnel_id);
    sb b = {0};
    sb_f(&b, "tunnel: %s\ncredentials-file: %s\ningress:\n", tunnel_id, cr);
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used && apps[i].host[0] && valid_host(apps[i].host)) sb_f(&b, "  - hostname: %s\n    service: http://127.0.0.1:%d\n", apps[i].host, apps[i].port);
    if (hook_host[0] && valid_host(hook_host)) sb_f(&b, "  - hostname: %s\n    service: http://127.0.0.1:%d\n", hook_host, cfg.port);
    sb_add(&b, "  - service: http_status:404\n", 30);
    spit(p, b.p); free(b.p);
}

/* ---------- ciclo de vida dos apps ---------- */
static void hist_add(const char *id, const char *sha, const char *msg, const char *trig, const char *res, long secs) {
    char p[PATH_MAX]; dpath(p, sizeof p, "apps/%s/history.tsv", id);
    FILE *f = fopen(p, "a");
    if (!f) return;
    fprintf(f, "%lld\t%.7s\t%s\t%s\t%s\t%ld\n", (long long)time(NULL), sha, trig, res, msg, secs);
    fclose(f);
}
static int port_free(int p) { // alguém no servidor já escuta nessa porta?
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), one = 1, r;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(p), .sin_addr.s_addr = INADDR_ANY};
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    r = bind(fd, (struct sockaddr *)&a, sizeof a);
    close(fd);
    return r == 0;
}
static int pick_port(void) { // chamar travado
    for (int p = 10000; p < 11000; p++) {
        int used = !port_free(p);
        for (int i = 0; i < MAXAPP; i++) if (apps[i].used && apps[i].port == p) used = 1;
        if (!used) return p;
    }
    return 0;
}
static int pick_iport(void) { // porta interna do app (só o proxy chega nela); chamar travado
    for (int p = 30000; p < 31000; p++) {
        int used = !port_free(p);
        for (int i = 0; i < MAXAPP; i++) if (apps[i].used && (apps[i].port == p || apps[i].iport == p)) used = 1;
        if (!used) return p;
    }
    return 0;
}
// copia o ambiente herdado para dst sem repetir nomes que já estão lá (glibc usa o primeiro valor, mas Python/Node usam o último)
static int env_dup(char **dst, int n, const char *e) {
    size_t k = strcspn(e, "=");
    for (int i = 0; i < n; i++) if (!strncmp(dst[i], e, k) && dst[i][k] == '=') return 1;
    return 0;
}
static void app_env_list(const App *a, char **dst, int *n, int max, int podman) { // KEY=VAL do usuário + banco vinculado
    char port[24]; Db *d = a->db[0] ? db_find(a->db) : NULL;
    const char *host = podman ? "host.containers.internal" : "127.0.0.1";
    if (*n + 8 >= max) return;
    snprintf(port, sizeof port, "PORT=%d", podman ? a->cport : a->iport); dst[(*n)++] = strdup(port);
    dst[(*n)++] = strdup(podman && a->expose ? "HOST=0.0.0.0" : "HOST=127.0.0.1"); // o proxy contador é quem abre para a rede; o app só precisa do loopback
    if (d) {
        int pg = !strcmp(d->engine, "postgres");
        char t[400];
        snprintf(t, sizeof t, "DATABASE_URL=%s://%s:%s@%s:%d/%s", pg ? "postgres" : "mysql", d->user, d->pw, host, pg ? 5432 : 3306, d->user); dst[(*n)++] = strdup(t);
        snprintf(t, sizeof t, "DB_HOST=%s", host); dst[(*n)++] = strdup(t);
        snprintf(t, sizeof t, "DB_PORT=%d", pg ? 5432 : 3306); dst[(*n)++] = strdup(t);
        snprintf(t, sizeof t, "DB_USER=%s", d->user); dst[(*n)++] = strdup(t);
        snprintf(t, sizeof t, "DB_PASSWORD=%s", d->pw); dst[(*n)++] = strdup(t);
        snprintf(t, sizeof t, "DB_NAME=%s", d->user); dst[(*n)++] = strdup(t);
    }
    char *e = strdup(a->env), *sv, *l;
    for (l = strtok_r(e, "\n", &sv); l && *n < max - 1; l = strtok_r(NULL, "\n", &sv)) dst[(*n)++] = strdup(l);
    free(e);
}
// Sobe o processo do app. Só o supervisor chama (PDEATHSIG vale por thread criadora). Chamar travado.
static void app_spawn(App *a) {
    char dir[PATH_MAX], src[PATH_MAX], lp[PATH_MAX], data[PATH_MAX];
    app_dir(dir, sizeof dir, a->id);
    snprintf(src, sizeof src, "%s/src", dir); snprintf(lp, sizeof lp, "%s/run.log", dir); snprintf(data, sizeof data, "%s/data", dir);
    struct stat st;
    if (!stat(lp, &st) && st.st_size > (2 << 20)) { char o[PATH_MAX + 4]; snprintf(o, sizeof o, "%s.1", lp); rename(lp, o); }
    int lfd = open(lp, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    int pod = !strcmp(a->rt, "podman");
    if (!pod && !a->start[0]) { // sem comando não há o que subir: não entra em laço, pede novo deploy (que detecta de novo)
        snprintf(a->last, sizeof a->last, "sem comando de início: faça um deploy para o servidor detectar");
        a->want = 0; app_save(a); if (lfd >= 0) close(lfd);
        return;
    }
    char *av[320], *ev[320], *own[320], *uenv[100]; // own: tudo que é strdup e precisa de free depois do fork
    int na = 0, ne = 0, no = 0, nu = 0;
    app_env_list(a, uenv, &nu, 100, pod);
    for (int i = 0; i < nu; i++) own[no++] = uenv[i];
    char t[PATH_MAX + 32], adir[PATH_MAX] = "";
    if (pod) {
        av[na++] = "podman"; av[na++] = "run"; av[na++] = "--rm";
        if (a->db[0]) av[na++] = "--network=pasta:--map-host-loopback,169.254.1.2"; // host.containers.internal -> loopback do host (onde o banco escuta)
        av[na++] = "--name";
        snprintf(t, sizeof t, "hs-%s", a->id); av[na++] = own[no++] = strdup(t);
        av[na++] = "--security-opt"; av[na++] = "no-new-privileges"; av[na++] = "--cap-drop=NET_RAW"; av[na++] = "--pids-limit=1024"; av[na++] = "--memory";
        snprintf(t, sizeof t, "%dm", a->mem); av[na++] = own[no++] = strdup(t);
        av[na++] = "-p";
        snprintf(t, sizeof t, "127.0.0.1:%d:%d", a->iport, a->cport); av[na++] = own[no++] = strdup(t);
        for (int i = 0; i < nu; i++) { // só o NOME no argv (qualquer usuário do servidor lê o argv em /proc); o valor segue pelo ambiente do podman, que só o dono lê
            size_t kn = strcspn(uenv[i], "=");
            av[na++] = "-e"; av[na++] = own[no++] = strndup(uenv[i], kn);
            ev[ne++] = uenv[i];
        }
        if (a->volume[0]) { snprintf(t, sizeof t, "hs-%s-data:%s", a->id, a->volume); av[na++] = "-v"; av[na++] = own[no++] = strdup(t); }
        snprintf(t, sizeof t, "localhost/hs-%s:latest", a->id); av[na++] = own[no++] = strdup(t);
    } else {
        mkdir(data, 0755);
        av[na++] = "sh"; av[na++] = "-c"; av[na++] = a->start;
        snprintf(t, sizeof t, "DATA_DIR=%s", data); ev[ne++] = own[no++] = strdup(t);
        if (cfg.sandbox && realpath(dir, adir)) { // HOME próprio (o home real fica fora do alcance do sandbox)
            char hd[PATH_MAX + 8]; snprintf(hd, sizeof hd, "%s/home", adir); mkdir(hd, 0700);
            snprintf(t, sizeof t, "HOME=%s", hd); ev[ne++] = own[no++] = strdup(t);
        }
        for (int i = 0; i < nu; i++) ev[ne++] = uenv[i]; // antes do environ: o primeiro valor vence
    }
    av[na] = NULL;
    for (char **e = environ; *e && ne < 300; e++) if (!env_dup(ev, ne, *e)) ev[ne++] = *e;
    ev[ne] = NULL;
    pid_t pid = fork();
    if (pid == 0) {
        setsid(); prctl(PR_SET_PDEATHSIG, SIGTERM);
        int nul = open("/dev/null", O_RDONLY);
        dup2(nul, 0); dup2(lfd >= 0 ? lfd : nul, 1); dup2(lfd >= 0 ? lfd : nul, 2);
        if (!pod && chdir(src)) _exit(126);
        if (!pod && adir[0]) sandbox_enter(adir);
        execvpe(av[0], av, ev);
        _exit(127);
    }
    if (lfd >= 0) close(lfd);
    for (int i = 0; i < no; i++) free(own[i]);
    a->pid = pid > 0 ? pid : 0; a->started = time(NULL); a->term_at = 0;
    if (pid < 0) a->nextstart = time(NULL) + 5;
}

static void *deploy_thread(void *arg);
typedef struct { char id[32]; char trig[12]; } DeployJob;
static int deploy_start(const char *id, const char *trig) { // chamar travado
    App *a = app_find(id);
    if (!a || a->deploying) return -1;
    a->deploying = 1;
    DeployJob *j = malloc(sizeof *j);
    snprintf(j->id, sizeof j->id, "%s", id); snprintf(j->trig, sizeof j->trig, "%s", trig);
    pthread_t t;
    pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &at, deploy_thread, j)) { a->deploying = 0; free(j); return -1; }
    return 0;
}

static void logf_(int fd, const char *fmt, ...) {
    char t[1024]; va_list a; va_start(a, fmt); int n = vsnprintf(t, sizeof t, fmt, a); va_end(a);
    if (fd >= 0 && write(fd, t, n < (int)sizeof t ? n : (int)sizeof t - 1) < 0) {}
}

/* ---------- projetos enviados por arquivo: extrair e entender a estrutura ---------- */
static int fexists(const char *dir, const char *f) { char p[PATH_MAX + 80]; snprintf(p, sizeof p, "%s/%s", dir, f); return !access(p, F_OK); }
// Extração (zip ou tar.gz) com limites e sem links: recusa caminhos absolutos ou que saem da pasta, passa de 50 mil arquivos ou de 2 GB
// descompactados (zip bomb), ignora links simbólicos, físicos, dispositivos e FIFOs, e devolve o bit de execução (sem setuid/setgid).
static const char *UNPACK_PY =
"import sys,os,zipfile,tarfile\n"
"up,dst,kind=sys.argv[1:4]\n"
"MAXN,MAXB=50000,2<<30\n"
"root=os.path.realpath(dst)\n"
"def bad(n):\n"
" p=os.path.realpath(os.path.join(root,n))\n"
" return not(p==root or p.startswith(root+os.sep))\n"
"def die(m): sys.exit('ERRO: '+m)\n"
"if kind=='zip':\n"
" z=zipfile.ZipFile(up); inf=z.infolist()\n"
" if len(inf)>MAXN or sum(i.file_size for i in inf)>MAXB: die('arquivo grande demais depois de extraído')\n"
" for i in inf:\n"
"  if bad(i.filename): die('caminho inválido no arquivo: '+i.filename)\n"
" z.extractall(dst)\n"
" for i in inf:\n"
"  m=(i.external_attr>>16)&0o777; p=os.path.join(dst,i.filename)\n"
"  if m and not i.is_dir() and os.path.isfile(p) and not os.path.islink(p): os.chmod(p,m|0o600)\n"
" print(len(inf),'arquivos extraídos')\n"
"else:\n"
" t=tarfile.open(up,'r:gz'); ms=t.getmembers()\n"
" if len(ms)>MAXN or sum(m.size for m in ms if m.isfile())>MAXB: die('arquivo grande demais depois de extraído')\n"
" keep=[m for m in ms if m.isfile() or m.isdir()]\n"
" for m in keep:\n"
"  if bad(m.name): die('caminho inválido no arquivo: '+m.name)\n"
"  m.mode&=0o777; m.uid=m.gid=0; m.uname=m.gname=''\n"
" try: t.extractall(dst,members=keep,filter='data')\n"
" except TypeError: t.extractall(dst,members=keep)\n"
" print(len(keep),'arquivos extraídos;',len(ms)-len(keep),'links/dispositivos ignorados')\n";
static int unpack(const char *dir, const char *src, int fd, char *res, size_t rc) {
    char up[PATH_MAX + 16]; unsigned char m[4] = {0};
    snprintf(up, sizeof up, "%s/upload.bin", dir);
    FILE *f = fopen(up, "rb");
    if (!f) { snprintf(res, rc, "nenhum arquivo foi enviado ainda: envie o zip pelo painel"); return -1; }
    if (fread(m, 1, 4, f) < 2) m[0] = 0;
    fclose(f);
    rm_rf(src); mkdir(src, 0755);
    RunOpt o = {.fd = fd, .to = 900};
    int r;
    const char *kind = m[0] == 'P' && m[1] == 'K' ? "zip" : m[0] == 0x1f && m[1] == 0x8b ? "tar" : NULL;
    if (!kind) { snprintf(res, rc, "formato não suportado: envie um .zip ou .tar.gz"); return -1; }
    char *av[] = {"python3", "-I", "-c", (char *)UNPACK_PY, up, (char *)src, (char *)kind, NULL};
    r = run(av, &o);
    if (r) { snprintf(res, rc, "não consegui extrair o arquivo (corrompido, grande demais ou com caminhos inválidos; veja o log)"); return -1; }
    char junk[PATH_MAX + 20]; snprintf(junk, sizeof junk, "%s/__MACOSX", src); rm_rf(junk);
    // zip que traz uma pasta única por fora (projeto/...): sobe o conteúdo um nível
    DIR *d = opendir(src); int n = 0; char only[256] = "";
    for (struct dirent *de; d && (de = readdir(d));) { if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") || !strcmp(de->d_name, ".DS_Store")) continue; n++; snprintf(only, sizeof only, "%s", de->d_name); }
    if (d) closedir(d);
    char sub_[PATH_MAX + 300]; struct stat st;
    snprintf(sub_, sizeof sub_, "%s/%s", src, only);
    if (n == 1 && !stat(sub_, &st) && S_ISDIR(st.st_mode)) {
        char tmp[PATH_MAX + 20]; snprintf(tmp, sizeof tmp, "%s/.hs-flatten", src);
        if (!rename(sub_, tmp)) {
            DIR *d2 = opendir(tmp);
            for (struct dirent *de; d2 && (de = readdir(d2));) {
                if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
                char from[PATH_MAX + 300], to[PATH_MAX + 300]; snprintf(from, sizeof from, "%s/%s", tmp, de->d_name); snprintf(to, sizeof to, "%s/%s", src, de->d_name);
                if (rename(from, to)) {}
            }
            if (d2) closedir(d2);
            rmdir(tmp);
            logf_(fd, "==> o arquivo tinha a pasta \"%s\" por fora; usando o conteúdo dela\n", only);
        }
    }
    return 0;
}
// descobre como construir e iniciar quando o usuário não informou (marcadores do projeto; heurística simples)
static int detect(const char *src, App *A, int fd, char *res, size_t rc) {
    char pj[8192] = "", p[PATH_MAX + 40];
    if (fexists(src, "package.json")) {
        snprintf(p, sizeof p, "%s/package.json", src); slurp(p, pj, sizeof pj);
        if (!have("npm")) { snprintf(res, rc, "projeto Node detectado, mas node/npm não estão instalados no servidor (use um Dockerfile ou instale o node)"); return -1; }
        int hb = strstr(pj, "\"build\"") != NULL, hs = strstr(pj, "\"start\"") != NULL; // ponytail: não lê o JSON, só procura a chave
        if (!A->build[0]) snprintf(A->build, sizeof A->build, "%s%s", fexists(src, "package-lock.json") ? "npm ci" : "npm install", hb ? " && npm run build" : "");
        snprintf(A->start, sizeof A->start, "%s", hs ? "npm start" : fexists(src, "server.js") ? "node server.js" : fexists(src, "index.js") ? "node index.js" : fexists(src, "app.js") ? "node app.js" : "");
        if (!A->start[0]) { snprintf(res, rc, "projeto Node sem script \"start\" nem server.js/index.js/app.js: informe o comando de início"); return -1; }
        logf_(fd, "==> estrutura detectada: Node.js\n");
    } else if (fexists(src, "requirements.txt") || fexists(src, "manage.py") || fexists(src, "app.py") || fexists(src, "main.py")) {
        int req = fexists(src, "requirements.txt");
        const char *py = req ? ".venv/bin/python" : "python3";
        if (req && !A->build[0]) snprintf(A->build, sizeof A->build, "python3 -m venv .venv && .venv/bin/pip install -r requirements.txt");
        if (fexists(src, "manage.py")) snprintf(A->start, sizeof A->start, "%s manage.py runserver 0.0.0.0:$PORT", py);
        else { const char *f = fexists(src, "app.py") ? "app.py" : fexists(src, "main.py") ? "main.py" : fexists(src, "server.py") ? "server.py" : NULL;
               if (!f) { snprintf(res, rc, "projeto Python sem app.py, main.py, server.py ou manage.py: informe o comando de início"); return -1; }
               snprintf(A->start, sizeof A->start, "%s %s", py, f); }
        logf_(fd, "==> estrutura detectada: Python%s\n", req ? " (com venv e requirements.txt)" : "");
    } else if (fexists(src, "go.mod")) {
        if (!have("go")) { snprintf(res, rc, "projeto Go detectado, mas o go não está instalado no servidor (use um Dockerfile)"); return -1; }
        if (!A->build[0]) snprintf(A->build, sizeof A->build, "go build -o app .");
        snprintf(A->start, sizeof A->start, "./app");
        logf_(fd, "==> estrutura detectada: Go\n");
    } else {
        const char *dirs[] = {"dist", "build", "public", "."};
        for (int i = 0; i < 4; i++) {
            char d[PATH_MAX + 20]; snprintf(d, sizeof d, "%s/%s", src, dirs[i]);
            if (fexists(d, "index.html")) {
                snprintf(A->start, sizeof A->start, "python3 -m http.server \"$PORT\" --bind \"$HOST\" -d %s", dirs[i]);
                logf_(fd, "==> estrutura detectada: site estático (%s/index.html)\n", dirs[i]);
                return 0;
            }
        }
        snprintf(res, rc, "não reconheci a estrutura (sem Dockerfile, package.json, requirements.txt, go.mod ou index.html): informe os comandos em Execução avançada");
        return -1;
    }
    logf_(fd, "==> build: %s\n==> início: %s\n", A->build[0] ? A->build : "(nenhum)", A->start);
    return 0;
}

static void *deploy_thread(void *arg) {
    DeployJob *j = arg;
    pthread_mutex_lock(&build_mx); // um build por vez: o servidor tem 4 núcleos
    pthread_mutex_lock(&gmx);
    App *ap = app_find(j->id), A;
    if (!ap) { pthread_mutex_unlock(&gmx); pthread_mutex_unlock(&build_mx); free(j); return NULL; }
    A = *ap;
    pthread_mutex_unlock(&gmx);

    char dir[PATH_MAX], src[PATH_MAX], lp[PATH_MAX], res[200] = "", sha[64] = "", msg[200] = "", rt[8];
    int detected = 0;
    time_t t0 = time(NULL);
    app_dir(dir, sizeof dir, A.id); mkdirp(dir);
    snprintf(src, sizeof src, "%s/src", dir); snprintf(lp, sizeof lp, "%s/deploy.log", dir);
    int fd = open(lp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (A.repo[0]) logf_(fd, "==> Deploy de %s (%s) a partir de %s@%s\n", A.name, j->trig, A.repo, A.branch);
    else logf_(fd, "==> Deploy de %s (%s) a partir do arquivo enviado\n", A.name, j->trig);

    // ambiente do git: o token vai por cabeçalho, nunca na URL
    char *genv[200]; int ng = 0;
    genv[ng++] = "GIT_TERMINAL_PROMPT=0";
    char hv[400] = "";
    if (A.token[0]) {
        char cred[200], enc[300]; snprintf(cred, sizeof cred, "x-access-token:%s", A.token); b64(cred, enc);
        snprintf(hv, sizeof hv, "GIT_CONFIG_VALUE_0=Authorization: Basic %s", enc);
        genv[ng++] = "GIT_CONFIG_COUNT=1"; genv[ng++] = "GIT_CONFIG_KEY_0=http.extraHeader"; genv[ng++] = hv;
    }
    for (char **e = environ; *e && ng < 195; e++) genv[ng++] = *e;
    genv[ng] = NULL;
    RunOpt go = {.cwd = NULL, .env = genv, .fd = fd, .to = 600};
    char url[300]; snprintf(url, sizeof url, "%s%s.git", cfg.git_base, A.repo);

    int rc;
    if (!A.repo[0]) { // projeto enviado por arquivo: extrai o upload e segue como qualquer outro
        if (unpack(dir, src, fd, res, sizeof res)) goto fail;
        struct stat us; char up[PATH_MAX + 16]; snprintf(up, sizeof up, "%s/upload.bin", dir);
        if (!stat(up, &us)) snprintf(sha, sizeof sha, "%016llx%016llx", (long long)us.st_size, (long long)us.st_mtime);
        snprintf(msg, sizeof msg, "Envio: %.100s", A.upname[0] ? A.upname : "arquivo");
        logf_(fd, "==> %s\n", msg);
    } else {
    struct stat st; char gd[PATH_MAX + 8]; snprintf(gd, sizeof gd, "%s/.git", src);
    if (!stat(gd, &st)) {
        logf_(fd, "==> git fetch\n");
        char *f1[] = {"git", "-C", src, "fetch", "--depth", "1", "origin", A.branch, NULL};
        rc = run(f1, &go);
        if (!rc) { char *f2[] = {"git", "-C", src, "reset", "--hard", "FETCH_HEAD", NULL}; rc = run(f2, &go); }
    } else {
        rm_rf(src);
        logf_(fd, "==> git clone\n");
        char *c1[] = {"git", "clone", "--depth", "1", "--branch", A.branch, url, src, NULL};
        rc = run(c1, &go);
    }
    if (rc) { snprintf(res, sizeof res, "falhou ao buscar o código no GitHub (confira repositório, branch e token)"); goto fail; }
    { sb o = {0}; char *r1[] = {"git", "-C", src, "rev-parse", "HEAD", NULL}; capture(r1, &o, NULL, 20); if (o.p) { snprintf(sha, sizeof sha, "%.40s", o.p); trim(sha); } free(o.p);
      o = (sb){0}; char *r2[] = {"git", "-C", src, "log", "-1", "--pretty=%s", NULL}; capture(r2, &o, NULL, 20); if (o.p) { snprintf(msg, sizeof msg, "%.119s", o.p); trim(msg); } free(o.p); }
    logf_(fd, "==> commit %.7s %s\n", sha, msg);
    }

    // runtime: auto escolhe container se o repositório tem Dockerfile
    char df[PATH_MAX + 20]; snprintf(df, sizeof df, "%s/Dockerfile", src);
    int has_df = reg_file(df); // link simbólico não vale: um Dockerfile -> /algum/arquivo do servidor vazaria o conteúdo no log do build
    if (!has_df) { snprintf(df, sizeof df, "%s/Containerfile", src); has_df = reg_file(df); }
    snprintf(rt, sizeof rt, "%s", !strcmp(A.runtime, "auto") ? (has_df ? "podman" : "native") : A.runtime);
    logf_(fd, "==> runtime: %s\n", rt);
    if (!strcmp(rt, "native") && !A.nat) { snprintf(res, sizeof res, "seu usuário só pode usar containers: coloque um Dockerfile na raiz do projeto"); goto fail; }

    // ambiente do build: variáveis do app também valem aqui
    char *uenv[100]; int nu = 0, ne = 0; char *benv[200];
    pthread_mutex_lock(&gmx); app_env_list(&A, uenv, &nu, 100, 0); pthread_mutex_unlock(&gmx);
    for (int i = 0; i < nu; i++) benv[ne++] = uenv[i];
    char badir[PATH_MAX] = "", hbuf[PATH_MAX + 16];
    if (cfg.sandbox && realpath(dir, badir)) { // build também no sandbox, com HOME próprio (npm/pip/go gravam cache em $HOME)
        char hd[PATH_MAX + 8]; snprintf(hd, sizeof hd, "%s/home", badir); mkdir(hd, 0700);
        snprintf(hbuf, sizeof hbuf, "HOME=%s", hd); benv[ne++] = hbuf;
    }
    for (char **e = environ; *e && ne < 195; e++) if (!env_dup(benv, ne, *e)) benv[ne++] = *e;
    benv[ne] = NULL;

    if (!strcmp(rt, "podman")) {
        if (!tools.podman) { snprintf(res, sizeof res, "podman não está instalado no servidor (rode hosting-setup.sh)"); goto fail_free; }
        if (!has_df) { snprintf(res, sizeof res, "runtime podman pede um Dockerfile na raiz do repositório"); goto fail_free; }
        logf_(fd, "==> podman build\n");
        { char *pr[] = {"podman", "image", "prune", "-f", NULL}; quiet(pr, 60); } // imagens sem tag e sem uso dos builds anteriores
        char tag[80]; snprintf(tag, sizeof tag, "localhost/hs-%s:latest", A.id);
        RunOpt bo = {.cwd = src, .fd = fd, .to = 1800};
        char *pb[] = {"podman", "build", "-t", tag, "-f", df, src, NULL};
        rc = run(pb, &bo);
    } else {
        if (!A.start[0]) { if (detect(src, &A, fd, res, sizeof res)) goto fail_free; detected = 1; }
        rc = 0;
        if (A.build[0]) {
            logf_(fd, "==> %s\n", A.build);
            RunOpt bo = {.cwd = src, .env = benv, .fd = fd, .to = 1800, .sandbox = badir[0] ? badir : NULL};
            char *sh[] = {"sh", "-c", A.build, NULL};
            rc = run(sh, &bo);
        }
    }
    for (int i = 0; i < nu; i++) free(uenv[i]);
    if (rc) { snprintf(res, sizeof res, "o build falhou (código %d); veja o log", rc); goto fail; }

    logf_(fd, "==> pronto em %lds\n", (long)(time(NULL) - t0));
    pthread_mutex_lock(&gmx);
    if ((ap = app_find(j->id))) {
        snprintf(ap->commit, sizeof ap->commit, "%s", sha); snprintf(ap->msg, sizeof ap->msg, "%s", msg); snprintf(ap->rt, sizeof ap->rt, "%s", rt);
        snprintf(ap->last, sizeof ap->last, "ok"); ap->deployed = time(NULL);
        if (detected) { snprintf(ap->build, sizeof ap->build, "%s", A.build); snprintf(ap->start, sizeof ap->start, "%s", A.start); }
        ap->want = 1; ap->respawn = 1; ap->fails = 0; ap->deploying = 0; // detectado fica salvo: o supervisor usa e o painel mostra
        if (ap->pid > 0) { kill(-ap->pid, SIGTERM); ap->term_at = time(NULL); } else ap->nextstart = 0;
        app_save(ap);
    }
    pthread_mutex_unlock(&gmx);
    hist_add(j->id, sha, msg, j->trig, "ok", (long)(time(NULL) - t0));
    goto end;
fail_free:
    for (int i = 0; i < nu; i++) free(uenv[i]);
fail:
    logf_(fd, "==> ERRO: %s\n", res);
    pthread_mutex_lock(&gmx);
    if ((ap = app_find(j->id))) { snprintf(ap->last, sizeof ap->last, "%s", res); ap->deploying = 0; app_save(ap); }
    pthread_mutex_unlock(&gmx);
    hist_add(j->id, sha[0] ? sha : "-", msg[0] ? msg : "-", j->trig, "erro", (long)(time(NULL) - t0));
end:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&build_mx);
    free(j);
    return NULL;
}

static void probe_tools(void) {
    int pg = 0, my = 0;
    sb o = {0};
    int ps = have("psql"), ms = have("mariadb") || have("mysql");
    if (ps) pg = db_run("postgres", NULL, "select 1", &o, 5) == 0;
    free(o.p); o = (sb){0};
    const char *mb = have("mariadb") ? "mariadb" : "mysql";
    snprintf(tools.mybin, sizeof tools.mybin, "%s", mb); // db_run usa tools.mybin
    if (ms) my = db_run("mysql", NULL, "select 1", &o, 5) == 0;
    free(o.p);
    pthread_mutex_lock(&gmx);
    tools.git = have("git"); tools.podman = have("podman"); tools.cloudflared = have("cloudflared");
    tools.psql = ps; tools.mysql = ms; tools.pg_up = pg; tools.my_up = my; snprintf(tools.mybin, sizeof tools.mybin, "%s", mb);
    pthread_mutex_unlock(&gmx);
}

// sondas lentas (servidores de banco) numa thread própria: um banco travado não pode atrasar o start dos apps
static void *prober(void *arg) {
    (void)arg;
    while (!quit) { probe_tools(); for (int i = 0; i < 20 && !quit; i++) sleep(1); }
    return NULL;
}

// supervisor: reaper, reinício com backoff, escalada TERM->KILL, túnel
static void stats_flush_all(void);
static void *supervisor(void *arg) {
    (void)arg;
    pid_t tpid = 0; time_t tnext = 0;
    while (!quit) {
        nanosleep(&(struct timespec){0, 500000000}, NULL);
        time_t now = time(NULL);
        pthread_mutex_lock(&gmx);
        for (int i = 0; i < MAXAPP; i++) {
            App *a = &apps[i];
            if (!a->used) continue;
            int st;
            if (a->pid > 0 && waitpid(a->pid, &st, WNOHANG) == a->pid) {
                // o líder (sh) morreu mas pode ter deixado filhos no grupo: encerra antes de religar, senão seguram a porta
                if (kill(-a->pid, 0) == 0) { kill(-a->pid, SIGTERM); a->pgid = a->pid; a->pg_kill = now + 10; }
                a->pid = 0;
                if (a->want && !a->respawn) {
                    a->fails = now - a->started > 60 ? 1 : a->fails + 1;
                    a->nextstart = now + (a->fails > 5 ? 30 : 1 << a->fails);
                    a->restarts++;
                }
                if (!a->want && !strcmp(a->rt, "podman")) { char n[48]; snprintf(n, sizeof n, "hs-%s", a->id); char *av[] = {"podman", "rm", "-f", n, NULL}; quiet(av, 20); }
            }
            if (a->pgid) { if (kill(-a->pgid, 0)) a->pgid = 0; else if (now >= a->pg_kill) kill(-a->pgid, SIGKILL); }
            if (a->pid > 0 && a->stop_req) { kill(-a->pid, SIGTERM); a->term_at = now; a->stop_req = 0; a->want = 0; app_save(a); }
            if (a->pid > 0 && a->term_at && now - a->term_at > 12) { kill(-a->pid, SIGKILL); a->term_at = 0; }
            if (a->pid == 0 && a->stop_req) { a->stop_req = 0; a->want = 0; app_save(a); }
            if (a->pid == 0 && !a->pgid && a->want && a->commit[0] && now >= a->nextstart) {
                if (!strcmp(a->rt, "podman")) { // sobra de uma execução anterior com o mesmo nome
                    char n[48]; snprintf(n, sizeof n, "hs-%s", a->id); char *av[] = {"podman", "rm", "-f", n, NULL};
                    pthread_mutex_unlock(&gmx); quiet(av, 20); pthread_mutex_lock(&gmx);
                    if (!a->used) continue;
                }
                a->respawn = 0; app_spawn(a);
            }
        }
        // túnel: sobe com ingress dos apps que têm domínio; reinicia quando a lista muda
        int want_tunnel = 0;
        for (int i = 0; i < MAXAPP; i++) if (apps[i].used && apps[i].host[0]) want_tunnel = 1;
        if (hook_host[0]) want_tunnel = 1;
        if (tpid > 0 && waitpid(tpid, NULL, WNOHANG) == tpid) { tpid = 0; tnext = now + 5; }
        if (tpid > 0 && (tunnel_dirty || !want_tunnel)) { kill(-tpid, SIGTERM); nanosleep(&(struct timespec){1, 0}, NULL); if (waitpid(tpid, NULL, WNOHANG) != tpid) { kill(-tpid, SIGKILL); waitpid(tpid, NULL, 0); } tpid = 0; tnext = 0; }
        if (!tpid && want_tunnel && tunnel_id[0] && now >= tnext) {
            tunnel_write_cfg(); tunnel_dirty = 0;
            char cfgp[PATH_MAX], lp[PATH_MAX]; dpath(cfgp, sizeof cfgp, "tunnel.yml"); dpath(lp, sizeof lp, "tunnel.log");
            int lfd = open(lp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
            pid_t p = fork();
            if (p == 0) {
                setsid(); prctl(PR_SET_PDEATHSIG, SIGTERM);
                int nul = open("/dev/null", O_RDONLY); dup2(nul, 0); dup2(lfd >= 0 ? lfd : nul, 1); dup2(lfd >= 0 ? lfd : nul, 2);
                execlp("cloudflared", "cloudflared", "tunnel", "--no-autoupdate", "--config", cfgp, "run", (char *)NULL);
                _exit(127);
            }
            if (lfd >= 0) close(lfd);
            tpid = p > 0 ? p : 0;
        } else if (!want_tunnel) tunnel_dirty = 0;
        tunnel_up = tpid > 0;
        pthread_mutex_unlock(&gmx);
    }
    // desligando: SIGTERM nos grupos dos apps e do túnel, espera de verdade (até 10 s), SIGKILL no que sobrar, e só então sai.
    // O main não decide a saída: um segundo sinal não pode matar o processo antes de os apps caírem.
    pid_t grp[2 * MAXAPP + 1]; int ng = 0;
    pthread_mutex_lock(&gmx);
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used) {
        if (apps[i].pid > 0) grp[ng++] = apps[i].pid;
        if (apps[i].pgid) grp[ng++] = apps[i].pgid;
    }
    if (tpid > 0) grp[ng++] = tpid;
    for (int i = 0; i < ng; i++) kill(-grp[i], SIGTERM);
    pthread_mutex_unlock(&gmx);
    for (int t = 0; t < 100; t++) {
        while (waitpid(-1, NULL, WNOHANG) > 0); // reapa os líderes para o grupo poder sumir
        int alive = 0;
        for (int i = 0; i < ng; i++) if (kill(-grp[i], 0) == 0) alive = 1;
        if (!alive) break;
        nanosleep(&(struct timespec){0, 100000000}, NULL);
    }
    for (int i = 0; i < ng; i++) kill(-grp[i], SIGKILL);
    stats_flush_all();
    exit(0);
}

// poller: sem webhook acessível, olha o GitHub a cada 2 min (git ls-remote) e faz deploy do que mudou
static void *poller(void *arg) {
    (void)arg;
    while (!quit) {
        for (int s = 0; s < 120 && !quit; s++) sleep(1);
        char ids[MAXAPP][32], br[MAXAPP][64], rp[MAXAPP][96], tk[MAXAPP][128], cm[MAXAPP][41]; int n = 0;
        pthread_mutex_lock(&gmx);
        for (int i = 0; i < MAXAPP; i++) if (apps[i].used && apps[i].repo[0] && apps[i].autodeploy && apps[i].commit[0] && !apps[i].deploying) {
            snprintf(ids[n], 32, "%s", apps[i].id); snprintf(br[n], 64, "%s", apps[i].branch); snprintf(rp[n], 96, "%s", apps[i].repo);
            snprintf(tk[n], 128, "%s", apps[i].token); snprintf(cm[n], 41, "%s", apps[i].commit); n++;
        }
        pthread_mutex_unlock(&gmx);
        for (int i = 0; i < n; i++) {
            char url[300], hv[400] = "", *env[200]; int ne = 0;
            snprintf(url, sizeof url, "%s%s.git", cfg.git_base, rp[i]);
            env[ne++] = "GIT_TERMINAL_PROMPT=0";
            if (tk[i][0]) { char c[200], e[300]; snprintf(c, sizeof c, "x-access-token:%s", tk[i]); b64(c, e); snprintf(hv, sizeof hv, "GIT_CONFIG_VALUE_0=Authorization: Basic %s", e); env[ne++] = "GIT_CONFIG_COUNT=1"; env[ne++] = "GIT_CONFIG_KEY_0=http.extraHeader"; env[ne++] = hv; }
            for (char **e = environ; *e && ne < 195; e++) env[ne++] = *e;
            env[ne] = NULL;
            sb o = {0}; char ref[100]; snprintf(ref, sizeof ref, "refs/heads/%s", br[i]);
            char *av[] = {"git", "ls-remote", url, ref, NULL};
            RunOpt ro = {.fd = -1, .out = &o, .env = env, .to = 30};
            int rc = run(av, &ro);
            if (!rc && o.p && strlen(o.p) >= 40 && strncmp(o.p, cm[i], 40) && isxdigit((unsigned char)o.p[0])) { pthread_mutex_lock(&gmx); deploy_start(ids[i], "poll"); pthread_mutex_unlock(&gmx); }
            free(o.p);
        }
    }
    return NULL;
}

/* ---------- http ---------- */
typedef struct {
    char method[8], path[512], query[1024], cookie[256], ip[48], xhr[24], sig[80], event[24], authz[160];
    int public; // veio pela internet (túnel do Cloudflare ou outro proxy reverso): só /hook/
    long long clen;
    const char *extra; size_t extra_len;
} Req;

static const char *status_text(int c) {
    switch (c) {
    case 200: return "OK"; case 400: return "Bad Request"; case 401: return "Unauthorized"; case 403: return "Forbidden";
    case 404: return "Not Found"; case 409: return "Conflict"; case 413: return "Payload Too Large"; case 503: return "Service Unavailable";
    default: return "Internal Server Error";
    }
}
static int send_all(int fd, const char *p, size_t n) {
    while (n) { ssize_t r = send(fd, p, n, MSG_NOSIGNAL); if (r <= 0) return -1; p += r; n -= r; }
    return 0;
}
static void reply(int c, int code, const char *ctype, const char *body, size_t n, const char *extra) {
    char h[768];
    int l = snprintf(h, sizeof h, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'\r\nConnection: close\r\n%s\r\n",
                     code, status_text(code), ctype, n, extra ? extra : "");
    if (send_all(c, h, l) == 0 && n) send_all(c, body, n);
}
static void jerr(int c, int code, const char *msg) {
    sb b = {0};
    sb_add(&b, "{\"error\":", 9); sb_str(&b, msg); sb_add(&b, "}", 1);
    reply(c, code, "application/json", b.p, b.n, NULL);
    free(b.p);
}
static void jok(int c) { reply(c, 200, "application/json", "{\"ok\":1}", 8, NULL); }
static void udec(char *o, const char *s, size_t n, size_t cap) {
    size_t j = 0;
    for (size_t i = 0; i < n && j + 1 < cap; i++) {
        if (s[i] == '%' && i + 2 < n && isxdigit((unsigned char)s[i+1]) && isxdigit((unsigned char)s[i+2])) { char h[3] = {s[i+1], s[i+2], 0}; o[j++] = strtol(h, NULL, 16); i += 2; }
        else if (s[i] == '+') o[j++] = ' ';
        else o[j++] = s[i];
    }
    o[j] = 0;
}
static int fget(const char *q, const char *key, char *out, size_t cap) {
    size_t kl = strlen(key);
    for (const char *p = q; p && *p;) {
        if (!strncmp(p, key, kl) && p[kl] == '=') { const char *v = p + kl + 1; udec(out, v, strcspn(v, "&"), cap); return 1; }
        p = strchr(p, '&'); if (p) p++;
    }
    out[0] = 0;
    return 0;
}
static const char *mime_of(const char *p) {
    const char *e = strrchr(p, '.');
    static const struct { const char *e, *m; } t[] = {{".html", "text/html; charset=utf-8"}, {".css", "text/css"}, {".js", "text/javascript"}, {".svg", "image/svg+xml"},
        {".png", "image/png"}, {".ico", "image/x-icon"}, {".woff2", "font/woff2"}, {NULL, NULL}};
    for (int i = 0; e && t[i].e; i++) if (!strcasecmp(e, t[i].e)) return t[i].m;
    return "application/octet-stream";
}
static void serve_static(int c, const Req *rq) {
    char p[PATH_MAX * 2];
    const char *u = !strcmp(rq->path, "/") ? "/index.html" : rq->path;
    if (strstr(u, "..")) { jerr(c, 400, "caminho inválido"); return; }
    snprintf(p, sizeof p, "%s%s", cfg.web, u);
    int fd = open(p, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || S_ISDIR(st.st_mode)) { if (fd >= 0) close(fd); jerr(c, 404, "não encontrado"); return; }
    char h[512];
    int l = snprintf(h, sizeof h, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %lld\r\nCache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n", mime_of(p), (long long)st.st_size);
    if (!send_all(c, h, l)) { off_t off = 0; long long left = st.st_size; while (left > 0) { ssize_t r = sendfile(c, fd, &off, left); if (r <= 0) break; left -= r; } }
    close(fd);
}
// corpo inteiro numa área alocada (o chamador libera); NULL se grande demais ou incompleto
static char *read_body(int c, const Req *rq, size_t max) {
    if (rq->clen < 0 || (size_t)rq->clen > max) return NULL;
    char *b = malloc(rq->clen + 1);
    size_t have = rq->extra_len < (size_t)rq->clen ? rq->extra_len : (size_t)rq->clen;
    memcpy(b, rq->extra, have);
    time_t dl = time(NULL) + 30; // prazo total: quem pinga um byte por vez não segura a conexão
    while (have < (size_t)rq->clen) {
        struct pollfd pf = {c, POLLIN, 0};
        int ms = (int)(dl - time(NULL)) * 1000;
        if (ms <= 0 || poll(&pf, 1, ms) <= 0) { free(b); return NULL; }
        ssize_t r = recv(c, b + have, rq->clen - have, 0);
        if (r <= 0) { free(b); return NULL; }
        have += r;
    }
    b[have] = 0;
    return b;
}

/* ---------- autenticação: pergunta ao homelabOS (porta 80 e a do gestor) quem é o dono do cookie e qual o papel ---------- */
static struct { char tok[33]; const char *user; time_t exp; } ac[16];
static char known[16][16]; static int known_adm[16]; // nomes já vistos (ponteiros estáveis para o resto do código) e se são administradores
static pthread_mutex_t acmx = PTHREAD_MUTEX_INITIALIZER;
static const char *intern(const char *u, int adm) { // acmx travado
    for (int i = 0; i < 16; i++) if (!strcmp(known[i], u)) { known_adm[i] = adm; return known[i]; }
    for (int i = 0; i < 16; i++) if (!known[i][0]) { snprintf(known[i], sizeof known[i], "%s", u); known_adm[i] = adm; return known[i]; }
    return NULL;
}
static int is_admin(const char *me) {
    int r = 0;
    pthread_mutex_lock(&acmx);
    for (int i = 0; i < 16; i++) if (known[i][0] && !strcmp(known[i], me)) r = known_adm[i];
    pthread_mutex_unlock(&acmx);
    return r;
}
static int native_ok(const char *me) { // comandos de build/início rodam no servidor: só o administrador e quem estiver em native_users=
    if (is_admin(me)) return 1;
    char l[sizeof cfg.native], *sv, *t; snprintf(l, sizeof l, "%s", cfg.native);
    for (t = strtok_r(l, ", ", &sv); t; t = strtok_r(NULL, ", ", &sv)) if (!strcasecmp(t, me)) return 1;
    return 0;
}
static int dash_me(int port, const char *tok, char *user, size_t cap, int *adm) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct timeval tv = {2, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    char req[200], buf[1024], role[16] = ""; size_t n = 0; int ok = 0;
    if (connect(s, (struct sockaddr *)&a, sizeof a)) { close(s); return 0; }
    int l = snprintf(req, sizeof req, "GET /api/me HTTP/1.1\r\nHost: localhost\r\nCookie: hl=%s\r\nConnection: close\r\n\r\n", tok);
    if (!send_all(s, req, l)) {
        ssize_t r;
        while (n < sizeof buf - 1 && (r = recv(s, buf + n, sizeof buf - 1 - n, 0)) > 0) n += r;
        buf[n] = 0;
        ok = strstr(buf, "\"ok\":1") && jfind(buf, "user", user, cap);
        jfind(buf, "role", role, sizeof role);
    }
    close(s);
    *adm = !strcmp(role, "admin");
    return ok;
}
/* token de API (para o MCP/automação): data/api_token, 0600. Header "Authorization: Bearer <token>" vale como o administrador (admin= no conf).
   Só chega aqui por /api/ na porta do painel (pelo túnel público só entra /hook/). */
static char api_tok[65];
static void api_token_load(void) {
    char p[PATH_MAX]; dpath(p, sizeof p, "api_token");
    char b[96];
    if (!slurp(p, b, sizeof b)) { trim(b); if (strlen(b) >= 32) { snprintf(api_tok, sizeof api_tok, "%.64s", b); return; } }
    rand_hex(api_tok, 32);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) { if (write(fd, api_tok, strlen(api_tok)) < 0) { /* sem token persistido: vale só até reiniciar */ } close(fd); }
}
static int bearer_ok(const char *h) {
    if (strncasecmp(h, "Bearer ", 7) || !api_tok[0]) return 0;
    const char *t = h + 7; size_t n = strlen(api_tok), diff = strlen(t) ^ n;
    for (size_t i = 0; i < n; i++) diff |= (unsigned char)(t[i] ^ api_tok[i]); // comparação em tempo constante
    return diff == 0;
}
static int user_ok(const char *u) { // nome seguro para virar "dono" gravado em disco
    size_t n = strlen(u);
    if (!n || n > 15 || !strcmp(u, "shared")) return 0;
    for (; *u; u++) if (!isalnum((unsigned char)*u) && !strchr("_-.", *u)) return 0;
    return 1;
}
static const char *auth(const Req *rq) {
    if (rq->authz[0]) {
        if (!bearer_ok(rq->authz)) return NULL;
        pthread_mutex_lock(&acmx); const char *u = intern(cfg.admin, 1); pthread_mutex_unlock(&acmx);
        return u;
    }
    char tok[33] = ""; // cookie "hl" com o nome exato (não vale "xhl=") e 32 hex
    for (const char *p = rq->cookie; *p;) {
        while (*p == ' ' || *p == ';') p++;
        size_t n = strcspn(p, ";");
        if (n == 35 && !strncmp(p, "hl=", 3) && strspn(p + 3, "0123456789abcdef") == 32) { memcpy(tok, p + 3, 32); break; }
        p += n;
    }
    if (!tok[0]) return NULL;
    pthread_mutex_lock(&acmx);
    for (int i = 0; i < 16; i++) if (ac[i].exp > time(NULL) && ct_eq(ac[i].tok, tok)) { const char *u = ac[i].user; pthread_mutex_unlock(&acmx); return u; }
    pthread_mutex_unlock(&acmx);
    char ports[64], *sv, *pt, user[32] = "";
    snprintf(ports, sizeof ports, "%s", cfg.dash);
    for (pt = strtok_r(ports, ",", &sv); pt; pt = strtok_r(NULL, ",", &sv)) {
        int adm = 0;
        if (!dash_me(atoi(pt), tok, user, sizeof user, &adm)) continue;
        for (char *c = user; *c; c++) *c = tolower((unsigned char)*c);
        if (!user_ok(user)) continue;
        pthread_mutex_lock(&acmx);
        const char *u = intern(user, adm);
        if (u) {
            int slot = 0;
            for (int k = 0; k < 16; k++) if (ac[k].exp < ac[slot].exp) slot = k;
            memcpy(ac[slot].tok, tok, 33); ac[slot].user = u; ac[slot].exp = time(NULL) + 20;
        }
        pthread_mutex_unlock(&acmx);
        return u;
    }
    return NULL;
}


/* ---------- estatísticas + proxy contador ----------
   Cada app tem um proxy na porta pública (a do túnel e da rede). O app de verdade escuta em 127.0.0.1:<iport>.
   O proxy lê o cabeçalho, repassa com "Connection: close" (uma requisição por conexão: contagem exata; Upgrade/WebSocket vira túnel)
   e registra. Guarda por hora (stats.tsv) e por dia os "tops" (top-<dia>.tsv), dentro de apps/<id>/. IP nunca é gravado: só um hash
   com sal que muda todo dia, então "visitante" é único por dia e não dá para seguir alguém entre dias. */
#define HB 10
#define TOPN 80
#define NKIND 5 // 0 páginas, 1 origens, 2 países, 3 navegadores, 4 dispositivos
#define HSET 4096
#define DSET 16384
#define KEEP_DAYS 35
static const int LATMS[HB] = {10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000};
enum { H_HOUR, H_REQ, H_PAGES, H_BOTS, H_S2, H_S3, H_S4, H_S5, H_BIN, H_BOUT, H_LATSUM, H_UNIQ, H_DUNIQ, H_LAT, H_N = H_LAT + HB };
typedef long long Row[H_N];
typedef struct { char k[96]; int n; } Top;
typedef struct {
    char id[32]; int used;
    Row cur; long long day, dcount;
    uint64_t *hset, *dset;
    struct { uint64_t h; time_t t; } seen[256];
    Top top[NKIND][TOPN];
} Stat;
static Stat sts[MAXAPP];
static pthread_mutex_t smx = PTHREAD_MUTEX_INITIALIZER; // ordem: gmx antes de smx, nunca o contrário
static char salt[33];

static long long hour_of(time_t t) { return (long long)t - (long long)t % 3600; }
static long long day_start(time_t t) { struct tm m; localtime_r(&t, &m); return (long long)t - m.tm_hour * 3600 - m.tm_min * 60 - m.tm_sec; }
static void row_write(FILE *f, const Row r) { for (int i = 0; i < H_N; i++) fprintf(f, i ? "\t%lld" : "%lld", r[i]); fputc('\n', f); }
static int row_parse(const char *l, Row r) {
    for (int i = 0; i < H_N; i++) { char *e; r[i] = strtoll(l, &e, 10); if (e == l) return 0; l = *e == '\t' ? e + 1 : e; }
    return 1;
}
static void st_path(char *o, size_t c, const char *id, const char *f) { dpath(o, c, "apps/%s/%s", id, f); }
static void st_append(const char *id, const Row r) { // só se a pasta do app existir (app apagado não ressuscita)
    char p[PATH_MAX]; st_path(p, sizeof p, id, "stats.tsv");
    FILE *f = fopen(p, "a");
    if (f) { row_write(f, r); fclose(f); }
}
static void top_file(char *o, size_t c, const char *id, long long day) { char f[48]; snprintf(f, sizeof f, "top-%lld.tsv", day); st_path(o, c, id, f); }
static void top_add_n(Top *t, int cap, const char *key, int n) { // cheio: soma em "(outros)" na última posição
    int i = 0;
    for (; i < cap - 1 && t[i].k[0]; i++) if (!strcmp(t[i].k, key)) { t[i].n += n; return; }
    if (i < cap - 1) { snprintf(t[i].k, sizeof t[i].k, "%s", key); t[i].n = n; return; }
    snprintf(t[cap - 1].k, sizeof t[cap - 1].k, "(outros)"); t[cap - 1].n += n;
}
static void top_save(Stat *s) {
    char p[PATH_MAX]; top_file(p, sizeof p, s->id, s->day);
    FILE *f = fopen(p, "w");
    if (!f) return;
    for (int k = 0; k < NKIND; k++) for (int i = 0; i < TOPN && s->top[k][i].k[0]; i++) fprintf(f, "%d\t%d\t%s\n", k, s->top[k][i].n, s->top[k][i].k);
    fclose(f);
}
// lê um arquivo de tops e soma em dst[NKIND] (cada um com cap posições)
static void top_load(const char *p, Top (*dst)[TOPN], int cap) {
    FILE *f = fopen(p, "r"); char l[200];
    while (f && fgets(l, sizeof l, f)) {
        l[strcspn(l, "\r\n")] = 0;
        int k, n, o;
        if (sscanf(l, "%d\t%d\t%n", &k, &n, &o) >= 2 && k >= 0 && k < NKIND) top_add_n(dst[k], cap, l + o, n);
    }
    if (f) fclose(f);
}
static void st_load(Stat *s, time_t now) { // restaura o que um reinício interrompeu
    char p[PATH_MAX], l[512]; Row r;
    st_path(p, sizeof p, s->id, "stats.cur");
    FILE *f = fopen(p, "r");
    if (f && fgets(l, sizeof l, f) && row_parse(l, r)) {
        if (r[H_HOUR] == hour_of(now)) memcpy(s->cur, r, sizeof r);
        else if (r[H_REQ]) st_append(s->id, r);
        if (day_start(r[H_HOUR]) == day_start(now)) s->dcount = r[H_DUNIQ];
    }
    if (f) fclose(f);
    s->day = day_start(now);
    s->cur[H_HOUR] = hour_of(now); s->cur[H_DUNIQ] = s->dcount;
    top_file(p, sizeof p, s->id, s->day);
    top_load(p, s->top, TOPN);
}
static Stat *st_get(const char *id, time_t now) { // travado em smx
    Stat *fr = NULL;
    for (int i = 0; i < MAXAPP; i++) {
        if (sts[i].used) { if (!strcmp(sts[i].id, id)) return &sts[i]; }
        else if (!fr) fr = &sts[i];
    }
    if (!fr) return NULL;
    memset(fr, 0, sizeof *fr);
    fr->used = 1; snprintf(fr->id, sizeof fr->id, "%s", id);
    fr->hset = calloc(HSET, sizeof(uint64_t)); fr->dset = calloc(DSET, sizeof(uint64_t));
    st_load(fr, now);
    return fr;
}
static void st_roll(Stat *s, time_t now) { // virou a hora (e talvez o dia)
    if (s->cur[H_HOUR] == hour_of(now)) return;
    if (s->cur[H_REQ]) st_append(s->id, s->cur);
    long long nd = day_start(now);
    if (nd != s->day) {
        top_save(s);
        memset(s->top, 0, sizeof s->top); memset(s->dset, 0, DSET * sizeof(uint64_t));
        s->dcount = 0; s->day = nd;
        char d[PATH_MAX]; DIR *dr; dpath(d, sizeof d, "apps/%s", s->id);
        if ((dr = opendir(d))) { // apaga tops antigos
            for (struct dirent *de; (de = readdir(dr));) {
                long long dd;
                if (sscanf(de->d_name, "top-%lld.tsv", &dd) == 1 && dd < nd - (long long)KEEP_DAYS * 86400) { char f[PATH_MAX * 2]; snprintf(f, sizeof f, "%s/%s", d, de->d_name); unlink(f); }
            }
            closedir(dr);
        }
    }
    memset(s->cur, 0, sizeof s->cur); s->cur[H_HOUR] = hour_of(now); s->cur[H_DUNIQ] = s->dcount;
    memset(s->hset, 0, HSET * sizeof(uint64_t));
}
static void st_flush(Stat *s) {
    char p[PATH_MAX], t[PATH_MAX + 8]; st_path(p, sizeof p, s->id, "stats.cur");
    snprintf(t, sizeof t, "%s.tmp", p);
    FILE *f = fopen(t, "w"); // sem mkdir: se o app foi apagado, simplesmente não grava
    if (!f) return;
    s->cur[H_DUNIQ] = s->dcount;
    row_write(f, s->cur); fclose(f); rename(t, p);
    top_save(s);
}
static int set_add(uint64_t *set, size_t cap, uint64_t h) { // 1 se era novo; conjunto saturado => 0 (conta a menos, não quebra)
    size_t i = h % cap;
    for (int n = 0; n < 64; n++, i = (i + 1) % cap) { if (!set[i]) { set[i] = h; return 1; } if (set[i] == h) return 0; }
    return 0;
}
static int stats_brief(const char *id, int *online, long long *vis) { // visitantes online (5 min) e únicos de hoje
    time_t now = time(NULL); *online = 0; *vis = 0;
    pthread_mutex_lock(&smx);
    for (int i = 0; i < MAXAPP; i++) if (sts[i].used && !strcmp(sts[i].id, id)) {
        for (int k = 0; k < 256; k++) if (sts[i].seen[k].h && now - sts[i].seen[k].t < 300) (*online)++;
        *vis = sts[i].day == day_start(now) ? sts[i].dcount : 0;
    }
    pthread_mutex_unlock(&smx);
    return 0;
}

typedef struct { char ip[64], method[12], path[300], ua[240], ref[240], host[128], country[8]; int status, ms; long long bin, bout; } Hit;
static int has_ci(const char *h, const char *n) { return strcasestr(h, n) != NULL; }
static int is_bot(const char *ua) {
    static const char *w[] = {"bot", "crawl", "spider", "slurp", "curl/", "wget", "python-", "go-http", "headless", "monitor", "uptime", "pingdom", "lighthouse", "preview", "scanner", "httpclient", "java/", "libwww", "axios", "node-fetch", "aiohttp", "okhttp", "cfnetwork", NULL};
    if (!ua[0]) return 1;
    for (int i = 0; w[i]; i++) if (has_ci(ua, w[i])) return 1;
    return 0;
}
static const char *ua_browser(const char *ua) {
    if (has_ci(ua, "edg/") || has_ci(ua, "edge/")) return "Edge";
    if (has_ci(ua, "opr/") || has_ci(ua, "opera")) return "Opera";
    if (has_ci(ua, "firefox") || has_ci(ua, "fxios")) return "Firefox";
    if (has_ci(ua, "chrome") || has_ci(ua, "crios")) return "Chrome";
    if (has_ci(ua, "safari")) return "Safari";
    return "Outro";
}
static const char *ua_device(const char *ua) {
    if (has_ci(ua, "ipad") || has_ci(ua, "tablet")) return "Tablet";
    if (has_ci(ua, "mobi") || has_ci(ua, "android") || has_ci(ua, "iphone")) return "Celular";
    return "Computador";
}
// caminho sem query; números e hashes longos viram :id para os "tops" não explodirem
static void norm_path(char *o, size_t cap, const char *in) {
    size_t j = 0;
    for (const char *p = in; *p && *p != '?' && *p != '#' && j + 8 < cap;) {
        if (*p == '/') { o[j++] = *p++; continue; }
        size_t n = strcspn(p, "/?#"), dig = 0, hex = 0;
        for (size_t k = 0; k < n; k++) { dig += isdigit((unsigned char)p[k]) != 0; hex += isxdigit((unsigned char)p[k]) != 0 || p[k] == '-'; }
        if ((n >= 3 && dig == n) || (n >= 16 && hex == n)) { memcpy(o + j, ":id", 3); j += 3; }
        else { size_t m = n < cap - j - 8 ? n : cap - j - 8; memcpy(o + j, p, m); j += m; }
        p += n;
    }
    o[j] = 0;
    if (!j) { o[0] = '/'; o[1] = 0; }
}
static void stats_record(const char *id, const Hit *h) {
    time_t now = time(NULL);
    int bot = is_bot(h->ua), ok = h->status > 0 && h->status < 400;
    const char *last = strrchr(h->path, '/'); last = last ? last + 1 : h->path;
    int page = !bot && ok && !strcmp(h->method, "GET") && (!strchr(last, '.') || has_ci(last, ".html") || has_ci(last, ".htm"));
    uint64_t hv = 0;
    if (!bot && ok) {
        char in[300], d[32]; uint8_t out[32];
        snprintf(d, sizeof d, "%lld", day_start(now));
        int n = snprintf(in, sizeof in, "%s|%s|%s|%s", salt, d, id, h->ip);
        sha256((uint8_t *)in, n, out); memcpy(&hv, out, 8); if (!hv) hv = 1;
    }
    char path[120] = "", ref[120] = "", ctry[16] = "", brw[16] = "", dev[16] = "";
    if (page) {
        norm_path(path + 0, sizeof path, h->path);
        const char *u = strstr(h->ref, "://"); u = u ? u + 3 : h->ref;
        size_t hl = strcspn(u, "/:"), mine = strcspn(h->host, ":");
        if (!h->ref[0]) snprintf(ref, sizeof ref, "(direto)");
        else if (!(hl == mine && !strncasecmp(u, h->host, hl))) snprintf(ref, sizeof ref, "%.*s", (int)(hl < 100 ? hl : 100), u); // navegação interna não conta
        if (h->country[0]) snprintf(ctry, sizeof ctry, "%s", h->country); else snprintf(ctry, sizeof ctry, "(rede local)");
        snprintf(brw, sizeof brw, "%s", ua_browser(h->ua)); snprintf(dev, sizeof dev, "%s", ua_device(h->ua));
    }
    pthread_mutex_lock(&smx);
    Stat *s = st_get(id, now);
    if (!s) { pthread_mutex_unlock(&smx); return; }
    st_roll(s, now);
    long long *c = s->cur;
    c[H_REQ]++; c[H_BIN] += h->bin; c[H_BOUT] += h->bout; c[H_LATSUM] += h->ms;
    if (bot) c[H_BOTS]++;
    int cl = h->status / 100;
    c[cl == 3 ? H_S3 : cl == 4 ? H_S4 : cl == 5 || cl == 0 ? H_S5 : H_S2]++;
    int b = 0; while (b < HB - 1 && h->ms > LATMS[b]) b++;
    c[H_LAT + b]++;
    if (hv) {
        if (set_add(s->hset, HSET, hv)) c[H_UNIQ]++;
        if (set_add(s->dset, DSET, hv)) { s->dcount++; c[H_DUNIQ] = s->dcount; }
        int slot = 0;
        for (int i = 0; i < 256; i++) { if (s->seen[i].h == hv) { slot = i; break; } if (s->seen[i].t < s->seen[slot].t) slot = i; }
        s->seen[slot].h = hv; s->seen[slot].t = now;
    }
    if (page) {
        c[H_PAGES]++;
        top_add_n(s->top[0], TOPN, path, 1);
        if (ref[0]) top_add_n(s->top[1], TOPN, ref, 1);
        top_add_n(s->top[2], TOPN, ctry, 1); top_add_n(s->top[3], TOPN, brw, 1); top_add_n(s->top[4], TOPN, dev, 1);
    }
    pthread_mutex_unlock(&smx);
}

/* --- proxy --- */
#define LIT(b, s) sb_add((b), (s), sizeof(s) - 1) // nunca contar o tamanho de um literal à mão
typedef struct { char id[32]; int port, iport, expose, fd; volatile int stop; } Lis;
typedef struct { char id[32]; int iport, c; struct in_addr peer; } PxCtx;
static Lis *lis[MAXAPP];
static int pxconn;

static const char *PX_502_BODY = "<!doctype html><meta charset=utf-8><title>Indisponível</title><body style=\"font:16px sans-serif;padding:3em\"><h1>Aplicação indisponível</h1>";
static void px_502(int c) {
    char h[256];
    int n = snprintf(h, sizeof h, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", strlen(PX_502_BODY));
    if (send_all(c, h, n) == 0) send_all(c, PX_502_BODY, strlen(PX_502_BODY));
}
static int hdr_is(const char *l, const char *name) { size_t n = strlen(name); return !strncasecmp(l, name, n) && l[n] == ':'; }
static void hdr_val(const char *l, char *dst, size_t cap) { const char *v = strchr(l, ':') + 1; while (*v == ' ') v++; snprintf(dst, cap, "%.*s", (int)strcspn(v, "\r\n"), v); }

// Copia o Cookie do visitante para o app SEM o cookie de sessão do painel ("hl"): cookies não isolam portas, então o navegador manda
// o "hl" do administrador para qualquer app deste IP; sem este filtro o dono do app roubaria a sessão.
static void ck_strip(sb *up, const char *l, size_t ll) {
    const char *v = strchr(l, ':') + 1, *end = l + ll;
    sb kept = {0};
    while (v < end) {
        while (v < end && (*v == ' ' || *v == ';')) v++;
        const char *e = memchr(v, ';', end - v); if (!e) e = end;
        size_t nl = strcspn(v, "=;"); if ((const char *)v + nl > e) nl = e - v;
        if (!(nl == 2 && !strncasecmp(v, "hl", 2)) && e > v) { if (kept.n) sb_add(&kept, "; ", 2); sb_add(&kept, v, e - v); }
        v = e;
    }
    if (kept.n) { LIT(up, "Cookie: "); sb_add(up, kept.p, kept.n); LIT(up, "\r\n"); }
    free(kept.p);
}
static void *px_conn(void *arg) {
    PxCtx *x = arg; int c = x->c, u = -1;
    struct timeval tv = {5, 0}; // cabeçalho: no máximo 10 s no total (slowloris)
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char *buf = malloc(16384), *rb = malloc(16384);
    size_t len = 0; char *he;
    time_t t_hdr = time(NULL) + 10;
    if (!buf || !rb) goto done;
    while (!(he = memmem(buf, len, "\r\n\r\n", 4))) {
        if (time(NULL) > t_hdr) goto done;
        if (len >= 16384) { { const char *e431 = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"; send_all(c, e431, strlen(e431)); } goto done; }
        ssize_t r = recv(c, buf + len, 16384 - len, 0);
        if (r <= 0) goto done;
        len += r;
    }
    tv.tv_sec = 30; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    Hit h = {0};
    char cfip[64] = "", target[400] = "", cc[16] = "";
    int upg = 0, has_xff = 0;
    size_t headlen = he + 4 - buf;
    *he = 0; // a primeira passada trata o cabeçalho como texto
    if (sscanf(buf, "%11s %399s", h.method, target) != 2) goto done;
    snprintf(h.path, sizeof h.path, "%s", target);
    for (char *l = strstr(buf, "\r\n"); l; l = strstr(l + 2, "\r\n")) {
        l += 2;
        if (hdr_is(l, "user-agent")) hdr_val(l, h.ua, sizeof h.ua);
        else if (hdr_is(l, "referer")) hdr_val(l, h.ref, sizeof h.ref);
        else if (hdr_is(l, "host")) hdr_val(l, h.host, sizeof h.host);
        else if (hdr_is(l, "cf-connecting-ip")) hdr_val(l, cfip, sizeof cfip);
        else if (hdr_is(l, "cf-ipcountry")) { hdr_val(l, cc, sizeof cc); }
        else if (hdr_is(l, "x-forwarded-for")) has_xff = 1;
        else if (hdr_is(l, "upgrade")) upg = 1;
    }
    char peer[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &x->peer, peer, sizeof peer);
    // CF-Connecting-IP só vale vindo do cloudflared (loopback) e só com cara de endereço
    int loop = (ntohl(x->peer.s_addr) >> 24) == 127;
    snprintf(h.ip, sizeof h.ip, "%s", loop && cfip[0] && strspn(cfip, "0123456789abcdefABCDEF.:") == strlen(cfip) ? cfip : peer);
    if (strlen(cc) == 2 && strcmp(cc, "XX") && strcmp(cc, "T1")) { h.country[0] = toupper((unsigned char)cc[0]); h.country[1] = toupper((unsigned char)cc[1]); }
    // monta a requisição para o app: tira Connection/Keep-Alive (exceto em Upgrade) e fecha a conexão ao fim
    sb up = {0};
    sb_f(&up, "%.*s\r\n", (int)strcspn(buf, "\r\n"), buf); // primeira linha (método, alvo, versão)
    for (char *l = strstr(buf, "\r\n"); l; ) {
        l += 2;
        char *nx = strstr(l, "\r\n");
        size_t ll = nx ? (size_t)(nx - l) : strlen(l);
        if (ll && hdr_is(l, "cookie")) { ck_strip(&up, l, ll); l = nx; continue; }
        if (ll && !(!upg && (hdr_is(l, "connection") || hdr_is(l, "proxy-connection") || hdr_is(l, "keep-alive")))) { sb_add(&up, l, ll); LIT(&up, "\r\n"); }
        l = nx;
    }
    if (!upg) LIT(&up, "Connection: close\r\n");
    if (!has_xff && !cfip[0]) sb_f(&up, "X-Forwarded-For: %s\r\n", peer);
    LIT(&up, "\r\n");
    size_t extra = len - headlen;
    if (extra) sb_add(&up, buf + headlen, extra);
    h.bin = extra;

    u = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(x->iport), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct timeval ct = {3, 0};
    setsockopt(u, SOL_SOCKET, SO_SNDTIMEO, &ct, sizeof ct);
    if (u < 0 || connect(u, (struct sockaddr *)&a, sizeof a) || send_all(u, up.p, up.n)) {
        px_502(c);
        h.status = 502; clock_gettime(CLOCK_MONOTONIC, &t1);
        h.ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        free(up.p);
        stats_record(x->id, &h);
        goto done;
    }
    free(up.p);
    int got = 0, cdone = 0, idle = upg ? 3600000 : 120000;
    for (;;) {
        struct pollfd p[2] = {{cdone ? -1 : c, POLLIN, 0}, {u, POLLIN, 0}};
        if (poll(p, 2, idle) <= 0) break;
        if (p[1].revents) {
            ssize_t n = recv(u, rb, 16384, 0);
            if (n <= 0) break;
            if (!got) {
                got = 1; clock_gettime(CLOCK_MONOTONIC, &t1);
                h.ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
                if (n >= 12 && !strncmp(rb, "HTTP/", 5)) h.status = atoi(rb + 9);
            }
            if (send_all(c, rb, n)) break;
            h.bout += n;
        }
        if (!cdone && p[0].revents) {
            ssize_t n = recv(c, rb, 16384, 0);
            if (n <= 0) { cdone = 1; shutdown(u, SHUT_WR); }
            else { if (send_all(u, rb, n)) break; h.bin += n; }
        }
    }
    if (!got) { clock_gettime(CLOCK_MONOTONIC, &t1); h.ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000; }
    if (h.status >= 100 && h.status < 200) h.status = 200; // 101 Switching Protocols (WebSocket) é sucesso
    stats_record(x->id, &h);
done:
    if (u >= 0) close(u);
    close(c); free(buf); free(rb); free(x);
    __atomic_fetch_sub(&pxconn, 1, __ATOMIC_RELAXED);
    return NULL;
}
static void *lis_thread(void *arg) {
    Lis *L = arg;
    pthread_attr_t at; pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 256 * 1024); pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    while (!L->stop && !quit) {
        struct pollfd p = {L->fd, POLLIN, 0};
        if (poll(&p, 1, 200) <= 0) continue;
        struct sockaddr_in pa; socklen_t pl = sizeof pa;
        int c = accept4(L->fd, (struct sockaddr *)&pa, &pl, SOCK_CLOEXEC);
        if (c < 0) continue;
        PxCtx *x = malloc(sizeof *x); pthread_t t;
        if (!x || __atomic_add_fetch(&pxconn, 1, __ATOMIC_RELAXED) > 512) { if (x) __atomic_fetch_sub(&pxconn, 1, __ATOMIC_RELAXED); free(x); close(c); continue; }
        snprintf(x->id, sizeof x->id, "%s", L->id); x->iport = L->iport; x->c = c; x->peer = pa.sin_addr;
        if (pthread_create(&t, &at, px_conn, x)) { __atomic_fetch_sub(&pxconn, 1, __ATOMIC_RELAXED); free(x); close(c); }
    }
    close(L->fd); free(L);
    return NULL;
}
// uma thread por app com porta; reconcilia a cada 0,5 s (app novo, porta ou exposição mudada, app apagado)
static void *proxy_mgr(void *arg) {
    (void)arg;
    while (!quit) {
        struct { char id[32]; int port, iport, expose; } w[MAXAPP]; int nw = 0;
        pthread_mutex_lock(&gmx);
        for (int i = 0; i < MAXAPP; i++) if (apps[i].used && apps[i].port > 0 && apps[i].iport > 0) {
            snprintf(w[nw].id, sizeof w[nw].id, "%s", apps[i].id); w[nw].port = apps[i].port; w[nw].iport = apps[i].iport; w[nw].expose = apps[i].expose; nw++;
        }
        pthread_mutex_unlock(&gmx);
        for (int i = 0; i < MAXAPP; i++) if (lis[i]) {
            int keep = 0;
            for (int k = 0; k < nw; k++) if (!strcmp(w[k].id, lis[i]->id) && w[k].port == lis[i]->port && w[k].iport == lis[i]->iport && w[k].expose == lis[i]->expose) keep = 1;
            if (!keep) { lis[i]->stop = 1; lis[i] = NULL; }
        }
        for (int k = 0; k < nw; k++) {
            int have_l = 0, slot = -1;
            for (int i = 0; i < MAXAPP; i++) { if (lis[i] && !strcmp(lis[i]->id, w[k].id)) have_l = 1; if (!lis[i] && slot < 0) slot = i; }
            if (have_l || slot < 0) continue;
            int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), one = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
            struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(w[k].port), .sin_addr.s_addr = w[k].expose ? INADDR_ANY : htonl(INADDR_LOOPBACK)};
            if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 128)) { if (fd >= 0) close(fd); continue; } // porta ainda ocupada (antigo proxy fechando): tenta no próximo ciclo
            Lis *L = calloc(1, sizeof *L); pthread_t t;
            snprintf(L->id, sizeof L->id, "%s", w[k].id); L->port = w[k].port; L->iport = w[k].iport; L->expose = w[k].expose; L->fd = fd;
            if (pthread_create(&t, NULL, lis_thread, L)) { close(fd); free(L); continue; }
            pthread_detach(t); lis[slot] = L;
        }
        nanosleep(&(struct timespec){0, 500000000}, NULL);
    }
    return NULL;
}
static void stats_flush_all(void) {
    char live[MAXAPP][32]; int nl = 0;
    pthread_mutex_lock(&gmx);
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used) snprintf(live[nl++], 32, "%s", apps[i].id);
    pthread_mutex_unlock(&gmx);
    time_t now = time(NULL);
    pthread_mutex_lock(&smx);
    for (int i = 0; i < MAXAPP; i++) if (sts[i].used) {
        int alive = 0;
        for (int k = 0; k < nl; k++) if (!strcmp(live[k], sts[i].id)) alive = 1;
        if (!alive) { free(sts[i].hset); free(sts[i].dset); memset(&sts[i], 0, sizeof sts[i]); continue; }
        st_roll(&sts[i], now); st_flush(&sts[i]);
    }
    pthread_mutex_unlock(&smx);
}
static void *stats_thread(void *arg) {
    (void)arg;
    char p[PATH_MAX]; dpath(p, sizeof p, "stats.salt");
    if (slurp(p, salt, sizeof salt) || strlen(salt) < 32) {
        rand_hex(salt, 16);
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd >= 0) { if (write(fd, salt, 32) < 0) {} close(fd); }
    }
    time_t now = time(NULL);
    pthread_mutex_lock(&gmx); // carrega o que ficou do último run
    char ids[MAXAPP][32]; int n = 0;
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used) snprintf(ids[n++], 32, "%s", apps[i].id);
    pthread_mutex_unlock(&gmx);
    pthread_mutex_lock(&smx); for (int i = 0; i < n; i++) st_get(ids[i], now); pthread_mutex_unlock(&smx);
    while (!quit) { for (int i = 0; i < 30 && !quit; i++) sleep(1); stats_flush_all(); }
    return NULL;
}

// GET /api/stats?app=<id|all>&range=24h|7d|30d
static int cmp_top(const void *a, const void *b) { return ((const Top *)b)->n - ((const Top *)a)->n; }
static void api_stats(int c, const Req *rq, const char *me) {
    char app[40], range[8];
    fget(rq->query, "app", app, sizeof app); fget(rq->query, "range", range, sizeof range);
    int nd = !strcmp(range, "30d") ? 30 : !strcmp(range, "7d") ? 7 : 1, nh = nd == 1 ? 24 : nd * 24;
    struct { char id[32], name[64]; } tg[MAXAPP]; int nt = 0, all = !app[0] || !strcmp(app, "all");
    pthread_mutex_lock(&gmx);
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used && can(me, apps[i].owner) && (all || !strcmp(apps[i].id, app))) {
        snprintf(tg[nt].id, 32, "%s", apps[i].id); snprintf(tg[nt].name, 64, "%s", apps[i].name); nt++;
    }
    pthread_mutex_unlock(&gmx);
    if (!nt && !all) { jerr(c, 404, "aplicação não encontrada"); return; }
    time_t now = time(NULL);
    long long w0 = hour_of(now) - (long long)(nh - 1) * 3600, d0 = day_start(now) - (long long)(nd - 1) * 86400;
    long long tot[H_N] = {0}, *hreq = calloc(nh, 8), *hvis = calloc(nh, 8), dv[31] = {0}, online = 0;
    Top (*agg)[256] = calloc(NKIND, sizeof *agg), (*day)[TOPN] = calloc(NKIND, sizeof *day);
    Row *rows = malloc(2400 * sizeof(Row));
    for (int a = 0; a < nt; a++) {
        long long dmax[31] = {0}; int aon = 0;
        int nr = 0;
        char p[PATH_MAX]; st_path(p, sizeof p, tg[a].id, "stats.tsv");
        FILE *f = fopen(p, "r"); char l[512];
        while (f && nr < 2399 && fgets(l, sizeof l, f)) if (row_parse(l, rows[nr])) nr++;
        if (f) fclose(f);
        pthread_mutex_lock(&smx);
        Stat *s = st_get(tg[a].id, now);
        if (s) {
            if (s->cur[H_HOUR]) memcpy(rows[nr++], s->cur, sizeof(Row));
            for (int k = 0; k < 256; k++) if (s->seen[k].h && now - s->seen[k].t < 300) aon++;
            for (int k = 0; k < NKIND; k++) for (int i = 0; i < TOPN && s->top[k][i].k[0]; i++) top_add_n(day[k], TOPN, s->top[k][i].k, s->top[k][i].n);
        }
        long long today = s ? s->day : 0;
        pthread_mutex_unlock(&smx);
        for (int r = 0; r < nr; r++) {
            long long hr = rows[r][H_HOUR];
            if (hr >= w0) {
                int ix = (int)((hr - w0) / 3600); if (ix >= nh) ix = nh - 1;
                for (int i = 1; i < H_N; i++) if (i != H_UNIQ && i != H_DUNIQ) tot[i] += rows[r][i];
                hreq[ix] += rows[r][H_REQ]; hvis[ix] += rows[r][H_UNIQ];
            }
            long long ds = day_start(hr);
            if (ds >= d0 - 3600) { int di = (int)((ds - d0 + 43200) / 86400); if (di >= 0 && di < nd && rows[r][H_DUNIQ] > dmax[di]) dmax[di] = rows[r][H_DUNIQ]; }
        }
        for (int d = 0; d < nd; d++) dv[d] += dmax[d];
        for (int d = 1; d < nd; d++) { // dias anteriores vêm dos arquivos; o de hoje já veio da memória
            char tf[PATH_MAX]; long long ds = day_start(day_start(now) + 12 * 3600 - (long long)d * 86400);
            if (ds == today) continue;
            top_file(tf, sizeof tf, tg[a].id, ds); top_load(tf, day, TOPN);
        }
        for (int k = 0; k < NKIND; k++) for (int i = 0; i < TOPN && day[k][i].k[0]; i++) top_add_n(agg[k], 256, day[k][i].k, day[k][i].n);
        memset(day, 0, NKIND * sizeof *day);
        online += aon;
    }
    free(rows);
    long long vis = 0; for (int d = 0; d < nd; d++) vis += dv[d];
    long long n50 = 0, n95 = 0, ln = 0; for (int i = 0; i < HB; i++) ln += tot[H_LAT + i];
    for (int i = 0, acc = 0; i < HB; i++) { acc += tot[H_LAT + i]; if (!n50 && acc * 2 >= ln && ln) n50 = LATMS[i]; if (!n95 && acc * 100 >= ln * 95 && ln) n95 = LATMS[i]; }
    sb b = {0};
    sb_f(&b, "{\"range\":\"%s\",\"now\":%lld,\"online\":%lld,\"visitors_today\":%lld,\"visitors\":%lld,\"req\":%lld,\"pages\":%lld,\"bots\":%lld,\"s2\":%lld,\"s3\":%lld,\"s4\":%lld,\"s5\":%lld,\"bin\":%lld,\"bout\":%lld,\"p50\":%lld,\"p95\":%lld,\"avg\":%lld",
         nd == 30 ? "30d" : nd == 7 ? "7d" : "24h", (long long)now, online, dv[nd - 1], vis, tot[H_REQ], tot[H_PAGES], tot[H_BOTS], tot[H_S2], tot[H_S3], tot[H_S4], tot[H_S5], tot[H_BIN], tot[H_BOUT], n50, n95, tot[H_REQ] ? tot[H_LATSUM] / tot[H_REQ] : 0);
    sb_f(&b, ",\"hours\":[");
    for (int i = 0; i < nh; i++) sb_f(&b, "%s[%lld,%lld,%lld]", i ? "," : "", w0 + (long long)i * 3600, hreq[i], hvis[i]);
    sb_f(&b, "],\"days\":[");
    for (int d = 0; d < nd; d++) sb_f(&b, "%s[%lld,%lld]", d ? "," : "", d0 + (long long)d * 86400, dv[d]);
    sb_f(&b, "],\"top\":{");
    static const char *KN[NKIND] = {"pages", "refs", "countries", "browsers", "devices"};
    for (int k = 0; k < NKIND; k++) {
        int n = 0; while (n < 256 && agg[k][n].k[0]) n++;
        qsort(agg[k], n, sizeof(Top), cmp_top);
        sb_f(&b, "%s\"%s\":[", k ? "," : "", KN[k]);
        for (int i = 0; i < n && i < 10; i++) { sb_f(&b, "%s[", i ? "," : ""); sb_str(&b, agg[k][i].k); sb_f(&b, ",%d]", agg[k][i].n); }
        sb_add(&b, "]", 1);
    }
    sb_add(&b, "}", 1);
    if (all) { // por aplicação (o nome sai à parte para escapar direito)
        sb_f(&b, ",\"apps\":[");
        for (int a = 0; a < nt; a++) { int on; long long v; stats_brief(tg[a].id, &on, &v); sb_f(&b, "%s{\"id\":", a ? "," : ""); sb_str(&b, tg[a].id); sb_add(&b, ",\"name\":", 8); sb_str(&b, tg[a].name); sb_f(&b, ",\"online\":%d,\"vis\":%lld}", on, v); }
        sb_add(&b, "]", 1);
    }
    sb_add(&b, "}", 1);
    reply(c, 200, "application/json", b.p, b.n, NULL);
    free(b.p); free(hreq); free(hvis); free(agg); free(day);
}

/* ---------- api ---------- */
static const char *app_state(const App *a) {
    if (a->deploying) return "building";
    if (a->want) return a->pid > 0 ? "running" : a->commit[0] ? "restarting" : "pending";
    return a->commit[0] ? "stopped" : "new";
}
static void overview(int c, const char *me) {
    sb b = {0};
    int adm = is_admin(me), nat = native_ok(me);
    pthread_mutex_lock(&gmx);
    sb_add(&b, "{\"me\":", 6); sb_str(&b, me); sb_f(&b, ",\"admin\":%d,\"native\":%d", adm, nat);
    sb_f(&b, ",\"tools\":{\"git\":%d,\"podman\":%d,\"cloudflared\":%d,\"psql\":%d,\"mysql\":%d,\"pg_up\":%d,\"my_up\":%d},\"tunnel\":{\"id\":", tools.git, tools.podman, tools.cloudflared, tools.psql, tools.mysql, tools.pg_up, tools.my_up);
    sb_str(&b, tunnel_id); sb_f(&b, ",\"up\":%d},\"hook_host\":", tunnel_up); sb_str(&b, hook_host);
    sb_add(&b, ",\"apps\":[", 9);
    int first = 1;
    for (int i = 0; i < MAXAPP; i++) {
        App *a = &apps[i];
        if (!a->used || !can(me, a->owner)) continue;
        sb_add(&b, first ? "{\"id\":" : ",{\"id\":", first ? 6 : 7); first = 0;
        sb_str(&b, a->id);
#define JS(k, v) sb_add(&b, ",\"" k "\":", sizeof k + 3), sb_str(&b, v)
        JS("name", a->name); JS("owner", a->owner); JS("repo", a->repo); JS("branch", a->branch); JS("build", a->build); JS("start", a->start);
        JS("runtime", a->runtime); JS("rt", a->rt); JS("host", a->host); JS("db", a->db); JS("volume", a->volume); JS("env", a->env);
        JS("commit", a->commit); JS("msg", a->msg); JS("last", a->last); JS("state", app_state(a)); JS("secret", a->secret); JS("upname", a->upname);
        int on; long long vis; stats_brief(a->id, &on, &vis);
        sb_f(&b, ",\"online\":%d,\"vis\":%lld,\"iport\":%d", on, vis, a->iport);
        sb_f(&b, ",\"port\":%d,\"cport\":%d,\"mem\":%d,\"expose\":%d,\"zip\":%d,\"autodeploy\":%d,\"has_token\":%d,\"deployed\":%lld,\"started\":%lld,\"restarts\":%d}",
             a->port, a->cport, a->mem, a->expose, !a->repo[0], a->autodeploy, a->token[0] != 0, (long long)a->deployed, a->pid > 0 ? (long long)a->started : 0, a->restarts);
    }
    sb_add(&b, "],\"dbs\":[", 9); first = 1;
    for (int i = 0; i < MAXDB; i++) {
        Db *d = &dbs[i];
        if (!d->used || !can(me, d->owner)) continue;
        int pg = !strcmp(d->engine, "postgres");
        sb_add(&b, first ? "{\"id\":" : ",{\"id\":", first ? 6 : 7); first = 0;
        sb_str(&b, d->id); JS("name", d->name); JS("engine", d->engine); JS("owner", d->owner); JS("user", d->user); JS("password", d->pw);
        sb_f(&b, ",\"port\":%d,\"created\":%lld}", pg ? 5432 : 3306, (long long)d->created);
    }
    sb_add(&b, "],\"domains\":[", 13); first = 1;
    for (int i = 0; i < MAXDOM; i++) {
        if (!doms[i].used || !can(me, doms[i].owner)) continue;
        sb_add(&b, first ? "{\"name\":" : ",{\"name\":", first ? 8 : 9); first = 0;
        sb_str(&b, doms[i].name); JS("owner", doms[i].owner);
        sb_f(&b, ",\"cert\":%d,\"has_token\":%d}", doms[i].cert, doms[i].token[0] != 0);
    }
    sb_add(&b, "]}", 2);
    pthread_mutex_unlock(&gmx);
    reply(c, 200, "application/json", b.p, b.n, NULL);
    free(b.p);
}

static int valid_host(const char *h) {
    size_t n = strlen(h);
    if (n < 3 || n > 120 || !strchr(h, '.') || strstr(h, "..") || h[0] == '.' || h[0] == '-' || h[n-1] == '.' || h[n-1] == '-') return 0;
    for (; *h; h++) if (!islower((unsigned char)*h) && !isdigit((unsigned char)*h) && *h != '.' && *h != '-') return 0;
    return 1;
}
static int valid_ident(const char *s, size_t max, const char *extra) {
    size_t n = strlen(s);
    if (!n || n > max) return 0;
    for (; *s; s++) if (!isalnum((unsigned char)*s) && !strchr(extra, *s)) return 0;
    return 1;
}
// aceita "dono/repo", "github.com/dono/repo" ou a URL completa; devolve "dono/repo"
static int norm_repo(const char *in, char *out, size_t cap) {
    char t[160]; snprintf(t, sizeof t, "%s", in); trim(t);
    char *s = t;
    if (!strncmp(s, "https://", 8)) s += 8; else if (!strncmp(s, "http://", 7)) s += 7;
    if (!strncmp(s, "github.com/", 11)) s += 11; else if (!strncmp(s, "git@github.com:", 15)) s += 15;
    size_t n = strlen(s);
    if (n > 4 && !strcmp(s + n - 4, ".git")) s[n -= 4] = 0;
    while (n && s[n-1] == '/') s[--n] = 0;
    char *sl = strchr(s, '/');
    if (!sl || strchr(sl + 1, '/') || sl == s || !sl[1]) return 0;
    for (char *p = s; *p; p++) if (!isalnum((unsigned char)*p) && !strchr("-_./", *p)) return 0;
    if (strstr(s, "..")) return 0;
    snprintf(out, cap, "%s", s);
    return 1;
}

static void app_expose(App *a, const char *me, char *warn, size_t wc) { // DNS + túnel para o host do app
    Domain d;
    pthread_mutex_lock(&gmx);
    Domain *p = dom_for(me, a->host);
    if (p) d = *p;
    pthread_mutex_unlock(&gmx);
    if (!p) { snprintf(warn, wc, "domínio não cadastrado"); return; }
    if (dns_route(&d, a->host, warn, wc) == 0) { warn[0] = 0; pthread_mutex_lock(&gmx); tunnel_dirty = 1; pthread_mutex_unlock(&gmx); }
}

static void api_app_save(int c, const Req *rq, const char *me) {
    char *f = read_body(c, rq, 24576);
    if (!f) { jerr(c, 400, "pedido inválido"); return; }
    char id[32], scope[12], repo_in[160], tok[128], dep[4], act[8], tmp[24], err[200] = "", source[8], ex[4], ptxt[12];
    App n; memset(&n, 0, sizeof n);
    fget(f, "id", id, sizeof id); fget(f, "scope", scope, sizeof scope);
    fget(f, "name", n.name, sizeof n.name); fget(f, "repo", repo_in, sizeof repo_in); fget(f, "branch", n.branch, sizeof n.branch);
    fget(f, "token", tok, sizeof tok); fget(f, "build", n.build, sizeof n.build); fget(f, "start", n.start, sizeof n.start);
    fget(f, "runtime", n.runtime, sizeof n.runtime); fget(f, "host", n.host, sizeof n.host); fget(f, "db", n.db, sizeof n.db);
    fget(f, "volume", n.volume, sizeof n.volume); fget(f, "env", n.env, sizeof n.env);
    fget(f, "cport", tmp, sizeof tmp); n.cport = atoi(tmp); fget(f, "mem", tmp, sizeof tmp); n.mem = atoi(tmp);
    fget(f, "autodeploy", dep, sizeof dep); n.autodeploy = dep[0] == '1'; fget(f, "deploy", act, sizeof act);
    fget(f, "source", source, sizeof source); fget(f, "expose", ex, sizeof ex); fget(f, "port", ptxt, sizeof ptxt);
    free(f);
    clean1(n.name); clean1(n.build); clean1(n.start); clean1(n.volume); trim(n.name);
    if (tok[0] && strcmp(tok, "-") && !valid_token(tok)) { jerr(c, 400, "Token inválido: use só letras, números e _ - . (copie o token inteiro, sem espaços)."); return; }
    char note[200] = "";
    if (!n.name[0]) { jerr(c, 400, "Digite um nome para a aplicação."); return; }
    if (!strcmp(source, "zip")) { n.repo[0] = 0; n.branch[0] = 0; n.autodeploy = 0; } // projeto por arquivo: sem GitHub
    else {
        if (!norm_repo(repo_in, n.repo, sizeof n.repo)) { jerr(c, 400, "Repositório inválido. Use dono/repositorio ou a URL do GitHub."); return; }
        if (!n.branch[0]) snprintf(n.branch, sizeof n.branch, "main");
        if (!valid_ident(n.branch, 60, "-_./") || strstr(n.branch, "..") || n.branch[0] == '-') { jerr(c, 400, "Branch inválida."); return; }
    }
    n.expose = ex[0] == '1';
    if (strcmp(n.runtime, "podman") && strcmp(n.runtime, "native")) snprintf(n.runtime, sizeof n.runtime, "auto");
    n.nat = native_ok(me);
    if (!n.nat) { // comandos de build/início rodam no servidor: só para quem tem esse direito; os demais ficam só com container
        snprintf(n.runtime, sizeof n.runtime, "podman"); n.build[0] = n.start[0] = 0;
        snprintf(note, sizeof note, "Seu usuário só pode rodar containers: coloque um Dockerfile na raiz do projeto.");
    }
    if (n.cport < 1 || n.cport > 65535) n.cport = 3000;
    if (n.mem < 64 || n.mem > 8192) n.mem = 512;
    if (n.volume[0] && (n.volume[0] != '/' || strpbrk(n.volume, ": \t"))) { jerr(c, 400, "O volume precisa ser um caminho absoluto dentro do container, como /data."); return; }
    for (char *s = n.host; *s; s++) *s = tolower((unsigned char)*s);
    trim(n.host);
    if (n.host[0] && !valid_host(n.host)) { jerr(c, 400, "Endereço inválido: use só letras minúsculas, números, pontos e hífens."); return; }
    // env: uma variável KEY=valor por linha; linhas inválidas são recusadas em vez de ignoradas
    { char *e = strdup(n.env), *sv, *l; n.env[0] = 0;
      for (l = strtok_r(e, "\n", &sv); l; l = strtok_r(NULL, "\n", &sv)) {
          l[strcspn(l, "\r")] = 0; if (!l[0]) continue;
          char *eq = strchr(l, '=');
          if (!eq || eq == l || (size_t)(eq - l) > 60 || !(isalpha((unsigned char)l[0]) || l[0] == '_')) { free(e); jerr(c, 400, "Variáveis de ambiente: use uma por linha, no formato NOME=valor."); return; }
          for (char *k = l; k < eq; k++) if (!isalnum((unsigned char)*k) && *k != '_') { free(e); jerr(c, 400, "Nome de variável inválido (só letras, números e _)."); return; }
          if (!strncmp(l, "PORT=", 5)) continue; // a porta é do painel
          if (strlen(n.env) + strlen(l) + 2 > sizeof n.env) { free(e); jerr(c, 400, "Variáveis de ambiente grandes demais."); return; }
          strcat(n.env, l); strcat(n.env, "\n");
      }
      free(e); }

    pthread_mutex_lock(&gmx);
    App *a = id[0] ? app_find(id) : NULL;
    if (id[0] && (!a || !can(me, a->owner))) { pthread_mutex_unlock(&gmx); jerr(c, 404, "aplicação não encontrada"); return; }
    const char *owner = !strcmp(scope, "shared") ? "shared" : me;
    if (a && !strcmp(scope, "") ) owner = a->owner;
    if (n.host[0]) {
        Domain *d = dom_for(me, n.host);
        if (!d) { pthread_mutex_unlock(&gmx); jerr(c, 400, "Esse domínio não está cadastrado para você. Adicione-o na aba Domínios."); return; }
        if (!strcmp(owner, "shared") && strcmp(d->owner, "shared")) { pthread_mutex_unlock(&gmx); jerr(c, 400, "Aplicação compartilhada só pode usar domínio compartilhado."); return; }
        for (int i = 0; i < MAXAPP; i++) if (apps[i].used && &apps[i] != a && !strcmp(apps[i].host, n.host)) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Esse endereço já está em uso por outra aplicação."); return; }
    }
    if (n.db[0]) {
        Db *d = db_find(n.db);
        if (!d || !can(me, d->owner)) { pthread_mutex_unlock(&gmx); jerr(c, 400, "Banco de dados não encontrado."); return; }
        if (!strcmp(owner, "shared") && strcmp(d->owner, "shared")) { pthread_mutex_unlock(&gmx); jerr(c, 400, "Aplicação compartilhada só pode usar banco compartilhado."); return; }
    }
    int want_port = atoi(ptxt);
    if (want_port) {
        if (want_port < 1024 || want_port > 65535 || want_port == cfg.port) { pthread_mutex_unlock(&gmx); jerr(c, 400, "Porta inválida: use um número entre 1024 e 65535."); return; }
        for (int i = 0; i < MAXAPP; i++) if (apps[i].used && &apps[i] != a && (apps[i].port == want_port || apps[i].iport == want_port)) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Essa porta já é de outra aplicação."); return; }
        if ((!a || a->port != want_port) && !port_free(want_port)) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Essa porta já está em uso por outro programa do servidor."); return; }
    }
    int created = !a, oldport = a ? a->port : 0, oldexp = a ? a->expose : 0;
    if (created) {
        char base[28]; slug(n.name, base, sizeof base, '-');
        if (!base[0]) snprintf(base, sizeof base, "app");
        snprintf(n.id, sizeof n.id, "%s", base);
        for (int k = 2; app_find(n.id); k++) snprintf(n.id, sizeof n.id, "%.24s-%d", base, k);
        for (int i = 0; i < MAXAPP && !a; i++) if (!apps[i].used) a = &apps[i];
        if (!a) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Limite de aplicações atingido."); return; }
        n.port = want_port ? want_port : pick_port(); n.iport = pick_iport(); rand_hex(n.secret, 16); n.used = 1; n.want = 0;
        snprintf(n.last, sizeof n.last, "novo");
    } else { // preserva o estado de execução e o que o formulário não edita
        n.port = want_port ? want_port : a->port; n.iport = a->iport; snprintf(n.upname, sizeof n.upname, "%s", a->upname); n.want = a->want; n.pid = a->pid; n.pgid = a->pgid; n.pg_kill = a->pg_kill; n.started = a->started; n.nextstart = a->nextstart; n.term_at = a->term_at;
        n.fails = a->fails; n.restarts = a->restarts; n.deploying = a->deploying; n.stop_req = a->stop_req; n.respawn = a->respawn;
        n.deployed = a->deployed; n.used = 1;
        snprintf(n.id, sizeof n.id, "%s", a->id); snprintf(n.secret, sizeof n.secret, "%s", a->secret); snprintf(n.commit, sizeof n.commit, "%s", a->commit);
        snprintf(n.msg, sizeof n.msg, "%s", a->msg); snprintf(n.rt, sizeof n.rt, "%s", a->rt); snprintf(n.last, sizeof n.last, "%s", a->last);
    }
    snprintf(n.owner, sizeof n.owner, "%s", owner);
    snprintf(n.token, sizeof n.token, "%s", tok[0] ? tok : created ? "" : a->token);
    if (!strcmp(tok, "-")) n.token[0] = 0; // "-" apaga o token salvo
    char oldhost[128] = ""; if (!created) snprintf(oldhost, sizeof oldhost, "%s", a->host);
    *a = n;
    app_save(a);
    if (strcmp(oldhost, n.host) || oldport != a->port) tunnel_dirty = 1;
    if (!created && a->pid > 0 && (oldport != a->port || oldexp != a->expose)) { kill(-a->pid, SIGTERM); a->term_at = time(NULL); a->respawn = 1; a->nextstart = 0; } // porta ou exposição mudou: religa já
    int do_deploy = act[0] == '1';
    if (do_deploy && deploy_start(a->id, "manual")) do_deploy = 0;
    char host[128]; snprintf(host, sizeof host, "%s", a->host);
    pthread_mutex_unlock(&gmx);

    if (host[0] && strcmp(oldhost, host)) { App cp; App *cur; pthread_mutex_lock(&gmx); cur = app_find(n.id); if (cur) cp = *cur; pthread_mutex_unlock(&gmx); if (cur) app_expose(&cp, me, err, sizeof err); }
    sb o = {0};
    sb_f(&o, "{\"ok\":1,\"id\":\"%s\"", n.id);
    if (err[0] || note[0]) { sb_add(&o, ",\"warn\":", 8); sb_str(&o, err[0] ? err : note); }
    sb_add(&o, "}", 1);
    reply(c, 200, "application/json", o.p, o.n, NULL);
    free(o.p);
}

// id da query com checagem de acesso; devolve a cópia do app (travado só durante a cópia)
static int app_get(int c, const Req *rq, const char *me, App *out) {
    char id[32]; fget(rq->query, "id", id, sizeof id);
    pthread_mutex_lock(&gmx);
    App *a = app_find(id);
    int ok = a && can(me, a->owner);
    if (ok) *out = *a;
    pthread_mutex_unlock(&gmx);
    if (!ok) jerr(c, 404, "aplicação não encontrada");
    return ok;
}

static void api_app_action(int c, const Req *rq, const char *me, const char *act) {
    App cp; if (!app_get(c, rq, me, &cp)) return;
    pthread_mutex_lock(&gmx);
    App *a = app_find(cp.id);
    if (!a) { pthread_mutex_unlock(&gmx); jerr(c, 404, "aplicação não encontrada"); return; }
    if (!strcmp(act, "deploy")) {
        if (!tools.git) { pthread_mutex_unlock(&gmx); jerr(c, 503, "git não está instalado no servidor"); return; }
        if (deploy_start(a->id, "manual")) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Já existe um deploy em andamento."); return; }
    } else if (!strcmp(act, "start")) {
        if (!a->commit[0]) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Faça o primeiro deploy antes de iniciar."); return; }
        a->want = 1; a->respawn = 0; a->nextstart = 0; a->fails = 0; app_save(a);
    } else if (!strcmp(act, "stop")) a->stop_req = 1;
    else if (!strcmp(act, "restart")) {
        if (!a->commit[0]) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Faça o primeiro deploy antes de reiniciar."); return; }
        a->want = 1; a->respawn = 1; a->nextstart = 0; a->fails = 0;
        if (a->pid > 0) { kill(-a->pid, SIGTERM); a->term_at = time(NULL); }
        app_save(a);
    }
    pthread_mutex_unlock(&gmx);
    jok(c);
}

static void api_app_delete(int c, const Req *rq, const char *me) {
    App cp; if (!app_get(c, rq, me, &cp)) return;
    pthread_mutex_lock(&gmx);
    App *a = app_find(cp.id);
    if (!a) { pthread_mutex_unlock(&gmx); jerr(c, 404, "aplicação não encontrada"); return; }
    if (a->deploying) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Espere o deploy terminar."); return; }
    if (a->pid > 0) { kill(-a->pid, SIGKILL); waitpid(a->pid, NULL, 0); }
    a->used = 0; tunnel_dirty = 1;
    pthread_mutex_unlock(&gmx);
    if (tools.podman) { // limpa container, imagem e volume
        char n[64], v[64], im[64]; snprintf(n, sizeof n, "hs-%s", cp.id); snprintf(v, sizeof v, "hs-%s-data", cp.id); snprintf(im, sizeof im, "localhost/hs-%s:latest", cp.id);
        char *a1[] = {"podman", "rm", "-f", n, NULL}, *a2[] = {"podman", "rmi", "-f", im, NULL}, *a3[] = {"podman", "volume", "rm", "-f", v, NULL};
        quiet(a1, 30); quiet(a2, 30); quiet(a3, 30);
    }
    char d[PATH_MAX]; app_dir(d, sizeof d, cp.id); rm_rf(d);
    jok(c);
}

// POST /api/app/upload?id=&name=  corpo = o arquivo (.zip ou .tar.gz); grava em streaming e dispara o deploy
#define UPLOAD_MAX (500LL << 20)
static void api_upload(int c, const Req *rq, const char *me) {
    char id[32], name[200], d[PATH_MAX], tmp[PATH_MAX + 16], fin[PATH_MAX + 16];
    fget(rq->query, "id", id, sizeof id); fget(rq->query, "name", name, sizeof name);
    pthread_mutex_lock(&gmx);
    App *a = app_find(id);
    int ok = a && can(me, a->owner) && !a->repo[0], busy = ok && a->deploying;
    pthread_mutex_unlock(&gmx);
    if (!ok) { jerr(c, 404, "aplicação não encontrada, ou ela usa GitHub em vez de arquivo"); return; }
    if (busy) { jerr(c, 409, "Já existe um deploy em andamento."); return; }
    if (rq->clen <= 0 || rq->clen > UPLOAD_MAX) { jerr(c, 413, "Arquivo vazio ou maior que 500 MB."); return; }
    app_dir(d, sizeof d, id); mkdirp(d);
    snprintf(tmp, sizeof tmp, "%s/upload.tmp", d); snprintf(fin, sizeof fin, "%s/upload.bin", d);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd < 0) { jerr(c, 500, "não consegui gravar o arquivo"); return; }
    long long left = rq->clen; int bad = 0;
    size_t first = rq->extra_len < (size_t)left ? rq->extra_len : (size_t)left;
    if (first && write(fd, rq->extra, first) != (ssize_t)first) bad = 1;
    left -= first;
    static __thread char buf[65536];
    while (left > 0 && !bad) {
        ssize_t r = recv(c, buf, left < (long long)sizeof buf ? left : (long long)sizeof buf, 0);
        if (r <= 0 || write(fd, buf, r) != r) bad = 1; else left -= r;
    }
    close(fd);
    if (bad) { unlink(tmp); jerr(c, 500, "envio interrompido (disco cheio ou conexão perdida)"); return; }
    rename(tmp, fin);
    const char *base = strrchr(name, '/'); base = base ? base + 1 : name;
    pthread_mutex_lock(&gmx);
    if ((a = app_find(id))) { snprintf(a->upname, sizeof a->upname, "%s", base[0] ? base : "arquivo"); clean1(a->upname); app_save(a); }
    int rc = deploy_start(id, "upload");
    pthread_mutex_unlock(&gmx);
    if (rc) { jerr(c, 409, "Arquivo recebido, mas já havia um deploy em andamento. Clique em Deploy."); return; }
    jok(c);
}

static void api_log(int c, const Req *rq, const char *me) {
    App cp; if (!app_get(c, rq, me, &cp)) return;
    char which[12], p[PATH_MAX]; fget(rq->query, "which", which, sizeof which);
    const char *f = !strcmp(which, "run") ? "run.log" : !strcmp(which, "hist") ? "history.tsv" : "deploy.log";
    dpath(p, sizeof p, "apps/%s/%s", cp.id, f);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { reply(c, 200, "text/plain; charset=utf-8", "", 0, NULL); return; }
    off_t sz = lseek(fd, 0, SEEK_END), off = sz > 40000 ? sz - 40000 : 0;
    char *buf = malloc(40001);
    ssize_t n = pread(fd, buf, 40000, off);
    close(fd);
    reply(c, 200, "text/plain; charset=utf-8", buf, n > 0 ? n : 0, NULL);
    free(buf);
}

static void api_webhook_create(int c, const Req *rq, const char *me) { // cria o webhook no GitHub usando o token do app
    App cp; if (!app_get(c, rq, me, &cp)) return;
    pthread_mutex_lock(&gmx); char hh[128]; snprintf(hh, sizeof hh, "%s", hook_host); pthread_mutex_unlock(&gmx);
    if (!hh[0]) { jerr(c, 409, "Defina o endereço público de webhooks em Configurações antes."); return; }
    if (!cp.token[0]) { jerr(c, 409, "Salve um token do GitHub (permissão de webhooks) neste app."); return; }
    char body[600];
    snprintf(body, sizeof body, "{\"name\":\"web\",\"active\":true,\"events\":[\"push\"],\"config\":{\"url\":\"https://%s/hook/%s\",\"content_type\":\"json\",\"secret\":\"%s\",\"insecure_ssl\":\"0\"}}", hh, cp.id, cp.secret);
    sb cf = {0};
    char gu[200], gh[200]; snprintf(gu, sizeof gu, "https://api.github.com/repos/%s/hooks", cp.repo); snprintf(gh, sizeof gh, "Authorization: Bearer %s", cp.token);
    SBS(&cf, "silent\nmax-time = 25\nurl = "); cfq(&cf, gu);
    SBS(&cf, "\nrequest = \"POST\"\nheader = "); cfq(&cf, gh);
    SBS(&cf, "\nheader = \"Accept: application/vnd.github+json\"\nheader = \"User-Agent: homelab-hosting\"\ndata = "); cfq(&cf, body);
    SBS(&cf, "\n");
    sb o = {0};
    char *av[] = {"curl", "-K", "-", NULL};
    capture(av, &o, cf.p, 30);
    free(cf.p);
    char gm[160] = "", m[220];
    if (o.p && (strstr(o.p, "\"type\": \"Repository\"") || strstr(o.p, "\"type\":\"Repository\""))) { free(o.p); jok(c); return; }
    if (o.p) jfind(o.p, "message", gm, sizeof gm);
    snprintf(m, sizeof m, "GitHub recusou: %s", gm[0] ? gm : "sem resposta");
    free(o.p);
    jerr(c, 409, !strcmp(gm, "Validation Failed") ? "O webhook já existe nesse repositório (ou a URL é inválida)." : m);
}

static void api_db_create(int c, const Req *rq, const char *me) {
    char *f = read_body(c, rq, 2048);
    if (!f) { jerr(c, 400, "pedido inválido"); return; }
    char name[64], eng[12], scope[12], sql[600], id[40];
    fget(f, "name", name, sizeof name); fget(f, "engine", eng, sizeof eng); fget(f, "scope", scope, sizeof scope);
    free(f);
    int pg = !strcmp(eng, "postgres");
    if (!pg && strcmp(eng, "mysql")) { jerr(c, 400, "Escolha PostgreSQL ou MySQL."); return; }
    trim(name); clean1(name);
    char sl[28]; slug(name, sl, sizeof sl, '_');
    if (!sl[0]) { jerr(c, 400, "Digite um nome para o banco."); return; }
    snprintf(id, sizeof id, "h_%s", sl);
    if (!(pg ? tools.pg_up : tools.my_up)) { jerr(c, 503, pg ? "PostgreSQL não está rodando no servidor (rode hosting-setup.sh)." : "MySQL/MariaDB não está rodando no servidor (rode hosting-setup.sh)."); return; }
    pthread_mutex_lock(&gmx);
    for (int i = 0; i < MAXDB; i++) if (dbs[i].used && !strcmp(dbs[i].id, id)) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Já existe um banco com esse nome."); return; }
    Db *d = NULL; for (int i = 0; i < MAXDB && !d; i++) if (!dbs[i].used) d = &dbs[i];
    if (!d) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Limite de bancos atingido."); return; }
    d->used = 2; // reservado enquanto cria
    pthread_mutex_unlock(&gmx);
    char pw[33]; rand_hex(pw, 16);
    sb o = {0}; int rc;
    if (pg) {
        snprintf(sql, sizeof sql, "CREATE ROLE \"%s\" LOGIN PASSWORD '%s'", id, pw);
        rc = db_sql("postgres", sql, &o);
        if (!rc) { free(o.p); o = (sb){0}; snprintf(sql, sizeof sql, "CREATE DATABASE \"%s\" OWNER \"%s\"", id, id); rc = db_sql("postgres", sql, &o); }
        if (!rc) { free(o.p); o = (sb){0}; snprintf(sql, sizeof sql, "REVOKE ALL ON DATABASE \"%s\" FROM PUBLIC", id); rc = db_sql("postgres", sql, &o); } // por padrão qualquer role conecta em qualquer banco
    } else {
        snprintf(sql, sizeof sql, "CREATE DATABASE `%s`; CREATE USER '%s'@'%%' IDENTIFIED BY '%s'; GRANT ALL ON `%s`.* TO '%s'@'%%'", id, id, pw, id, id);
        rc = db_sql("mysql", sql, &o);
    }
    if (rc) {
        char m[300]; snprintf(m, sizeof m, "O servidor de banco recusou: %.200s", o.p ? o.p : "sem resposta");
        free(o.p); pthread_mutex_lock(&gmx); d->used = 0; pthread_mutex_unlock(&gmx);
        jerr(c, 500, m); return;
    }
    free(o.p);
    pthread_mutex_lock(&gmx);
    snprintf(d->id, sizeof d->id, "%s", id); snprintf(d->name, sizeof d->name, "%s", name); snprintf(d->engine, sizeof d->engine, "%s", eng);
    snprintf(d->owner, sizeof d->owner, "%s", !strcmp(scope, "shared") ? "shared" : me); snprintf(d->user, sizeof d->user, "%s", id); snprintf(d->pw, sizeof d->pw, "%s", pw);
    d->created = time(NULL); d->used = 1; db_save(d);
    pthread_mutex_unlock(&gmx);
    jok(c);
}
static void api_db_delete(int c, const Req *rq, const char *me) {
    char id[40]; fget(rq->query, "id", id, sizeof id);
    pthread_mutex_lock(&gmx);
    Db *d = db_find(id), cp;
    if (!d || !can(me, d->owner)) { pthread_mutex_unlock(&gmx); jerr(c, 404, "banco não encontrado"); return; }
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used && !strcmp(apps[i].db, id)) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Este banco está ligado a uma aplicação. Desligue-o dela primeiro."); return; }
    cp = *d;
    pthread_mutex_unlock(&gmx);
    char sql[300]; sb o = {0}; int pg = !strcmp(cp.engine, "postgres");
    if (db_up(cp.engine)) {
        if (pg) {
            snprintf(sql, sizeof sql, "DROP DATABASE IF EXISTS \"%s\" WITH (FORCE)", cp.id); db_sql("postgres", sql, &o);
            snprintf(sql, sizeof sql, "DROP ROLE IF EXISTS \"%s\"", cp.id); db_sql("postgres", sql, &o);
        } else { snprintf(sql, sizeof sql, "DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS '%s'@'%%'", cp.id, cp.id); db_sql("mysql", sql, &o); }
    }
    free(o.p);
    char p[PATH_MAX]; dpath(p, sizeof p, "dbs/%s.conf", cp.id); unlink(p);
    pthread_mutex_lock(&gmx); if ((d = db_find(id))) d->used = 0; pthread_mutex_unlock(&gmx);
    jok(c);
}

static void api_domain_add(int c, const Req *rq, const char *me) {
    char *f = read_body(c, rq, 2048);
    if (!f) { jerr(c, 400, "pedido inválido"); return; }
    char name[128], scope[12], tok[96]; Domain n; memset(&n, 0, sizeof n);
    fget(f, "name", name, sizeof name); fget(f, "scope", scope, sizeof scope); fget(f, "token", tok, sizeof tok);
    free(f);
    trim(name); for (char *s = name; *s; s++) *s = tolower((unsigned char)*s);
    if (!valid_host(name)) { jerr(c, 400, "Domínio inválido. Digite algo como meusite.com.br."); return; }
    if (!tok[0]) { jerr(c, 400, "Informe um token do Cloudflare com permissão de editar DNS nessa zona."); return; }
    if (!valid_token(tok)) { jerr(c, 400, "Token inválido: use só letras, números e _ - . (copie o token inteiro, sem espaços)."); return; }
    snprintf(n.name, sizeof n.name, "%s", name); snprintf(n.token, sizeof n.token, "%s", tok);
    sb o = {0}; char pth[200], zid[40], err[200];
    snprintf(pth, sizeof pth, "/zones?name=%s", name);
    cf_api(&n, "GET", pth, NULL, &o);
    const char *r = o.p ? jarr(o.p, "result") : NULL;
    int ok = r && jfind(r, "id", zid, sizeof zid);
    if (!ok) { cf_err(&o, err, sizeof err); free(o.p); jerr(c, 400, err); return; }
    free(o.p);
    pthread_mutex_lock(&gmx);
    for (int i = 0; i < MAXDOM; i++) if (doms[i].used && !strcmp(doms[i].name, name)) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Esse domínio já está cadastrado."); return; }
    Domain *d = NULL; for (int i = 0; i < MAXDOM && !d; i++) if (!doms[i].used) d = &doms[i];
    if (!d) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Limite de domínios atingido."); return; }
    *d = n; d->used = 1; snprintf(d->owner, sizeof d->owner, "%s", !strcmp(scope, "shared") ? "shared" : me);
    dom_save();
    pthread_mutex_unlock(&gmx);
    jok(c);
}
static void api_domain_delete(int c, const Req *rq, const char *me) {
    char name[128]; fget(rq->query, "name", name, sizeof name);
    pthread_mutex_lock(&gmx);
    Domain *d = NULL; for (int i = 0; i < MAXDOM; i++) if (doms[i].used && !strcmp(doms[i].name, name)) d = &doms[i];
    if (!d || !can(me, d->owner)) { pthread_mutex_unlock(&gmx); jerr(c, 404, "domínio não encontrado"); return; }
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used && dom_for(me, apps[i].host) == d) { pthread_mutex_unlock(&gmx); jerr(c, 409, "Há aplicações usando esse domínio."); return; }
    if (hook_host[0] && dom_for(me, hook_host) == d) { pthread_mutex_unlock(&gmx); jerr(c, 409, "O endereço de webhooks usa esse domínio."); return; }
    d->used = 0; dom_save();
    pthread_mutex_unlock(&gmx);
    jok(c);
}
static void api_settings(int c, const Req *rq, const char *me) {
    if (!is_admin(me)) { jerr(c, 403, "Só o administrador altera isto."); return; }
    char *f = read_body(c, rq, 1024);
    if (!f) { jerr(c, 400, "pedido inválido"); return; }
    char h[128], err[200] = ""; fget(f, "hook_host", h, sizeof h);
    free(f);
    trim(h); for (char *s = h; *s; s++) *s = tolower((unsigned char)*s);
    Domain d, *p = NULL;
    if (h[0]) {
        if (!valid_host(h)) { jerr(c, 400, "Endereço inválido."); return; }
        pthread_mutex_lock(&gmx); p = dom_for(me, h); if (p) d = *p; pthread_mutex_unlock(&gmx);
        if (!p) { jerr(c, 400, "Esse domínio não está cadastrado para você."); return; }
        if (dns_route(&d, h, err, sizeof err)) { jerr(c, 500, err); return; }
    }
    pthread_mutex_lock(&gmx);
    snprintf(hook_host, sizeof hook_host, "%s", h); tunnel_dirty = 1; settings_save();
    pthread_mutex_unlock(&gmx);
    jok(c);
}

// POST /hook/<id>: push do GitHub com assinatura HMAC; dispara deploy se a branch for a do app
static void api_hook(int c, const Req *rq) {
    const char *id = rq->path + 6;
    char *body = read_body(c, rq, 2 << 20);
    if (!body) { jerr(c, 413, "corpo inválido ou grande demais"); return; }
    char want[65], sig[80], ref[100], br[80];
    pthread_mutex_lock(&gmx);
    App *a = app_find(id);
    if (!a || !a->secret[0]) { pthread_mutex_unlock(&gmx); free(body); jerr(c, 404, "não encontrado"); return; }
    hmac_hex(a->secret, (uint8_t *)body, rq->clen, want);
    snprintf(sig, sizeof sig, "sha256=%s", want);
    int good = ct_eq(sig, rq->sig);
    snprintf(br, sizeof br, "refs/heads/%s", a->branch);
    int ad = a->autodeploy;
    pthread_mutex_unlock(&gmx);
    if (!good) { free(body); jerr(c, 401, "assinatura inválida"); return; }
    if (!strcmp(rq->event, "ping")) { free(body); reply(c, 200, "text/plain", "pong", 4, NULL); return; }
    jfind(body, "ref", ref, sizeof ref);
    free(body);
    if (strcmp(rq->event, "push") || strcmp(ref, br) || !ad) { reply(c, 200, "text/plain", "ignorado", 8, NULL); return; }
    pthread_mutex_lock(&gmx); int rc = deploy_start(id, "webhook"); pthread_mutex_unlock(&gmx);
    reply(c, 200, "text/plain", rc ? "ocupado" : "deploy iniciado", rc ? 7 : 15, NULL);
}

static void route(int c, Req *rq) {
    const char *p = rq->path;
    int post = !strcmp(rq->method, "POST");
    if (rq->public) { // pelo túnel só entra o webhook
        if (post && !strncmp(p, "/hook/", 6)) api_hook(c, rq); else jerr(c, 404, "não encontrado");
        return;
    }
    if (post && !strncmp(p, "/hook/", 6)) { api_hook(c, rq); return; }
    if (strncmp(p, "/api/", 5)) { serve_static(c, rq); return; }
    const char *me = auth(rq);
    if (!me) { jerr(c, 401, "faça login no painel"); return; }
    if (post && strcmp(rq->xhr, "hosting")) { jerr(c, 403, "origem não permitida"); return; } // bloqueia POST cruzado vindo de outro app/porta
    if (!strcmp(p, "/api/me")) { char b[64]; int n = snprintf(b, sizeof b, "{\"ok\":1,\"user\":\"%s\"}", me); reply(c, 200, "application/json", b, n, NULL); return; }
    if (!strcmp(p, "/api/overview")) { overview(c, me); return; }
    if (!strcmp(p, "/api/stats")) { api_stats(c, rq, me); return; }
    if (!strcmp(p, "/api/app/log")) { api_log(c, rq, me); return; }
    if (post && !strcmp(p, "/api/app/save")) { api_app_save(c, rq, me); return; }
    if (post && !strcmp(p, "/api/app/upload")) { api_upload(c, rq, me); return; }
    if (post && !strcmp(p, "/api/app/delete")) { api_app_delete(c, rq, me); return; }
    if (post && !strcmp(p, "/api/app/webhook")) { api_webhook_create(c, rq, me); return; }
    if (post && !strncmp(p, "/api/app/", 9) && (!strcmp(p + 9, "deploy") || !strcmp(p + 9, "start") || !strcmp(p + 9, "stop") || !strcmp(p + 9, "restart"))) { api_app_action(c, rq, me, p + 9); return; }
    if (post && !strcmp(p, "/api/db/create")) { api_db_create(c, rq, me); return; }
    if (post && !strcmp(p, "/api/db/delete")) { api_db_delete(c, rq, me); return; }
    if (post && !strcmp(p, "/api/domain/add")) { api_domain_add(c, rq, me); return; }
    if (post && !strcmp(p, "/api/domain/delete")) { api_domain_delete(c, rq, me); return; }
    if (post && !strcmp(p, "/api/settings")) { api_settings(c, rq, me); return; }
    jerr(c, 404, "rota inexistente");
}

static int nconn;
static void *conn_thread(void *arg) {
    int c = (int)(intptr_t)arg;
    struct timeval tv = {5, 0}; // cabeçalho: no máximo 10 s no total (slowloris); depois o prazo de cada recv sobe
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    char buf[16384];
    size_t len = 0;
    char *he;
    time_t t_hdr = time(NULL) + 10;
    while (!(he = memmem(buf, len, "\r\n\r\n", 4))) {
        if (len >= sizeof buf || time(NULL) > t_hdr) goto done;
        ssize_t r = recv(c, buf + len, sizeof buf - len, 0);
        if (r <= 0) goto done;
        len += r;
    }
    tv.tv_sec = 60; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    Req rq = {0};
    rq.extra = he + 4; rq.extra_len = buf + len - (he + 4);
    *he = 0;
    char target[1600];
    if (sscanf(buf, "%7s %1599s", rq.method, target) != 2) goto done;
    char *qm = strchr(target, '?');
    if (qm) { *qm++ = 0; snprintf(rq.query, sizeof rq.query, "%s", qm); }
    udec(rq.path, target, strlen(target), sizeof rq.path);
    for (char *l = strstr(buf, "\r\n"); l; l = strstr(l + 2, "\r\n")) {
        l += 2;
        const char *v;
#define HDR(name, dst) if (!strncasecmp(l, name ":", sizeof name)) { v = l + sizeof name; while (*v == ' ') v++; snprintf(dst, sizeof dst, "%.*s", (int)strcspn(v, "\r\n"), v); }
        HDR("cookie", rq.cookie) else HDR("x-requested-with", rq.xhr) else HDR("x-hub-signature-256", rq.sig) else HDR("x-github-event", rq.event) else HDR("authorization", rq.authz)
        else if (!strncasecmp(l, "cf-connecting-ip:", 17) || !strncasecmp(l, "cf-ray:", 7)) rq.public = 1;
        else if (!cfg.behind_proxy && (!strncasecmp(l, "x-forwarded-for:", 16) || !strncasecmp(l, "forwarded:", 10) || !strncasecmp(l, "x-real-ip:", 10) || !strncasecmp(l, "x-forwarded-host:", 17))) rq.public = 1;
        else if (!strncasecmp(l, "content-length:", 15)) rq.clen = atoll(l + 15);
    }
    route(c, &rq);
done:
    close(c);
    __atomic_fetch_sub(&nconn, 1, __ATOMIC_RELAXED);
    return NULL;
}

static void on_sig(int s) { (void)s; quit = 1; }

int main(int argc, char **argv) {
    cfg_load(argc > 2 && !strcmp(argv[1], "-c") ? argv[2] : "hosting.conf");
    umask(077); // tudo o que o hosting cria é só do dono (tokens, logs, estatísticas, código dos apps)
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = {.sa_handler = on_sig}; sigaction(SIGTERM, &sa, NULL); sigaction(SIGINT, &sa, NULL);
    if (!getenv("XDG_RUNTIME_DIR")) { char t[48]; snprintf(t, sizeof t, "/run/user/%d", (int)getuid()); setenv("XDG_RUNTIME_DIR", t, 0); } // podman rootless
    char p[PATH_MAX];
    dpath(p, sizeof p, "apps"); mkdirp(p); dpath(p, sizeof p, "dbs"); mkdirp(p);
    chmod(cfg.data, 0700);
    dom_load(); db_load_all(); api_token_load();
    { char pf[PATH_MAX]; dpath(pf, sizeof pf, "pgpass"); setenv("PGPASSFILE", pf, 1); } // só o caminho; a senha está no arquivo (0600, fora do sandbox)
    pthread_mutex_lock(&acmx); intern(cfg.admin, 1); pthread_mutex_unlock(&acmx);
    if (!user_ok(cfg.admin)) { fprintf(stderr, "admin=%s inválido\n", cfg.admin); return 1; }
    dpath(p, sizeof p, "apps");
    DIR *d = opendir(p);
    for (struct dirent *de; d && (de = readdir(d));) if (de->d_name[0] != '.') app_load(de->d_name);
    if (d) closedir(d);
    dpath(p, sizeof p, "settings.conf"); { char b[200]; if (!slurp(p, b, sizeof b)) { char *h = strstr(b, "hook_host="); if (h) { snprintf(hook_host, sizeof hook_host, "%s", h + 10); hook_host[strcspn(hook_host, "\r\n")] = 0; } } }
    dpath(p, sizeof p, "tunnel.id"); slurp(p, tunnel_id, sizeof tunnel_id); trim(tunnel_id);
    tools.git = have("git"); tools.podman = have("podman"); tools.cloudflared = have("cloudflared"); // o resto (bancos) a thread prober preenche

    pthread_mutex_lock(&gmx);
    for (int i = 0; i < MAXAPP; i++) if (apps[i].used && !apps[i].iport) { apps[i].iport = pick_iport(); app_save(&apps[i]); } // apps criados antes do proxy
    pthread_mutex_unlock(&gmx);

    pthread_t t;
    pthread_create(&t, NULL, prober, NULL); pthread_detach(t);
    pthread_create(&t, NULL, proxy_mgr, NULL); pthread_detach(t);
    pthread_create(&t, NULL, stats_thread, NULL); pthread_detach(t);
    pthread_create(&t, NULL, supervisor, NULL); pthread_detach(t);
    pthread_create(&t, NULL, poller, NULL); pthread_detach(t);

    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(cfg.port)};
    if (inet_pton(AF_INET, cfg.bind, &a.sin_addr) != 1) { fprintf(stderr, "bind=%s não é um endereço IPv4\n", cfg.bind); return 1; }
    int bound = -1;
    for (int tr = 0; tr < 40 && bound; tr++) { bound = bind(s, (struct sockaddr *)&a, sizeof a); if (bound) usleep(250000); } // reinício: a instância anterior pode estar saindo
    if (bound || listen(s, 64)) { perror("bind/listen"); return 1; }
    fprintf(stderr, "hosting em http://%s:%d (dados: %s)\n", cfg.bind, cfg.port, cfg.data);
    fprintf(stderr, "sandbox dos apps nativos: %s\n", !cfg.sandbox ? "desligado (sandbox=0)" : ll_abi() >= 1 ? "ativo (Landlock)" : "INDISPONÍVEL neste kernel: apps nativos têm os mesmos acessos do serviço");

    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 512 * 1024);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    while (!quit) {
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) continue;
        if (__atomic_add_fetch(&nconn, 1, __ATOMIC_RELAXED) > 128 || pthread_create(&t, &at, conn_thread, (void *)(intptr_t)c)) {
            __atomic_fetch_sub(&nconn, 1, __ATOMIC_RELAXED);
            close(c);
        }
    }
    for (int i = 0; i < 20; i++) sleep(1); // o supervisor encerra o processo (exit) depois de derrubar os apps; isto é só o limite
    return 0;
}
