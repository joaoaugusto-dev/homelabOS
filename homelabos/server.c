// homelabOS: servidor único em C. Métricas (/proc, /sys), SSE, gerenciador de arquivos e site estático.
// Build: make   |   Senha do administrador: ./homelabos --hash   |   Senha do gestor: ./homelabos -c homelab.conf --manager-password
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
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

/* ---------- config ---------- */
static struct {
    int port;
    char root[PATH_MAX], web[PATH_MAX], data[PATH_MAX];
    char salt[64], hash[160], power_file[PATH_MAX];
    char bind[48], admin[32], manager[32]; // bind: endereço do painel; admin/manager: nomes das duas contas (manager é opcional)
    double idle_w, max_w, offset_w;
} cfg = {.port = 80, .root = "/srv/compartilhado", .web = "web", .data = "data", .bind = "127.0.0.1", .admin = "admin",
         .idle_w = 15, .max_w = 65, .offset_w = 8};

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
        S("root", cfg.root); S("web", cfg.web); S("data", cfg.data);
        S("salt", cfg.salt); S("password_hash", cfg.hash); S("power_file", cfg.power_file);
        S("bind", cfg.bind); S("admin", cfg.admin); S("manager", cfg.manager);
        if (!strcmp(l, "port")) cfg.port = atoi(v);
        if (!strcmp(l, "idle_w")) cfg.idle_w = atof(v);
        if (!strcmp(l, "max_w")) cfg.max_w = atof(v);
        if (!strcmp(l, "offset_w")) cfg.offset_w = atof(v);
    }
    fclose(f);
}

/* ---------- sha256 (hash de senha) ---------- */
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
// formato ANTIGO (senhas feitas antes do PBKDF2): 30000 rodadas de sha256. Só serve para conferir; novas senhas usam pbkdf2.
static void pwhash(const char *pw, const char *salt, char hex[65]) {
    uint8_t buf[256], d[32];
    size_t n = snprintf((char *)buf, sizeof buf, "%s%s", salt, pw);
    sha256(buf, n, d);
    for (int i = 0; i < 30000; i++) {
        memcpy(buf, d, 32);
        size_t m = snprintf((char *)buf + 32, sizeof buf - 32, "%s", pw);
        sha256(buf, 32 + m, d);
    }
    for (int i = 0; i < 32; i++) sprintf(hex + i * 2, "%02x", d[i]);
}

static void rand_bytes(uint8_t *o, size_t n) { // sem entropia boa não existe token seguro: aborta em vez de gerar zeros
    for (size_t i = 0; i < n;) { ssize_t r = getrandom(o + i, n - i, 0); if (r <= 0) { perror("getrandom"); abort(); } i += r; }
}
static int ct_eq(const char *a, const char *b) { // comparação em tempo constante
    size_t n = strlen(a); unsigned d = n != strlen(b);
    for (size_t i = 0; i < n && !d; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return !d;
}
static void hmac_sha256(const uint8_t *key, size_t kl, const uint8_t *msg, size_t n, uint8_t out[32]) {
    uint8_t k[64] = {0}, d[32], *buf = malloc(64 + (n > 32 ? n : 32));
    if (kl > 64) sha256(key, kl, k); else memcpy(k, key, kl);
    for (int i = 0; i < 64; i++) buf[i] = k[i] ^ 0x36;
    memcpy(buf + 64, msg, n); sha256(buf, 64 + n, d);
    for (int i = 0; i < 64; i++) buf[i] = k[i] ^ 0x5c;
    memcpy(buf + 64, d, 32); sha256(buf, 96, out);
    free(buf);
}
static void sha_state(const uint8_t k[64], uint8_t pad, uint32_t h[8]) { // estado após o bloco de chave (ipad/opad) do HMAC
    static const uint32_t I[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t b[64]; memcpy(h, I, 32);
    for (int i = 0; i < 64; i++) b[i] = k[i] ^ pad;
    sha_block(h, b);
}
static void hmac_fast(const uint32_t *ist, const uint32_t *ost, const uint8_t m[32], uint8_t out[32]) { // HMAC de 32 bytes com estados prontos: 2 blocos
    uint8_t b[64]; uint32_t h[8];
    memcpy(b, m, 32); b[32] = 0x80; memset(b + 33, 0, 29); b[62] = 3; b[63] = 0; // 96 bytes = 768 bits
    memcpy(h, ist, 32); sha_block(h, b);
    for (int k = 0; k < 8; k++) { b[k*4] = h[k] >> 24; b[k*4+1] = h[k] >> 16; b[k*4+2] = h[k] >> 8; b[k*4+3] = h[k]; }
    memcpy(h, ost, 32); sha_block(h, b);
    for (int k = 0; k < 8; k++) { out[k*4] = h[k] >> 24; out[k*4+1] = h[k] >> 16; out[k*4+2] = h[k] >> 8; out[k*4+3] = h[k]; }
}
static void pbkdf2(const char *pw, const uint8_t *salt, size_t sl, int iters, uint8_t out[32]) { // PBKDF2-HMAC-SHA256, 1 bloco (32 bytes)
    uint8_t k[64] = {0}, u[32], s[80], t[32]; uint32_t ist[8], ost[8];
    size_t kl = strlen(pw);
    if (kl > 64) sha256((const uint8_t *)pw, kl, k); else memcpy(k, pw, kl);
    sha_state(k, 0x36, ist); sha_state(k, 0x5c, ost);
    if (sl > 64) sl = 64;
    memcpy(s, salt, sl); s[sl] = s[sl+1] = s[sl+2] = 0; s[sl+3] = 1;
    hmac_sha256(k, 64, s, sl + 4, u); memcpy(t, u, 32);
    for (int i = 1; i < iters; i++) { hmac_fast(ist, ost, u, u); for (int j = 0; j < 32; j++) t[j] ^= u[j]; }
    memcpy(out, t, 32);
}
#define PW_ITERS 600000
static void hex_of(const uint8_t *b, size_t n, char *o) { for (size_t i = 0; i < n; i++) sprintf(o + i * 2, "%02x", b[i]); }
static int unhex(const char *h, uint8_t *o, size_t n) {
    for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(h + i * 2, "%2x", &v) != 1) return -1; o[i] = v; }
    return 0;
}
// "pbkdf2$iterações$sal$hash" (novo) ou sal + sha256 antigo
static void pw_new(const char *pw, char *out, size_t cap) {
    uint8_t salt[16], d[32]; char sx[33], hx[65];
    rand_bytes(salt, 16); pbkdf2(pw, salt, 16, PW_ITERS, d);
    hex_of(salt, 16, sx); hex_of(d, 32, hx);
    snprintf(out, cap, "pbkdf2$%d$%s$%s", PW_ITERS, sx, hx);
}
static int pw_ok(const char *pw, const char *salt, const char *stored) {
    if (!strncmp(stored, "pbkdf2$", 7)) {
        int it; char sx[33], hx[65]; uint8_t s[16], d[32], want[32], got[32];
        if (sscanf(stored, "pbkdf2$%d$%32[0-9a-f]$%64[0-9a-f]", &it, sx, hx) != 3 || it < 1000 || it > 5000000 || strlen(sx) != 32 || strlen(hx) != 64) return 0;
        if (unhex(sx, s, 16) || unhex(hx, want, 32)) return 0;
        pbkdf2(pw, s, 16, it, d); memcpy(got, d, 32);
        return !memcmp(got, want, 32) ? 1 : 0; // ponytail: memcmp em 32 bytes de hash derivado; o atacante não controla o alvo
    }
    char hx[65]; pwhash(pw, salt, hx);
    return ct_eq(hx, stored);
}
static int read_pw_tty(const char *prompt, char *out, size_t cap) { // lê sem eco quando é terminal; senão uma linha do stdin
    struct termios o, n; int tty = isatty(0);
    if (tty) { fprintf(stderr, "%s", prompt); tcgetattr(0, &o); n = o; n.c_lflag &= ~ECHO; tcsetattr(0, TCSANOW, &n); }
    char *r = fgets(out, cap, stdin);
    if (tty) { tcsetattr(0, TCSANOW, &o); fputc('\n', stderr); }
    if (!r) return -1;
    out[strcspn(out, "\r\n")] = 0;
    return 0;
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
        else if (ch < 0x20) sb_f(b, "\\u%04x", ch);
        else sb_add(b, (char *)&ch, 1);
    }
    sb_add(b, "\"", 1);
}

/* ---------- utilidades de leitura de /proc e /sys ---------- */
static long long read_ll(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long long v = -1;
    if (fscanf(f, "%lld", &v) != 1) v = -1;
    fclose(f);
    return v;
}
// bateria do notebook: pct = -1 sem bateria; status do kernel (Charging, Discharging, Full, Not charging)
static void battery(int *pct, char *st, size_t cap) {
    *pct = (int)read_ll("/sys/class/power_supply/BAT0/capacity");
    st[0] = 0;
    FILE *f = fopen("/sys/class/power_supply/BAT0/status", "r");
    if (f) { if (fgets(st, cap, f)) st[strcspn(st, "\n")] = 0; fclose(f); }
}
static int read_str(const char *path, char *out, size_t cap) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, cap, f)) out[0] = 0;
    out[strcspn(out, "\n")] = 0;
    fclose(f);
    return 0;
}
static int find_hwmon(const char **names, char *out, size_t cap) {
    char p[PATH_MAX], nm[64];
    for (int i = 0; i < 32; i++) {
        snprintf(p, sizeof p, "/sys/class/hwmon/hwmon%d/name", i);
        if (read_str(p, nm, sizeof nm)) continue;
        for (const char **n = names; *n; n++)
            if (!strcmp(nm, *n)) { snprintf(out, cap, "/sys/class/hwmon/hwmon%d/temp1_input", i); return 0; }
    }
    return -1;
}

/* ---------- estado compartilhado ---------- */
#define HN 600
#define NCPU_MAX 128
static pthread_mutex_t mx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static unsigned long seq;
static char snap[16384];
static float h_cpu[HN], h_temp[HN], h_w[HN], h_rx[HN], h_tx[HN], h_mem[HN];
static int hcount, hhead;
static time_t h_end;
static volatile sig_atomic_t quit;

static double price = 0.95;
static char since[11];
static struct { char d[11]; double k; } days[400];
static int ndays;

static void state_path(char *o, size_t c, const char *f) { snprintf(o, c, "%s/%s", cfg.data, f); }

static void state_load(void) {
    char p[PATH_MAX], l[128];
    state_path(p, sizeof p, "state.txt");
    FILE *f = fopen(p, "r");
    if (!f) return;
    while (fgets(l, sizeof l, f) && ndays < 400) {
        if (!strncmp(l, "price ", 6)) price = atof(l + 6);
        else if (!strncmp(l, "since ", 6)) snprintf(since, sizeof since, "%.10s", l + 6);
        else if (!strncmp(l, "day ", 4) && strlen(l) > 15) {
            snprintf(days[ndays].d, 11, "%.10s", l + 4);
            days[ndays++].k = atof(l + 15);
        }
    }
    fclose(f);
}
static void state_save(void) { // chamar com mx travado
    char p[PATH_MAX], t[PATH_MAX];
    state_path(p, sizeof p, "state.txt");
    snprintf(t, sizeof t, "%s.tmp", p);
    FILE *f = fopen(t, "w");
    if (!f) return;
    fprintf(f, "price %.4f\nsince %s\n", price, since);
    for (int i = 0; i < ndays; i++) fprintf(f, "day %s %.6f\n", days[i].d, days[i].k);
    fclose(f);
    rename(t, p);
}

/* ---------- amostrador ---------- */
typedef struct { char m[128], dev[64]; double t, u, f; } disk_t;
static disk_t disks[16];
static int ndisks;

static void scan_disks(void) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f) return;
    char l[512], dev[256], mp[256], fs[64], seen[16][64];
    int n = 0, ns = 0;
    static const char *ok[] = {"ext4", "ext3", "xfs", "btrfs", "ntfs", "ntfs3", "fuseblk", "zfs", "f2fs", "exfat", "vfat", NULL};
    disk_t tmp[16];
    while (fgets(l, sizeof l, f) && n < 16) {
        if (sscanf(l, "%255s %255s %63s", dev, mp, fs) != 3) continue;
        if (strncmp(dev, "/dev/", 5) || !strncmp(dev, "/dev/loop", 9) || !strncmp(mp, "/boot", 5) || !strncmp(mp, "/snap", 5)) continue;
        int good = 0, dup = 0;
        for (const char **o = ok; *o; o++) if (!strcmp(fs, *o)) good = 1;
        for (int i = 0; i < ns; i++) if (!strcmp(seen[i], dev)) dup = 1;
        if (!good || dup) continue;
        struct statvfs s;
        if (statvfs(mp, &s) || !s.f_blocks) continue;
        snprintf(seen[ns++], 64, "%s", dev);
        for (char *c = mp; *c; c++) if (*c == '\\') *c = '/'; // ponytail: \040 de mounts não decodificado
        snprintf(tmp[n].m, sizeof tmp[n].m, "%s", mp);
        snprintf(tmp[n].dev, sizeof tmp[n].dev, "%s", dev + 5);
        tmp[n].t = (double)s.f_blocks * s.f_frsize;
        tmp[n].f = (double)s.f_bavail * s.f_frsize;
        tmp[n].u = tmp[n].t - (double)s.f_bfree * s.f_frsize;
        n++;
    }
    fclose(f);
    pthread_mutex_lock(&mx);
    memcpy(disks, tmp, sizeof tmp); ndisks = n;
    pthread_mutex_unlock(&mx);
}

static void today_str(char *o, struct tm *tm) { strftime(o, 11, "%Y-%m-%d", tm); }

static void add_energy(double kwh) {
    time_t now = time(NULL);
    struct tm tm; localtime_r(&now, &tm);
    char d[11]; today_str(d, &tm);
    if (!since[0]) memcpy(since, d, 11);
    if (!ndays || strcmp(days[ndays - 1].d, d)) {
        if (ndays == 400) { memmove(days, days + 1, sizeof days - sizeof days[0]); ndays--; }
        memcpy(days[ndays].d, d, 11); days[ndays++].k = 0;
    }
    days[ndays - 1].k += kwh;
}

static void *sampler(void *arg) {
    (void)arg;
    char temp_path[PATH_MAX] = "", nvme_path[PATH_MAX] = "";
    static const char *cpu_names[] = {"coretemp", "k10temp", "zenpower", "cpu_thermal", NULL};
    static const char *nvme_names[] = {"nvme", NULL};
    if (find_hwmon(cpu_names, temp_path, sizeof temp_path)) snprintf(temp_path, sizeof temp_path, "/sys/class/thermal/thermal_zone0/temp");
    find_hwmon(nvme_names, nvme_path, sizeof nvme_path);

    const char *rapl = "/sys/class/powercap/intel-rapl:0/energy_uj";
    long long rapl_max = read_ll("/sys/class/powercap/intel-rapl:0/max_energy_range_uj");
    long long rapl_prev = read_ll(rapl);
    int rapl_ok = rapl_prev >= 0;

    struct utsname un; uname(&un);
    char host[64]; gethostname(host, sizeof host);
    char os[128] = "Linux";
    FILE *of = fopen("/etc/os-release", "r");
    if (of) {
        char l[256];
        while (fgets(l, sizeof l, of)) if (!strncmp(l, "PRETTY_NAME=", 12)) {
            l[strcspn(l, "\n")] = 0;
            char *v = l + 12; if (*v == '"') v++;
            size_t n = strlen(v); if (n && v[n - 1] == '"') v[n - 1] = 0;
            snprintf(os, sizeof os, "%s", v);
        }
        fclose(of);
    }

    unsigned long long pb[NCPU_MAX], pt[NCPU_MAX];
    int first = 1, ncpu = 0, tick = 0;
    double prx = 0, ptx = 0;
    struct timespec nxt, last;
    clock_gettime(CLOCK_MONOTONIC, &nxt); last = nxt;
    scan_disks();

    while (1) {
        nxt.tv_sec += 1;
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &nxt, NULL);
        struct timespec nowt; clock_gettime(CLOCK_MONOTONIC, &nowt);
        double dt = (nowt.tv_sec - last.tv_sec) + (nowt.tv_nsec - last.tv_nsec) / 1e9;
        last = nowt;
        if (quit) { pthread_mutex_lock(&mx); state_save(); pthread_mutex_unlock(&mx); exit(0); }

        /* cpu */
        double cores[NCPU_MAX], cpu_total = 0;
        FILE *f = fopen("/proc/stat", "r");
        char l[512];
        int idx = -1;
        while (f && fgets(l, sizeof l, f) && !strncmp(l, "cpu", 3)) {
            unsigned long long u, n, s, i, io, ir, so, st;
            char *sp = l + 3;
            int core = isdigit((unsigned char)*sp) ? (int)strtol(sp, &sp, 10) : -1;
            if (sscanf(sp, "%llu %llu %llu %llu %llu %llu %llu %llu", &u, &n, &s, &i, &io, &ir, &so, &st) != 8) continue;
            unsigned long long tot = u + n + s + i + io + ir + so + st, busy = tot - i - io;
            idx = core + 1;
            if (idx >= NCPU_MAX) break;
            double pct = (!first && tot > pt[idx]) ? 100.0 * (busy - pb[idx]) / (tot - pt[idx]) : 0;
            pb[idx] = busy; pt[idx] = tot;
            if (core < 0) cpu_total = pct; else { cores[core] = pct; if (core + 1 > ncpu) ncpu = core + 1; }
        }
        if (f) fclose(f);

        /* temperatura / frequência */
        long long tr = read_ll(temp_path), tn = nvme_path[0] ? read_ll(nvme_path) : -1;
        double temp = tr > 0 ? tr / 1000.0 : 0, dtemp = tn > 0 ? tn / 1000.0 : 0;
        double mhz = 0; int nf = 0;
        for (int c = 0; c < ncpu; c++) {
            char p[96]; snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", c);
            long long v = read_ll(p);
            if (v > 0) { mhz += v / 1000.0; nf++; }
        }
        if (nf) mhz /= nf;

        /* memória */
        long long mt = 0, ma = 0, mc = 0, st = 0, sf = 0;
        f = fopen("/proc/meminfo", "r");
        while (f && fgets(l, sizeof l, f)) {
            sscanf(l, "MemTotal: %lld", &mt); sscanf(l, "MemAvailable: %lld", &ma);
            sscanf(l, "Cached: %lld", &mc); sscanf(l, "SwapTotal: %lld", &st); sscanf(l, "SwapFree: %lld", &sf);
        }
        if (f) fclose(f);

        /* rede */
        double rx = 0, tx = 0;
        f = fopen("/proc/net/dev", "r");
        while (f && fgets(l, sizeof l, f)) {
            char *c = strchr(l, ':');
            if (!c) continue;
            *c = 0;
            char *nm = l; while (*nm == ' ') nm++;
            if (!strcmp(nm, "lo") || !strncmp(nm, "veth", 4) || !strncmp(nm, "docker", 6) || !strncmp(nm, "br-", 3) || !strncmp(nm, "virbr", 5)) continue;
            unsigned long long a, b, d[6], e;
            if (sscanf(c + 1, "%llu %llu %llu %llu %llu %llu %llu %llu %llu", &a, &b, &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], &e) == 9) { rx += a; tx += e; }
        }
        if (f) fclose(f);
        double rxr = first || rx < prx ? 0 : (rx - prx) / dt, txr = first || tx < ptx ? 0 : (tx - ptx) / dt;
        prx = rx; ptx = tx;

        /* potência */
        double w = 0; const char *src = "estimativa";
        if (cfg.power_file[0]) {
            FILE *pf = fopen(cfg.power_file, "r"); double v;
            if (pf && fscanf(pf, "%lf", &v) == 1) { w = v; src = "medidor"; }
            if (pf) fclose(pf);
        } else if (rapl_ok) {
            long long cur = read_ll(rapl);
            if (cur >= 0 && !first) {
                long long d = cur >= rapl_prev ? cur - rapl_prev : cur + rapl_max - rapl_prev;
                w = d / 1e6 / dt + cfg.offset_w; src = "rapl";
            }
            rapl_prev = cur;
        }
        if (!w) w = cfg.idle_w + (cfg.max_w - cfg.idle_w) * cpu_total / 100.0;
        if (!first) { pthread_mutex_lock(&mx); add_energy(w * dt / 3.6e6); pthread_mutex_unlock(&mx); }

        if (tick % 10 == 0) scan_disks();
        if (tick % 60 == 59) { pthread_mutex_lock(&mx); state_save(); pthread_mutex_unlock(&mx); }
        tick++; first = 0;

        /* uptime / load */
        double up = 0, ld[3] = {0};
        f = fopen("/proc/uptime", "r"); if (f) { if (fscanf(f, "%lf", &up) != 1) up = 0; fclose(f); }
        f = fopen("/proc/loadavg", "r"); if (f) { if (fscanf(f, "%lf %lf %lf", &ld[0], &ld[1], &ld[2]) != 3) ld[0] = 0; fclose(f); }

        /* snapshot json */
        pthread_mutex_lock(&mx);
        time_t now = time(NULL);
        struct tm tm; localtime_r(&now, &tm);
        char ym[8]; strftime(ym, sizeof ym, "%Y-%m", &tm);
        double today = ndays ? days[ndays - 1].k : 0, month = 0, total = 0;
        for (int i = 0; i < ndays; i++) { total += days[i].k; if (!strncmp(days[i].d, ym, 7)) month += days[i].k; }
        sb b = {0};
        sb_f(&b, "{\"t\":%ld,\"host\":", (long)now); sb_str(&b, host);
        sb_add(&b, ",\"os\":", 6); sb_str(&b, os);
        sb_add(&b, ",\"kernel\":", 10); sb_str(&b, un.release);
        sb_f(&b, ",\"up\":%.0f,\"load\":[%.2f,%.2f,%.2f],\"ncpu\":%d,", up, ld[0], ld[1], ld[2], ncpu);
        sb_f(&b, "\"cpu\":{\"u\":%.1f,\"mhz\":%.0f,\"cores\":[", cpu_total, mhz);
        for (int i = 0; i < ncpu; i++) sb_f(&b, "%s%.0f", i ? "," : "", cores[i]);
        sb_f(&b, "]},\"temp\":%.1f,\"dtemp\":%.1f,", temp, dtemp);
        sb_f(&b, "\"mem\":{\"t\":%lld,\"a\":%lld,\"c\":%lld,\"st\":%lld,\"sf\":%lld},", mt, ma, mc, st, sf);
        sb_f(&b, "\"net\":{\"rx\":%.0f,\"tx\":%.0f,\"rxt\":%.0f,\"txt\":%.0f},", rxr, txr, rx, tx);
        sb_f(&b, "\"pw\":{\"w\":%.2f,\"src\":\"%s\"},", w, src);
        int bpct; char bst[24]; battery(&bpct, bst, sizeof bst);
        sb_f(&b, "\"bat\":{\"p\":%d,\"s\":\"%s\"},", bpct, bst);
        sb_f(&b, "\"en\":{\"price\":%.4f,\"today\":%.5f,\"month\":%.5f,\"total\":%.5f,\"since\":\"%s\"},\"disks\":[", price, today, month, total, since);
        for (int i = 0; i < ndisks; i++) {
            sb_add(&b, i ? ",{\"m\":" : "{\"m\":", i ? 6 : 5); sb_str(&b, disks[i].m);
            sb_add(&b, ",\"d\":", 5); sb_str(&b, disks[i].dev);
            sb_f(&b, ",\"t\":%.0f,\"u\":%.0f,\"f\":%.0f}", disks[i].t, disks[i].u, disks[i].f);
        }
        sb_add(&b, "]}", 2);
        if (b.n < sizeof snap) memcpy(snap, b.p, b.n + 1);
        free(b.p);

        h_cpu[hhead] = cpu_total; h_temp[hhead] = temp; h_w[hhead] = w; h_rx[hhead] = rxr; h_tx[hhead] = txr;
        h_mem[hhead] = mt ? 100.0 * (mt - ma) / mt : 0;
        hhead = (hhead + 1) % HN; if (hcount < HN) hcount++;
        h_end = now; seq++;
        pthread_cond_broadcast(&cv);
        pthread_mutex_unlock(&mx);
    }
    return NULL;
}

/* ---------- http ---------- */
typedef struct {
    char method[8], path[1024], query[2048], cookie[256], ip[48], xhr[24];
    int https;
    long long clen, r0, r1;
    int has_range;
    const char *extra; size_t extra_len; // bytes do corpo já lidos junto com o cabeçalho
} Req;

static const char *status_text(int c) {
    switch (c) {
    case 200: return "OK"; case 206: return "Partial Content"; case 400: return "Bad Request";
    case 401: return "Unauthorized"; case 403: return "Forbidden"; case 404: return "Not Found";
    case 409: return "Conflict"; case 429: return "Too Many Requests"; case 416: return "Range Not Satisfiable"; case 503: return "Service Unavailable";
    default: return "Internal Server Error";
    }
}
static int send_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}
static void reply(int c, int code, const char *ctype, const char *body, size_t n, const char *extra) {
    char h[768];
    int l = snprintf(h, sizeof h, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n%s\r\n",
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

static void urldecode(char *o, const char *s, size_t cap) {
    size_t n = 0;
    for (; *s && n + 1 < cap; s++) {
        if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) { char h[3] = {s[1], s[2], 0}; o[n++] = strtol(h, NULL, 16); s += 2; }
        else if (*s == '+') o[n++] = ' ';
        else o[n++] = *s;
    }
    o[n] = 0;
}
static int qget(const char *q, const char *key, char *out, size_t cap) {
    size_t kl = strlen(key);
    for (const char *p = q; p && *p;) {
        if (!strncmp(p, key, kl) && p[kl] == '=') {
            char raw[2048]; const char *v = p + kl + 1;
            size_t n = strcspn(v, "&");
            if (n >= sizeof raw) n = sizeof raw - 1;
            memcpy(raw, v, n); raw[n] = 0;
            urldecode(out, raw, cap);
            return 1;
        }
        p = strchr(p, '&'); if (p) p++;
    }
    out[0] = 0;
    return 0;
}

static const char *mime_of(const char *p) {
    const char *e = strrchr(p, '.');
    if (!e) return "application/octet-stream";
    static const struct { const char *e, *m; } t[] = {
        {".html", "text/html; charset=utf-8"}, {".css", "text/css"}, {".js", "text/javascript"}, {".json", "application/json"},
        {".svg", "image/svg+xml"}, {".png", "image/png"}, {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"}, {".gif", "image/gif"},
        {".webp", "image/webp"}, {".avif", "image/avif"}, {".ico", "image/x-icon"}, {".mp4", "video/mp4"}, {".webm", "video/webm"},
        {".mkv", "video/x-matroska"}, {".mov", "video/quicktime"}, {".mp3", "audio/mpeg"}, {".ogg", "audio/ogg"}, {".wav", "audio/wav"},
        {".flac", "audio/flac"}, {".m4a", "audio/mp4"}, {".pdf", "application/pdf"}, {".txt", "text/plain; charset=utf-8"},
        {".md", "text/plain; charset=utf-8"}, {".woff2", "font/woff2"}, {NULL, NULL}};
    for (int i = 0; t[i].e; i++) if (!strcasecmp(e, t[i].e)) return t[i].m;
    return "application/octet-stream";
}

// envia fd inteiro ou com Range (vídeo precisa de 206 para seek)
static void serve_fd(int c, int fd, const Req *rq, const char *mime, const char *extra) {
    struct stat st;
    if (fstat(fd, &st) || S_ISDIR(st.st_mode)) { jerr(c, 404, "não encontrado"); return; }
    long long a = 0, b = st.st_size - 1;
    int code = 200;
    if (rq->has_range) {
        a = rq->r0 < 0 ? st.st_size - rq->r1 : rq->r0;
        b = (rq->r0 < 0 || rq->r1 < 0 || rq->r1 >= st.st_size) ? st.st_size - 1 : rq->r1;
        if (a < 0) a = 0;
        if (a > b || a >= st.st_size) {
            char h[160]; int l = snprintf(h, sizeof h, "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */%lld\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", (long long)st.st_size);
            send_all(c, h, l); return;
        }
        code = 206;
    }
    char h[1024];
    int l = snprintf(h, sizeof h, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %lld\r\nAccept-Ranges: bytes\r\nCache-Control: no-cache\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n%s",
                     code, status_text(code), mime, b - a + 1, extra ? extra : "");
    if (code == 206) l += snprintf(h + l, sizeof h - l, "Content-Range: bytes %lld-%lld/%lld\r\n", a, b, (long long)st.st_size);
    l += snprintf(h + l, sizeof h - l, "\r\n");
    if (send_all(c, h, l)) return;
    off_t off = a;
    long long left = b - a + 1;
    while (left > 0) {
        ssize_t r = sendfile(c, fd, &off, left > (1 << 20) ? (1 << 20) : left);
        if (r <= 0) break;
        left -= r;
    }
}

/* ---------- usuários e sessões ---------- */
// 0 = administrador (senha em homelab.conf). 1 = gestor, opcional (manager= no conf): só gerenciamento do servidor,
// senha em data/<gestor>.pw, criada pelo administrador na linha de comando (--manager-password). Não existe "primeiro acesso" aberto.
static const char *uname_(int u) { return u ? cfg.manager : cfg.admin; }
static char sess[32][33];
static int sess_u[32];
static time_t sexp[32];
static pthread_mutex_t smx = PTHREAD_MUTEX_INITIALIZER;
static int auth_on(void) { return cfg.hash[0] != 0; }

static void session_new(char *tok, int user) {
    uint8_t r[16];
    rand_bytes(r, 16);
    hex_of(r, 16, tok);
    pthread_mutex_lock(&smx);
    int slot = 0;
    for (int i = 0; i < 32; i++) if (sexp[i] < sexp[slot]) slot = i;
    memcpy(sess[slot], tok, 33); sess_u[slot] = user; sexp[slot] = time(NULL) + 7 * 86400;
    pthread_mutex_unlock(&smx);
}
// token do cookie "hl" (nome exato, 32 hex); 0 se não houver
static int cookie_tok(const Req *rq, char tok[33]) {
    for (const char *p = rq->cookie; *p;) {
        while (*p == ' ' || *p == ';') p++;
        size_t n = strcspn(p, ";");
        if (n == 35 && !strncmp(p, "hl=", 3) && strspn(p + 3, "0123456789abcdef") == 32) { memcpy(tok, p + 3, 32); tok[32] = 0; return 1; }
        p += n;
    }
    return 0;
}
// -1 sem sessão, 0 administrador, 1 gestor
static int session_user(const Req *rq) {
    if (!auth_on()) return 0;
    char tok[33]; int u = -1;
    if (!cookie_tok(rq, tok)) return -1;
    pthread_mutex_lock(&smx);
    for (int i = 0; i < 32; i++) if (sexp[i] > time(NULL) && ct_eq(sess[i], tok)) u = sess_u[i];
    pthread_mutex_unlock(&smx);
    return u;
}
static void session_end(const Req *rq) {
    char tok[33];
    if (!cookie_tok(rq, tok)) return;
    pthread_mutex_lock(&smx);
    for (int i = 0; i < 32; i++) if (ct_eq(sess[i], tok)) sexp[i] = 0;
    pthread_mutex_unlock(&smx);
}
// limite de tentativas de login por IP: 5 erros bloqueiam o IP por 15 min
static struct { char ip[48]; int fails; time_t until, last; } rl[64];
static pthread_mutex_t rmx = PTHREAD_MUTEX_INITIALIZER;
static int rl_wait(const char *ip) { // segundos restantes de bloqueio
    int w = 0;
    pthread_mutex_lock(&rmx);
    for (int i = 0; i < 64; i++) if (!strcmp(rl[i].ip, ip) && rl[i].until > time(NULL)) w = (int)(rl[i].until - time(NULL));
    pthread_mutex_unlock(&rmx);
    return w;
}
static void rl_fail(const char *ip) {
    time_t now = time(NULL);
    pthread_mutex_lock(&rmx);
    int slot = -1, old = 0;
    for (int i = 0; i < 64; i++) { if (!strcmp(rl[i].ip, ip)) slot = i; if (rl[i].last < rl[old].last) old = i; }
    if (slot < 0) { slot = old; memset(&rl[slot], 0, sizeof rl[slot]); snprintf(rl[slot].ip, sizeof rl[slot].ip, "%s", ip); }
    if (now - rl[slot].last > 900) rl[slot].fails = 0;
    rl[slot].last = now;
    if (++rl[slot].fails >= 5) { rl[slot].until = now + 900; rl[slot].fails = 0; }
    pthread_mutex_unlock(&rmx);
}
static void rl_clear(const char *ip) {
    pthread_mutex_lock(&rmx);
    for (int i = 0; i < 64; i++) if (!strcmp(rl[i].ip, ip)) memset(&rl[i], 0, sizeof rl[i]);
    pthread_mutex_unlock(&rmx);
}
static int rl_block(int c, const Req *rq) { // responde 429 e devolve 1 se o IP está bloqueado
    int w = rl_wait(rq->ip);
    if (!w) return 0;
    char m[128], b[160];
    snprintf(m, sizeof m, "Muitas tentativas. Tente de novo em %d min.", (w + 59) / 60);
    int n = snprintf(b, sizeof b, "{\"error\":\"%s\"}", m);
    reply(c, 429, "application/json", b, n, NULL);
    return 1;
}
static void cookie_hdr(char *o, size_t cap, const Req *rq, const char *tok) {
    snprintf(o, cap, "Set-Cookie: hl=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d%s\r\n", tok, tok[0] ? 604800 : 0, rq->https ? "; Secure" : "");
}
static void hq_path(char *o, size_t c) { snprintf(o, c, "%s/%s.pw", cfg.data, cfg.manager); }
static int hq_load(char *salt, char *hash) { // "pbkdf2$..." numa palavra, ou "sal sha256" (formato antigo)
    char p[PATH_MAX], l[256]; hq_path(p, sizeof p);
    FILE *f = fopen(p, "r");
    if (!f) return 0;
    char *r = fgets(l, sizeof l, f);
    fclose(f);
    if (!r) return 0;
    l[strcspn(l, "\r\n")] = 0;
    salt[0] = 0;
    if (!strncmp(l, "pbkdf2$", 7)) { snprintf(hash, 160, "%s", l); return 1; }
    return sscanf(l, "%63s %159s", salt, hash) == 2;
}
static int hq_create(const char *pw) { // usado só pelo --manager-password (terminal do servidor): grava/troca a senha do gestor
    char p[PATH_MAX], l[200]; hq_path(p, sizeof p);
    pw_new(pw, l, sizeof l - 1); strcat(l, "\n");
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600), rc = -1;
    if (fd >= 0) { rc = write(fd, l, strlen(l)) == (ssize_t)strlen(l) ? 0 : -1; close(fd); if (rc) unlink(p); }
    return rc;
}
// extrai o valor string de uma chave de um JSON simples
static void jstr(const char *body, const char *key, char *out, size_t cap) {
    char k[48]; snprintf(k, sizeof k, "\"%s\"", key);
    out[0] = 0;
    const char *p = strstr(body, k);
    if (!p || !(p = strchr(p + strlen(k), ':')) || !(p = strchr(p, '"'))) return;
    size_t n = 0;
    for (p++; *p && *p != '"' && n + 1 < cap; p++) { if (*p == '\\' && p[1]) p++; out[n++] = *p; }
    out[n] = 0;
}
/* Primeiro acesso do gestor: só existe se o administrador armar um convite no terminal do servidor (--invite-manager). O convite tem
   um código de uso único e validade; sem ele ninguém na rede consegue definir a senha de uma conta alheia. Armar também aposenta a
   senha antiga (data/<gestor>.pw vira .pw.old), então "esqueci a senha" e "primeiro acesso" são o mesmo caminho. */
static int inv_fails; // erros de código desde que o servidor subiu: com 10, o convite é queimado
static void inv_path(char *o, size_t c) { snprintf(o, c, "%s/%s.invite", cfg.data, cfg.manager); }
static int inv_load(char *code) { // 1 se há convite válido; o código volta em code[16]
    char p[PATH_MAX], l[64]; long long exp = 0; inv_path(p, sizeof p);
    FILE *f = fopen(p, "r"); if (!f) return 0;
    char *r = fgets(l, sizeof l, f); fclose(f);
    return r && sscanf(l, "%15s %lld", code, &exp) == 2 && exp > (long long)time(NULL);
}
static int inv_arm(int hours, char *code) { // 0 ok
    static const char A[] = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // sem 0/O/1/I/L
    uint8_t r[8]; char p[PATH_MAX], pw[PATH_MAX], old[PATH_MAX + 8], l[64];
    rand_bytes(r, 8); for (int i = 0; i < 8; i++) code[i] = A[r[i] % (sizeof A - 1)]; code[8] = 0;
    inv_path(p, sizeof p); hq_path(pw, sizeof pw); snprintf(old, sizeof old, "%s.old", pw);
    if (!access(pw, F_OK)) rename(pw, old);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    int n = snprintf(l, sizeof l, "%s %lld\n", code, (long long)time(NULL) + (long long)hours * 3600);
    int rc = write(fd, l, n) == n ? 0 : -1; close(fd);
    return rc;
}
static int user_idx(const char *name) {
    if (!strcasecmp(name, cfg.admin)) return 0;
    if (cfg.manager[0] && !strcasecmp(name, cfg.manager)) return 1;
    return -1;
}

/* ---------- arquivos ---------- */
static char root_real[PATH_MAX];

static int in_root(const char *p) {
    size_t n = strlen(root_real);
    return !strncmp(p, root_real, n) && (p[n] == 0 || p[n] == '/');
}
static int resolve(const char *rel, char *out) {
    char t[PATH_MAX * 2];
    snprintf(t, sizeof t, "%s/%s", root_real, rel);
    return (realpath(t, out) && in_root(out)) ? 0 : -1;
}
static int ok_name(const char *n) {
    if (!*n || strlen(n) > 250 || !strcmp(n, ".") || !strcmp(n, "..")) return 0;
    for (; *n; n++) if (*n == '/' || (unsigned char)*n < 0x20) return 0;
    return 1;
}
static const char *rel_of(const char *abs) { const char *r = abs + strlen(root_real); return *r ? r : "/"; }

typedef struct { char n[256]; int d; long long s; long m; } Ent;
static int ent_cmp(const void *a, const void *b) {
    const Ent *x = a, *y = b;
    return x->d != y->d ? y->d - x->d : strcasecmp(x->n, y->n);
}
static void fs_list(int c, const char *q) {
    char rel[PATH_MAX], dir[PATH_MAX];
    qget(q, "path", rel, sizeof rel);
    if (resolve(rel, dir)) { jerr(c, 404, "pasta não encontrada"); return; }
    DIR *d = opendir(dir);
    if (!d) { jerr(c, 403, "sem permissão para abrir a pasta"); return; }
    Ent *e = NULL; int n = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char p[PATH_MAX * 2]; struct stat st;
        snprintf(p, sizeof p, "%s/%s", dir, de->d_name);
        if (stat(p, &st)) continue;
        if (n == cap) { cap = cap ? cap * 2 : 128; e = realloc(e, cap * sizeof *e); }
        snprintf(e[n].n, sizeof e[n].n, "%s", de->d_name);
        e[n].d = S_ISDIR(st.st_mode); e[n].s = st.st_size; e[n].m = st.st_mtime; n++;
    }
    closedir(d);
    qsort(e, n, sizeof *e, ent_cmp);
    sb b = {0};
    sb_add(&b, "{\"path\":", 8); sb_str(&b, rel_of(dir)); sb_add(&b, ",\"items\":[", 10);
    for (int i = 0; i < n; i++) {
        sb_add(&b, i ? ",{\"n\":" : "{\"n\":", i ? 6 : 5); sb_str(&b, e[i].n);
        sb_f(&b, ",\"d\":%d,\"s\":%lld,\"m\":%ld}", e[i].d, e[i].s, e[i].m);
    }
    sb_add(&b, "]}", 2);
    reply(c, 200, "application/json", b.p, b.n, NULL);
    free(b.p); free(e);
}
static void fs_get(int c, const Req *rq) {
    char rel[PATH_MAX], p[PATH_MAX], dl[8];
    qget(rq->query, "path", rel, sizeof rel);
    qget(rq->query, "dl", dl, sizeof dl);
    if (resolve(rel, p)) { jerr(c, 404, "arquivo não encontrado"); return; }
    int fd = open(p, O_RDONLY);
    if (fd < 0) { jerr(c, 403, "sem permissão para ler o arquivo"); return; }
    const char *mime = mime_of(p);
    // arquivo enviado pelo usuário nunca roda como página nem script na origem do painel
    if (!strncmp(mime, "text/html", 9) || !strcmp(mime, "text/javascript") || !strcmp(mime, "text/css")) mime = "text/plain; charset=utf-8";
    const char *base = strrchr(p, '/') + 1;
    char enc[800] = "", hdr[1100];
    for (const char *s = base; *s && strlen(enc) < 760; s++) {
        char t[4]; if (isalnum((unsigned char)*s) || *s == '.' || *s == '-' || *s == '_') { t[0] = *s; t[1] = 0; } else snprintf(t, sizeof t, "%%%02X", (unsigned char)*s);
        strcat(enc, t);
    }
    snprintf(hdr, sizeof hdr, "Content-Security-Policy: sandbox; default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'\r\nContent-Disposition: %s; filename*=UTF-8''%s\r\n", dl[0] == '1' ? "attachment" : "inline", enc);
    serve_fd(c, fd, rq, dl[0] == '1' ? "application/octet-stream" : mime, hdr);
    close(fd);
}
static int rm_cb(const char *p, const struct stat *s, int t, struct FTW *f) { (void)s; (void)t; (void)f; return remove(p); }

static void fs_upload(int c, Req *rq) {
    char rel[PATH_MAX], dir[PATH_MAX], name[300], fin[PATH_MAX * 2 + 400];
    qget(rq->query, "path", rel, sizeof rel); qget(rq->query, "name", name, sizeof name);
    if (resolve(rel, dir) || !ok_name(name)) { jerr(c, 400, "destino ou nome inválido"); return; }
    int fd = -1;
    for (int i = 0; i < 1000 && fd < 0; i++) {
        if (!i) snprintf(fin, sizeof fin, "%s/%s", dir, name);
        else {
            char *dot = strrchr(name, '.');
            int stem = dot && dot != name ? (int)(dot - name) : (int)strlen(name);
            snprintf(fin, sizeof fin, "%s/%.*s (%d)%s", dir, stem, name, i, dot && dot != name ? dot : "");
        }
        fd = open(fin, O_WRONLY | O_CREAT | O_EXCL, 0664);
        if (fd < 0 && errno != EEXIST) { jerr(c, 403, "sem permissão para gravar nessa pasta"); return; }
    }
    if (fd < 0) { jerr(c, 409, "nome em uso"); return; }
    long long left = rq->clen;
    int bad = 0;
    size_t first = rq->extra_len < (size_t)left ? rq->extra_len : (size_t)left;
    if (first && write(fd, rq->extra, first) != (ssize_t)first) bad = 1;
    left -= first;
    static __thread char buf[65536];
    while (left > 0 && !bad) {
        ssize_t r = recv(c, buf, left < (long long)sizeof buf ? left : (long long)sizeof buf, 0);
        if (r <= 0 || write(fd, buf, r) != r) bad = 1;
        else left -= r;
    }
    close(fd);
    if (bad) { unlink(fin); jerr(c, 500, "upload interrompido (disco cheio ou conexão perdida)"); return; }
    jok(c);
}
static void fs_op(int c, const char *op, const char *q) {
    char rel[PATH_MAX], p[PATH_MAX], name[300], t[PATH_MAX * 2 + 400];
    qget(q, "path", rel, sizeof rel); qget(q, "name", name, sizeof name);
    if (resolve(rel, p)) { jerr(c, 404, "não encontrado"); return; }
    if (!strcmp(op, "mkdir")) {
        if (!ok_name(name)) { jerr(c, 400, "nome inválido"); return; }
        snprintf(t, sizeof t, "%s/%s", p, name);
        if (mkdir(t, 0775)) { jerr(c, errno == EEXIST ? 409 : 403, errno == EEXIST ? "já existe uma pasta com esse nome" : "sem permissão para criar a pasta"); return; }
    } else {
        if (!strcmp(p, root_real)) { jerr(c, 403, "a pasta raiz não pode ser alterada"); return; }
        if (!strcmp(op, "rename")) {
            if (!ok_name(name)) { jerr(c, 400, "nome inválido"); return; }
            char *sl = strrchr(p, '/');
            snprintf(t, sizeof t, "%.*s/%s", (int)(sl - p), p, name);
            if (!access(t, F_OK)) { jerr(c, 409, "já existe um item com esse nome"); return; }
            if (rename(p, t)) { jerr(c, 403, "não foi possível renomear"); return; }
        } else if (nftw(p, rm_cb, 16, FTW_DEPTH | FTW_PHYS)) { jerr(c, 403, "não foi possível excluir (sem permissão)"); return; }
    }
    jok(c);
}

/* ---------- rotas ---------- */
static void serve_static(int c, const Req *rq) {
    char p[PATH_MAX * 2];
    const char *u = !strcmp(rq->path, "/") ? "/index.html" : rq->path;
    if (strstr(u, "..")) { jerr(c, 400, "caminho inválido"); return; }
    snprintf(p, sizeof p, "%s%s", cfg.web, u);
    int fd = open(p, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { jerr(c, 404, "não encontrado"); return; }
    serve_fd(c, fd, rq, mime_of(p), "Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'\r\n");
    close(fd);
}
static void snap_copy(char *o, size_t cap) { pthread_mutex_lock(&mx); snprintf(o, cap, "%s", snap); pthread_mutex_unlock(&mx); }

static void sse(int c) {
    const char *h = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    if (send_all(c, h, strlen(h))) return;
    unsigned long last = 0;
    char *buf = malloc(sizeof snap + 16);
    for (;;) {
        pthread_mutex_lock(&mx);
        struct timespec to; clock_gettime(CLOCK_REALTIME, &to); to.tv_sec += 15;
        int timed = 0;
        while (seq == last && !timed) timed = pthread_cond_timedwait(&cv, &mx, &to);
        int fresh = seq != last;
        if (fresh) { last = seq; memcpy(buf, "data: ", 6); memcpy(buf + 6, snap, strlen(snap) + 1); }
        pthread_mutex_unlock(&mx);
        if (fresh) { strcat(buf, "\n\n"); if (send_all(c, buf, strlen(buf))) break; }
        else if (send_all(c, ": ping\n\n", 8)) break;
    }
    free(buf);
}
static void history(int c) {
    sb b = {0};
    pthread_mutex_lock(&mx);
    int n = hcount, start = (hhead - n + HN) % HN;
    sb_f(&b, "{\"n\":%d,\"end\":%ld", n, (long)h_end);
    const struct { const char *k; float *a; } f[] = {{"cpu", h_cpu}, {"temp", h_temp}, {"w", h_w}, {"rx", h_rx}, {"tx", h_tx}, {"mem", h_mem}};
    for (int k = 0; k < 6; k++) {
        sb_f(&b, ",\"%s\":[", f[k].k);
        for (int i = 0; i < n; i++) sb_f(&b, "%s%.1f", i ? "," : "", f[k].a[(start + i) % HN]);
        sb_add(&b, "]", 1);
    }
    sb_add(&b, ",\"days\":[", 9);
    for (int i = ndays > 31 ? ndays - 31 : 0; i < ndays; i++) sb_f(&b, "%s{\"d\":\"%s\",\"k\":%.4f}", i == (ndays > 31 ? ndays - 31 : 0) ? "" : ",", days[i].d, days[i].k);
    sb_add(&b, "]}", 2);
    pthread_mutex_unlock(&mx);
    reply(c, 200, "application/json", b.p, b.n, NULL);
    free(b.p);
}
static int read_body(int c, Req *rq, char *out, size_t cap) {
    if (rq->clen <= 0 || (size_t)rq->clen >= cap) return -1;
    size_t have = rq->extra_len < (size_t)rq->clen ? rq->extra_len : (size_t)rq->clen;
    memcpy(out, rq->extra, have);
    while (have < (size_t)rq->clen) { ssize_t r = recv(c, out + have, rq->clen - have, 0); if (r <= 0) return -1; have += r; }
    out[have] = 0;
    return 0;
}
static void apps_path(char *o, size_t c) { state_path(o, c, "apps.json"); }
// o gestor só enxerga os atalhos marcados "all": true (ex.: hospedagem); o resto continua só do administrador
static void apps_shared(int c, const char *src) {
    sb b = {0};
    sb_add(&b, "[", 1);
    int depth = 0, in = 0, first = 1;
    const char *obj = NULL;
    for (const char *p = src; *p; p++) {
        if (in) { if (*p == '\\' && p[1]) p++; else if (*p == '"') in = 0; continue; }
        if (*p == '"') in = 1;
        else if (*p == '{') { if (!depth++) obj = p; }
        else if (*p == '}' && depth && !--depth) {
            size_t n = p - obj + 1;
            char *o = strndup(obj, n);
            if (strstr(o, "\"all\": true") || strstr(o, "\"all\":true")) { if (!first) sb_add(&b, ",", 1); first = 0; sb_add(&b, o, n); }
            free(o);
        }
    }
    sb_add(&b, "]", 1);
    reply(c, 200, "application/json", b.p, b.n, NULL);
    free(b.p);
}

static void route(int c, Req *rq) {
    const char *p = rq->path;
    int post = !strcmp(rq->method, "POST") || !strcmp(rq->method, "PUT");
    if (strncmp(p, "/api/", 5)) { serve_static(c, rq); return; }
    // POST/PUT só com o cabeçalho que o painel manda: um formulário ou fetch de outra origem (inclusive outra porta deste IP,
    // que o SameSite do cookie considera "mesmo site") não consegue enviá-lo sem pré-verificação CORS, que não é concedida
    if (post && strcmp(rq->xhr, "homelabos")) { jerr(c, 403, "origem não permitida"); return; }

    if (!strcmp(p, "/api/login") && post) {
        char body[768], name[48], pw[256], salt[64] = "", want[160] = "";
        if (read_body(c, rq, body, sizeof body)) { jerr(c, 400, "pedido inválido"); return; }
        jstr(body, "user", name, sizeof name); jstr(body, "password", pw, sizeof pw);
        if (rl_block(c, rq)) return;
        int u = auth_on() ? user_idx(name) : 0;
        if (u == 1 && !hq_load(salt, want)) { // gestor sem senha: só há "primeiro acesso" se o administrador armou um convite
            char ic[16];
            if (inv_load(ic)) { const char *m = "{\"error\":\"Primeiro acesso: defina sua senha.\",\"setup\":1}"; reply(c, 409, "application/json", m, strlen(m), NULL); return; }
            u = -1;
        }
        if (u == 0) { snprintf(salt, sizeof salt, "%s", cfg.salt); snprintf(want, sizeof want, "%s", cfg.hash); }
        int good = u >= 0 && want[0] && pw_ok(pw, salt, want);
        if (u < 0) pw_ok(pw, "", "pbkdf2$600000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000"); // mesmo custo com usuário inválido, para o tempo não revelar quem existe
        if (u >= 0 && (!auth_on() || good)) {
            char tok[33], ex[200];
            session_new(tok, u); rl_clear(rq->ip);
            cookie_hdr(ex, sizeof ex, rq, tok);
            reply(c, 200, "application/json", "{\"ok\":1}", 8, ex);
        } else { rl_fail(rq->ip); sleep(1); jerr(c, 401, "Usuário ou senha incorretos."); }
        return;
    }
    if (!strcmp(p, "/api/setup") && post) {
        char body[768], name[48], pw[256], code[32], ic[16], tok[33], ex[200];
        if (read_body(c, rq, body, sizeof body)) { jerr(c, 400, "pedido inválido"); return; }
        jstr(body, "user", name, sizeof name); jstr(body, "password", pw, sizeof pw); jstr(body, "code", code, sizeof code);
        if (rl_block(c, rq)) return;
        if (user_idx(name) != 1 || !inv_load(ic)) { rl_fail(rq->ip); jerr(c, 403, "Não há convite aberto para esta conta. Peça ao administrador."); return; }
        for (char *q = code; *q; q++) *q = toupper((unsigned char)*q);
        if (!ct_eq(code, ic)) {
            rl_fail(rq->ip);
            if (++inv_fails >= 10) { char ip[PATH_MAX]; inv_path(ip, sizeof ip); unlink(ip); }
            sleep(1); jerr(c, 403, "Código de convite incorreto."); return;
        }
        if (strlen(pw) < 8) { jerr(c, 400, "A senha precisa ter pelo menos 8 caracteres."); return; }
        if (hq_create(pw)) { jerr(c, 500, "não foi possível gravar a senha"); return; }
        { char ip[PATH_MAX]; inv_path(ip, sizeof ip); unlink(ip); } // uso único
        session_new(tok, 1); rl_clear(rq->ip);
        cookie_hdr(ex, sizeof ex, rq, tok);
        reply(c, 200, "application/json", "{\"ok\":1}", 8, ex);
        return;
    }
    if (!strcmp(p, "/api/logout")) {
        char ex[200];
        session_end(rq); cookie_hdr(ex, sizeof ex, rq, "");
        reply(c, 200, "application/json", "{\"ok\":1}", 8, ex);
        return;
    }
    int user = session_user(rq);
    if (user < 0) { jerr(c, 401, "faça login"); return; }
    int admin = user == 0;

    if (!strcmp(p, "/api/me")) {
        char b[96]; int n = snprintf(b, sizeof b, "{\"ok\":1,\"user\":\"%s\",\"role\":\"%s\"}", uname_(user), admin ? "admin" : "gestor");
        reply(c, 200, "application/json", b, n, NULL); return;
    }
    // o gestor (manager=) só vê o painel do servidor: nada de arquivos ou tarifa; atalhos só os marcados "all" (leitura)
    if (!admin && (!strncmp(p, "/api/fs/", 8) || (post && !strcmp(p, "/api/apps")) || !strcmp(p, "/api/settings"))) {
        jerr(c, 403, "Sem permissão para esta área."); return;
    }
    if (post && !strncmp(p, "/api/power/", 11)) { // desligar/reiniciar: só administrador; o sudoers libera só estes dois comandos
        const char *op = !strcmp(p + 11, "poweroff") ? "poweroff" : !strcmp(p + 11, "reboot") ? "reboot" : NULL;
        if (!admin) { jerr(c, 403, "Sem permissão para esta ação."); return; }
        if (!op) { jerr(c, 404, "rota inexistente"); return; }
        pthread_mutex_lock(&mx); state_save(); pthread_mutex_unlock(&mx);
        pid_t pid = fork();
        if (pid == 0) { execl("/usr/bin/sudo", "sudo", "-n", "/usr/bin/systemctl", op, (char *)NULL); _exit(127); }
        int st = 0;
        if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st) || WEXITSTATUS(st)) { jerr(c, 500, "O servidor não liberou esta ação. Rode o script de configuração de energia."); return; }
        jok(c); return;
    }
    if (!strcmp(p, "/api/metrics")) { char b[sizeof snap]; snap_copy(b, sizeof b); reply(c, 200, "application/json", b, strlen(b), NULL); return; }
    if (!strcmp(p, "/api/stream")) { sse(c); return; }
    if (!strcmp(p, "/api/history")) { history(c); return; }
    if (!strcmp(p, "/api/settings") && post) {
        char body[128];
        if (read_body(c, rq, body, sizeof body)) { jerr(c, 400, "pedido inválido"); return; }
        char *k = strstr(body, "\"price\"");
        double v = k && (k = strchr(k, ':')) ? atof(k + 1) : -1;
        if (v < 0 || v > 100) { jerr(c, 400, "valor do kWh inválido"); return; }
        pthread_mutex_lock(&mx); price = v; state_save(); pthread_mutex_unlock(&mx);
        jok(c); return;
    }
    if (!strcmp(p, "/api/apps")) {
        char ap[PATH_MAX];
        apps_path(ap, sizeof ap);
        if (post) {
            static char body[65536];
            static pthread_mutex_t am = PTHREAD_MUTEX_INITIALIZER;
            pthread_mutex_lock(&am);
            if (read_body(c, rq, body, sizeof body) || body[0] != '[') { pthread_mutex_unlock(&am); jerr(c, 400, "lista de atalhos inválida"); return; }
            FILE *f = fopen(ap, "w");
            if (f) { fputs(body, f); fclose(f); }
            pthread_mutex_unlock(&am);
            if (f) jok(c); else jerr(c, 500, "não foi possível salvar");
        } else {
            int fd = open(ap, O_RDONLY);
            if (fd >= 0 && !admin) {
                char all[65536];
                ssize_t n = read(fd, all, sizeof all - 1);
                close(fd);
                all[n > 0 ? n : 0] = 0;
                apps_shared(c, all);
                return;
            }
            if (fd < 0) reply(c, 200, "application/json", "[]", 2, NULL);
            else { Req r2 = *rq; r2.has_range = 0; serve_fd(c, fd, &r2, "application/json", NULL); close(fd); }
        }
        return;
    }
    if (!root_real[0]) { jerr(c, 503, "pasta compartilhada não encontrada no servidor"); return; }
    if (!strcmp(p, "/api/fs/list")) { fs_list(c, rq->query); return; }
    if (!strcmp(p, "/api/fs/get")) { fs_get(c, rq); return; }
    if (post && !strcmp(p, "/api/fs/upload")) { fs_upload(c, rq); return; }
    if (post && !strcmp(p, "/api/fs/mkdir")) { fs_op(c, "mkdir", rq->query); return; }
    if (post && !strcmp(p, "/api/fs/rename")) { fs_op(c, "rename", rq->query); return; }
    if (post && !strcmp(p, "/api/fs/delete")) { fs_op(c, "delete", rq->query); return; }
    jerr(c, 404, "rota inexistente");
}

static int nconn;
static void *conn_thread(void *arg) {
    int c = (int)(intptr_t)arg;
    struct timeval tv = {5, 0}; // cabeçalho: no máximo 10 s no total (slowloris); depois o prazo de cada recv sobe
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int one = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
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
    struct sockaddr_in pa; socklen_t pl = sizeof pa;
    int loop = 0;
    if (!getpeername(c, (struct sockaddr *)&pa, &pl)) { inet_ntop(AF_INET, &pa.sin_addr, rq.ip, sizeof rq.ip); loop = (ntohl(pa.sin_addr.s_addr) >> 24) == 127; }
    rq.extra = he + 4; rq.extra_len = buf + len - (he + 4);
    *he = 0;
    char target[3072];
    if (sscanf(buf, "%7s %3071s", rq.method, target) != 2) goto done;
    char *qm = strchr(target, '?');
    if (qm) { *qm++ = 0; snprintf(rq.query, sizeof rq.query, "%s", qm); }
    urldecode(rq.path, target, sizeof rq.path);
    for (char *l = strstr(buf, "\r\n"); l; l = strstr(l + 2, "\r\n")) {
        l += 2;
        if (loop && !strncasecmp(l, "cf-connecting-ip:", 17)) {
            const char *v = l + 17; while (*v == ' ') v++;
            size_t n = strspn(v, "0123456789abcdefABCDEF:.");
            if (n && n < sizeof rq.ip) snprintf(rq.ip, sizeof rq.ip, "%.*s", (int)n, v);
        }
        else if (loop && !strncasecmp(l, "x-forwarded-proto:", 18)) rq.https = strncasecmp(l + 18 + strspn(l + 18, " "), "https", 5) == 0;
        else if (!strncasecmp(l, "x-requested-with:", 17)) snprintf(rq.xhr, sizeof rq.xhr, "%.*s", (int)strcspn(l + 17 + strspn(l + 17, " "), "\r\n"), l + 17 + strspn(l + 17, " "));
        else if (!strncasecmp(l, "cookie:", 7)) snprintf(rq.cookie, sizeof rq.cookie, "%.*s", (int)strcspn(l + 7, "\r\n"), l + 7);
        else if (!strncasecmp(l, "content-length:", 15)) rq.clen = atoll(l + 15);
        else if (!strncasecmp(l, "range:", 6)) {
            const char *r = strstr(l, "bytes=");
            if (r && r < l + strcspn(l, "\r\n")) {
                r += 6; rq.has_range = 1;
                if (*r == '-') { rq.r0 = -1; rq.r1 = atoll(r + 1); }
                else { rq.r0 = atoll(r); const char *d = strchr(r, '-'); rq.r1 = d && isdigit((unsigned char)d[1]) ? atoll(d + 1) : -1; }
            }
        }
    }
    route(c, &rq);
done:
    close(c);
    __atomic_fetch_sub(&nconn, 1, __ATOMIC_RELAXED);
    return NULL;
}

static void on_sig(int s) { (void)s; quit = 1; }

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--hash")) { // a senha vem do terminal (ou do stdin), nunca de um argumento visível no ps
        char pw[256], out[200];
        if (read_pw_tty("Senha do administrador: ", pw, sizeof pw) || strlen(pw) < 8) { fprintf(stderr, "A senha precisa ter pelo menos 8 caracteres.\n"); return 1; }
        pw_new(pw, out, sizeof out);
        printf("password_hash=%s\n", out);
        return 0;
    }
    cfg_load(argc > 2 && !strcmp(argv[1], "-c") ? argv[2] : "homelab.conf");
    if (argc > 3 && !strcmp(argv[3], "--invite-manager")) { // homelabos -c homelab.conf --invite-manager [horas]
        char code[16]; int hrs = argc > 4 ? atoi(argv[4]) : 72;
        if (!cfg.manager[0]) { fprintf(stderr, "Defina manager=<nome> no homelab.conf antes.\n"); return 1; }
        mkdir(cfg.data, 0700);
        if (inv_arm(hrs, code)) { perror("gravar o convite"); return 1; }
        fprintf(stderr, "Convite aberto para \"%s\" por %d h. A senha antiga dele deixou de valer.\n", cfg.manager, hrs);
        printf("%s\n", code);
        return 0;
    }
    if (argc > 3 && !strcmp(argv[3], "--manager-password")) {
        char pw[256], pw2[256];
        if (!cfg.manager[0]) { fprintf(stderr, "Defina manager=<nome> no homelab.conf antes.\n"); return 1; }
        mkdir(cfg.data, 0700);
        if (read_pw_tty("Nova senha do gestor: ", pw, sizeof pw) || strlen(pw) < 8) { fprintf(stderr, "A senha precisa ter pelo menos 8 caracteres.\n"); return 1; }
        if (isatty(0) && (read_pw_tty("Repita: ", pw2, sizeof pw2) || strcmp(pw, pw2))) { fprintf(stderr, "As senhas não são iguais.\n"); return 1; }
        if (hq_create(pw)) { perror("gravar a senha"); return 1; }
        fprintf(stderr, "Senha do gestor \"%s\" gravada.\n", cfg.manager);
        return 0;
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_sig); signal(SIGINT, on_sig);
    umask(077);
    mkdir(cfg.data, 0700);
    if (!realpath(cfg.root, root_real)) { root_real[0] = 0; fprintf(stderr, "aviso: pasta %s não existe, gerenciador de arquivos desativado\n", cfg.root); }
    struct in_addr bind_ip;
    if (inet_pton(AF_INET, cfg.bind, &bind_ip) != 1) { fprintf(stderr, "bind=%s não é um endereço IPv4\n", cfg.bind); return 1; }
    if (!auth_on()) { // sem senha o painel entrega o gerenciador de arquivos e o desligar: só vale em loopback
        if ((ntohl(bind_ip.s_addr) >> 24) != 127) { fprintf(stderr, "recusado: sem password_hash configurado, o painel só pode escutar em 127.0.0.1 (use --hash)\n"); return 1; }
        fprintf(stderr, "aviso: sem senha configurada (painel só acessível neste computador)\n");
    } else if (strncmp(cfg.hash, "pbkdf2$", 7)) fprintf(stderr, "aviso: password_hash no formato antigo; gere um novo com ./homelabos --hash\n");
    state_load();

    pthread_t t;
    pthread_create(&t, NULL, sampler, NULL);
    pthread_detach(t);

    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(cfg.port), .sin_addr = bind_ip};
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 128)) { perror("bind/listen"); return 1; }
    fprintf(stderr, "homelabOS em http://%s:%d (arquivos: %s)\n", cfg.bind, cfg.port, root_real[0] ? root_real : "desativado");

    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 512 * 1024);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        if (__atomic_add_fetch(&nconn, 1, __ATOMIC_RELAXED) > 256 || pthread_create(&t, &at, conn_thread, (void *)(intptr_t)c)) {
            __atomic_fetch_sub(&nconn, 1, __ATOMIC_RELAXED);
            close(c);
        }
    }
}
