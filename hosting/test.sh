#!/usr/bin/env bash
# Teste hermético: sobe o hosting numa porta de teste, com um painel falso (login) e um repositório git local no lugar do GitHub.
# Cobre: login, privado x compartilhado, deploy nativo, app respondendo, webhook assinado, parar/iniciar, apagar.
# Uso: ./test.sh   (precisa de gcc, git, python3, curl, openssl)
set -u
cd "$(dirname "$0")"
T=$(mktemp -d "$PWD/.t.XXXXXX") # fora de /tmp, senão o sandbox (que libera /tmp) não tem o que esconder
stop_hosting() { local p; for p in $(pgrep -f "^$T/hosting -c"); do kill -TERM $p; done; for _ in $(seq 1 120); do pgrep -f "^$T/hosting -c" >/dev/null || return 0; sleep 0.1; done; return 1; }
trap 'stop_hosting; kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
PORT=18430; DASH=18080; APP=$T/data
J=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; H=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb   # cookies falsos: ana e beto
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
diag() { # estado completo quando algo falha: ajuda a achar corrida em vez de adivinhar
  echo "   --- diag: $(api ana GET /api/overview | python3 -c 'import sys,json; print([(a["id"],a["state"],a["restarts"],a["port"],a["last"]) for a in json.load(sys.stdin)["apps"]])' 2>&1)"
  echo "   --- procs: $(ps -eo pid,ppid,pgid,cmd | grep -E "app.py|$T/hosting" | grep -v grep | tr '\n' ';')"
  for d in "$APP"/apps/*/; do echo "   --- run.log $(basename $d): $(tail -c 300 $d/run.log 2>/dev/null | tr '\n' '|')"; done
  echo "   --- err.log: $(tail -c 300 "$T/err.log" | tr '\n' '|')"
}
check() { if eval "$2"; then ok "$1"; else bad "$1  ($2)"; [ -n "${DIAG:-}" ] && diag; fi; }

gcc -O2 -Wall -Wextra -Wno-format-truncation -pthread -o "$T/hosting" hosting.c || { echo "compilação falhou"; exit 1; }

# painel falso: /api/me devolve o usuário conforme o cookie
cat > "$T/dash.py" <<'EOF'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        c = s.headers.get("Cookie", "")
        u = "ana" if "hl=" + "a"*32 in c else "beto" if "hl=" + "b"*32 in c else None
        b = ('{"ok":1,"user":"%s","role":"%s"}' % (u, "admin" if u == "ana" else "gestor")) if u else '{"error":"faça login"}'
        s.send_response(200 if u else 401); s.send_header("Content-Length", str(len(b.encode()))); s.end_headers(); s.wfile.write(b.encode())
    def log_message(*a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
python3 "$T/dash.py" $DASH &

# "GitHub" local: acme/site.git com um app python que responde a versão
mkdir -p "$T/gh/acme/site.git" && cd "$T/gh/acme/site.git" && git init -q -b main . && git config user.email t@t && git config user.name t
cat > app.py <<'EOF'
import http.server, os
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        b = ("v=%s db=%s n=%s" % (open("VERSION").read().strip(), os.environ.get("MEU_VAR", ""), os.environ.get("DB_NAME", ""))).encode()
        s.send_response(200); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(*a): pass
http.server.HTTPServer(("127.0.0.1", int(os.environ["PORT"])), H).serve_forever()
EOF
echo 1 > VERSION && git add -A && git commit -qm "v1" && cd - >/dev/null
mkdir -p "$T/gh/acme/dock.git" && ( cd "$T/gh/acme/dock.git" && git init -q -b main . && git config user.email t@t && git config user.name t && printf 'FROM alpine\nCMD ["sleep","1000"]\n' > Dockerfile && git add -A && git commit -qm "dock" )

mkdir "$T/bin"
export PODMAN_LOG=$T/podman.log PODMAN_ENV=$T/podman.env
cat > "$T/bin/podman" <<'EOF'
#!/bin/sh
echo "$@" >> "$PODMAN_LOG"
[ "$1" = run ] && env | grep -E '^(PORT|HOST|DB_[A-Z]+|DATABASE_URL|A)=' | sort >> "$PODMAN_ENV"
case "$1" in
  build) echo "STEP 1/1: FROM scratch"; echo "Successfully tagged"; exit 0 ;;
  run) exec sleep 601 ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$T/bin/podman"
for b in psql mariadb; do
  printf '#!/bin/sh\necho "ARGS $*" >> "$FAKE_LOG"\nsed "s/^/IN /" >> "$FAKE_LOG"\n[ -e "$FAKE_DOWN" ] && { echo "connection refused"; exit 2; }\nexit 0\n' > "$T/bin/$b"
  chmod +x "$T/bin/$b"
done
export FAKE_LOG=$T/db.log FAKE_DOWN=$T/db_down; touch "$FAKE_DOWN"; export PATH=$T/bin:$PATH

# cloudflared falso: registra os argumentos; "list" só acha o túnel depois de "create"; o túnel em si é um sleep
export CF_LOG=$T/cf.log CF_CREATED=$T/tunnel_created
cat > "$T/bin/cloudflared" <<'EOF'
#!/bin/sh
echo "$@" >> "$CF_LOG"
case "$*" in
  "tunnel list"*) if [ -e "$CF_CREATED" ]; then echo '[{"id":"11111111-2222-3333-4444-555555555555","name":"hosting","connections":[{"id":"zzz"}]}]'; else echo '[]'; fi ;;
  "tunnel create"*) touch "$CF_CREATED"; echo "Created tunnel hosting with id 11111111-2222-3333-4444-555555555555" ;;
  "tunnel route dns"*) echo "Added CNAME" ;;
  "tunnel --no-autoupdate"*) exec sleep 600 ;;
esac
EOF
chmod +x "$T/bin/cloudflared"
# API do Cloudflare falsa: só aceita "Bearer goodtoken"; registra método, caminho, auth e corpo
cat > "$T/cfapi.py" <<'EOF'
import http.server, json, sys
LOG = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def _go(s):
        n = int(s.headers.get("Content-Length") or 0); body = s.rfile.read(n).decode() if n else ""
        auth = s.headers.get("Authorization", "")
        open(LOG, "a").write("%s %s %s %s\n" % (s.command, s.path, auth, body))
        if auth != "Bearer goodtoken": out, code = {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]}, 403
        elif s.path.startswith("/zones?name="): out, code = {"success": True, "result": [{"id": "zone123", "name": "example.com"}]}, 200
        elif "/dns_records?" in s.path and "name=taken.example.com" in s.path: out, code = {"success": True, "result": [{"id": "r9", "content": "outro.exemplo.net"}]}, 200
        elif "/dns_records?" in s.path: out, code = {"success": True, "result": []}, 200
        else: out, code = {"success": True, "result": {"id": "rec1"}}, 200
        b = json.dumps(out).encode(); s.send_response(code); s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)
    do_GET = do_POST = do_PUT = _go
    def log_message(*a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
EOF
python3 "$T/cfapi.py" 18099 "$T/cfapi.log" &

cat > "$T/hosting.conf" <<EOF
port=$PORT
web=$PWD/web
data=$APP
dash_ports=$DASH
admin=ana
cert_domain=cert.example
native_users=beto
git_base=file://$T/gh/
cf_api=http://127.0.0.1:18099
EOF
"$T/hosting" -c "$T/hosting.conf" 2>"$T/err.log" & sleep 1.5

api() { # api USER METHOD PATH [data]
  local ck=$J; [ "$1" = beto ] && ck=$H
  curl -s -m 20 -X "$2" -H "Cookie: hl=$ck" -H "X-Requested-With: hosting" ${4:+--data "$4"} "http://127.0.0.1:$PORT$3"
}
wait_state() { for _ in $(seq 1 60); do api ana GET /api/overview | grep -q "\"state\":\"$2\"" && return 0; sleep 0.5; done; return 1; }

check "sem cookie => 401" '[ "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:$PORT/api/overview)" = 401 ]'
check "POST sem X-Requested-With => 403" '[ "$(curl -s -o /dev/null -w %{http_code} -X POST -H "Cookie: hl=$J" http://127.0.0.1:$PORT/api/app/save)" = 403 ]'
check "pagina inicial serve" '[ "$(curl -s -o /dev/null -w %{http_code} http://127.0.0.1:$PORT/)" != 000 ]'

R=$(api ana POST /api/app/save "name=Site Privado&scope=private&repo=acme/site&branch=main&runtime=native&start=python3 app.py&env=MEU_VAR=ola&deploy=1")
check "criar app privado" 'echo "$R" | grep -q "\"id\":\"site-privado\""'
R=$(api ana POST /api/app/save "name=Site Comum&scope=shared&repo=https://github.com/acme/site.git&branch=main&runtime=native&start=python3 app.py&deploy=1")
check "criar app compartilhado" 'echo "$R" | grep -q "\"id\":\"site-comum\""'
check "repo invalido recusado" 'api ana POST /api/app/save "name=x&repo=../etc&branch=main" | grep -q error'
check "env invalido recusado" 'api ana POST /api/app/save "name=y&repo=acme/site&env=ruim sem igual" | grep -q error'

check "ana ve os dois" '[ "$(api ana GET /api/overview | grep -o "\"state\"" | wc -l)" = 2 ]'
check "beto ve so o compartilhado" 'api beto GET /api/overview | grep -q "site-comum" && ! api beto GET /api/overview | grep -q "site-privado"'
check "beto nao mexe no privado" 'api beto POST "/api/app/stop?id=site-privado" | grep -q error'
check "beto edita o compartilhado" 'api beto POST "/api/app/save" "id=site-comum&name=Site Comum&scope=shared&repo=acme/site&branch=main&runtime=native&start=python3 app.py" | grep -q "\"ok\":1"'

check "deploy termina e app sobe" 'wait_state x running'
sleep 1.5
PP=$(api ana GET /api/overview | python3 -c 'import sys,json; print([a["port"] for a in json.load(sys.stdin)["apps"] if a["id"]=="site-privado"][0])')
check "app privado responde com a versao e a env" '[ "$(curl -s -m 5 127.0.0.1:$PP)" = "v=1 db=ola n=" ]'
check "token nao vaza na api" '! api ana GET /api/overview | grep -q "x-access-token"'

# novo commit + webhook assinado (secret do app)
( cd "$T/gh/acme/site.git" && echo 2 > VERSION && git commit -qam "v2" )
SEC=$(api ana GET /api/overview | python3 -c 'import sys,json; print([a["secret"] for a in json.load(sys.stdin)["apps"] if a["id"]=="site-privado"][0])')
api ana POST "/api/app/save" "id=site-privado&name=Site Privado&scope=private&repo=acme/site&branch=main&runtime=native&start=python3 app.py&env=MEU_VAR=ola&autodeploy=1" >/dev/null
BODY='{"ref":"refs/heads/main","commits":[]}'
SIG="sha256=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$SEC" | awk '{print $NF}')"
check "webhook com assinatura ruim => 401" '[ "$(curl -s -o /dev/null -w %{http_code} -X POST -H "X-Hub-Signature-256: sha256=00" -H "X-GitHub-Event: push" --data "$BODY" http://127.0.0.1:$PORT/hook/site-privado)" = 401 ]'
check "webhook push outra branch ignorado" '[ "$(curl -s -X POST -H "X-Hub-Signature-256: sha256=$(printf %s "{\"ref\":\"refs/heads/dev\"}" | openssl dgst -sha256 -hmac "$SEC" | awk "{print \$NF}")" -H "X-GitHub-Event: push" --data "{\"ref\":\"refs/heads/dev\"}" http://127.0.0.1:$PORT/hook/site-privado)" = ignorado ]'
check "webhook push da branch => deploy" '[ "$(curl -s -X POST -H "X-Hub-Signature-256: $SIG" -H "X-GitHub-Event: push" --data "$BODY" http://127.0.0.1:$PORT/hook/site-privado)" = "deploy iniciado" ]'
sleep 4
check "app privado atualizou para v2" '[ "$(curl -s -m 5 127.0.0.1:$PP)" = "v=2 db=ola n=" ]'
check "historico registra 2 deploys" '[ "$(api ana GET "/api/app/log?id=site-privado&which=hist" | wc -l)" -ge 2 ]'
check "log do deploy tem o commit" 'api ana GET "/api/app/log?id=site-privado&which=deploy" | grep -q "v2"'

check "parar" 'api ana POST "/api/app/stop?id=site-privado" | grep -q ok && wait_state x stopped'
sleep 1; check "app parado => o proxy segue na porta e responde 502" '[ "$(curl -s -m 2 -o /dev/null -w %{http_code} 127.0.0.1:$PP)" = 502 ]'
check "iniciar de novo" 'api ana POST "/api/app/start?id=site-privado" | grep -q ok; sleep 2; [ "$(curl -s -m 5 127.0.0.1:$PP)" = "v=2 db=ola n=" ]'
# queda do líder do grupo (o sh) deixa o python órfão: o hosting precisa encerrá-lo e religar o app, sem ficar preso na porta
LEAD=$(pgrep -f "^sh -c python3 app.py" | head -1)
check "app que cai e reiniciado (mata o sh, o python fica órfão)" 'kill -9 $LEAD; sleep 6; curl -s -m 3 127.0.0.1:$PP | grep -q "v="'
check "hosting nao deixou python orfao segurando a porta" '[ "$(ps -eo ppid,cmd | awk "\$1==1 && /python3 app.py/" | wc -l)" = 0 ]'
check "apagar" 'api ana POST "/api/app/delete?id=site-privado" | grep -q ok && ! api ana GET /api/overview | grep -q site-privado'
check "dados do app sumiram" '[ ! -d "$APP/apps/site-privado" ]'

check "dominio sem cadastro recusado" 'api ana POST /api/app/save "name=z&repo=acme/site&host=app.outro.com" | grep -q "não está cadastrado"'
check "dominio do ana e privado" 'api ana GET /api/overview | grep -q cert.example && ! api beto GET /api/overview | grep -q cert.example'
check "beto nao usa dominio do ana" 'api beto POST /api/app/save "name=z&repo=acme/site&host=x.cert.example" | grep -q "não está cadastrado"'
# ---- Cloudflare (simulado): cloudflared falso + API do Cloudflare falsa; nada de túnel ou DNS de verdade ----
TID=11111111-2222-3333-4444-555555555555
check "domínio com token ruim => erro da API do Cloudflare" 'api ana POST /api/domain/add "name=example.com&token=ruim&scope=shared" | grep -q "Invalid access token"'
check "domínio compartilhado com token bom" 'api ana POST /api/domain/add "name=example.com&token=goodtoken&scope=shared" | grep -q "\"ok\":1"'
check "token do Cloudflare nao vaza na api" '! api ana GET /api/overview | grep -q goodtoken'
check "beto ve o dominio compartilhado e nao o do ana" 'api beto GET /api/overview | grep -q example.com'
check "app privado do beto em dominio compartilhado" 'api beto POST /api/app/save "name=Loja&scope=private&repo=acme/site&runtime=native&start=python3 app.py&host=loja.example.com" | grep -q "\"ok\":1"'
sleep 2.5
check "túnel foi criado pelo cloudflared (list vazio -> create -> list)" 'grep -q "^tunnel create hosting" "$CF_LOG" && [ "$(grep -c "^tunnel list" "$CF_LOG")" -ge 2 ]'
check "DNS: CNAME proxied apontando para o túnel via API" 'grep -q "POST /zones/zone123/dns_records .*\"name\":\"loja.example.com\".*$TID.cfargotunnel.com.*\"proxied\":true" "$T/cfapi.log"'
check "API recebeu o token como Bearer" 'grep -q "Bearer goodtoken" "$T/cfapi.log"'
check "ingress gerado: host do app -> porta local do app" 'grep -q "hostname: loja.example.com" "$APP/tunnel.yml" && grep -A1 "hostname: loja.example.com" "$APP/tunnel.yml" | grep -q "service: http://127.0.0.1:100"'
check "ingress termina com 404 e usa o id do túnel" 'tail -1 "$APP/tunnel.yml" | grep -q http_status:404 && grep -q "^tunnel: $TID" "$APP/tunnel.yml"'
check "supervisor subiu o cloudflared com o config" 'grep -q "^tunnel --no-autoupdate --config .*tunnel.yml run" "$CF_LOG" && [ "$(api ana GET /api/overview | python3 -c "import sys,json; print(json.load(sys.stdin)[\"tunnel\"][\"up\"])")" = 1 ]'
check "domínio do cert.pem usa o cloudflared route dns (não a API)" 'api ana POST /api/app/save "name=Pub&scope=private&repo=acme/site&runtime=native&start=python3 app.py&host=pub.cert.example" | grep -q "\"ok\":1" && grep -q "^tunnel route dns --overwrite-dns $TID pub.cert.example" "$CF_LOG"'
check "endereço fora dos domínios do dono é recusado" 'api ana POST /api/app/save "name=X&scope=private&repo=acme/site&host=evil.cert.example.outro.com" | grep -q "não está cadastrado"'
check "app compartilhado não usa domínio privado" 'api ana POST /api/app/save "name=Y&scope=shared&repo=acme/site&host=y.cert.example" | grep -q "domínio compartilhado"'
R1=$(grep -c "^tunnel --no-autoupdate" "$CF_LOG")
api ana POST /api/settings "hook_host=hooks.cert.example" >/dev/null; sleep 3
check "webhook público: DNS pelo cloudflared e ingress para o próprio hosting" 'grep -q "route dns --overwrite-dns $TID hooks.cert.example" "$CF_LOG" && grep -A1 "hostname: hooks.cert.example" "$APP/tunnel.yml" | grep -q "service: http://127.0.0.1:$PORT"'
check "mudar os hostnames reinicia o túnel com o config novo" '[ "$(grep -c "^tunnel --no-autoupdate" "$CF_LOG")" -gt "$R1" ]'
check "pelo túnel (Cf-Connecting-Ip) o painel inteiro some, mesmo com cookie válido" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Cf-Connecting-Ip: 1.2.3.4" -H "Cookie: hl=$J" -H "X-Requested-With: hosting" http://127.0.0.1:$PORT/api/overview)" = 404 ] && [ "$(curl -s -o /dev/null -w %{http_code} -H "Cf-Connecting-Ip: 1.2.3.4" http://127.0.0.1:$PORT/)" = 404 ]'
check "pelo túnel o /hook continua funcionando (assinatura ruim => 401)" '[ "$(curl -s -o /dev/null -w %{http_code} -X POST -H "Cf-Connecting-Ip: 1.2.3.4" -H "X-Hub-Signature-256: sha256=00" -H "X-GitHub-Event: push" --data "{}" http://127.0.0.1:$PORT/hook/site-comum)" = 401 ]'
check "endereço de webhooks em domínio sem acesso é recusado" 'api beto POST /api/settings "hook_host=hooks.cert.example" | grep -q "Só o administrador"'
check "domínio em uso não pode ser removido" 'api ana POST "/api/domain/delete?name=example.com" | grep -q "usando"'

check "banco com servidor parado => erro claro" 'api ana POST /api/db/create "name=t&engine=postgres&scope=private" | grep -q "não está rodando"'

# reinício do painel mantém o estado (e agora o "servidor de banco" está de pé)
rm -f "$FAKE_DOWN"; check "desligar com SIGTERM encerra o hosting e os apps" 'stop_hosting && [ -z "$(for p in /proc/[0-9]*; do readlink $p/cwd 2>/dev/null | grep -F "$T/data" ; done)" ]'
"$T/hosting" -c "$T/hosting.conf" 2>>"$T/err.log" & sleep 3
check "estado persiste e o app compartilhado volta a rodar" 'api beto GET /api/overview | grep -q "\"state\":\"running\""'

R=$(api ana POST /api/db/create "name=Meu Banco&engine=postgres&scope=private")
check "criar banco postgres" 'echo "$R" | grep -q "\"ok\":1"'
check "postgres: o SQL com a senha vai pelo stdin e o banco novo é fechado ao PUBLIC" 'grep -q "^IN CREATE ROLE" "$FAKE_LOG" && grep -q "^IN REVOKE ALL ON DATABASE \"h_meu_banco\" FROM PUBLIC" "$FAKE_LOG"'
check "sql do postgres: role e banco do dono" 'grep -q "CREATE ROLE \"h_meu_banco\" LOGIN PASSWORD" "$FAKE_LOG" && grep -q "CREATE DATABASE \"h_meu_banco\" OWNER \"h_meu_banco\"" "$FAKE_LOG"'
check "banco privado do ana some para o beto" 'api ana GET /api/overview | grep -q h_meu_banco && ! api beto GET /api/overview | grep -q h_meu_banco'
check "criar banco mysql compartilhado" 'api beto POST /api/db/create "name=Comum&engine=mysql&scope=shared" | grep -q "\"ok\":1" && grep -q "CREATE USER .h_comum.@.%. IDENTIFIED BY" "$FAKE_LOG"'
check "banco duplicado recusado" 'api ana POST /api/db/create "name=meu banco&engine=postgres" | grep -q "Já existe"'
check "app compartilhado nao liga banco privado" 'api ana POST /api/app/save "id=site-comum&name=Site Comum&scope=shared&repo=acme/site&runtime=native&start=python3 app.py&db=h_meu_banco" | grep -q "só pode usar banco compartilhado"'
api ana POST /api/app/save "id=site-comum&name=Site Comum&scope=shared&repo=acme/site&runtime=native&start=python3 app.py&db=h_comum&deploy=1" >/dev/null; sleep 5
CP=$(api ana GET /api/overview | python3 -c 'import sys,json; print([a["port"] for a in json.load(sys.stdin)["apps"] if a["id"]=="site-comum"][0])')
check "app com banco compartilhado recebe DB_NAME" 'curl -s -m 5 127.0.0.1:$CP | grep -q "n=h_comum"'
check "banco ligado a app nao pode ser apagado" 'api ana POST "/api/db/delete?id=h_comum" | grep -q "ligado a uma aplicação"'
check "apagar banco solto roda DROP" 'api ana POST "/api/db/delete?id=h_meu_banco" | grep -q ok && grep -q "DROP DATABASE IF EXISTS \"h_meu_banco\"" "$FAKE_LOG"'

# ---- podman (simulado): confere o comando exato de build e de run ----
check "banco compartilhado para o app em container" 'api ana POST /api/db/create "name=Pod&engine=postgres&scope=shared" | grep -q "\"ok\":1"'
check "app com Dockerfile: runtime auto escolhe podman, faz build e run" 'api ana POST /api/app/save "name=Boxed&scope=shared&repo=acme/dock&runtime=auto&cport=8080&mem=256&volume=/data&db=h_pod&env=A=1&deploy=1" | grep -q "\"ok\":1"; sleep 5; grep -q "^build -t localhost/hs-boxed:latest -f .*/apps/boxed/src/Dockerfile .*/apps/boxed/src" "$PODMAN_LOG"'
BX=$(api ana GET /api/overview | python3 -c 'import sys,json; print([a["iport"] for a in json.load(sys.stdin)["apps"] if a["id"]=="boxed"][0])')
RUNL=$(grep "^run " "$PODMAN_LOG" | tail -1)
check "podman run: loopback do host (app com banco), nome, memória, porta só no loopback, segurança" 'echo "$RUNL" | grep -q -- "--rm --network=pasta:--map-host-loopback,169.254.1.2 --name hs-boxed --security-opt no-new-privileges --cap-drop=NET_RAW --pids-limit=1024 --memory 256m -p 127.0.0.1:$BX:8080 "'
check "podman run: PORT é a do container; banco aponta para host.containers.internal (valores pelo ambiente, só o NOME no argv)" 'echo "$RUNL" | grep -q -- "-e PORT " && echo "$RUNL" | grep -q -- "-e DB_PASSWORD " && grep -q "^PORT=8080" "$PODMAN_ENV" && grep -q "^DB_HOST=host.containers.internal" "$PODMAN_ENV" && grep -q "^DATABASE_URL=postgres://h_pod:.*@host.containers.internal:5432/h_pod" "$PODMAN_ENV" && grep -q "^A=1" "$PODMAN_ENV"'
check "senha do banco nunca aparece no argv do podman nem do psql/mariadb" '! echo "$RUNL" | grep -q "$(sed -n "s/^DB_PASSWORD=//p" "$PODMAN_ENV" | tail -1)" && ! grep "^ARGS" "$FAKE_LOG" | grep -qi "password"'
check "podman run: volume nomeado e imagem local por último" 'echo "$RUNL" | grep -q -- "-v hs-boxed-data:/data localhost/hs-boxed:latest$"'
check "container conta como rodando" 'api ana GET /api/overview | python3 -c "import sys,json; a=[x for x in json.load(sys.stdin)[\"apps\"] if x[\"id\"]==\"boxed\"][0]; sys.exit(0 if a[\"state\"]==\"running\" and a[\"rt\"]==\"podman\" else 1)"'
check "excluir app limpa container, imagem e volume no podman" 'api ana POST "/api/app/delete?id=boxed" | grep -q ok && grep -q "^rm -f hs-boxed" "$PODMAN_LOG" && grep -q "^rmi -f localhost/hs-boxed:latest" "$PODMAN_LOG" && grep -q "^volume rm -f hs-boxed-data" "$PODMAN_LOG"'
api ana POST "/api/db/delete?id=h_pod" >/dev/null

# ---- projetos por arquivo (zip / tar.gz), detecção da estrutura e acesso por porta ----
cat > "$T/mkzip.py" <<'PYEOF'
import zipfile, tarfile, io, sys
T = sys.argv[1]
def z(name, files):
    with zipfile.ZipFile(f"{T}/{name}.zip", "w") as zf:
        for p, c, m in files:
            i = zipfile.ZipInfo(p); i.external_attr = m << 16; zf.writestr(i, c)
z("static", [("meusite/index.html", "<h1>ola estatico</h1>", 0o644), ("__MACOSX/meusite/._index.html", "x", 0o644)])
z("shell", [("start.sh", '#!/bin/sh\nexec python3 -m http.server "$PORT" --bind "$HOST"\n', 0o755), ("index.html", "shell ok", 0o644)])
z("pyapp", [("app.py", "import http.server,os\nhttp.server.HTTPServer((os.environ['HOST'],int(os.environ['PORT'])),http.server.SimpleHTTPRequestHandler).serve_forever()\n", 0o644), ("index.html", "py ok", 0o644)])
z("echo", [("app.py", "import http.server,os\nclass H(http.server.BaseHTTPRequestHandler):\n def do_POST(s):\n  n=int(s.headers.get('Content-Length') or 0); b=s.rfile.read(n)\n  r=('%d:%s:%s:%s' % (len(b), s.headers.get('X-Forwarded-For',''), s.headers.get('Host',''), s.headers.get('Connection','')) + ':' + s.headers.get('Cookie','')).encode()\n  s.send_response(200); s.send_header('Content-Length',str(len(r))); s.end_headers(); s.wfile.write(r)\n def log_message(*a): pass\nhttp.server.HTTPServer((os.environ['HOST'],int(os.environ['PORT'])),H).serve_forever()\n", 0o644)])
z("vazio", [("README.txt", "nada", 0o644)])
z("slip", [("../evil.txt", "x", 0o644), ("index.html", "slip ok", 0o644)])
with tarfile.open(f"{T}/link.tar.gz", "w:gz") as t:
    d = b"<h1>com link</h1>"; ti = tarfile.TarInfo("index.html"); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
    ln = tarfile.TarInfo("link"); ln.type = tarfile.SYMTYPE; ln.linkname = "/etc"; t.addfile(ln)
z("snoop", [("app.py", """import http.server,os
def can(p):
    try: open(p).read(1); return 'ok'
    except Exception: return 'negado'
def own():
    try: open(os.environ['DATA_DIR']+'/f','w').write('x'); return 'ok'
    except Exception: return 'negado'
nnp=[l.split()[1] for l in open('/proc/self/status') if l.startswith('NoNewPrivs')][0]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(s):
        b=('token=%s etc=%s own=%s nnp=%s home=%s' % (can(os.environ['SNOOP_TOKEN']), can('/etc/hostname'), own(), nnp, os.environ.get('HOME','').split('/')[-1])).encode()
        s.send_response(200); s.send_header('Content-Length',str(len(b))); s.end_headers(); s.wfile.write(b)
    def log_message(*a): pass
http.server.HTTPServer((os.environ['HOST'],int(os.environ['PORT'])),H).serve_forever()
""", 0o644)])
open(f"{T}/ruim.zip", "wb").write(b"isto nao e um zip")
with tarfile.open(f"{T}/dock.tar.gz", "w:gz") as t:
    d = b'FROM alpine\nCMD ["sleep","1000"]\n'; ti = tarfile.TarInfo("proj/Dockerfile"); ti.size = len(d); t.addfile(ti, io.BytesIO(d))
PYEOF
python3 "$T/mkzip.py" "$T"
upload() { curl -s -m 30 -X POST -H "Cookie: hl=${UPK:-$J}" -H "X-Requested-With: hosting" --data-binary "@$2" "http://127.0.0.1:$PORT/api/app/upload?id=$1&name=$(basename $2)"; }
appf() { api ana GET /api/overview | python3 -c "import sys,json; a=[x for x in json.load(sys.stdin)['apps'] if x['id']=='$1'][0]; print(a['$2'])"; }
wait_state() { for _ in $(seq 1 40); do [ "$(appf $1 state)" = "$2" ] && return 0; sleep 0.5; done; return 1; }
wait_last() { for _ in $(seq 1 40); do appf $1 last | grep -q "$2" && return 0; sleep 0.5; done; return 1; }
LAN=$(hostname -I | awk '{print $1}')
enc() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }
START=$(enc 'python3 -m http.server "$PORT" --bind "$HOST" -d .')

check "zip: criar app sem GitHub" 'api ana POST /api/app/save "name=Estatico&scope=private&source=zip&expose=1" | grep -q "\"id\":\"estatico\""'
check "zip: deploy sem arquivo avisa" 'api ana POST "/api/app/deploy?id=estatico" | grep -q ok && wait_last estatico "nenhum arquivo"'
check "zip: arquivo corrompido => formato não suportado" 'upload estatico "$T/ruim.zip" | grep -q ok; wait_last estatico "formato não suportado"'
check "zip: upload do site estático (pasta por fora + __MACOSX)" 'upload estatico "$T/static.zip" | grep -q "\"ok\":1" && wait_state estatico running'
EP=$(appf estatico port)
check "zip: site servido, estrutura detectada, pasta de fora achatada" '[ "$(curl -s -m 5 127.0.0.1:$EP)" = "<h1>ola estatico</h1>" ] && api ana GET "/api/app/log?id=estatico&which=deploy" | grep -q "site estático" && api ana GET "/api/app/log?id=estatico&which=deploy" | grep -q "pasta \"meusite\""'
check "zip: __MACOSX removido e histórico mostra origem upload" '[ ! -e "$APP/apps/estatico/src/__MACOSX" ] && api ana GET "/api/app/log?id=estatico&which=hist" | grep -q "upload"'
check "zip: comando detectado fica salvo e visível" 'appf estatico start | grep -q "python3 -m http.server"'
check "porta: expose=1 abre pelo IP da rede" '[ -z "$LAN" ] || [ "$(curl -s -m 5 http://$LAN:$EP)" = "<h1>ola estatico</h1>" ]'
check "porta: expose=0 religa e fecha para a rede, mantém o loopback" 'api ana POST /api/app/save "id=estatico&name=Estatico&scope=private&source=zip&expose=0&start=$START" | grep -q ok; sleep 4; [ "$(curl -s -m 5 127.0.0.1:$EP)" = "<h1>ola estatico</h1>" ] && { [ -z "$LAN" ] || ! curl -s -m 2 http://$LAN:$EP >/dev/null; }'
check "porta: escolher a porta e religar nela" 'api ana POST /api/app/save "id=estatico&name=Estatico&scope=private&source=zip&expose=1&port=19555&start=$START" | grep -q ok; sleep 4; [ "$(curl -s -m 5 127.0.0.1:19555)" = "<h1>ola estatico</h1>" ] && [ "$(appf estatico port)" = 19555 ]'
check "porta: já é de outra aplicação" 'api ana POST /api/app/save "name=Outro&scope=private&source=zip&port=19555" | grep -q "já é de outra"'
check "porta: abaixo de 1024 recusada" 'api ana POST /api/app/save "name=Outro&scope=private&source=zip&port=80" | grep -q "Porta inválida"'
check "porta: em uso por outro programa recusada" '( python3 -m http.server 19556 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$T/p.pid" ); sleep 1; api ana POST /api/app/save "name=Outro&scope=private&source=zip&port=19556" | grep -q "em uso por outro programa"; kill $(cat "$T/p.pid")'

api ana POST /api/app/save "name=Shell&scope=private&source=zip&expose=0&start=./start.sh" >/dev/null
check "zip: bit de execução preservado (start.sh)" 'upload shell "$T/shell.zip" | grep -q ok && wait_state shell running && [ "$(curl -s -m 5 127.0.0.1:$(appf shell port)/index.html)" = "shell ok" ]'
api ana POST /api/app/save "name=PyApp&scope=private&source=zip&expose=0" >/dev/null
check "zip: Python sem requirements detectado (python3 app.py)" 'upload pyapp "$T/pyapp.zip" | grep -q ok && wait_state pyapp running && [ "$(appf pyapp start)" = "python3 app.py" ] && [ "$(curl -s -m 5 127.0.0.1:$(appf pyapp port)/index.html)" = "py ok" ]'
api ana POST /api/app/save "name=Vazio&scope=private&source=zip" >/dev/null
check "zip: estrutura desconhecida => mensagem clara" 'upload vazio "$T/vazio.zip" | grep -q ok; wait_last vazio "não reconheci a estrutura"'
api ana POST /api/app/save "name=Slip&scope=private&source=zip&expose=0" >/dev/null
check "zip-slip: arquivo com ../ é recusado inteiro e nada escapa da pasta do app" 'upload slip "$T/slip.zip" | grep -q ok; wait_last slip "não consegui extrair" && [ ! -e "$APP/apps/slip/evil.txt" ] && [ ! -e "$APP/apps/evil.txt" ] && [ ! -e "$APP/apps/slip/src/evil.txt" ] && api ana GET "/api/app/log?id=slip&which=deploy" | grep -q "caminho inválido"'
api ana POST /api/app/save "name=Dock&scope=private&source=zip&expose=1&cport=8080" >/dev/null
check "tar.gz com Dockerfile: runtime podman, build no src achatado" 'upload dock "$T/dock.tar.gz" | grep -q ok; wait_state dock running; grep -q "^build -t localhost/hs-dock:latest -f .*/apps/dock/src/Dockerfile" "$PODMAN_LOG"'
check "podman publica só no loopback, na porta interna (o proxy contador abre a pública)" 'grep "^run " "$PODMAN_LOG" | grep -- "--name hs-dock " | tail -1 | grep -q -- "-p 127.0.0.1:$(appf dock iport):8080 "'
check "upload em app do GitHub é recusado" 'upload site-comum "$T/static.zip" | grep -q "usa GitHub"'
check "upload de app alheio é recusado" 'curl -s -X POST -H "Cookie: hl=$H" -H "X-Requested-With: hosting" --data-binary "@$T/static.zip" "http://127.0.0.1:$PORT/api/app/upload?id=estatico&name=x.zip" | grep -q "não encontrada"'
check "nova versão por upload substitui a anterior" 'upload estatico "$T/static.zip" | grep -q ok; sleep 4; wait_state estatico running; [ "$(appf estatico upname)" = "static.zip" ]'

# ---- proxy contador + estatísticas ----
st() { api ana GET "/api/stats?app=$1&range=${2:-24h}"; }
stj() { st "$1" ${3:-} | python3 -c "import sys,json; d=json.load(sys.stdin); print($2)"; }
hit() { curl -s -m 5 -o /dev/null -w "%{http_code}" -A "$1" -H "CF-Connecting-IP: $2" -H "CF-IPCountry: ${3:-BR}" ${4:+-H "Referer: $4"} "http://127.0.0.1:19555${5:-/}"; }
check "app abre direto na porta interna só no loopback (e a pública é o proxy)" 'IP=$(appf estatico iport); [ "$IP" -ge 30000 ] && [ "$(curl -s -m 5 127.0.0.1:$IP)" = "<h1>ola estatico</h1>" ] && { [ -z "$LAN" ] || ! curl -s -m 2 http://$LAN:$IP >/dev/null; }'
CH="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
MOB="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605 Version/17 Mobile Safari/604"
B0=$(stj estatico 'd["pages"]'); V0=$(stj estatico 'd["visitors_today"]')
hit "$CH" 203.0.113.1 BR "https://news.example/post" >/dev/null; hit "$CH" 203.0.113.1 BR >/dev/null; hit "$MOB" 203.0.113.2 US >/dev/null; hit "$CH" 203.0.113.2 US "" /nope >/dev/null
check "só CF-Connecting-IP (sem X-Forwarded-For) não trava: cabeçalho repassado bem formado" '[ "$(curl -s -m 3 -o /dev/null -w %{http_code} -H "CF-Connecting-IP: 203.0.113.9" 127.0.0.1:19555/)" = 200 ] && [ "$(curl -s -m 3 -o /dev/null -w %{http_code} 127.0.0.1:19555/)" = 200 ]'
check "visitante único por dia: 2 IPs => 2 visitantes, 3 páginas" '[ "$(stj estatico "d[\"visitors_today\"]")" = $((V0+2)) ] && [ "$(stj estatico "d[\"pages\"]")" = $((B0+3)) ]'
check "online agora = 2" '[ "$(stj estatico "d[\"online\"]")" = 2 ]'
check "curl conta como bot e não como visitante" 'curl -s -m 5 -o /dev/null 127.0.0.1:19555/; [ "$(stj estatico "d[\"bots\"]")" -ge 1 ] && [ "$(stj estatico "d[\"visitors_today\"]")" = $((V0+2)) ]'
check "404 conta em 4xx e não vira visitante nem página" '[ "$(stj estatico "d[\"s4\"]")" -ge 1 ] && ! st estatico | grep -q "/nope"'
check "tops: página, origem, país, navegador, dispositivo" 'st estatico | python3 -c "
import sys,json; t=json.load(sys.stdin)[\"top\"]
k=lambda n:[x[0] for x in t[n]]
assert \"/\" in k(\"pages\") and \"news.example\" in k(\"refs\") and \"(direto)\" in k(\"refs\"), t
assert \"BR\" in k(\"countries\") and \"US\" in k(\"countries\") and \"Chrome\" in k(\"browsers\") and \"Celular\" in k(\"devices\"), t"'
for n in 12345 98765; do mkdir -p "$APP/apps/estatico/src/p/$n" && echo x > "$APP/apps/estatico/src/p/$n/index.html"; done
hit "$CH" 203.0.113.1 BR "" /p/12345/ >/dev/null; hit "$CH" 203.0.113.1 BR "" /p/98765/ >/dev/null
check "rota com número/hash vira :id nos tops (não explode a tabela)" 'st estatico | python3 -c "
import sys,json; p=dict(json.load(sys.stdin)[\"top\"][\"pages\"]); assert p.get(\"/p/:id/\")==2 and not any(\"12345\" in k for k in p), p"'
check "série por hora tem 24 pontos e a hora atual tem requisições" 'st estatico | python3 -c "
import sys,json; d=json.load(sys.stdin); assert len(d[\"hours\"])==24 and d[\"hours\"][-1][1]>=4 and d[\"hours\"][-1][2]>=2, d[\"hours\"][-1]"'
check "7d tem 168 pontos e 30d tem 720; dias somam os visitantes" '[ "$(stj estatico "len(d[\"hours\"])" 7d)" = 168 ] && [ "$(stj estatico "len(d[\"hours\"])" 30d)" = 720 ] && [ "$(stj estatico "d[\"visitors\"]" 30d)" -ge 2 ]'
check "latência registrada (p95 > 0) e tráfego contado" '[ "$(stj estatico "d[\"p95\"]")" -gt 0 ] && [ "$(stj estatico "d[\"bout\"]")" -gt 0 ]'
check "visão geral traz online e visitantes por app" 'api ana GET /api/overview | python3 -c "
import sys,json; a=[x for x in json.load(sys.stdin)[\"apps\"] if x[\"id\"]==\"estatico\"][0]; assert a[\"online\"]==2 and a[\"vis\"]>=2, a"'
check "app=all lista as apps visíveis" 'st all | python3 -c "
import sys,json; d=json.load(sys.stdin); assert \"estatico\" in [a[\"id\"] for a in d[\"apps\"]], d[\"apps\"]"'
check "beto não vê estatísticas de app privado do ana" 'api beto GET "/api/stats?app=estatico&range=24h" | grep -q "não encontrada" && ! api beto GET "/api/stats?app=all" | grep -q estatico'
check "stats sem login => 401" '[ "$(curl -s -o /dev/null -w %{http_code} "http://127.0.0.1:$PORT/api/stats?app=all")" = 401 ]'

api ana POST /api/app/save "name=Echo&scope=private&source=zip&expose=0" >/dev/null
check "proxy repassa corpo POST grande, Host e X-Forwarded-For; troca Connection por close" 'upload echo "$T/echo.zip" | grep -q ok && wait_state echo running; head -c 200000 /dev/urandom > "$T/big.bin"; [ "$(curl -s -m 10 -H "Host: meuhost.test" -H "Connection: keep-alive" --data-binary "@$T/big.bin" 127.0.0.1:$(appf echo port))" = "200000:127.0.0.1:meuhost.test:close:" ]'
check "parar o app => proxy responde 502 e conta como erro 5xx" 'api ana POST "/api/app/stop?id=echo" | grep -q ok; sleep 2; [ "$(curl -s -m 5 -o /dev/null -w %{http_code} 127.0.0.1:$(appf echo port))" = 502 ] && [ "$(stj echo "d[\"s5\"]")" -ge 1 ]'
check "mudar a porta pública move o proxy (a antiga fecha)" 'OLD=$(appf echo port); api ana POST /api/app/save "id=echo&name=Echo&scope=private&source=zip&expose=0&port=19600" | grep -q ok; sleep 2; [ "$(curl -s -m 5 -o /dev/null -w %{http_code} 127.0.0.1:19600)" = 502 ] && ! curl -s -m 2 127.0.0.1:$OLD >/dev/null'
check "apagar o app remove as estatísticas" 'api ana POST "/api/app/delete?id=echo" | grep -q ok && [ ! -d "$APP/apps/echo" ] && api ana GET "/api/stats?app=echo" | grep -q "não encontrada"'


# ================= segurança =================
echo "-- segurança"
mkdir -p "$T/gh/acme/sym.git" && ( cd "$T/gh/acme/sym.git" && git init -q -b main . && git config user.email t@t && git config user.name t && ln -s /etc/hostname Dockerfile && echo oi > index.html && git add -A && git commit -qm sym )
BAD_HOST=$(enc $'a.cert.example\n  - hostname: evil.cert.example\n    service: http://127.0.0.1:22\nz.cert.example')
check "host com quebra de linha (YAML do túnel) é recusado" 'api ana POST /api/app/save "name=Inj&scope=private&source=zip&host=$BAD_HOST" | grep -q "Endereço inválido" && ! grep -q "evil" "$APP/tunnel.yml"'
check "host com caracteres estranhos é recusado" 'api ana POST /api/app/save "name=Inj2&scope=private&source=zip&host=$(enc "x y.cert.example")" | grep -q "Endereço inválido"'
INJ=$(enc $'abc"\noutput = "'$T'/pwn"')
check "token do Cloudflare com aspas/quebra de linha (injeção no curl -K) é recusado" 'api ana POST /api/domain/add "name=novo.example&token=$INJ" | grep -q "Token inválido" && [ ! -e "$T/pwn" ]'
check "token do GitHub com quebra de linha é recusado" 'api ana POST /api/app/save "name=Inj3&repo=acme/site&token=$INJ" | grep -q "Token inválido"'
check "branch que começa com - é recusada (injeção de opção do git)" 'api ana POST /api/app/save "name=Inj4&repo=acme/site&branch=--upload-pack" | grep -q "Branch inválida"'
check "env grande demais não estoura o buffer" 'api ana POST /api/app/save "name=Inj5&source=zip&env=$(python3 -c "print(\"A=\"+\"x\"*2046)")" | grep -q "\"ok\":1" ; api ana POST /api/app/save "name=Inj6&source=zip&env=$(python3 -c "print(\"A=\"+\"x\"*3000)")" | grep -qi "ok\|grandes\|inválid"; kill -0 $(pgrep -f "^$T/hosting -c" | head -1)'

check "Dockerfile que é link simbólico não vira build (não vaza arquivo do servidor no log)" 'api ana POST /api/app/save "name=Sym&scope=private&repo=acme/sym&runtime=auto&deploy=1" >/dev/null; sleep 5; ! grep -q "hs-sym" "$PODMAN_LOG" && ! api ana GET "/api/app/log?id=sym&which=deploy" | grep -q "$(cat /etc/hostname)"'
check "tar.gz: link simbólico é ignorado (não aponta para /etc dentro do app)" 'api ana POST /api/app/save "name=Lnk&scope=private&source=zip&expose=0" >/dev/null; upload lnk "$T/link.tar.gz" | grep -q ok; wait_state lnk running; [ ! -e "$APP/apps/lnk/src/link" ] && api ana GET "/api/app/log?id=lnk&which=deploy" | grep -q "ignorados"'

check "proxy tira o cookie de sessão do painel (hl) mas deixa os outros" 'api ana POST /api/app/save "name=Echo2&scope=private&source=zip&expose=0" >/dev/null; upload echo2 "$T/echo.zip" | grep -q ok; wait_state echo2 running; R=$(curl -s -m 10 -H "Cookie: hl=$J; tema=escuro; x=1" --data x 127.0.0.1:$(appf echo2 port)); echo "$R" | grep -q ":tema=escuro; x=1$" && ! echo "$R" | grep -q "hl="'
check "proxy: só o cookie hl some (nenhum Cookie sobra, nem vazio)" 'R=$(curl -s -m 10 -H "Cookie: hl=$J" --data x 127.0.0.1:$(appf echo2 port)); [ "${R##*:}" = "" ]'

if grep -q "sandbox dos apps nativos: ativo" "$T/err.log"; then
  api ana POST /api/app/save "name=Snoop&scope=private&source=zip&expose=0&env=SNOOP_TOKEN=$APP/api_token" >/dev/null
  check "sandbox: app nativo NÃO lê data/ (api_token), lê o sistema, grava na própria pasta, no_new_privs ligado e HOME próprio" 'upload snoop "$T/snoop.zip" | grep -q ok; wait_state snoop running; sleep 1; [ "$(curl -s -m 5 127.0.0.1:$(appf snoop port))" = "token=negado etc=ok own=ok nnp=1 home=home" ]'
else echo "skip sandbox (kernel sem Landlock)"; fi

check "Cloudflare: registro que já existe e aponta para outro lugar não é sobrescrito" 'api beto POST /api/app/save "name=Tomada&scope=private&source=zip&host=taken.example.com" | grep -q "aponta para outro lugar" && ! grep -q "PUT /zones/zone123/dns_records/r9" "$T/cfapi.log"'
check "só o administrador muda as configurações globais" 'api beto POST /api/settings "hook_host=hooks.example.com" | grep -q "Só o administrador"'
check "pedido com X-Forwarded-For (proxy reverso/internet) só alcança o /hook" '[ "$(curl -s -o /dev/null -w %{http_code} -H "X-Forwarded-For: 1.2.3.4" -H "Cookie: hl=$J" -H "X-Requested-With: hosting" http://127.0.0.1:$PORT/api/overview)" = 404 ]'
check "cookie com nome parecido (xhl=) não autentica" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Cookie: xhl=$J" http://127.0.0.1:$PORT/api/overview)" = 401 ]'
check "overview informa admin/native do usuário" 'api ana GET /api/overview | grep -q "\"admin\":1,\"native\":1" && api beto GET /api/overview | grep -q "\"admin\":0,\"native\":1"'
check "painel: conexão que pinga 1 byte por vez é derrubada em ~10 s" 'python3 - <<PY
import socket, time
s = socket.create_connection(("127.0.0.1", $PORT)); t = time.time(); closed = None
while time.time() - t < 25 and closed is None:
    s.send(b"G"); s.settimeout(3)
    try:
        if s.recv(10) == b"": closed = time.time() - t
    except socket.timeout: pass
raise SystemExit(0 if closed and closed < 16 else 1)
PY'
check "proxy dos apps: conexão que pinga 1 byte por vez é derrubada em ~10 s" 'EP2=$(appf estatico port); python3 - <<PY
import socket, time
s = socket.create_connection(("127.0.0.1", $EP2)); t = time.time(); closed = None
while time.time() - t < 25 and closed is None:
    s.send(b"G"); s.settimeout(3)
    try:
        if s.recv(10) == b"": closed = time.time() - t
    except socket.timeout: pass
raise SystemExit(0 if closed and closed < 16 else 1)
PY'

appb() { api beto GET /api/overview | python3 -c "import sys,json; a=[x for x in json.load(sys.stdin)['apps'] if x['id']=='$1'][0]; print(a['$2'])"; }
# administrador de banco por senha (modo seguro): credenciais em data/, entrada por TCP no loopback, não pelo socket
printf '127.0.0.1:5432:*:hosting_admin:x\n' > "$APP/pgpass"; printf '[client]\nhost=127.0.0.1\nuser=hosting_admin\npassword=x\n' > "$APP/mysql.cnf"; chmod 600 "$APP/pgpass" "$APP/mysql.cnf"
check "com data/pgpass, o psql entra como hosting_admin por TCP (não pelo socket do usuário do serviço)" 'api ana POST /api/db/create "name=Seguro&engine=postgres&scope=private" | grep -q "\"ok\":1" && grep -q "^ARGS -X -h 127.0.0.1 -U hosting_admin -q .* -f -" "$FAKE_LOG"'
check "com data/mysql.cnf, o cliente do MariaDB recebe --defaults-extra-file como primeiro argumento" 'api ana POST /api/db/create "name=SeguroMy&engine=mysql&scope=private" | grep -q "\"ok\":1" && grep -q "^ARGS --defaults-extra-file=.*/mysql.cnf --batch" "$FAKE_LOG"'
# sem native_users: o segundo usuário só roda container
stop_hosting; sed -i '/^native_users=/d' "$T/hosting.conf"
"$T/hosting" -c "$T/hosting.conf" 2>>"$T/err.log" & sleep 2
check "usuário sem direito a nativo: runtime vira podman e o aviso diz por quê" 'R=$(api beto POST /api/app/save "name=Nat&scope=private&source=zip&runtime=native&start=python3%20-m%20http.server"); echo "$R" | grep -q "só pode rodar containers" && [ "$(appb nat runtime)" = podman ] && [ -z "$(appb nat start)" ]'
UPK=$H
check "e o deploy sem Dockerfile falha em vez de rodar comando no servidor" 'upload nat "$T/static.zip" | grep -q ok; sleep 3; appb nat last | grep -q "Dockerfile" && [ "$(appb nat state)" != running ]'
UPK=
check "administrador continua podendo native" 'api ana POST /api/app/save "name=NatAna&scope=private&source=zip&runtime=native&start=python3%20-m%20http.server" | grep -q "\"ok\":1" && [ "$(appf natana runtime)" = native ]'

stop_hosting
check "ao desligar as estatísticas são gravadas (hora atual e tops do dia)" '[ -s "$APP/apps/estatico/stats.cur" ] && ls "$APP"/apps/estatico/top-*.tsv >/dev/null'
check "IP puro nunca vai para o disco (só hash com sal)" '! grep -rqF "203.0.113" "$APP" && [ "$(stat -c %a "$APP/stats.salt")" = 600 ]'
check "no fim, nenhum app nem túnel sobra depois de desligar" '[ -z "$(for p in /proc/[0-9]*; do readlink $p/cwd 2>/dev/null | grep -F "$T/data" ; done)" ] && ! pgrep -x -f "sleep 600" >/dev/null'

echo; [ $fail = 0 ] && echo "TUDO OK" || { echo "HOUVE FALHAS"; tail -5 "$T/err.log"; }
exit $fail
