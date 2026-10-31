#!/usr/bin/env bash
# Teste hermético do homelabOS: sobe o servidor numa porta de teste, com pastas temporárias, e confere login, CSRF, gestor,
# gerenciador de arquivos (fuga da pasta compartilhada) e proteção contra conexões lentas. Não toca em nada do sistema.
# Uso: ./test.sh   (precisa de gcc, curl, python3)
set -u
cd "$(dirname "$0")"
T=$(mktemp -d "$PWD/.t.XXXXXX")
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
PORT=18500; BASE=http://127.0.0.1:$PORT
fail=0; ok() { echo "ok   $1"; }; bad() { echo "FAIL $1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1  ($2)"; fi; }

gcc -O2 -Wall -Wextra -Wno-format-truncation -pthread -o "$T/homelabos" server.c || { echo "compilação falhou"; exit 1; }

mkdir -p "$T/root/docs" "$T/data" "$T/outside"
echo segredo > "$T/outside/passwd.txt"; echo publico > "$T/root/docs/a.txt"
ln -s "$T/outside" "$T/root/fuga"                       # link que aponta para fora da pasta compartilhada
ln -s "$T/outside/passwd.txt" "$T/root/fuga.txt"

HASH=$(printf 'senha-do-admin' | "$T/homelabos" --hash | cut -d= -f2)
conf() { cat > "$T/homelab.conf" <<EOF
port=$PORT
bind=127.0.0.1
root=$T/root
web=$PWD/web
data=$T/data
admin=ana
manager=beto
password_hash=$HASH
EOF
}
conf
check "hash novo é PBKDF2 e confere com o hashlib do Python" 'python3 - "$HASH" <<PY
import sys, hashlib
_, it, salt, h = sys.argv[1].split("\$")
sys.exit(0 if hashlib.pbkdf2_hmac("sha256", b"senha-do-admin", bytes.fromhex(salt), int(it)).hex() == h else 1)
PY'
check "--hash recusa senha curta" '! printf curta | "$T/homelabos" --hash 2>/dev/null'

# sem senha configurada: recusa escutar fora do loopback
printf 'port=18501\nbind=0.0.0.0\nroot=%s\nweb=%s/web\ndata=%s/d2\n' "$T/root" "$PWD" "$T" > "$T/open.conf"
check "sem senha + bind fora do loopback => recusa subir" '! timeout 3 "$T/homelabos" -c "$T/open.conf" 2>&1 | grep -q "em http" && timeout 3 "$T/homelabos" -c "$T/open.conf" 2>&1 | grep -q recusado'

# gestor: a senha só nasce pelo terminal do servidor
check "--manager-password grava a senha do gestor (0600, PBKDF2)" 'printf "senha-do-beto\n" | "$T/homelabos" -c "$T/homelab.conf" --manager-password 2>/dev/null; [ "$(stat -c %a "$T/data/beto.pw")" = 600 ] && grep -q "^pbkdf2\\$" "$T/data/beto.pw"'

srv() { "$T/homelabos" -c "$T/homelab.conf" 2>>"$T/$1" & SRV=$!; sleep 1; }
srv err.log
H=(-H "X-Requested-With: homelabos")
login() { curl -s -m 20 -c "$T/ck.$1" -o /dev/null -w "%{http_code}" "${H[@]}" --data "{\"user\":\"$1\",\"password\":\"$2\"}" $BASE/api/login; }
get() { curl -s -m 10 -b "$T/ck.$1" "$BASE$2"; }          # get USER PATH
code() { curl -s -m 10 -o /dev/null -w "%{http_code}" -b "$T/ck.$1" "${@:3}" "$BASE$2"; }

check "sem sessão => 401" '[ "$(curl -s -o /dev/null -w %{http_code} $BASE/api/metrics)" = 401 ]'
check "login sem o cabeçalho anti-CSRF => 403" '[ "$(curl -s -o /dev/null -w %{http_code} --data "{\"user\":\"ana\",\"password\":\"senha-do-admin\"}" $BASE/api/login)" = 403 ]'
check "senha errada => 401" '[ "$(login ana errada)" = 401 ]'
check "admin entra com a senha certa" '[ "$(login ana senha-do-admin)" = 200 ]'
check "/api/me devolve o nome configurado e o papel admin" 'get ana /api/me | grep -q "\"user\":\"ana\".*\"role\":\"admin\""'
check "cookie é HttpOnly, SameSite=Strict e vale 7 dias" 'curl -s -D - -o /dev/null "${H[@]}" --data "{\"user\":\"ana\",\"password\":\"senha-do-admin\"}" $BASE/api/login | grep -qi "^set-cookie: hl=[0-9a-f]\{32\}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800"'
check "POST autenticado sem o cabeçalho anti-CSRF => 403 (poweroff não dispara)" '[ "$(code ana /api/power/poweroff -X POST)" = 403 ]'
check "POST autenticado de outra origem (cabeçalho errado) => 403" '[ "$(code ana /api/fs/delete?path=/docs/a.txt -X POST -H "X-Requested-With: x")" = 403 ] && [ -e "$T/root/docs/a.txt" ]'
check "cookie com nome parecido (xhl=) não autentica" 'TOK=$(awk "/hl\t/ {print \$7}" "$T/ck.ana"); [ "$(curl -s -o /dev/null -w %{http_code} -H "Cookie: xhl=$TOK" $BASE/api/me)" = 401 ] && [ "$(curl -s -o /dev/null -w %{http_code} -H "Cookie: a=b; hl=$TOK" $BASE/api/me)" = 200 ]'
check "token curto/prefixo não autentica" 'TOK=$(awk "/hl\t/ {print \$7}" "$T/ck.ana"); [ "$(curl -s -o /dev/null -w %{http_code} -H "Cookie: hl=${TOK:0:31}" $BASE/api/me)" = 401 ]'

# gerenciador de arquivos
check "lista a pasta compartilhada" 'get ana "/api/fs/list?path=/docs" | grep -q a.txt'
check "../ não escapa da pasta compartilhada" 'get ana "/api/fs/get?path=/../outside/passwd.txt" | grep -q -v segredo; ! get ana "/api/fs/get?path=%2e%2e/outside/passwd.txt" | grep -q segredo'
check "link simbólico para fora não lê (diretório)" '! get ana "/api/fs/list?path=/fuga" | grep -q passwd.txt'
check "link simbólico para fora não lê (arquivo)" '! get ana "/api/fs/get?path=/fuga.txt" | grep -q segredo'
check "upload com / no nome é recusado" '[ "$(code ana "/api/fs/upload?path=/docs&name=../x.txt" -X POST "${H[@]}" --data x)" = 400 ] && [ ! -e "$T/root/x.txt" ] && [ ! -e "$T/x.txt" ]'
check "upload normal funciona" '[ "$(code ana "/api/fs/upload?path=/docs&name=novo.txt" -X POST "${H[@]}" --data ola)" = 200 ] && [ "$(cat "$T/root/docs/novo.txt")" = ola ]'
check "arquivo enviado nunca roda como página (CSP sandbox + text/plain)" 'echo "<script>1</script>" > "$T/root/docs/p.html"; curl -s -D - -b "$T/ck.ana" "$BASE/api/fs/get?path=/docs/p.html" | tr -d "\r" | grep -qi "^content-type: text/plain" '
check "a pasta raiz não pode ser apagada" '[ "$(code ana "/api/fs/delete?path=/" -X POST "${H[@]}")" = 403 ] && [ -d "$T/root" ]'

# estático
check "../ na rota estática é recusado" '[ "$(curl -s -o /dev/null -w %{http_code} --path-as-is $BASE/../server.c)" != 200 ] && ! curl -s --path-as-is "$BASE/%2e%2e/server.c" | grep -q getrandom'
check "página inicial traz CSP e não permite iframe" 'curl -s -D - -o /dev/null $BASE/ | tr -d "\r" | grep -qi "^content-security-policy: default-src .self.*frame-ancestors .none" && curl -s -D - -o /dev/null $BASE/ | grep -qi "^x-frame-options: DENY"'

# gestor
check "gestor com senha entra" '[ "$(login beto senha-do-beto)" = 200 ] && get beto /api/me | grep -q "\"role\":\"gestor\""'
check "gestor não vê arquivos nem desliga" '[ "$(code beto "/api/fs/list?path=/")" = 403 ] && [ "$(code beto /api/power/poweroff -X POST "${H[@]}")" = 403 ]'
check "/api/setup não existe mais: ninguém define senha de conta alheia" 'rm -f "$T/data/beto.pw"; R=$(curl -s -o /dev/null -w "%{http_code}" "${H[@]}" --data "{\"user\":\"beto\",\"password\":\"tomei-a-conta\"}" $BASE/api/setup); [ "$R" = 401 ] && [ ! -e "$T/data/beto.pw" ]'
check "gestor sem senha definida: login falha igual a usuário inexistente (sem pista de 'primeiro acesso')" '[ "$(login beto qualquer-coisa)" = 401 ] && ! curl -s "${H[@]}" --data "{\"user\":\"beto\",\"password\":\"x\"}" $BASE/api/login | grep -qi "primeiro"'

# formato antigo (30000 rodadas de sha256) continua valendo até a senha ser trocada
OLD=$(python3 - <<'PY'
import hashlib
salt = "0123456789abcdef"; pw = b"senha-antiga"
d = hashlib.sha256(salt.encode() + pw).digest()
for _ in range(30000): d = hashlib.sha256(d + pw).digest()
print(salt, d.hex())
PY
)
kill $SRV; sleep 1
conf; sed -i "s/^password_hash=.*/salt=${OLD% *}\npassword_hash=${OLD#* }/" "$T/homelab.conf"
srv err2.log
check "senha no formato antigo ainda entra (e o servidor avisa para regerar)" '[ "$(login ana senha-antiga)" = 200 ] && grep -q "formato antigo" "$T/err2.log"'

# conexões lentas não seguram o servidor
check "conexão que não envia o cabeçalho é derrubada em até ~6 s" 'python3 - <<PY
import socket, time
s = socket.create_connection(("127.0.0.1", $PORT)); t = time.time(); s.settimeout(9)
try: d = s.recv(10)
except Exception: d = b"timeout"
sys_ok = d == b"" and time.time() - t < 8
raise SystemExit(0 if sys_ok else 1)
PY'
check "conexão que pinga 1 byte por vez é derrubada em ~10 s (prazo total)" 'python3 - <<PY
import socket, time
s = socket.create_connection(("127.0.0.1", $PORT)); t = time.time(); closed = None
while time.time() - t < 25 and closed is None:
    s.send(b"G"); s.settimeout(3)
    try:
        if s.recv(10) == b"": closed = time.time() - t
    except socket.timeout: pass
raise SystemExit(0 if closed and closed < 16 else 1)
PY'
check "o servidor segue respondendo depois disso" '[ "$(curl -s -o /dev/null -w %{http_code} $BASE/)" = 200 ]'

echo; [ $fail = 0 ] && echo "TUDO OK" || { echo "HOUVE FALHAS"; tail -5 "$T/err.log"; }
exit $fail
