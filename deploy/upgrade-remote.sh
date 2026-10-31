#!/usr/bin/env bash
# Roda NO SERVIDOR (como o dono da instalação antiga, com sudo disponível): atualiza um homelabOS + Hospedagem já instalados em
# ~/homelabOS e ~/hosting para esta versão endurecida. Quem chama é deploy/upgrade-existing.sh (no seu PC).
#   MANAGER=nome bash upgrade-remote.sh <pasta-com-o-código-novo> [--dry-run]
# Faz: compila (se falhar, nada muda) → backup → ajusta as configs → [opcional] administrador de bancos por senha →
#      troca binários e painéis → reinicia → confere; se algum serviço não subir, restaura o backup sozinho.
# NÃO mexe: dados (data/), a instância do gestor em /opt, bancos dos apps, túnel, o cinema.
set -euo pipefail
SRC=${1:?uso: upgrade-remote.sh <pasta-com-o-código-novo> [--dry-run]}; SRC=$(cd "$SRC" && pwd)
DRY=0; [ "${2:-}" = "--dry-run" ] && DRY=1
H=${HOME_DIR:-$HOME}; OS=$H/homelabOS; HS=$H/hosting; ME=${USER:-$(id -un)}
TS=$(date +%Y%m%d-%H%M%S); BK=$H/backup-hardening-$TS
step() { printf '\n==> %s\n' "$*"; }
warn() { printf 'AVISO: %s\n' "$*"; }
run() { if [ $DRY = 1 ]; then echo "   [dry-run] $*"; else "$@"; fi; }
ask() { [ $DRY = 1 ] && return 1; local r; read -rp "$1 [s/N] " r </dev/tty; [[ $r =~ ^[sSyY]$ ]]; }
# setkey ARQUIVO CHAVE VALOR: troca a linha CHAVE=... ou acrescenta; nunca duplica (e respeita o que você já tinha se for "keep")
setkey() { local f=$1 k=$2 v=$3 mode=${4:-set}
  if grep -q "^$k=" "$f"; then [ "$mode" = keep ] && return 0; [ $DRY = 1 ] && { echo "   [dry-run] $f: $k=$v"; return 0; }; sed -i "s|^$k=.*|$k=$v|" "$f"
  else [ $DRY = 1 ] && { echo "   [dry-run] $f: +$k=$v"; return 0; }; printf '%s=%s\n' "$k" "$v" >> "$f"; fi; }

[ -x "$OS/homelabos" ] && [ -f "$OS/homelab.conf" ] || { echo "Não achei a instalação antiga em $OS"; exit 1; }
[ -x "$HS/hosting" ] && [ -f "$HS/hosting.conf" ] || { echo "Não achei a instalação antiga em $HS"; exit 1; }

step "1/7 Compilando (nada muda se falhar)"
B=$(mktemp -d); trap 'rm -rf "$B"' EXIT
gcc -O2 -Wall -Wextra -Wno-format-truncation -pthread -o "$B/homelabos" "$SRC/homelabos/server.c"
gcc -O2 -Wall -Wextra -Wno-format-truncation -pthread -o "$B/hosting" "$SRC/hosting/hosting.c"
echo "   ok"

step "2/7 Backup em $BK"
umask 077; mkdir -p "$BK/os" "$BK/hs"
cp -a "$OS/homelabos" "$OS/homelab.conf" "$OS/web" "$BK/os/"; [ -f "$OS/data/apps.json" ] && cp -a "$OS/data/apps.json" "$BK/os/"
cp -a "$HS/hosting" "$HS/hosting.conf" "$HS/web" "$BK/hs/"
cp -a "$HS/data/domains.conf" "$HS/data/settings.conf" "$BK/hs/" 2>/dev/null || true
echo "   ok"

step "3/7 Configurações (só acrescenta o que falta; o que você já tinha fica)"
# nomes: o homelabOS antigo tinha os dois nomes de conta fixos no código; agora vêm do conf
OS_ADMIN=$ME; MANAGER=${MANAGER:-}   # MANAGER=nome (opcional): conta de gestor do homelabOS
OS_PORT=$(sed -n 's/^port=//p' "$OS/homelab.conf"); OS_PORT=${OS_PORT:-80}
setkey "$OS/homelab.conf" bind 0.0.0.0 keep          # como era antes: acessível pela rede local
setkey "$OS/homelab.conf" admin "$OS_ADMIN" keep
[ -n "$MANAGER" ] && setkey "$OS/homelab.conf" manager "$MANAGER" keep
setkey "$HS/hosting.conf" bind 0.0.0.0 keep
setkey "$HS/hosting.conf" admin "$OS_ADMIN" keep
[ -n "$MANAGER" ] && setkey "$HS/hosting.conf" native_users "$MANAGER" keep   # o gestor continua podendo rodar processo direto, como hoje; apague a linha para limitar a container
setkey "$HS/hosting.conf" dash_ports "$OS_PORT" keep   # se você já tinha mais de uma porta (ex.: 80,8081), fica como estava
if [ -f "$HS/data/domains.conf" ] && grep -q "|$OS_ADMIN|1|" "$HS/data/domains.conf"; then
  CD=$(grep "|$OS_ADMIN|1|" "$HS/data/domains.conf" | head -1 | cut -d'|' -f1); setkey "$HS/hosting.conf" cert_domain "$CD" keep
fi
grep -q '^password_hash=pbkdf2\$' "$OS/homelab.conf" || warn "a senha do admin está no formato antigo (SHA-256). Funciona, mas troque: $OS/homelabos --hash  (cole a linha password_hash no homelab.conf)"

step "4/7 Administrador dos bancos por senha (fecha o acesso de superusuário pelo socket que os apps nativos alcançam)"
DBOK=0
if ask "Criar o hosting_admin agora (precisa de sudo)?"; then
  sudo bash "$SRC/deploy/db-admin.sh" "$ME" "$HS/data"
  if { [ ! -f "$HS/data/pgpass" ] || PGPASSFILE="$HS/data/pgpass" psql -h 127.0.0.1 -U hosting_admin -d postgres -Atc 'select 1' >/dev/null; } &&
     { [ ! -f "$HS/data/mysql.cnf" ] || mariadb --defaults-extra-file="$HS/data/mysql.cnf" -e 'select 1' >/dev/null; }; then
    DBOK=1; echo "   hosting_admin entra por TCP: ok"
    if ask "Tirar o poder de superusuário do usuário '$ME' nos bancos (reversível; recomendado)?"; then
      sudo -u postgres psql -qAt -c "ALTER ROLE \"$ME\" NOSUPERUSER NOCREATEDB NOCREATEROLE" 2>/dev/null || true
      sudo mariadb -e "REVOKE ALL PRIVILEGES, GRANT OPTION FROM '$ME'@'localhost'" 2>/dev/null || true
      echo "   poderes revogados (para voltar: ALTER ROLE \"$ME\" SUPERUSER; GRANT ALL ON *.* ... )"
    fi
  else warn "o hosting_admin não conseguiu entrar; deixei o modo antigo (nada foi revogado)"; fi
else echo "   pulado (rode depois: sudo bash $SRC/deploy/db-admin.sh $ME $HS/data)"; fi

step "5/7 Trocando binários e painéis"
swap() { # swap NOVO DESTINO  (mv atômico: o processo antigo segue com o arquivo velho até o restart)
  run install -m 755 "$1" "$2.new"; run mv -f "$2.new" "$2"; }
swap "$B/homelabos" "$OS/homelabos"; swap "$B/hosting" "$HS/hosting"
for p in "homelabos:$OS" "hosting:$HS"; do d=${p%%:*}; t=${p#*:}
  run rm -rf "$t/web.new"; run cp -r "$SRC/$d/web" "$t/web.new"; run rm -rf "$t/web.old"; run mv "$t/web" "$t/web.old"; run mv "$t/web.new" "$t/web"
done
echo "   (painéis antigos ficam em web.old; os atalhos em data/apps.json não mudam)"

rollback() {
  warn "falhou: restaurando o backup $BK"
  cp -a "$BK/os/homelabos" "$OS/homelabos"; cp -a "$BK/os/homelab.conf" "$OS/homelab.conf"
  rm -rf "$OS/web"; cp -a "$BK/os/web" "$OS/web"
  cp -a "$BK/hs/hosting" "$HS/hosting"; cp -a "$BK/hs/hosting.conf" "$HS/hosting.conf"
  rm -rf "$HS/web"; cp -a "$BK/hs/web" "$HS/web"
  sudo systemctl restart homelabos hosting; echo "restaurado."
}

step "6/7 Reiniciando (os apps ficam fora alguns segundos e voltam sozinhos)"
if [ $DRY = 1 ]; then echo "   [dry-run] sudo systemctl restart homelabos hosting"; else
  sudo systemctl restart homelabos hosting; sleep 4
  if ! systemctl is-active --quiet homelabos || ! systemctl is-active --quiet hosting; then
    journalctl -u homelabos -u hosting -n 12 --no-pager 2>/dev/null | sed 's/^/   /'; rollback; exit 1
  fi
fi

step "7/7 Conferindo"
if [ $DRY = 0 ]; then
  C=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$OS_PORT/") && echo "   homelabOS responde ($C)" || { rollback; exit 1; }
  [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST "http://127.0.0.1:$OS_PORT/api/power/poweroff")" = 403 ] && echo "   POST sem o cabeçalho anti-CSRF é recusado (403): ok"
  P=$(sed -n 's/^port=//p' "$HS/hosting.conf"); P=${P:-8430}
  [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$P/")" = 200 ] && echo "   Hospedagem responde" || { rollback; exit 1; }
  journalctl -u hosting -n 20 --no-pager 2>/dev/null | grep -E "sandbox|hosting em" | tail -2 | sed 's/^/   /'
  echo "   apps:"; curl -s -m 5 -H "Authorization: Bearer $(cat "$HS/data/api_token")" "http://127.0.0.1:$P/api/overview" |
    python3 -c 'import sys,json; [print("    %-20s %s" % (a["name"], a["state"])) for a in json.load(sys.stdin)["apps"]]' || true
  echo "   (apps 'restarting' por mais de 1 min? veja o run.log; se dependem de arquivos fora da pasta deles, ponha sandbox=0 no hosting.conf)"
fi
printf '\nPronto. Backup: %s\nPara desfazer: copie de volta %s/os/* e %s/hs/* e rode: sudo systemctl restart homelabos hosting\n' "$BK" "$BK" "$BK"
