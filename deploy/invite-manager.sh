#!/usr/bin/env bash
# Faz o gestor (ex.: Henrique) definir a própria senha no próximo acesso. Roda no SEU PC:
#   bash deploy/invite-manager.sh [host-ssh] [--hours 72]        # host padrão: server-debian
# Atualiza o homelabOS no servidor (se ainda não tiver o fluxo de convite), reinicia, e abre um convite com CÓDIGO de uso único.
# A senha antiga do gestor deixa de valer agora. Você passa o código a ele; na tela de login ele digita o usuário, vê
# "Defina sua senha", coloca o código e escolhe a senha. Sem o código ninguém da rede consegue tomar a conta.
set -euo pipefail

if [ "${1:-}" = "--remote" ]; then                                   # ----------------------- parte do servidor
  SRC=$(cd "$2" && pwd); HOURS=$3; D=${OS_DIR:-$HOME/homelabOS}; CONF=$D/homelab.conf
  step() { printf '\n==> %s\n' "$*"; }
  [ -x "$D/homelabos" ] && [ -f "$CONF" ] || { echo "Não achei o homelabOS em $D"; exit 1; }
  grep -q '^manager=' "$CONF" || { echo "O homelab.conf não tem manager= (rode antes deploy/upgrade-existing.sh --manager NOME)"; exit 1; }
  B=$(mktemp -d); trap 'rm -rf "$B"' EXIT
  step "Compilando"; gcc -O2 -Wall -Wextra -Wno-format-truncation -pthread -o "$B/homelabos" "$SRC/homelabos/server.c"; echo "   ok"
  step "Backup em ~/backup-invite-$(date +%Y%m%d-%H%M%S)"
  BK=$HOME/backup-invite-$(date +%Y%m%d-%H%M%S); umask 077; mkdir -p "$BK"; cp -a "$D/homelabos" "$CONF" "$D/web" "$BK/"
  [ -f "$D/data/$(sed -n 's/^manager=//p' "$CONF").pw" ] && cp -a "$D/data/$(sed -n 's/^manager=//p' "$CONF").pw" "$BK/"
  step "Trocando binário e painel (ícones seus são preservados)"
  install -m 755 "$B/homelabos" "$D/homelabos.new" && mv -f "$D/homelabos.new" "$D/homelabos"
  rm -rf "$D/web.new"; cp -r "$SRC/homelabos/web" "$D/web.new"
  [ -d "$D/web/icons" ] && { mkdir -p "$D/web.new/icons"; cp -rn "$D/web/icons/." "$D/web.new/icons/"; }
  rm -rf "$D/web.old"; mv "$D/web" "$D/web.old"; mv "$D/web.new" "$D/web"
  if [ -z "${NO_SUDO:-}" ]; then
    step "Reiniciando o homelabOS"; sudo systemctl restart homelabos; sleep 2
    PORT=$(sed -n 's/^port=//p' "$CONF"); PORT=${PORT:-80}
    if [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$PORT/")" != 200 ]; then
      echo "FALHOU: restaurando"; cp -a "$BK/homelabos" "$D/homelabos"; rm -rf "$D/web"; cp -a "$BK/web" "$D/web"; sudo systemctl restart homelabos; exit 1
    fi; echo "   no ar"
  fi
  step "Abrindo o convite (válido por $HOURS h)"
  CODE=$("$D/homelabos" -c "$CONF" --invite-manager "$HOURS")
  printf '\n=============================================\n  CÓDIGO DE CONVITE: %s\n=============================================\n' "$CODE"
  exit 0
fi

HOST=server-debian; HOURS=72
while [ $# -gt 0 ]; do case $1 in --hours) HOURS=$2; shift;; *) HOST=$1;; esac; shift; done
R=$(cd "$(dirname "$0")/.." && pwd)
git -C "$R" diff --quiet HEAD || echo "AVISO: há mudanças não commitadas; só o que está commitado é enviado."
echo "==> Teste local do homelabOS"; (cd "$R/homelabos" && ./test.sh 2>&1 | grep -E "FAIL|TUDO OK") | sort | uniq -c
echo "==> Enviando $(git -C "$R" rev-parse --short HEAD) para $HOST"
git -C "$R" archive --format=tar HEAD homelabos | ssh "$HOST" 'rm -rf ~/homelabOS-src && mkdir ~/homelabOS-src && tar xf - -C ~/homelabOS-src && mkdir -p ~/homelabOS-src/deploy'
ssh "$HOST" 'cat > ~/homelabOS-src/deploy/invite-manager.sh' < "$0"
ssh -t "$HOST" "bash ~/homelabOS-src/deploy/invite-manager.sh --remote ~/homelabOS-src $HOURS"
echo; echo "Passe o código ao gestor. Na tela de login do homelabOS ele digita o usuário dele, aparece \"Defina sua senha\"."
