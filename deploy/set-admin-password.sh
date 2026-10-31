#!/usr/bin/env bash
# Troca a senha do administrador do homelabOS no servidor, pedindo a senha aqui no seu PC (não aparece na tela nem em argumentos).
#   bash deploy/set-admin-password.sh [host-ssh]        # padrão: server-debian
# Faz: grava o hash novo (PBKDF2) no homelab.conf (com backup), testa numa instância temporária, reinicia o homelabOS (pede o sudo)
# e confere o login de verdade; se algo falhar, restaura o arquivo antigo e reinicia de novo.
set -euo pipefail

if [ "${1:-}" = "--remote" ]; then                                   # ----------------------- parte do servidor
  MODE=$2; D=${OS_DIR:-$HOME/homelabOS}; CONF=$D/homelab.conf
  ADMIN=$(sed -n 's/^admin=//p' "$CONF"); ADMIN=${ADMIN:-joao}
  case $MODE in
    set)   IFS= read -r PW; [ ${#PW} -ge 8 ] || { echo "senha curta"; exit 1; }
           H=$(printf %s "$PW" | "$D/homelabos" --hash); case $H in password_hash=pbkdf2\$*) ;; *) echo "hash inesperado"; exit 1;; esac
           cp -p "$CONF" "$CONF.bak-prev-password"
           sed -i '/^password_hash=/d;/^salt=/d' "$CONF"; printf '%s\n' "$H" >> "$CONF"
           # teste numa instância temporária com a mesma conf (outra porta, só loopback, dados temporários)
           T=$(mktemp -d); trap 'kill ${P:-0} 2>/dev/null; rm -rf "$T"' EXIT
           sed -e 's/^port=.*/port=18999/' -e 's/^bind=.*/bind=127.0.0.1/' -e "s|^data=.*|data=$T|" "$CONF" > "$T/c.conf"
           "$D/homelabos" -c "$T/c.conf" 2>/dev/null & P=$!; sleep 1
           ok=$(curl -s -o /dev/null -w %{http_code} -H 'X-Requested-With: homelabos' --data "{\"user\":\"$ADMIN\",\"password\":\"$PW\"}" http://127.0.0.1:18999/api/login)
           if [ "$ok" != 200 ]; then cp -p "$CONF.bak-prev-password" "$CONF"; echo "teste falhou ($ok): arquivo antigo mantido"; exit 1; fi
           echo "teste ok";;
    check) IFS= read -r PW; PORT=$(sed -n 's/^port=//p' "$CONF"); PORT=${PORT:-80}
           [ "$(curl -s -o /dev/null -w %{http_code} -H 'X-Requested-With: homelabos' --data "{\"user\":\"$ADMIN\",\"password\":\"$PW\"}" http://127.0.0.1:$PORT/api/login)" = 200 ];;
    restore) cp -p "$CONF.bak-prev-password" "$CONF"; echo "arquivo antigo restaurado";;
  esac
  exit 0
fi

HOST=${1:-server-debian}
read -rsp "Nova senha do administrador (mín. 8 caracteres): " PW1 </dev/tty; echo
read -rsp "Repita: " PW2 </dev/tty; echo
[ "$PW1" = "$PW2" ] || { echo "As senhas não são iguais."; exit 1; }
[ ${#PW1} -ge 8 ] || { echo "Use pelo menos 8 caracteres."; exit 1; }
ssh "$HOST" 'cat > ~/.set-admin-password.sh && chmod 700 ~/.set-admin-password.sh' < "$0"
trap 'ssh "$HOST" "rm -f ~/.set-admin-password.sh" 2>/dev/null || true' EXIT
R="bash ~/.set-admin-password.sh --remote"
echo "==> Gravando e testando o hash novo no servidor"
printf '%s\n' "$PW1" | ssh "$HOST" "$R set"
echo "==> Reiniciando o homelabOS (o sudo do servidor pede a senha dele)"
ssh -t "$HOST" 'sudo systemctl restart homelabos'; sleep 2
echo "==> Conferindo o login com a senha nova"
if printf '%s\n' "$PW1" | ssh "$HOST" "$R check"; then
  echo "Pronto: a senha nova está valendo. (O backup do arquivo antigo fica em ~/homelabOS/homelab.conf.bak-prev-password; apague quando quiser.)"
else
  echo "FALHOU: restaurando o arquivo antigo"; ssh "$HOST" "$R restore"; ssh -t "$HOST" 'sudo systemctl restart homelabos'; exit 1
fi
