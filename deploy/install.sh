#!/usr/bin/env bash
# Instala o homelabOS (e, com --hosting, a Hospedagem) como serviços systemd.
#   make && sudo bash deploy/install.sh [--hosting] [--user NOME]
# Código em /opt/homelabos (do root: um app comprometido não consegue trocar o binário), configuração em /etc/homelabos,
# dados em /var/lib/homelabos (do usuário do serviço, 0700). Idempotente: pode rodar de novo para atualizar.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Rode com sudo: sudo bash $0"; exit 1; }
HOST=0; U=homelabos
while [ $# -gt 0 ]; do case $1 in --hosting) HOST=1;; --user) U=$2; shift;; *) echo "uso: $0 [--hosting] [--user NOME]"; exit 1;; esac; shift; done
R=$(cd "$(dirname "$0")/.." && pwd)
[ -x "$R/homelabos/homelabos" ] || { echo "Compile antes: make"; exit 1; }
step() { printf '\n==> %s\n' "$*"; }

step "Usuário do serviço: $U"
if ! id "$U" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir /var/lib/homelabos --shell /usr/sbin/nologin "$U"
  grep -q "^$U:" /etc/subuid || usermod --add-subuids 200000-265535 --add-subgids 200000-265535 "$U"
fi
UID_=$(id -u "$U")
install -d -m 755 /opt/homelabos /etc/homelabos
install -d -m 700 -o "$U" /var/lib/homelabos/os

step "homelabOS"
rm -rf /opt/homelabos/homelabos && install -d /opt/homelabos/homelabos
install -m 755 "$R/homelabos/homelabos" /opt/homelabos/homelabos/homelabos
cp -r "$R/homelabos/web" /opt/homelabos/homelabos/web
if [ ! -e /etc/homelabos/homelab.conf ]; then
  read -rp "IP onde o painel vai escutar (ex.: 192.168.1.10; vazio = só neste computador): " B; B=${B:-127.0.0.1}
  read -rp "Nome do administrador [admin]: " A; A=${A:-admin}
  H=$("$R/homelabos/homelabos" --hash)
  install -d -m 755 /srv/compartilhado; chown "$U" /srv/compartilhado
  umask 077
  cat > /etc/homelabos/homelab.conf <<CONF
port=80
bind=$B
admin=$A
$H
root=/srv/compartilhado
web=/opt/homelabos/homelabos/web
data=/var/lib/homelabos/os
CONF
  chown root:"$U" /etc/homelabos/homelab.conf; chmod 640 /etc/homelabos/homelab.conf
fi
sed "s/@USER@/$U/" "$R/deploy/homelabos.service" > /etc/systemd/system/homelabos.service
# o painel só liga/desliga a máquina por estes dois comandos exatos
printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl poweroff, /usr/bin/systemctl reboot\n' "$U" > /etc/sudoers.d/homelabos
chmod 440 /etc/sudoers.d/homelabos; visudo -cf /etc/sudoers.d/homelabos >/dev/null

if [ $HOST = 1 ]; then
  step "Hospedagem: pacotes (podman, postgresql, mariadb, python3, git)"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y podman uidmap passt postgresql postgresql-client mariadb-server mariadb-client python3 python3-venv python3-pip git curl
  rm -rf /opt/homelabos/hosting && install -d /opt/homelabos/hosting
  install -m 755 "$R/hosting/hosting" /opt/homelabos/hosting/hosting
  cp -r "$R/hosting/web" /opt/homelabos/hosting/web
  install -d -m 700 -o "$U" /var/lib/homelabos/hosting
  if [ ! -e /etc/homelabos/hosting.conf ]; then
    A=$(sed -n 's/^admin=//p' /etc/homelabos/homelab.conf); B=$(sed -n 's/^bind=//p' /etc/homelabos/homelab.conf)
    cat > /etc/homelabos/hosting.conf <<CONF
port=8430
bind=$B
web=/opt/homelabos/hosting/web
data=/var/lib/homelabos/hosting
dash_ports=$(sed -n 's/^port=//p' /etc/homelabos/homelab.conf)
admin=$A
CONF
    chown root:"$U" /etc/homelabos/hosting.conf; chmod 640 /etc/homelabos/hosting.conf
  fi
  step "Administrador dos bancos (senha em /var/lib/homelabos/hosting, fora do alcance dos apps)"
  bash "$R/deploy/db-admin.sh" "$U" /var/lib/homelabos/hosting
  loginctl enable-linger "$U"
  sed -e "s/@USER@/$U/" -e "s/@UID@/$UID_/" "$R/deploy/hosting.service" > /etc/systemd/system/hosting.service
fi

step "Iniciando"
systemctl daemon-reload
systemctl enable --now homelabos; [ $HOST = 1 ] && systemctl enable --now hosting
sleep 1; systemctl is-active homelabos; [ $HOST = 1 ] && systemctl is-active hosting
echo "Pronto. Painel: http://$(sed -n 's/^bind=//p' /etc/homelabos/homelab.conf):$(sed -n 's/^port=//p' /etc/homelabos/homelab.conf)"
[ $HOST = 1 ] && echo "Hospedagem: porta 8430 (atalho no homelabOS: aba Atalhos, endereço :8430)"
true
