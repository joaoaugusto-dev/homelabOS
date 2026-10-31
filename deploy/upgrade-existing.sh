#!/usr/bin/env bash
# Roda no SEU PC: envia o código commitado deste repositório ao servidor (pela LAN) e roda a atualização lá.
#   bash deploy/upgrade-existing.sh [host-ssh] [--manager NOME] [--dry-run]   # host padrão: server-debian (LAN)
set -euo pipefail
HOST=server-debian; DRY=; MGR=
while [ $# -gt 0 ]; do case $1 in --dry-run) DRY=--dry-run;; --manager) MGR=$2; shift;; *) HOST=$1;; esac; shift; done
R=$(cd "$(dirname "$0")/.." && pwd)
git -C "$R" diff --quiet HEAD || echo "AVISO: há mudanças não commitadas; só o que está commitado é enviado."
echo "==> Testes locais"; make -C "$R" test 2>&1 | grep -E "FAIL|TUDO OK" | sort | uniq -c
echo "==> Enviando $(git -C "$R" rev-parse --short HEAD) para $HOST"
git -C "$R" archive --format=tar HEAD | ssh "$HOST" 'rm -rf ~/homelabOS-src && mkdir ~/homelabOS-src && tar xf - -C ~/homelabOS-src'
ssh -t "$HOST" "MANAGER=$MGR bash ~/homelabOS-src/deploy/upgrade-remote.sh ~/homelabOS-src $DRY"
