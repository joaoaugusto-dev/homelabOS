#!/usr/bin/env bash
# Cria o administrador de bancos do hosting: usuário "hosting_admin" com senha, que entra por TCP no loopback.
# A senha fica em data/pgpass e data/mysql.cnf (0600). O sandbox esconde data/ dos apps nativos, então eles não conseguem
# usar os bancos como administrador (o modo antigo, por socket com o mesmo usuário do serviço, qualquer app nativo alcançava).
# Uso: sudo bash deploy/db-admin.sh <usuário-do-serviço> <pasta data do hosting>
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Rode com sudo."; exit 1; }
U=${1:?usuário do serviço}; D=${2:?pasta data do hosting}
install -d -m 700 -o "$U" "$D"
PW=$(openssl rand -hex 24)
if command -v psql >/dev/null; then
  sudo -u postgres psql -qAt -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='hosting_admin') THEN CREATE ROLE hosting_admin LOGIN SUPERUSER; END IF; END \$\$"
  sudo -u postgres psql -qAt -c "ALTER ROLE hosting_admin PASSWORD '$PW'"
  install -m 600 -o "$U" /dev/null "$D/pgpass"; printf '127.0.0.1:5432:*:hosting_admin:%s\n' "$PW" > "$D/pgpass"
  echo "postgres: hosting_admin criado (pgpass gravado)"
fi
if command -v mariadb >/dev/null || command -v mysql >/dev/null; then
  M=$(command -v mariadb || command -v mysql)
  # tudo o que o hosting precisa para criar bancos e usuários, menos FILE/SUPER/PROCESS/SHUTDOWN
  "$M" -e "CREATE USER IF NOT EXISTS 'hosting_admin'@'127.0.0.1' IDENTIFIED BY '$PW'; ALTER USER 'hosting_admin'@'127.0.0.1' IDENTIFIED BY '$PW'; GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, EVENT, TRIGGER, REFERENCES, CREATE USER ON *.* TO 'hosting_admin'@'127.0.0.1' WITH GRANT OPTION; FLUSH PRIVILEGES"
  install -m 600 -o "$U" /dev/null "$D/mysql.cnf"; printf '[client]\nprotocol=tcp\nhost=127.0.0.1\nuser=hosting_admin\npassword=%s\n' "$PW" > "$D/mysql.cnf"
  echo "mariadb: hosting_admin criado (mysql.cnf gravado)"
fi
for s in postgresql mariadb mysql; do
  systemctl is-active --quiet $s 2>/dev/null && ss -ltn | awk -v s=$s '$4 !~ /^(127\.0\.0\.1|\[::1\]|\*):?/ && $4 ~ /:(5432|3306)$/ {print "AVISO: banco escutando fora do loopback: " $4}' || true
done
echo "Pronto. Reinicie o hosting: sudo systemctl restart hosting"
