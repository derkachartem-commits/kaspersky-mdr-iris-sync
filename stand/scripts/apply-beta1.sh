#!/usr/bin/env bash
# ============================================================================
#  Наложение патчей стенда на УЖЕ установленный IRIS 3.0.0-beta.1
#  (compose-проект iris-web, каталог /opt/iris-web, порт 8446).
#
#  Проверено 26.11.2026 на хосте IRIS_HOST.
#  Скрипт идемпотентный: повторный запуск ничего не ломает.
#
#  Запуск (от root):  sudo ./apply-beta1.sh
#  Переопределяемо:    IRIS_DIR=/opt/iris-web PROJECT=iris-web
# ============================================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IRIS_DIR="${IRIS_DIR:-/opt/iris-web}"
PROJECT="${PROJECT:-iris-web}"
DB_CTR="${DB_CTR:-iris_db}"

log() { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускать от root"
[[ -f "$IRIS_DIR/docker-compose.yml" ]] || die "нет $IRIS_DIR/docker-compose.yml"
docker compose version >/dev/null || die "нужен docker compose v2"

log "1/5 копирую патчи в $IRIS_DIR/patches"
mkdir -p "$IRIS_DIR/patches"
cp "$SRC_DIR/patches/patches/named_aggregations.py"   "$IRIS_DIR/patches/"
cp "$SRC_DIR/patches/patches/models_cases_beta1.py"   "$IRIS_DIR/patches/models_cases.py"
cp "$SRC_DIR/patches/backend/tasks.py"                "$IRIS_DIR/patches/tasks.py"
cp "$SRC_DIR/patches/patches/40-iris-static.sh"       "$IRIS_DIR/patches/"
cp "$SRC_DIR/patches/patches/50-iris-patch-after-start.sh" "$IRIS_DIR/patches/"
chmod +x "$IRIS_DIR/patches/"*.sh

log "2/5 ставлю docker-compose.override.yml"
cp "$SRC_DIR/patches/compose/docker-compose.override.yml" "$IRIS_DIR/docker-compose.override.yml"

log "3/5 пересоздаю app/worker/nginx с патчами"
cd "$IRIS_DIR"
docker compose -p "$PROJECT" up -d app worker nginx

log "4/5 перевожу open_date/close_date в timestamp (идемпотентно)"
docker exec "$DB_CTR" psql -U postgres -d iris_db -tAc \
  "select data_type from information_schema.columns where table_name='cases' and column_name='open_date'" \
  | grep -q 'timestamp' || docker exec "$DB_CTR" psql -U postgres -d iris_db -v ON_ERROR_STOP=1 -c \
  "alter table cases alter column open_date type timestamp without time zone using open_date::timestamp;"
docker exec "$DB_CTR" psql -U postgres -d iris_db -tAc \
  "select data_type from information_schema.columns where table_name='cases' and column_name='close_date'" \
  | grep -q 'timestamp' || docker exec "$DB_CTR" psql -U postgres -d iris_db -v ON_ERROR_STOP=1 -c \
  "alter table cases alter column close_date type timestamp without time zone using close_date::timestamp;"

log "5/5 проверки"
sleep 25
docker ps --format '{{.Names}} {{.Status}}' | grep -E 'iris_(app|worker|nginx)'
curl -sk -o /dev/null -w 'UI=%{http_code}\n' "https://127.0.0.1:8446/"
curl -sk -o /dev/null -D - -H 'Accept-Encoding: gzip' "https://127.0.0.1:8446/" | grep -i content-encoding || true
echo | openssl s_client -connect 127.0.0.1:8446 -alpn h2 -servername neko.vbrr.online 2>/dev/null | grep -i 'ALPN protocol' || true
echo
echo "Готово. Дашборд «SOC — открытые кейсы и алерты» создаётся отдельно:"
echo "  python3 scripts/create-soc-dashboard.py   (нужен API-ключ администратора)"
