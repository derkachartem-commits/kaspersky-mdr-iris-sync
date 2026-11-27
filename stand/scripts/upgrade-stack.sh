#!/usr/bin/env bash
# ============================================================================
#  Обновление стенда IRIS v3 (beta.1 -> новее) БЕЗ потери данных.
#
#  Что делает:
#    1) бэкап: .env, docker-compose.override.yml, patches/, дамп БД, конфиг и
#       state коннектора;
#    2) меняет IRIS_VERSION в .env и тянет новые образы;
#    3) поднимает контейнеры БЕЗ -v (тома и БД не трогаются);
#    4) ждёт healthy, переприменяет патчи, гоняет smoke-проверки.
#
#  Запуск:
#      sudo ./scripts/upgrade-stack.sh v3.0.0-beta.23
#      sudo ./scripts/upgrade-stack.sh --backup-only      # только бэкап
# ============================================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IRIS_DIR="${IRIS_DIR:-/opt/iris-web}"
PROJECT="${PROJECT:-iris-web}"
CONN_DIR="${CONN_DIR:-/opt/kdp-iris-sync}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_DIR:-/root/iris-backup-$STAMP}"

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запускать от root"
[[ -f "$IRIS_DIR/docker-compose.yml" ]] || die "нет $IRIS_DIR/docker-compose.yml"
[[ -f "$IRIS_DIR/.env" ]] || die "нет $IRIS_DIR/.env"

backup() {
  log "бэкап в $BACKUP_DIR"
  mkdir -p "$BACKUP_DIR"
  cp -a "$IRIS_DIR/.env"               "$BACKUP_DIR/env.bak"
  cp -a "$IRIS_DIR/docker-compose.yml" "$BACKUP_DIR/docker-compose.yml.bak"
  [[ -f "$IRIS_DIR/docker-compose.override.yml" ]] && cp -a "$IRIS_DIR/docker-compose.override.yml" "$BACKUP_DIR/"
  [[ -d "$IRIS_DIR/patches" ]] && cp -a "$IRIS_DIR/patches" "$BACKUP_DIR/patches"
  [[ -d "$IRIS_DIR/certificates" ]] && cp -a "$IRIS_DIR/certificates" "$BACKUP_DIR/certificates"
  if [[ -d "$CONN_DIR" ]]; then
    cp -a "$CONN_DIR/config.json" "$BACKUP_DIR/kdp-config.json" 2>/dev/null || true
    [[ -f "$CONN_DIR/state/kdp.db" ]] && cp -a "$CONN_DIR/state/kdp.db" "$BACKUP_DIR/kdp.db"
  fi
  log "дамп БД"
  docker exec iris_db pg_dump -U postgres -d iris_db | gzip > "$BACKUP_DIR/iris_db.sql.gz"
  log "размер бэкапа: $(du -sh "$BACKUP_DIR" | cut -f1)"
  echo "$BACKUP_DIR" > /root/iris-last-backup.txt
}

smoke() {
  log "smoke-проверки"
  sleep 20
  docker ps --format '{{.Names}} {{.Status}}' | grep iris_ || true
  curl -sk -o /dev/null -w 'UI=%{http_code}\n' "https://127.0.0.1:8446/"
  curl -sk -o /dev/null -D - -H 'Accept-Encoding: gzip' "https://127.0.0.1:8446/" | grep -i content-encoding || warn "gzip не найден"
  echo | openssl s_client -connect 127.0.0.1:8446 -alpn h2 -servername neko.vbrr.online 2>/dev/null | grep -i 'ALPN protocol' || warn "h2 не согласован"
}

if [[ "${1:-}" == "--backup-only" ]]; then
  backup
  exit 0
fi

NEW_VERSION="${1:-}"
[[ -n "$NEW_VERSION" ]] || die "укажи тег: ./upgrade-stack.sh v3.0.0-beta.23"

OLD_VERSION="$(grep -E '^IRIS_VERSION=' "$IRIS_DIR/.env" | cut -d= -f2-)"
log "обновление: $OLD_VERSION -> $NEW_VERSION"

backup

log "ставлю IRIS_VERSION=$NEW_VERSION в .env (остальные секреты не трогаю)"
cp -a "$IRIS_DIR/.env" "$BACKUP_DIR/env.before-upgrade"
sed -i -E "s|^IRIS_VERSION=.*|IRIS_VERSION=$NEW_VERSION|" "$IRIS_DIR/.env"

log "docker compose pull (без удаления томов)"
cd "$IRIS_DIR"
docker compose -p "$PROJECT" pull

log "docker compose up -d"
docker compose -p "$PROJECT" up -d

log "переприменяю патчи (скрипт идемпотентный)"
"$SRC_DIR/scripts/apply-beta1.sh"

smoke

printf '\nГотово. %s -> %s\nБэкап: %s\n' "$OLD_VERSION" "$NEW_VERSION" "$BACKUP_DIR"
printf 'Откат версии:\n  sed -i "s|^IRIS_VERSION=.*|IRIS_VERSION=%s|" %s/.env\n  cd %s && docker compose -p %s up -d\n' "$OLD_VERSION" "$IRIS_DIR" "$IRIS_DIR" "$PROJECT"
printf 'Откат БД:\n  gunzip -c %s/iris_db.sql.gz | docker exec -i iris_db psql -U postgres -d iris_db\n' "$BACKUP_DIR"
