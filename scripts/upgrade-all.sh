#!/usr/bin/env bash
# ============================================================================
#  Обновление ВСЕГО контура: коннекторы (KDP/MDR -> IRIS) + патчи стенда IRIS.
#
#  Один вход: подтягивает репозиторий, обновляет код коннектора, ставит
#  патчи стенда (и при желании поднимает версию IRIS), проверяет здоровье.
#
#  Использование (от root):
#      sudo ./scripts/upgrade-all.sh                              # код + патчи
#      sudo ./scripts/upgrade-all.sh --version v3.0.0-beta.23     # ещё и версия IRIS
#      sudo ./scripts/upgrade-all.sh --backup-only                # только бэкап
#      sudo ./scripts/upgrade-all.sh --check                      # только проверка
#      sudo ./scripts/upgrade-all.sh --connector-only
#      sudo ./scripts/upgrade-all.sh --stand-only
#
#  Конфиги не перезаписываются: /opt/kdp-iris-sync/config.json и state/ остаются,
#  /opt/iris-web/.env правится только строкой IRIS_VERSION (и только с --version).
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAND_DIR="$REPO_DIR/stand"
CONN_DIR="${CONN_DIR:-/opt/kdp-iris-sync}"
SERVICE="${SERVICE:-kdp-iris-sync}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8098/healthz}"
IRIS_URL="${IRIS_URL:-https://127.0.0.1:8446}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_DIR:-/root/iris-backup-$STAMP}"

VERSION=""; DO_CONNECTOR=1; DO_STAND=1; CHECK=0; BACKUP_ONLY=0

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --connector-only) DO_STAND=0; shift ;;
    --stand-only) DO_CONNECTOR=0; shift ;;
    --check) CHECK=1; shift ;;
    --backup-only) BACKUP_ONLY=1; shift ;;
    -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "неизвестный аргумент: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "запускать от root"
[[ -d "$REPO_DIR/.git" ]] || die "запускать из git-клона монорепозитория (сейчас: $REPO_DIR)"

backup() {
  log "бэкап в $BACKUP_DIR"
  mkdir -p "$BACKUP_DIR/connector"
  [[ -f "$CONN_DIR/config.json" ]] && cp -a "$CONN_DIR/config.json" "$BACKUP_DIR/connector/"
  [[ -f "$CONN_DIR/state/kdp.db" ]] && cp -a "$CONN_DIR/state/kdp.db" "$BACKUP_DIR/connector/"
  git -C "$REPO_DIR" rev-parse HEAD > "$BACKUP_DIR/repo-commit.txt"
  echo "$BACKUP_DIR" > /root/iris-last-backup.txt
}

update_repo() {
  log "git pull в $REPO_DIR"
  OLD_COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
  git -C "$REPO_DIR" pull --ff-only || die "git pull не прошёл — разберись с локальными изменениями"
  NEW_COMMIT="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
  log "репозиторий: $OLD_COMMIT -> $NEW_COMMIT"
}

update_connector() {
  [[ -d "$CONN_DIR" ]] || { warn "нет $CONN_DIR — коннектор не установлен, пропускаю"; return; }
  log "останавливаю $SERVICE"
  systemctl stop "$SERVICE" || true

  log "синхронизирую код коннектора (config.json и state/ не трогаю)"
  if command -v rsync >/dev/null; then
    rsync -a --delete \
      --exclude 'config.json' --exclude 'state/' --exclude '.venv/' --exclude '__pycache__/' \
      "$REPO_DIR/kdp-iris-sync/" "$CONN_DIR/"
  else
    ( cd "$REPO_DIR/kdp-iris-sync" && tar -cf - \
        --exclude='config.json' --exclude='state' --exclude='.venv' --exclude='__pycache__' . ) \
      | ( cd "$CONN_DIR" && tar -xf - )
  fi

  if [[ -x "$CONN_DIR/.venv/bin/pip" && -f "$REPO_DIR/kdp-iris-sync/requirements.txt" ]]; then
    log "pip install -r requirements.txt"
    "$CONN_DIR/.venv/bin/pip" install -q -r "$REPO_DIR/kdp-iris-sync/requirements.txt"
  fi

  log "запускаю $SERVICE"
  systemctl start "$SERVICE"
  sleep 5
  systemctl is-active --quiet "$SERVICE" || die "$SERVICE не поднялся"
}

verify_connector() {
  log "проверяю healthz и конфиг коннектора"
  curl -s -m 10 "$HEALTH_URL" || die "healthz не отвечает"
  python3 - "$CONN_DIR/config.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
ae = cfg.get("auto_escalate") or {}
ok = bool(cfg.get("iris", {}).get("api_key")) and bool(cfg.get("kdp", {}).get("token")) and ae.get("enabled")
print("config: api_key=%s kdp_token=%s auto_escalate=%s" % (
    bool(cfg.get("iris", {}).get("api_key")), bool(cfg.get("kdp", {}).get("token")), ae.get("enabled")))
sys.exit(0 if ok else 1)
PY
  if [[ $? -ne 0 ]]; then warn "в config.json не хватает api_key/token/auto_escalate — проверь руками"; fi
}

update_stand() {
  if [[ -n "$VERSION" ]]; then
    log "обновляю стенд до $VERSION"
    "$STAND_DIR/scripts/upgrade-stack.sh" "$VERSION"
  else
    log "версию не меняю, переприменяю патчи стенда"
    "$STAND_DIR/scripts/apply-beta1.sh"
  fi
}

smoke() {
  log "смоук"
  docker ps --format '{{.Names}} {{.Status}}' | grep iris_ || warn "контейнеры iris_* не найдены"
  curl -sk -o /dev/null -w 'UI=%{http_code}\n' "$IRIS_URL/"
  curl -sk -o /dev/null -D - -H 'Accept-Encoding: gzip' "$IRIS_URL/" | grep -i content-encoding || warn "gzip нет"
  echo | openssl s_client -connect 127.0.0.1:8446 -alpn h2 -servername "${IRIS_HOST:-neko.vbrr.online}" 2>/dev/null | grep -i 'ALPN protocol' || warn "h2 не согласован"
  curl -s -m 10 "$HEALTH_URL" || warn "healthz не отвечает"
}

if [[ $CHECK -eq 1 ]]; then
  log "режим проверки (ничего не меняю)"
  git -C "$REPO_DIR" log --oneline -1
  git -C "$REPO_DIR" status --short || true
  systemctl is-active "$SERVICE" || true
  curl -s -m 10 "$HEALTH_URL" || warn "healthz не отвечает"
  docker ps --format '{{.Names}} {{.Status}}' | grep iris_ || true
  grep -E '^IRIS_VERSION=' /opt/iris-web/.env 2>/dev/null || true
  exit 0
fi

backup
if [[ $BACKUP_ONLY -eq 1 ]]; then log "только бэкап — выхожу"; exit 0; fi

update_repo
if [[ $DO_CONNECTOR -eq 1 ]]; then update_connector; verify_connector || true; fi
if [[ $DO_STAND -eq 1 ]]; then update_stand; fi
smoke

printf '\nГотово. Бэкап: %s\n' "$BACKUP_DIR"
printf 'Откат кода: git -C %s reset --hard %s && systemctl restart %s\n' "$REPO_DIR" "$(cat "$BACKUP_DIR/repo-commit.txt")" "$SERVICE"
printf 'Откат версии IRIS: см. %s/UPGRADE.md, раздел «Откат»\n' "$STAND_DIR"
