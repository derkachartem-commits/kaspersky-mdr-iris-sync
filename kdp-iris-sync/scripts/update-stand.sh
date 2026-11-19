#!/usr/bin/env bash
# KDP -> IRIS connector: update on a stand where Docker runs on the host
# (no VM). Pulls the code from GitHub, rebuilds the image, recreates the
# container and verifies /healthz. Config (with credentials/token), state
# and logs inside APP_DIR are preserved.
#
# Usage:
#   sudo ./update-stand.sh
#   REPO_BRANCH=dev APP_DIR=/opt/kdp-iris-sync sudo -E ./update-stand.sh
#
# Env overrides:
#   REPO_URL     git remote (default: public repo below)
#   REPO_BRANCH  default: main
#   SRC_SUBDIR   connector path inside the repo (default: kdp-iris-sync)
#   APP_DIR      deployed dir with config.json/state (default: /opt/kdp-iris-sync)
#   SRC_DIR      checkout dir (default: /opt/kdp-iris-sync-src)
#   IMAGE        image tag (default: kdp-iris-sync:latest)
#   CONTAINER    container name (default: kdp-iris-sync)
#   HEALTH_URL   default: http://127.0.0.1:8088/healthz

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/derkachartem-commits/kaspersky-mdr-iris-sync.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
SRC_SUBDIR="${SRC_SUBDIR:-kdp-iris-sync}"
APP_DIR="${APP_DIR:-/opt/kdp-iris-sync}"
SRC_DIR="${SRC_DIR:-/opt/kdp-iris-sync-src}"
IMAGE="${IMAGE:-kdp-iris-sync:latest}"
CONTAINER="${CONTAINER:-kdp-iris-sync}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8088/healthz}"
BACKUP_DIR="${BACKUP_DIR:-/opt/kdp-iris-sync-backups}"

log()  { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found"
command -v git    >/dev/null 2>&1 || die "git not found (apt-get install -y git)"
command -v curl   >/dev/null 2>&1 || die "curl not found"

# --- 1. fetch sources -------------------------------------------------------
if [ -d "$SRC_DIR/.git" ]; then
  log "fetching $REPO_BRANCH from $REPO_URL"
  git -C "$SRC_DIR" fetch --depth 1 origin "$REPO_BRANCH"
  git -C "$SRC_DIR" checkout -q -f FETCH_HEAD
else
  log "cloning $REPO_URL ($REPO_BRANCH) into $SRC_DIR"
  rm -rf "$SRC_DIR"
  git clone -q --depth 1 --branch "$REPO_BRANCH" "$REPO_URL" "$SRC_DIR"
fi
SRC="$SRC_DIR/$SRC_SUBDIR"
[ -f "$SRC/kdp_iris_sync/app.py" ] || die "connector sources not found in $SRC"
REV="$(git -C "$SRC_DIR" rev-parse --short HEAD)"
log "code revision: $REV"

# --- 2. backup config/state -------------------------------------------------
mkdir -p "$APP_DIR" "$BACKUP_DIR"
TS="$(date '+%Y%m%d-%H%M%S')"
if [ -f "$APP_DIR/config.json" ]; then
  mkdir -p "$BACKUP_DIR/$TS"
  cp -a "$APP_DIR/config.json" "$BACKUP_DIR/$TS/config.json"
  [ -d "$APP_DIR/state" ] && cp -a "$APP_DIR/state" "$BACKUP_DIR/$TS/state"
  log "backup: $BACKUP_DIR/$TS"
fi

# --- 3. build image (before touching the running container) ----------------
log "building $IMAGE from $SRC"
docker build -q -t "$IMAGE" "$SRC" >/dev/null

# --- 4. swap container ------------------------------------------------------
if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  log "recreating container $CONTAINER"
  docker stop "$CONTAINER" >/dev/null
  docker rm "$CONTAINER" >/dev/null
fi

for item in requirements.txt Dockerfile kdp_iris_sync; do
  [ -e "$SRC/$item" ] || continue
  rm -rf "${APP_DIR:?}/$item"
  cp -a "$SRC/$item" "$APP_DIR/$item"
done
find "$APP_DIR/kdp_iris_sync" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

if [ ! -f "$APP_DIR/config.json" ]; then
  cp -a "$SRC/config.example.json" "$APP_DIR/config.json"
  chmod 600 "$APP_DIR/config.json"
  log "WARNING: config.json was missing - installed config.example.json (fill it in!)"
fi

log "starting $CONTAINER"
docker run -d --name "$CONTAINER" --restart always --network host \
  -v "$APP_DIR:/app" -w /app -e KDP_CONFIG=config.json "$IMAGE" >/dev/null

# --- 5. health check --------------------------------------------------------
for _ in $(seq 1 30); do
  if curl -fsS --max-time 3 "$HEALTH_URL" -o /tmp/kdp-health.json 2>/dev/null; then
    log "healthz OK: $(cat /tmp/kdp-health.json)"
    log "done, revision $REV"
    exit 0
  fi
  sleep 2
done

log "healthz is not responding, last log lines:"
docker logs --tail 40 "$CONTAINER" 2>&1 || true
die "update finished with errors (backup: $BACKUP_DIR/$TS)"
