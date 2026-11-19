#!/usr/bin/env bash
# Full stand update: pull everything from GitHub and refresh BOTH pieces
# running on the host's Docker:
#   1) the KDP -> IRIS connector (container kdp-iris-sync)
#   2) the IRIS patches (iris-backend:tasks-fix, static client, nginx, config)
#
# Configs, state, logs and credentials stay untouched (KDP config.json is
# backed up before the update; IRIS compose override is backed up too).
#
# Usage:
#   sudo ./update-stand.sh
#   SKIP_IRIS=1 sudo ./update-stand.sh          # only the KDP connector
#   REPO_BRANCH=dev sudo -E ./update-stand.sh
#
# Env:
#   REPO_URL, REPO_BRANCH, SRC_SUBDIR, APP_DIR, SRC_DIR, IMAGE, CONTAINER,
#   HEALTH_URL, BACKUP_DIR, IRIS_DIR (/opt/iris3), SKIP_IRIS=1

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
IRIS_DIR="${IRIS_DIR:-/opt/iris3}"
SKIP_IRIS="${SKIP_IRIS:-0}"

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

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

# --- 2. backup KDP config/state --------------------------------------------
mkdir -p "$APP_DIR" "$BACKUP_DIR"
TS="$(date '+%Y%m%d-%H%M%S')"
if [ -f "$APP_DIR/config.json" ]; then
  mkdir -p "$BACKUP_DIR/$TS"
  cp -a "$APP_DIR/config.json" "$BACKUP_DIR/$TS/config.json"
  [ -d "$APP_DIR/state" ] && cp -a "$APP_DIR/state" "$BACKUP_DIR/$TS/state"
  log "backup: $BACKUP_DIR/$TS"
fi

# --- 3. build connector image (old container keeps running on failure) ------
log "building $IMAGE from $SRC"
docker build -q -t "$IMAGE" "$SRC" >/dev/null

# --- 4. swap connector container -------------------------------------------
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

# --- 5. connector health check ---------------------------------------------
for _ in $(seq 1 30); do
  if curl -fsS --max-time 3 "$HEALTH_URL" -o /tmp/kdp-health.json 2>/dev/null; then
    log "kdp healthz OK: $(cat /tmp/kdp-health.json)"
    break
  fi
  sleep 2
done
if [ ! -s /tmp/kdp-health.json ]; then
  docker logs --tail 40 "$CONTAINER" 2>&1 || true
  die "KDP connector did not become healthy (backup: $BACKUP_DIR/$TS)"
fi

# --- 6. IRIS patches --------------------------------------------------------
if [ "$SKIP_IRIS" = "1" ]; then
  log "SKIP_IRIS=1 - IRIS update skipped"
elif [ -d "$IRIS_DIR" ]; then
  log "updating IRIS patches in $IRIS_DIR"
  IRIS_DIR="$IRIS_DIR" PATCH_DIR="$SRC_DIR/stand/iris-patch" bash "$SRC_DIR/stand/update-iris.sh"
else
  log "IRIS not found in $IRIS_DIR - skipped"
fi

log "done, revision $REV"
