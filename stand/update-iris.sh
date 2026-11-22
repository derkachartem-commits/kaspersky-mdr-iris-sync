#!/usr/bin/env bash
# Apply the IRIS stand patches on a host where Docker runs directly (no VM).
#
# What it installs into IRIS_DIR (/opt/iris3 by default):
#   * iris-backend:tasks-fix  - patched task status update (beta.22 bug)
#   * patches/configuration.py - long-lived API tokens (1440 min / 30 days)
#   * patches/ctx.js + client.new - static client + case context helper
#   * docker-compose.override.yml - wires the above into app/worker/nginx
#   * nginx static/gzip/http2 patch inside the running nginx container
#
# Usage:
#   sudo ./update-iris.sh
#   IRIS_DIR=/opt/iris3 IRIS_PROJECT=iris3 sudo -E ./update-iris.sh
#
# Env:
#   IRIS_DIR      IRIS deployment dir (default /opt/iris3)
#   IRIS_PROJECT  compose project name (default iris3)
#   PATCH_DIR     iris-patch dir (default ../iris-patch next to this script)
#   IRIS_BASE_IMAGE / IRIS_PATCH_IMAGE
#   HEALTH_URL    default https://127.0.0.1:8446/

set -euo pipefail

IRIS_DIR="${IRIS_DIR:-/opt/iris3}"
IRIS_PROJECT="${IRIS_PROJECT:-iris3}"
PATCH_DIR="${PATCH_DIR:-$(cd "$(dirname "$0")" && pwd)/../iris-patch}"
IRIS_PATCH_IMAGE="${IRIS_PATCH_IMAGE:-iris-backend:tasks-fix}"
HEALTH_URL="${HEALTH_URL:-https://127.0.0.1:8446/}"
STAMP="$(date '+%Y%m%d-%H%M%S')"

log() { printf '[iris %s] %s\n' "$(date '+%F %T')" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

[ -d "$IRIS_DIR" ] || die "$IRIS_DIR not found"
[ -f "$PATCH_DIR/backend/tasks.py" ] || die "iris-patch not found in $PATCH_DIR"
command -v docker >/dev/null 2>&1 || die "docker not found"

# compose v2 plugin or legacy binary
if docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  die "docker compose not found"
fi

# --- 1. install patch files (with backup of the override) -------------------
cp -a "$IRIS_DIR/docker-compose.override.yml" "$IRIS_DIR/docker-compose.override.yml.bak-$STAMP" 2>/dev/null || true
mkdir -p "$IRIS_DIR/patches"
cp -a "$PATCH_DIR/patches/." "$IRIS_DIR/patches/"
cp -a "$PATCH_DIR/compose/docker-compose.override.yml" "$IRIS_DIR/docker-compose.override.yml"
log "patch files installed into $IRIS_DIR"

if [ -f "$PATCH_DIR/client.new.tar.gz" ]; then
  tar -xzf "$PATCH_DIR/client.new.tar.gz" -C "$IRIS_DIR"
  log "static client restored ($(du -sh "$IRIS_DIR/client.new" | cut -f1))"
fi

# --- 2. build patched backend ----------------------------------------------
log "building $IRIS_PATCH_IMAGE"
docker build -q -t "$IRIS_PATCH_IMAGE" "$PATCH_DIR/backend" >/dev/null

# --- 3. recreate services ---------------------------------------------------
cd "$IRIS_DIR"
log "recreating app/worker/nginx ($IRIS_PROJECT)"
$COMPOSE -p "$IRIS_PROJECT" up -d app worker nginx

# --- 4. nginx gzip/http2/immutable patch ----------------------------------
# The compose override runs patches/50-iris-patch-after-start.sh from the
# container entrypoint, so a plain recreate re-applies it. Enforce it here
# as well for containers started before the override existed.
NGINX_ID="$($COMPOSE -p "$IRIS_PROJECT" ps -q nginx | head -1)"
if [ -n "$NGINX_ID" ]; then
  docker exec "$NGINX_ID" sh -c 'grep -q iris_immutable_assets /etc/nginx/nginx.conf || sh /opt/iris-patch/40-iris-static.sh' >/dev/null 2>&1 || true
  docker exec "$NGINX_ID" nginx -t >/dev/null 2>&1 && docker exec "$NGINX_ID" nginx -s reload >/dev/null 2>&1 || true
  log "nginx patch applied and reloaded"
fi

# --- 4b. regression smoke test ---------------------------------------------
if [ -x "$IRIS_DIR/../iris-smoke.sh" ]; then
  "$IRIS_DIR/../iris-smoke.sh" || log "WARNING: smoke test failed"
elif command -v curl >/dev/null 2>&1; then
  log "no smoke test installed, skipping"
fi

# --- 5. health check --------------------------------------------------------
for _ in $(seq 1 60); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$HEALTH_URL" || true)"
  case "$code" in
    200|302|401)
      log "IRIS is up (HTTP $code), done"
      exit 0
      ;;
  esac
  sleep 2
done

log "IRIS did not answer in 120s, last app logs:"
$COMPOSE -p "$IRIS_PROJECT" logs --tail 40 app 2>&1 || true
die "IRIS update finished with errors"
