#!/usr/bin/env bash
# Production update for the IRIS stand (docker compose project "iris3").
#
#   ./update-prod.sh v3.0.0-beta.24          # dry-run: show the plan
#   ./update-prod.sh v3.0.0-beta.24 --apply  # do it
#   ./update-prod.sh --apply                 # re-apply patches, keep versions
#
# What it does, in order:
#   1. backup: pg_dump + .env + patches/ + compose files
#   2. pull images for the requested version (backend, frontend, nginx, db)
#   3. regenerate mounted patches (models/cases.py, schema/marshables.py,
#      configuration.py) from the new backend image + migrate the date columns
#   4. rebuild the backend image with tasks.py and the dashboard aggregations
#   5. point compose at the new image/version and recreate the stack
#   6. run /root/iris-smoke.sh
#
# Anything that fails aborts before the stack is recreated. Manual steps that
# this script cannot know about are listed in UPGRADE_CHECKLIST.md.
set -euo pipefail

IRIS_DIR="${IRIS_DIR:-/opt/iris3}"
PROJECT="${IRIS_PROJECT:-iris3}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/iris3-backups}"
FIX_DIR="$IRIS_DIR-fix"
SMOKE="${SMOKE:-/root/iris-smoke.sh}"
APPLY=0
VER=""

for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    v*) VER="$arg" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[iris-update %s] %s\n' "$(date '+%F %T')" "$*"; }
die()  { log "ERROR: $*" >&2; exit 1; }
run()  { if [ "$APPLY" = "1" ]; then "$@"; else echo "DRY: $*"; fi; }

[ "$(id -u)" = "0" ] || die "run as root"
[ -d "$IRIS_DIR" ] || die "$IRIS_DIR not found"
command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose plugin not found"

STAMP="$(date '+%Y%m%d-%H%M%S')"
COMPOSE_BACKUP_DIR="$BACKUP_ROOT/$STAMP"

if [ -n "$VER" ]; then
  BACKEND_IMAGE="ghcr.io/dfir-iris/iris-backend:$VER"
else
  BACKEND_IMAGE="$(grep -oE 'iris-backend:[A-Za-z0-9._-]+' "$IRIS_DIR/docker-compose.override.yml" | head -1 || true)"
fi

log "IRIS_DIR=$IRIS_DIR project=$PROJECT version=${VER:-<unchanged>} apply=$APPLY"

# ---------------------------------------------------------------- 1. backup
run mkdir -p "$COMPOSE_BACKUP_DIR"
run cp -a "$IRIS_DIR/.env" "$COMPOSE_BACKUP_DIR/env" || true
run cp -a "$IRIS_DIR/docker-compose.yml" "$COMPOSE_BACKUP_DIR/" || true
run cp -a "$IRIS_DIR/docker-compose.override.yml" "$COMPOSE_BACKUP_DIR/" || true
if [ "$APPLY" = "1" ]; then
  run cp -a "$IRIS_DIR/patches" "$COMPOSE_BACKUP_DIR/patches"
  log "dumping database"
  docker exec "${PROJECT}_db" pg_dump -U postgres -d iris_db | gzip > "$COMPOSE_BACKUP_DIR/iris_db.sql.gz"
  log "backup in $COMPOSE_BACKUP_DIR"
fi

# ---------------------------------------------------------------- 2. images
if [ -n "$VER" ]; then
  for img in backend frontend nginx db; do
    run docker pull "ghcr.io/dfir-iris/iris-$img:$VER"
  done
fi

# ------------------------------------------------------- 3. mounted patches
if [ -n "$VER" ]; then
  if [ -x "$IRIS_DIR/../reapply-patches.sh" ]; then
    run "$IRIS_DIR/../reapply-patches.sh" "$VER"
  elif [ -x /root/reapply-patches.sh ]; then
    run /root/reapply-patches.sh "$VER"
  else
    log "WARNING: reapply-patches.sh not found - regenerate patches by hand (UPGRADE_CHECKLIST items 2-5)"
  fi
else
  log "no version given: keeping the mounted patches as they are"
fi

# ------------------------------------------------------ 4. backend image
if [ -n "$VER" ]; then
  TARGET="iris-backend:patch-$STAMP"
  log "building $TARGET from $BACKEND_IMAGE"
  if [ "$APPLY" = "1" ]; then
    cat > "$FIX_DIR/Dockerfile" <<EOF
FROM $BACKEND_IMAGE
COPY tasks.py /iriswebapp/app/blueprints/rest/v2/case_routes/tasks.py
EOF
    docker build -q -t "$TARGET" "$FIX_DIR"
    # dashboard aggregations are applied at runtime and committed
    CID="$(docker create "$TARGET")"
    docker cp "$IRIS_DIR/patches/dash-aggregations.py" "$CID":/tmp/dash.py
    docker cp "$IRIS_DIR/patches/dash-aggregations-import.py" "$CID":/tmp/dash-import.py
    docker start "$CID" >/dev/null
    sleep 3
    docker exec "$CID" python3 /tmp/dash.py || true
    docker exec "$CID" python3 /tmp/dash-import.py || true
    docker commit "$CID" "$TARGET" >/dev/null
    docker rm -f "$CID" >/dev/null
    log "built $TARGET"
  else
    echo "DRY: build $TARGET and apply dashboard aggregations"
  fi
fi

# ------------------------------------------------------- 5. point & recreate
if [ -n "$VER" ]; then
  run sed -i "s|^IRIS_VERSION=.*|IRIS_VERSION=$VER|" "$IRIS_DIR/.env"
  run sed -i "s|ghcr.io/dfir-iris/iris-frontend:[A-Za-z0-9._-]*|ghcr.io/dfir-iris/iris-frontend:$VER|" "$IRIS_DIR/docker-compose.override.yml"
  if [ "$APPLY" = "1" ]; then
    sed -i "s|image: iris-backend:[A-Za-z0-9._-]*|image: $TARGET|" "$IRIS_DIR/docker-compose.override.yml"
  else
    echo "DRY: image: $TARGET"
  fi
fi

run bash -c "cd '$IRIS_DIR' && docker compose -p '$PROJECT' up -d"

# --------------------------------------------------------------- 6. verify
if [ -x "$SMOKE" ]; then
  if [ "$APPLY" = "1" ]; then
    sleep 20
    "$SMOKE" || die "smoke test failed - see $COMPOSE_BACKUP_DIR for rollback"
  else
    echo "DRY: $SMOKE"
  fi
else
  log "WARNING: $SMOKE not found, run the smoke checks manually"
fi

log "done. rollback: restore $COMPOSE_BACKUP_DIR (env, compose) and the image tag, then recreate"
