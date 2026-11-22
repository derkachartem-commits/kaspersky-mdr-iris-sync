#!/usr/bin/env bash
# Re-generate the mounted IRIS patches after an image update.
#
#   ./reapply-patches.sh v3.0.0-beta.23
#
# Copies models/cases.py, schema/marshables.py and configuration.py out of the
# new backend image, re-applies the local edits into /opt/iris3/patches, and
# migrates the case date columns to timestamp. Does NOT rebuild the backend
# image: tasks.py and the dashboard aggregations still have to be re-applied by
# hand (see UPGRADE_CHECKLIST.md, item 1).
set -euo pipefail

VER="${1:?usage: $0 <backend-image-tag>, e.g. v3.0.0-beta.23}"
BASE="${IRIS_BASE_IMAGE:-ghcr.io/dfir-iris/iris-backend:$VER}"
DIR="${IRIS_DIR:-/opt/iris3}"
P="$DIR/patches"
TMP="iris_patch_tmp_$$"

[ -d "$P" ] || { echo "no $P"; exit 1; }

STAMP="$(date +%Y%m%d-%H%M%S)"
for f in models_cases.py schema_marshables.py configuration.py; do
  [ -f "$P/$f" ] && cp -a "$P/$f" "$P/$f.bak-$STAMP"
done

docker create --name "$TMP" "$BASE" >/dev/null
trap 'docker rm -f "$TMP" >/dev/null 2>&1 || true' EXIT
docker cp "$TMP":/iriswebapp/app/models/cases.py "$P/models_cases.py"
docker cp "$TMP":/iriswebapp/app/schema/marshables.py "$P/schema_marshables.py"
docker cp "$TMP":/iriswebapp/app/configuration.py "$P/configuration.py"

python3 - "$P" <<'PY'
import sys
from pathlib import Path

base = Path(sys.argv[1])

def patch(name, pairs):
    path = base / name
    text = path.read_text(encoding="utf-8")
    for old, new in pairs:
        if new in text:
            continue
        if old not in text:
            raise SystemExit(f"{name}: expected snippet not found: {old[:60]!r}")
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")
    print(f"patched {name}")

patch("models_cases.py", [
    ("open_date = Column(Date)", "open_date = Column(DateTime)"),
    ("close_date = Column(Date)", "close_date = Column(DateTime)"),
])

patch("schema_marshables.py", [
    ("open_date: Optional[datetime.date] = auto_field('open_date', dump_only=True)",
     "open_date: Optional[datetime.datetime] = auto_field('open_date', required=False)"),
])
PY

echo "=== migrating case date columns"
docker exec iris3_db psql -U postgres -d iris_db -v ON_ERROR_STOP=1 -c \
  "ALTER TABLE cases ALTER COLUMN open_date TYPE timestamp USING open_date::timestamp;
   ALTER TABLE cases ALTER COLUMN close_date TYPE timestamp USING close_date::timestamp;"

cat <<NOTE

Patches regenerated from $BASE.
Still manual (UPGRADE_CHECKLIST.md, item 1):
  * case_routes/tasks.py            -> partial task status update
  * custom_dashboard/named_aggregations.py -> cases_open_total / _over_24h / _avg_close_hours
Then: docker compose -p iris3 up -d app worker && bash /root/iris-smoke.sh
NOTE
