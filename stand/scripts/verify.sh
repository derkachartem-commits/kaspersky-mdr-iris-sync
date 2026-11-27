#!/usr/bin/env bash
# Проверка перенесённого стенда. Запуск от root или от пользователя в группе docker.
set -uo pipefail
PROJECT="${PROJECT:-iris3}"
CTR_PREFIX="${CTR_PREFIX:-iris3_}"
HOST_HTTPS_PORT="${HOST_HTTPS_PORT:-8446}"
IRIS_DIR="${IRIS_DIR:-/opt/iris3}"
SYNC_DIR="${SYNC_DIR:-/opt/mdr-iris-sync}"
ok=0; bad=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "  OK   $1"; ok=$((ok+1)); else echo "  FAIL $1"; bad=$((bad+1)); fi; }

echo "== контейнеры =="
docker compose -p "$PROJECT" ps 2>/dev/null || echo "  (compose-проект $PROJECT не найден)"
for c in app worker db rabbitmq nginx frontend; do
  chk "$c healthy" "[[ \$(docker inspect -f '{{.State.Health.Status}}' ${CTR_PREFIX}$c 2>/dev/null) == healthy ]]"
done

echo "== HTTP =="
chk "UI https://127.0.0.1:$HOST_HTTPS_PORT -> 200" \
  "[[ \$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:$HOST_HTTPS_PORT/) == 200 ]]"

echo "== API =="
if [[ -f "$IRIS_DIR/iris-secrets.txt" ]]; then
  tok=$(grep -i 'api' "$IRIS_DIR/iris-secrets.txt" | sed 's/.*[:=][[:space:]]*//' | head -1)
  chk "GET /api/v2/cases" \
    "[[ \$(curl -sk -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer $tok' https://127.0.0.1:$HOST_HTTPS_PORT/api/v2/cases) == 200 ]]"
else
  echo "  SKIP нет $IRIS_DIR/iris-secrets.txt"
fi

echo "== sync =="
chk "mdr-iris-sync active" "[[ \$(systemctl is-active mdr-iris-sync) == active ]]"
chk "последний цикл без ошибок" "journalctl -u mdr-iris-sync -n 40 --no-pager | grep -q 'errors=0'"
chk "sqlite на месте" "[[ -f $SYNC_DIR/state/sync.db ]]"

echo
echo "итого: OK=$ok FAIL=$bad"
[[ $bad -eq 0 ]] || exit 1
