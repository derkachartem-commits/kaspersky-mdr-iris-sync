# Чек-лист обновления IRIS-стенда

Актуально на 22.11.2026.

Текущий стек:
- backend: `ghcr.io/dfir-iris/iris-backend:v3.0.0-beta.22` + образ `iris-backend:tasks-fix-23`
- frontend: `v3.0.0-beta.24`
- nginx: `v3.0.0-beta.22`
- db / rabbitmq: `v3.0.0-beta.22` / `rabbitmq:3-management-alpine`

> Имя `tasks-fix-23` не означает beta.23: базовый образ — beta.22.

## Что нужно переложить/допатчить после обновления

### 1. Образ backend (`iris-backend:tasks-fix-23`)
Две правки в исходниках, вшиты в образ:
- `app/blueprints/rest/v2/case_routes/tasks.py` — терпимый partial-update статуса задачи (assignee больше не обязателен, `partial=True`). Фикс beta.22 «Done не нажимается».
- `app/datamgmt/custom_dashboard/named_aggregations.py` — агрегации `cases_open_total`, `cases_open_over_24h`, `cases_avg_close_hours` (скрипты `patches/dash-aggregations.py`, `patches/dash-aggregations-import.py`).
Образ собирался вручную (docker cp + commit), `/opt/iris3-fix/Dockerfile` покрывает только tasks.py.
**Действие:** скопировать оба файла из нового образа, перенести правки, собрать образ, обновить тег в `docker-compose.override.yml`.
**Проверка:** `PUT /api/v2/cases/<id>/tasks/<tid>` только со статусом; дашборд «SOC — открытые кейсы и алерты» отдаёт KPI.

### 2. `patches/configuration.py` (mount в app)
`ACCESS_TOKEN_EXPIRES_MINUTES=1440`, `REFRESH_TOKEN_EXPIRES_DAYS=30`.
**Действие:** взять файл из нового образа, повторить правку, смонтировать.

### 3. `patches/models_cases.py` (mount app + worker)
`open_date = Column(DateTime)`, `close_date = Column(DateTime)` (было `Date`).
**Действие:** `docker cp <new-image>:/iriswebapp/app/models/cases.py`, заменить две строки.

### 4. `patches/schema_marshables.py` (mount app + worker)
`open_date: Optional[datetime.datetime] = auto_field('open_date', required=False)` вместо dump_only-даты.

### 5. Миграция БД (одноразово; повторить при восстановлении из дампа)
```
ALTER TABLE cases ALTER COLUMN open_date TYPE timestamp USING open_date::timestamp;
ALTER TABLE cases ALTER COLUMN close_date TYPE timestamp USING close_date::timestamp;
```

### 6. nginx-патч (persistent, монтируется)
`patches/40-iris-static.sh` — gzip, http2, `/_app/` проксируется в frontend с `Cache-Control: immutable`;
`patches/50-iris-patch-after-start.sh` запускается из `entrypoint` (свой `/entrypoint.sh` делает envsubst и сразу exec nginx, поэтому патч накладывается после старта и делает reload).
**Действие:** после обновления nginx-образа проверить, что блок `location ^~ /_app/` не конфликтует с новым конфигом и что gzip снова не выключен.

### 7. `.env`
```
IRIS_ALLOW_ORIGIN=https://neko.vbrr.online:8446,https://IRIS_HOST_OLD:8446
PUBLIC_EXTERNAL_API_URL=https://neko.vbrr.online:8446
```
Без домена в `IRIS_ALLOW_ORIGIN` Socket.IO отклоняет рукопожатие → тело кейса висит скелетоном.

### 8. Данные (проверить после обновления)
- шаблоны кейсов KDP/MDR — прогнать `scripts/apply_case_templates.py`, если БД пересоздана;
- дашборд «SOC — открытые кейсы и алерты» — при пересоздании БД создать заново.

### 9. Вне IRIS (не ломается обновлением IRIS, но проверить)
- коннектор `/opt/kdp-iris-sync` (bind-mount, обновляется отдельно; после смены API KDP пересмотреть поля);
- уведомления о новых кейсах: `/usr/local/bin/iris-case-notify.sh` + automation `IRIS new case` в OpenClaw;
- `bash /root/iris-smoke.sh` — обязательный прогон.

## Порядок обновления

1. Бэкап: дамп БД, `/opt/iris3/.env`, `/opt/iris3/patches/`, `docker-compose.override.yml`.
2. Забрать новые образы (backend/frontend/nginx/db), не запуская.
3. Перегенерировать патчи 2–4 из новых образов (см. `reapply-datetime-patch.sh`).
4. Проверить/применить миграцию БД (п.5).
5. Собрать backend-образ (п.1) и обновить тег в override.
6. `docker compose -p iris3 up -d`.
7. `bash /root/iris-smoke.sh` → SMOKE OK; открыть кейс (тело рендерится), проверить дашборд и closing_note при авто-закрытии.

## Грабли

- `POST /api/v2/cases/<id>/close` игнорирует тело: `closing_note` писать отдельным `PUT /api/v2/cases/<id>`.
- `open_date` в beta.22 был `dump_only` и тип `date` — время терялось; после патча передаётся ISO-время (UTC).
- `/entrypoint.sh` образа iris-nginx — свой, `/docker-entrypoint.d` не обрабатывает; патч только после старта.
- В PowerShell JSON для `--command-argv` не передаётся — использовать `.bat`.
