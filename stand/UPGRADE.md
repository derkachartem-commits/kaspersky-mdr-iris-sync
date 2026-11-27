# Обновление стенда IRIS v3 до последней версии (без потери данных)

> Все пути ниже — относительно каталога `stand/` этого репозитория.

Проверено на тестовом стенде (Ubuntu 24.04, `/opt/iris-web`, проект `iris-web`).
Текущая версия стенда: **v3.0.0-beta.1**. Последний тег upstream на 27.11.2026 — **v3.0.0-beta.23**.

## Главные правила

1. **Никогда** `docker compose down -v`: `-v` удаляет тома, а там БД IRIS. Только `up -d`.
2. **Не пересоздавать `.env`**: в нём `POSTGRES_*`, `IRIS_SECRET_KEY`, `IRIS_SECURITY_PASSWORD_SALT`. Смена `IRIS_SECRET_KEY`/соли = разлогин всех и битые сессии; смена пароля Postgres = потеря доступа к БД.
3. **`/opt/kdp-iris-sync/config.json` не в git** — обновление коннектора его не трогает. После апгрейда проверить, что на месте `iris.api_key`, `kdp.token` и `auto_escalate.enabled`.
4. Перед любыми работами — **бэкап** (шаг 1). Без бэкапа обновление не начинать.
5. Обновлять сначала стенд, потом коннектор: коннектор ходит в API стенда.

## Шаг 1. Бэкап

```bash
cd /opt/mdr-soc && git pull          # свежие скрипты (каталог stand/)
sudo ./scripts/upgrade-stack.sh --backup-only
```

Кладёт в `/root/iris-backup-<дата-время>` (путь дублируется в `/root/iris-last-backup.txt`):

- `env.bak` — весь `.env` с секретами;
- `docker-compose.yml.bak`, `docker-compose.override.yml`, `patches/`;
- `certificates/` — TLS-ключи и серты;
- `kdp-config.json` — конфиг коннектора, `kdp.db` — его state (дедупликация/группировка);
- `iris_db.sql.gz` — полный `pg_dump` базы IRIS.

Бэкап БД без остановки сервиса (pg_dump консистентный). Раз в неделю стоит копировать каталог бэкапов с хоста.

## Шаг 2. Выбрать целевую версию

```bash
git ls-remote --tags https://github.com/dfir-iris/iris-web.git \
  | sed 's#.*refs/tags/##' | grep -v '\^{}' | sort -V | tail -5
```

Теги — это и версия образов на ghcr.io, и тег исходников. Обновляться лучше на **последний стабильный** тег; пропускать несколько мажорных бет подряд не рекомендуется.

## Шаг 3. Важно про патчи

Набор патчей **зависит от версии IRIS**:

- `beta.1` (текущий стенд): `scripts/apply-beta1.sh` — монтирует `app/models/cases.py`, `named_aggregations.py`, `tasks.py`, nginx-патч;
- `beta.22 … beta.24`: другой набор — `models_cases.py`, `schema_marshables.py`, `ctx.js` (этих файлов в beta.1 нет). Для них используется `patches/compose/docker-compose.override.yml` из истории репозитория и собранный образ backend.

Поэтому **нельзя** просто применить beta1-патчи к beta.23: перед апгрейдом уточнить, под какую версию собран набор, и при необходимости обновить его в репозитории (файлы патчей обязаны соответствовать целевой версии — их содержимое руками не «подгоняется»).

## Шаг 4. Обновление стенда

```bash
cd /opt/mdr-soc/stand
sudo ./scripts/upgrade-stack.sh v3.0.0-beta.23
```

Что делает скрипт:

1. бэкап (как в шаге 1);
2. `sed` только строки `IRIS_VERSION=` в `.env` — остальные секреты не трогает;
3. `docker compose pull` + `up -d` (тома, БД, сертификаты на месте);
4. ждёт старта, переприменяет патчи (идемпотентно), гоняет smoke: HTTP 200, gzip, ALPN h2, статусы контейнеров;
5. печатает команды откатa.

Миграции схемы БД применяются автоматически при старте app (alembic). Отдельно ничего запускать не нужно.

## Шаг 5. Проверка после обновления

```bash
docker ps --format '{{.Names}} {{.Status}}' | grep iris_        # все healthy
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8446/
docker logs --tail 30 iris_app | grep -i -E 'error|traceback'   # пусто
```

В UI руками:

1. вход под administrator;
2. список кейсов открывается, кейс открывается (тело рендерится, не пустое);
3. в кейсе есть время Opened/Closed (часы-минуты), а не только дата;
4. дашборд «SOC — открытые кейсы и алерты» считает цифры;
5. новые KDP-кейсы приходят (коннектор + уведомления).

## Шаг 6. Обновление коннектора KDP→IRIS

```bash
cd /opt/kdp-iris-sync                     # рабочая копия кода
# если это git-копия:
git pull && .venv/bin/pip install -r requirements.txt
sudo systemctl restart kdp-iris-sync
curl -s http://127.0.0.1:8098/healthz
```

Проверить, что в `config.json` сохранились `iris.api_key`, `kdp.token` и `auto_escalate`:

```bash
python3 -c "import json;c=json.load(open('/opt/kdp-iris-sync/config.json'));print(c['auto_escalate'], bool(c['iris']['api_key']), bool(c['kdp']['token']))"
```

Если API-ключ менялся (сброс пароля/пересборка БД) — вписать новый и перезапустить сервис.

## Откат

Версия:

```bash
sudo sed -i 's|^IRIS_VERSION=.*|IRIS_VERSION=v3.0.0-beta.1|' /opt/iris-web/.env
cd /opt/iris-web && docker compose -p iris-web up -d
```

База (если миграции новой версии сломали схему; делать при остановленном app):

```bash
docker stop iris_app iris_worker
gunzip -c /root/iris-backup-<дата>/iris_db.sql.gz | docker exec -i iris_db psql -U postgres -d iris_db
docker start iris_app iris_worker
```

## Чего НЕ делать

- `docker compose down -v`, `docker volume prune`, `docker system prune --volumes`;
- редактировать `.env` через пересоздание файла (потеря секретов) — только точечный `sed` нужной строки;
- `git clean -xdf` в `/opt/iris-web` — снесёт `certificates/` и `patches/`;
- обновлять образы без бэкапа БД;
- менять `IRIS_SECRET_KEY`/`IRIS_SECURITY_PASSWORD_SALT` «для чистоты» — это разлогин и несовместимость сессий.
