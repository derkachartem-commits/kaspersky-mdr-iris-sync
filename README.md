# Kaspersky MDR ↔ DFIR-IRIS synchronization

Двусторонняя интеграция между **Kaspersky Managed Detection and Response (MDR Web Console)** и **DFIR-IRIS**.

Скрипт каждые 3 минуты:

1. забирает из MDR новые и изменённые инциденты;
2. создаёт в IRIS алерт и сразу эскалирует его в кейс (либо мерджит в заранее заданный кейс);
3. синхронизирует статусы инцидентов MDR и алертов/кейсов IRIS в обе стороны;
4. синхронизирует комментарии в обе стороны;
5. пишет ошибки и диагностику в ротируемый лог.

Обновление авторизационного токена MDR вынесено в отдельную процедуру с повторами: при любой ошибке `session/confirm` она делает backoff и запускается заново, пока не получит новую пару токенов. Фоновый `TokenKeeper` дополнительно проверяет срок действия `access_token` и обновляет его заранее.

## Возможности

- **Импорт инцидентов MDR как алертов IRIS** с заголовком, описанием, приоритетом, тенантом, хостами, MITRE-тактиками/техниками и ссылкой на MDR Console.
- **Немедленная эскалация алерта в кейс IRIS** (`/api/v2/alerts/escalate/<id>`) или **мердж в существующий кейс** (`/api/v2/alerts/merge/<id>`) — режим настраивается.
- **Двусторонняя синхронизация статусов**:
  - MDR → IRIS: статус алерта и (опционально) кейса;
  - IRIS → MDR: закрытие инцидента MDR при закрытии кейса/алерта в IRIS.
- **Двусторонняя синхронизация комментариев** с защитой от эха и повторной публикации.
- **Идемпотентность** за счёт SQLite-базы состояния: повторный запуск не создаёт дубликаты алертов, кейсов и комментариев.
- **Ротация refresh token** MDR с атомарным сохранением на диск и сериализацией обновлений.
- **Прокси** для одного или обоих сервисов (HTTP/HTTPS/SOCKS5), глобально или отдельно для MDR и IRIS.
- **Ротация логов** (`RotatingFileHandler`) и подробное логирование ошибок по каждому инциденту/комментарию.

## Архитектура

```
┌─────────────────────┐        HTTPS (proxy optional)        ┌──────────────────┐
│  Kaspersky MDR      │  POST /api/v1/<client>/incidents/... │  sync process    │
│  Web Console API    │ <───────────────────────────────────>│  (this project)  │
└─────────────────────┘                                      │                  │
                                                             │  SQLite state    │
┌─────────────────────┐        HTTPS (proxy optional)        │  + rotating log  │
│  DFIR-IRIS API v2   │ <───────────────────────────────────>│                  │
│  alerts/cases/...   │                                      └──────────────────┘
└─────────────────────┘
```

Цикл синхронизации:

```
ingest (MDR incidents)
  └─ IRIS alert add
       └─ IRIS alert escalate -> case  (или merge -> существующий case)

sync statuses (каждые 3 минуты)
  ├─ MDR status  -> IRIS alert status / case status
  └─ IRIS closed -> MDR incidents/close (обратного reopen в MDR API нет)

sync comments (каждые 3 минуты)
  ├─ MDR comment -> IRIS case/alert comment
  └─ IRIS comment -> MDR comment
```

## Требования

- Python **3.10+**.
- `requests` (единственная обязательная зависимость).
- DFIR-IRIS **2.1+** с включённым Alerts API (в 2.4.x работает).
- Доступ к MDR Web Console API: `client_id` и refresh token (JWT).
- Для SOCKS5-прокси: `pip install "requests[socks]"`.

## Установка

```bash
git clone <repo-url> mdr-iris-sync
cd mdr-iris-sync
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp config.example.json config.json
chmod 600 config.json
```

Заполните `config.json`. Секреты можно не хранить в файле, а передавать через переменные окружения:

```bash
export MDR_CLIENT_ID="..."
export MDR_REFRESH_TOKEN="..."
export IRIS_API_KEY="..."
export IRIS_API_URL="https://iris.example.local"
export MDR_API_URL="https://mdr.kaspersky.com/api/v1"
```

## Получение доступов

### Kaspersky MDR

1. MDR Web Console → **Settings → API**.
2. **Connection Name** — имя, под которым интеграция будет автором комментариев.
3. **Role** — права на чтение инцидентов/комментариев и закрытие инцидентов.
4. **Tenant** — при необходимости ограничьте тенантом.
5. **Generate** → получите **JWT** (это refresh token) и **Client ID**.

Первый refresh token живёт 24 часа, последующие — 7 дней. Интеграция сама обновляет пару токенов и сохраняет её в `state/mdr_tokens.json` (chmod 600). Если refresh token истёк, сгенерируйте новый в консоли и положите его в `config.json` или в `state/mdr_tokens.json`.

### DFIR-IRIS

1. Создайте сервисного пользователя и API-ключ: **My settings → API Key**.
2. Пользователю нужны права:
   - `alerts_read`, `alerts_write`;
   - `cases_read`, `cases_write`;
   - доступ к клиенту (`customer_id`), от имени которого создаются алерты.
3. Определите ID справочников вашего инстанса (они **не совпадают** между инсталляциями):
   - `customer_id`, `classification_id`, `asset_type_id`;
   - ID статусов алертов: `alert_status_id`, `closed_alert_status_id`;
   - ID статусов кейсов: `case_status_id`, `closed_case_status_id`;
   - ID критичностей для маппинга приоритетов MDR.

Их можно посмотреть в UI (справочники) или запросить через API, например:

```bash
curl -k -H "Authorization: Bearer $IRIS_API_KEY" \
  https://iris.example.local/api/v2/alerts/1
```

## Конфигурация

### Прокси (web proxy)

Прокси — это **исходящий HTTP/HTTPS-прокси**, через который процесс ходит к API. Это не прокси для входящих подключений к скрипту: скрипт сам является клиентом MDR и IRIS.

Для MDR это означает, что **все** запросы к `https://mdr.kaspersky.com` — включая `session/confirm` и обновление токена — идут через указанный web-прокси. HTTPS передаётся через `CONNECT`; прокси должен разрешать `CONNECT mdr.kaspersky.com:443`.

Пример: MDR через корпоративный web-прокси, IRIS напрямую:

```json
"mdr": {
  "proxy": {
    "enabled": true,
    "url": "http://proxy.corp.local:3128",
    "username": "svc_mdr",
    "password": "***"
  }
},
"iris": {
  "proxy": { "enabled": false }
}
```

Учётные данные можно указать в URL (`http://user:pass@proxy:3128`) или полями `username` / `password` — второй вариант удобнее, спецсимволы кодируются автоматически.

Глобальный блок `proxy` задаёт значения по умолчанию для обоих сервисов; `mdr.proxy` / `iris.proxy` переопределяют их. `null` или отсутствие ключа — наследовать, `false` — отключить прокси для сервиса.

- `url` — прокси для HTTP и HTTPS; `http` / `https` — раздельные прокси.
- `no_proxy` — список хостов/доменов, которые идут напрямую.
- Поддерживаются `http://`, `https://`, `socks5://`, `socks5h://`. Для SOCKS нужен `pip install "requests[socks]"`.
- Basic-auth прокси поддерживается. Для NTLM/Kerberos-прокси нужен дополнительный адаптер (`requests-ntlm` / `requests-kerberos`), в текущей версии он не включён.

Переменные окружения:

- `SYNC_PROXY_URL` — включить глобальный прокси;
- `MDR_PROXY_URL`, `IRIS_PROXY_URL` — прокси только для конкретного сервиса.

Прокси не применяется, если целевой хост попадает в `no_proxy` (проверка через `requests.utils.should_bypass_proxies`). Логин/пароль в URL прокси маскируются в логах.

### Основные параметры

| Параметр | Назначение |
|---|---|
| `interval_seconds` | Период цикла, по умолчанию `180` (3 минуты). |
| `state_db` | Путь к SQLite с маппингом и идемпотентностью. |
| `mdr.client_id` | Client ID из MDR Web Console. |
| `mdr.refresh_token` | Стартовый refresh token (далее хранится в `mdr.tokens_file`). |
| `mdr.tokens_file` | Файл с актуальной парой токенов. |
| `mdr.initial_lookback_hours` | Начальная глубина импорта при пустой БД. |
| `mdr.max_incidents_per_cycle` | Защита от лавины при первом запуске. |
| `mdr.ignore_comment_authors` | Авторы MDR, комментарии которых не импортируются (например, имя API-подключения). |
| `mdr.token_refresh.*` | Порог обновления, задержки и backoff процедуры смены токена. |
| `iris.api_url`, `iris.api_key` | Подключение к IRIS. |
| `iris.customer_id` | Клиент IRIS для создаваемых алертов. |
| `iris.classification_id` | Классификация алертов (обязательное поле IRIS). |
| `iris.alert_status_id` | Статус нового алерта. |
| `iris.case_status_id` | Статус кейса «в работе». |
| `iris.closed_case_status_id` | ID закрытого статуса кейса. |
| `iris.closed_alert_status_id` | ID закрытого статуса алерта. |
| `iris.ignore_comment_authors` | Авторы IRIS, чьи комментарии не отправляются в MDR (сервисный пользователь). |
| `mapping.mode` | `escalate` — создавать кейс из алерта; `merge` — мерджить в существующий кейс. |
| `mapping.merge_target_case_id` | Кейс для режима `merge`. |
| `mapping.merge_target_by_tenant` | Переопределение целевого кейса по имени тенанта MDR. |
| `mapping.severity` | Приоритет MDR → ID критичности IRIS. |
| `mapping.status_to_iris` | Статус MDR → ID статуса алерта IRIS. |
| `mapping.conflict_policy` | `mdr_wins`, `iris_wins` или `last_write` при одновременном изменении с двух сторон. |
| `mapping.close_mdr_resolution` | `resolution_status` для `incidents/close` (например, `TRUE_POSITIVE`). |
| `mapping.sync_case_status` | Синхронизировать ли статус кейса IRIS со статусом MDR. |
| `mapping.reopen_iris_case` | Открывать закрытый кейс IRIS, если MDR-инцидент снова открыт. |

## Запуск

```bash
python -m mdr_iris_sync --config config.json
```

Один цикл (для cron/systemd timer):

```bash
python -m mdr_iris_sync --config config.json --once
```

Уровень логирования можно переопределить: `--log-level DEBUG`.

Пример unit-файла — `deploy/mdr-iris-sync.service`.

## Развёртывание на сервере IRIS

Типовая схема — скрипт работает на том же хосте, что и DFIR-IRIS, и обращается к MDR через корпоративный web-прокси:

```
DFIR-IRIS (127.0.0.1:443)  <--  mdr-iris-sync  -->  web proxy  -->  mdr.kaspersky.com:443
```

Настройки для этого варианта:

- `iris.api_url` — локальный адрес IRIS: `https://127.0.0.1:443`, `https://127.0.0.1:8445` и т.п. Порт зависит от того, как опубликован nginx IRIS.
- `iris.proxy.enabled` — `false`: запросы к локальному IRIS не должны идти через прокси. `127.0.0.1`/`localhost` также можно держать в `no_proxy`.
- `iris.verify` — `false` для самоподписанного сертификата либо путь к CA в `iris.ca_bundle`.
- `mdr.proxy` — корпоративный web-прокси. Через него идут все запросы к MDR, включая обновление токена.
- `mdr.verify` — `true` (MDR использует доверенный сертификат); при необходимости `mdr.ca_bundle`.

Готовый пример: `examples/config.iris-server.json`.

Секреты лучше держать не в `config.json`, а в `.env` рядом (systemd-юнит читает `EnvironmentFile=-/opt/mdr-iris-sync/.env`):

```ini
MDR_CLIENT_ID=...
MDR_REFRESH_TOKEN=***
IRIS_API_KEY=***
MDR_PROXY_URL=http://proxy.corp.local:3128
# IRIS_API_URL=https://127.0.0.1:443
```

Установка на хост IRIS:

```bash
sudo mkdir -p /opt/mdr-iris-sync
sudo cp -r . /opt/mdr-iris-sync
cd /opt/mdr-iris-sync
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp examples/config.iris-server.json config.json
cp deploy/mdr-iris-sync.env.example .env
chmod 600 config.json .env
# отредактируйте config.json и .env
sudo cp deploy/mdr-iris-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mdr-iris-sync
```

Если IRIS и скрипт находятся в одном Docker-сети, вместо `127.0.0.1` укажите имя сервиса IRIS (например, `https://iris-nginx`), а `iris.proxy` оставьте выключенным.

## Как работает синхронизация

### Импорт инцидентов

MDR API не отдаёт «список всех инцидентов» одним запросом, поэтому используется `incidents/list` с фильтром `min_update_time` (epoch ms). В состоянии хранится watermark последнего успешно обработанного `update_time`; при ошибке импорта watermark не сдвигается дальше проблемного инцидента, чтобы он был повторён.

Для каждого нового инцидента:

1. `POST /api/v2/alerts` — создаётся IRIS-алерт.
2. `POST /api/v2/alerts/escalate/<alert_id>` — создаётся кейс (режим `escalate`), либо `POST /api/v2/alerts/merge/<alert_id>` с `target_case_id` (режим `merge`).
3. Маппинг `incident_id → alert_id → case_id` сохраняется в SQLite.

Если IRIS принял алерт, но эскалация упала, на следующем цикле интеграция сначала проверяет `alert_case_id` у алерта и не создаёт второй кейс.

### Статусы

- **MDR → IRIS.** Изменение статуса MDR обновляет `alert_status_id` алерта и (если включено) `status_id` кейса.
- **IRIS → MDR.** Закрытие кейса или алерта в IRIS вызывает `POST /api/v1/<client_id>/incidents/close` с настроенной резолюцией.
- **Одновременное изменение.** Разрешается по `mapping.conflict_policy`.
- **Ограничение MDR API.** У MDR нет метода «переоткрыть инцидент». Если в IRIS кейс переоткрыли, интеграция пишет предупреждение в лог, но MDR остаётся закрытым.

### Комментарии

- Комментарии MDR импортируются в кейс IRIS (или в алерт, если кейса ещё нет) с заголовком `**[MDR] автор — дата**`.
- Комментарии IRIS отправляются в MDR с заголовком `**[IRIS] автор — дата**`.
- Идемпотентность: таблица `comments` хранит направление и `source_key`; повторно обработанный комментарий не публикуется.
- Защита от эха: комментарии, созданные самой интеграцией, распознаются по `target_key` и по автору из `ignore_comment_authors`.
- При потере БД возможны дубликаты; для восстановления используйте резервную копию `state/sync.db`.

## Логи

Файл по умолчанию — `logs/mdr-iris-sync.log`, ротация 10 МБ × 5 файлов. Формат:

```
2026-11-16 10:15:00 INFO     mdr_iris_sync.sync: incident INC-123 imported as IRIS alert #42
```

Все ошибки по конкретному инциденту/комментарию логируются с traceback (`logger.exception`), цикл при этом продолжается. Ошибка одного инцидента не блокирует остальные.

## Тесты

```bash
python -m unittest discover -s tests -v
```

Тесты не обращаются к сети: проверяются маппинг, преобразование времени, разбор комментариев и слияние конфигурации.

## Совместимость с DFIR-IRIS 3.0.0-beta.1

Проверено по исходникам тега `v3.0.0-beta.1`:

- **Alerts API v2** не изменился: `POST /api/v2/alerts`, `GET/PUT /api/v2/alerts/<id>`, `POST /api/v2/alerts/escalate/<id>`, `POST /api/v2/alerts/merge/<id>`.
- **Кейсы:** в v3 статус хранится в `state_id` (в v2.4 — `status_id`), а закрытие вынесено в `POST /api/v2/cases/<id>/close`. Клиент отправляет оба поля и сначала пробует новый `/close`, затем fallback для v2.4.
- **Комментарии кейсов:** в v3.0.0-beta.1 маршрута `/api/v2/cases/<id>/comments` нет. При `comments_object: auto` интеграция автоматически переключается на комментарии алерта. Если нужен именно case-thread, в v3 его нужно заменить на activities или другой механизм.
- **Аутентификация** по API-ключу (`Authorization: Bearer ...`) сохранена.

Проверка статическая, по исходникам бэкенда; на живом инстансе 3.0.0-beta.1 интеграция не запускалась. Перед production-запуском стоит прогнать один цикл с `--once` и `--log-level DEBUG`.

## Ограничения

- Синхронизируются **статусы и комментарии**. Вложения, Response-действия и теги MDR не синхронизируются (MDR-вложения можно добавить отдельным модулем).
- MDR API не позволяет переоткрыть инцидент или произвольно изменить его статус, кроме закрытия.
- IRIS-алерт после эскалации остаётся отдельной сущностью; интеграция обновляет и алерт, и кейс.
- При первом запуске с большой историей используйте `mdr.initial_lookback_hours` и `mdr.max_incidents_per_cycle`, чтобы не перегрузить IRIS.
- ID справочников IRIS индивидуальны для инсталляции — их нужно сверить перед запуском.

## Полезные ссылки

- Kaspersky MDR REST API: <https://support.kaspersky.com/mdr/204471>
- Kaspersky MDR Open REST API Reference: <https://support.kaspersky.com/MDR/RestAPI/REST_API_doc.html>
- DFIR-IRIS API v2 reference: <https://docs.dfir-iris.org/latest/_static/iris_api_reference_v2.0.0.html>
- DFIR-IRIS alerts: <https://docs.dfir-iris.org/latest/operations/alerts/>

## Лицензия

MIT — см. `LICENSE`.
