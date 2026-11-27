# Перенос стенда IRIS 3.0.0-beta.1 на прод (пошагово)

> Все пути ниже — относительно каталога `stand/` этого репозитория.

Проверено 26.11.2026 на тестовом стенде (Ubuntu 24.04, /opt/iris-web, проект `iris-web`, порт 8446).

## 0. Что где лежит

| Что | Репозиторий / путь |
|---|---|
| Патчи стенда (этот репозиторий) | `iris-stand-patches` — compose-override, named_aggregations, tasks.py, nginx-патч, модель кейсов beta.1 |
| Коннектор KDP→IRIS | `kaspersky-mdr-iris-sync` — `kdp-iris-sync/` (Python), ставится как systemd-сервис |
| Секреты стенда | `/opt/iris-web/.env` (chmod 600) |
| Конфиг коннектора | `/opt/kdp-iris-sync/config.json` (chmod 600), API-ключ IRIS внутри |

## 1. Подготовка хоста

```bash
apt-get update && apt-get install -y docker.io git curl openssl python3
apt-get install -y docker-compose-v2        # в docker.io плагина compose нет
```

## 2. IRIS из upstream

```bash
git clone --depth 1 --branch v3.0.0-beta.1 https://github.com/dfir-iris/iris-web.git /opt/iris-web
cd /opt/iris-web && mkdir -p certificates/web_certificates
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout certificates/web_certificates/iris_dev_key.pem \
  -out certificates/web_certificates/iris_dev_cert.pem \
  -subj "/CN=<домен>" -addext "subjectAltName=DNS:<домен>,IP:<внешний IP>"
```

`.env` (минимум): `IRIS_VERSION=v3.0.0-beta.1`, `IRIS_HOSTNAME`, `SERVER_NAME`,
`INTERFACE_HTTPS_PORT=8446`, `POSTGRES_*`, `IRIS_SECRET_KEY`,
`IRIS_SECURITY_PASSWORD_SALT`, `IRIS_AUTHENTICATION_TYPE=local`.
Сгенерировать: `POSTGRES_PASSWORD=$(openssl rand -hex 24)`, `IRIS_SECRET_KEY=$(openssl rand -hex 32)` и т.д.

```bash
ufw allow 8446/tcp
docker compose pull && docker compose up -d
```

## 3. Патчи стенда

```bash
git clone https://github.com/derkachartem-commits/kaspersky-mdr-iris-sync.git /opt/mdr-soc
cd /opt/mdr-soc/stand && ./scripts/apply-beta1.sh
```

Скрипт идемпотентный: копирует патчи, ставит `docker-compose.override.yml`,
пересоздаёт `app/worker/nginx`, переводит `cases.open_date/close_date` в `timestamp`.

Что даёт:
- дашборд-агрегации `cases_open_total`, `cases_open_over_24h`, `cases_avg_close_hours`;
- время в Opened/Closed (не только дата);
- gzip, HTTP/2, immutable-кэш для SvelteKit-ассетов.

Проверка:

```bash
curl -sk -o /dev/null -D - -H 'Accept-Encoding: gzip' https://127.0.0.1:8446/ | grep -i content-encoding
echo | openssl s_client -connect 127.0.0.1:8446 -alpn h2 2>/dev/null | grep -i 'ALPN protocol'
```

## 4. Дашборд SOC

```bash
IRIS_API_KEY=<ключ administrator> python3 scripts/create-soc-dashboard.py https://127.0.0.1:8446
```

## 5. Коннектор KDP→IRIS

```bash
git clone <kaspersky-mdr-iris-sync> /opt/kdp-iris-sync-src
cp -a /opt/kdp-iris-sync-src/kdp-iris-sync/. /opt/kdp-iris-sync/
cd /opt/kdp-iris-sync && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp config.example.json config.json && chmod 600 config.json
```

В `config.json` обязательно:
- `iris.api_key` — ключ администратора IRIS;
- `auto_escalate.enabled = true` (+ `attack_template_id`/`anomaly_template_id` при наличии шаблонов) — **без этого алерты не превращаются в кейсы**;
- `kdp.token` — токен KDP.

```bash
systemctl enable --now kdp-iris-sync
curl -s http://127.0.0.1:8098/healthz
```

## 6. Уведомления о новых кейсах

`/usr/local/bin/iris-case-notify.sh` берёт `api_key` из `config.json` коннектора и печатает новые кейсы.
На агенте — cron-обёртка `ssh-tunnel/iris-case-check.cmd` (ключ `iris_notify` в `/root/.ssh/authorized_keys`).

## Грабли, на которые уже наступили

- `docker compose up` без блока `auto_escalate` в конфиге — кейсы не создаются, только алерты.
- IRIS beta.1: `POST /api/v2/alerts/escalate/<id>` падает 500, если в теле нет `iocs_import_list`/`assets_import_list` (исправлено в коннекторе, коммит `62c03e7`).
- `auto_escalate` с `attack_template_id`/`anomaly_template_id` добавляет к имени кейса `title_prefix` шаблона (у шаблонов MDR он `[MDR]`) и навешивает их задачи. Для чистых KDP-кейсов шаблоны не привязывать: только `{"enabled": true}`.
- Дашборд-схема beta.1 не принимает фильтр `is_null` — скрипт такие виджеты отбрасывает.
- nginx-патч ищет `listen <port> ssl;` — при другом порте регулярка должна быть порт-независимой (уже так).
- fail2ban (jail `sshd`) банит за неверные пароли — залить ключ, `fail2ban-client set sshd unbanip <ip>`.
