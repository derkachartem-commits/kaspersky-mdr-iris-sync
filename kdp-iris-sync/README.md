# KDP → DFIR-IRIS connector

Забирает события **Kaspersky DDoS Protection по REST API** (исходящий HTTPS, входящих
портов нет) и заводит алерты в IRIS. Эскалация в кейс — **только вручную**.

Вебхук удалён: в проде ingress закрыт, приём входящих событий не используется.

## Как работает

1. Раз в `kdp.poll_interval_seconds` (по умолчанию 60) коннектор опрашивает KDP API:
   активные атаки (`attacks_path`) и активные аномалии (`anomalies_path`).
2. Каждое событие нормализуется в payload и проходит общий пайплайн:
   алерт `alert_source = Kaspersky KDP`, теги `kdp`, `kdp:<kind>`, `kdp-id:<kind>:<id>`, `svc:<ресурс>`.
3. Дедупликация по `attack_id` / `anomaly_id` — повторный опрос не создаёт второй алерт.
4. Событие, пропавшее из активного списка, закрывается (`attack_stop`/`anomaly_stop`)
   с комментарием (длительность, пик) после `close_grace_seconds`.
5. Если эндпоинт аномалий не настроен или упал — аномалии не закрываются
   («нет данных» ≠ «событие закончилось»).
6. Метрики в `/healthz`: `pull.last_success`, `pull.last_error`, `pull.last_stats`.
7. Дашборд активных событий — `GET /` на `127.0.0.1:8088` (доступ через SSH-туннель).

## Конфиг

```json
"kdp": {
  "enabled": true,
  "api_url": "https://<kdp-api-host>/api/v1",
  "attacks_path": "/attacks",
  "anomalies_path": "/anomalies",
  "attacks_method": "GET",
  "anomalies_method": "GET",
  "token": "<api-token>",
  "auth_header": "Authorization",
  "auth_scheme": "Bearer",
  "verify": true,
  "ca_bundle": null,
  "proxy": null,
  "timeout": 30,
  "poll_interval_seconds": 60,
  "close_missing": true,
  "close_grace_seconds": 90
}
```

- `auth_header`/`auth_scheme` — под любую схему авторизации KDP (например `X-Api-Key` + пустая схема).
- `attacks_method`/`anomalies_method` — HTTP-метод на эндпоинт (по умолчанию GET). В кабинете KDP `portal.kdp.global` список атак отдаётся только через **POST** `/api/attacks/` (пустое тело `{}`, ответ `{"data": [...], "count": N}`), аномалии — `GET /api/anomalies/` (просто массив).
- Токен кабинета `portal.kdp.global` — из `localStorage.token` после входа (opaque, ~86 символов), передаётся как `Authorization: Bearer <token>`; живёт, пока жива сессия в кабинете.
- `refresh_token`/`token_refresh_hours` — авто-обновление сессионного токена: коннектор сам логинится в кабинет раз в N часов (по умолчанию 12), переписывает токен в `config.json` (0600) и подхватывает его без перезапуска. При 401/403 от API обновление запускается сразу.
- Логин/пароль в репозиторий не попадают: читаются из `kdp.login`/`kdp.password` развёрнутого конфига или (приоритетнее) из переменных окружения `KDP_LOGIN`/`KDP_PASSWORD`.
- `verify`/`ca_bundle`/`proxy` — корпоративный TLS и egress-прокси.
- `iris.alert_status_new` / `alert_status_closed` — id статусов в конкретной инсталляции IRIS.
- `thresholds` — границы severity для атак (bps) и аномалий (процент превышения).

## Обновление на стенде (Docker на хосте, без VM)

```bash
sudo ./scripts/update-stand.sh
```

Скрипт: забирает код из GitHub (`main`), делает бэкап `config.json` и `state/`, собирает образ, пересоздаёт контейнер `kdp-iris-sync` (`--network host`, `-v /opt/kdp-iris-sync:/app`) и проверяет `/healthz`. Конфиг с кредами/токеном и state не перезаписывает. Переопределяется через env: `REPO_BRANCH`, `REPO_URL`, `APP_DIR`, `IMAGE`, `CONTAINER`, `HEALTH_URL`.

## Запуск

```bash
docker build -t kdp-iris-sync:1.2 .
docker run -d --name kdp-iris-sync --restart always --network host \
  -v /opt/kdp-iris-sync:/app -w /app -e KDP_CONFIG=config.json kdp-iris-sync:1.2
curl -s http://127.0.0.1:8088/healthz
```

## Проверка без доступа к KDP

Поднять мок, отдающий `[attack]` по `/attacks`, и указать в тестовом конфиге
`api_url: http://127.0.0.1:8099`. Алерт должен появиться в IRIS; после удаления
события из ответа мока — закрыться через grace-период.

## Ограничения

- Схема ответа KDP API уточняется по документации заказчика; маппер терпим
  к вариантам имён (`attack_id|id`, `resource_name|resource|target`, `max_point_values|bps|peak_bps`).
- Нет истории закрытий: если событие завершилось между опросами, длительность берётся
  из `start_time`/`end_time` при их наличии, иначе — от первого опроса до закрытия.
