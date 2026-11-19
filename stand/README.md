# Стенд: обновление из Git

Один скрипт обновляет обе части, которые крутятся в Docker на хосте (без VM):

1. **KDP → IRIS коннектор** — контейнер `kdp-iris-sync` (код из `kdp-iris-sync/`).
2. **Патчи IRIS** — образ `iris-backend:tasks-fix`, статический клиент, nginx-патч, конфиг с длинными токенами.

## Запуск

```bash
curl -fsSL https://raw.githubusercontent.com/derkachartem-commits/kaspersky-mdr-iris-sync/main/stand/update-stand.sh -o /root/update-stand.sh
sudo bash /root/update-stand.sh
```

Опции (env): `REPO_BRANCH` (main), `APP_DIR` (/opt/kdp-iris-sync), `IRIS_DIR` (/opt/iris3), `SKIP_IRIS=1` (только коннектор), `IRIS_PROJECT` (iris3).

Что сохраняется: `/opt/kdp-iris-sync/config.json` (креды/токен), `state/`, `logs/`. Перед обновлением конфиг и state бэкапятся в `/opt/kdp-iris-sync-backups/<timestamp>`.

## Что в iris-patch

* `backend/tasks.py` + `backend/Dockerfile` — фикс beta.22: сохранение статуса задачи (`partial=True`, assignee больше не обязателен). Образ `iris-backend:tasks-fix`.
* `patches/configuration.py` — `ACCESS_TOKEN_EXPIRES_MINUTES=1440`, `REFRESH_TOKEN_EXPIRES_DAYS=30` (стенд, иначе 15 минут).
* `patches/ctx.js` + `client.new.tar.gz` — статический клиент IRIS и контекст кейса для UI.
* `patches/40-iris-static.sh` — патч nginx в контейнере: gzip, http2, раздача `/_app/` из `/www/client`.
* `compose/docker-compose.override.yml` — подключает образ и монтирования к `app`/`worker`/`nginx`.

**Важно:** патчи привязаны к версии IRIS `v3.0.0-beta.22` (см. `backend/Dockerfile`). После обновления IRIS на другую версию `tasks.py` нужно переложить на новый файл и пересобрать образ.
