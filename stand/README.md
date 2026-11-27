# Стенд IRIS v3 + патчи (часть монорепозитория)

Здесь лежит всё, что касается самого стенда DFIR-IRIS: compose-override, патчи
backend/nginx, скрипты установки/обновления и дашборд SOC.

## Состав

| Путь | Что это |
|---|---|
| `DEPLOY.md` | пошаговый перенос стенда на новый хост (IRIS, патчи, коннектор, уведомления) |
| `UPGRADE.md` | обновление до новой версии без потери данных (бэкап, откат) |
| `UPGRADE_CHECKLIST.md` | чек-лист того, что нужно переложить при обновлении |
| `scripts/apply-beta1.sh` | идемпотентное накатывание патчей на установленный IRIS 3.0.0-beta.1 |
| `scripts/upgrade-stack.sh` | бэкап + смена версии + pull/up + переприменение патчей + smoke |
| `scripts/create-soc-dashboard.py` | создание дашборда «SOC — открытые кейсы и алерты» |
| `scripts/verify.sh` | smoke-проверка стенда (gzip, h2, origin, логин, API) |
| `patches/` | актуальный набор патчей под **beta.1** (override, named_aggregations, tasks.py, модель кейсов, nginx, дашборд) |
| `iris-patch/` | **legacy** набор под beta.22–beta.24 (Dockerfile backend, models_cases.py, schema_marshables.py, ctx.js) — историческая справка |
| `update-stand.sh`, `update-prod.sh`, `update-iris.sh` | ранние скрипты обновления (оставлены для истории) |
| `reapply-patches.sh` | переприменение mounted-патчей после обновления образа |

## Быстрый старт

```bash
# патчи на уже установленный стенд
sudo ./scripts/apply-beta1.sh

# обновление до новой версии (с бэкапом)
sudo ./scripts/upgrade-stack.sh --backup-only
sudo ./scripts/upgrade-stack.sh v3.0.0-beta.23
```

Подробности — `DEPLOY.md` и `UPGRADE.md`. Все пути в них указаны относительно этого каталога (`stand/`).

## Важно

- Наборы патчей **версионно-зависимы**: `patches/` — под beta.1, `iris-patch/` — под beta.22+.
- `.env` стенда и `config.json` коннектора в git не попадают: это секреты, обновление их не трогает.
- Коннектор KDP→IRIS живёт в этом же репозитории: `kdp-iris-sync/` (см. корневой `README.md`).
