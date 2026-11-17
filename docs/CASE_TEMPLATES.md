# Шаблоны кейсов IRIS и автоназначение

Документ описывает, как создавать и сопровождать шаблоны кейсов и как настраивать
автоматическое назначение шаблона при появлении алертов (MDR и KDP).

## 1. Как устроены шаблоны

Шаблон кейса в IRIS — это запись в таблице `case_template`:

| Поле | Назначение |
|---|---|
| `name` | машинный идентификатор (slug), по нему ищем шаблон при обновлении |
| `display_name` | название в выпадающем списке «Case template» |
| `title_prefix` | префикс названия кейса (например `[MDR]`) |
| `description`, `summary` | описание для аналитика |
| `tags` | JSON-массив тегов |
| `tasks` | JSON-массив задач `[{"title": "...", "description": "..."}]` |
| `note_directories` | каталоги заметок (обычно `[]`) |

При создании кейса из шаблона задачи копируются в кейс (`case_tasks`) со статусом
`To do`. Статусы задач: `1 To do`, `2 In progress`, `3 On hold`, `4 Done`, `5 Canceled`.
Задачи существуют **только на кейсе** — у алерта задач нет (ограничение модели IRIS).

## 2. REST API шаблонов

База: `https://<iris-host>:8446`, авторизация `Authorization: Bearer <API_KEY>`
(ключ — в `/opt/iris3/iris-secrets.txt` на стенде).

| Метод | Путь | Что делает |
|---|---|---|
| GET | `/api/v2/manage/case-templates` | список шаблонов (`total`, `data[]`) |
| POST | `/api/v2/manage/case-templates` | создать (обязательны `name`, `display_name`) |
| PUT | `/api/v2/manage/case-templates/<id>` | обновить (шлём полный объект) |
| DELETE | `/api/v2/manage/case-templates/<id>` | удалить шаблон |

Пример создания:

```bash
KEY=$(grep -oE '[A-Fa-f0-9]{64}' /opt/iris3/iris-secrets.txt | head -1)
curl -sk -X POST https://127.0.0.1:8446/api/v2/manage/case-templates \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{
    "name": "mdr_cryptomining",
    "display_name": "MDR — Криптомайнинг",
    "title_prefix": "[MDR]",
    "description": "Добыча криптовалюты на хосте",
    "summary": "Найти процесс, изолировать, оценить ресурсы и скоуп",
    "tags": ["mdr", "mining"],
    "tasks": [
      {"title": "Найти процесс", "description": "Имя, путь, хеш, командная строка майнера."},
      {"title": "Изолировать хост", "description": "Сеть/учётка, остановить процесс."},
      {"title": "Определить скоуп", "description": "Другие хосты по пулу/хешу."},
      {"title": "Устранение", "description": "Удалить, закрыть вектор, проверить persistence."}
    ],
    "note_directories": []
  }'
```

Обновление: сначала `GET` нужного шаблона, меняем поля, затем `PUT` тем же объектом
на `/api/v2/manage/case-templates/<id>`. Ответ `200` — сохранено.

## 3. Импорт шаблонов из файла (скрипт)

В репозитории:

- `examples/case_templates/mdr_templates.json` — пример набора шаблонов;
- `scripts/apply_case_templates.py` — upsert по `name`: создаёт отсутствующие,
  обновляет существующие, печатает id.

Запуск на стенде (в контейнере коннектора, где есть `requests` и смонтирован код):

```bash
docker cp examples/case_templates/mdr_templates.json kdp-iris-sync:/app/templates.json
docker exec kdp-iris-sync python /app/scripts/apply_case_templates.py /app/templates.json
```

Скрипт идемпотентен: повторный запуск обновляет шаблоны, а не плодит дубли.

## 4. Автоназначение для MDR

Настройки в `/opt/mdr-iris-sync/config.json` (0600), секция `mapping`:

```json
"mapping": {
  "case_template_id": 3,
  "case_template_rules": [
    {"template_id": 4, "mitre": ["t1486", "t1490"], "keywords": ["ransom", "шифр", "вымог"]},
    {"template_id": 5, "mitre": ["t1003"], "keywords": ["lsass", "mimikatz", "дамп памяти"]}
  ]
}
```

Правила:

1. Правила проверяются **по порядку**, первое совпадение выигрывает — приоритет
   задаётся позицией в массиве (поставь правило выше, если оно важнее).
2. `mitre` — подстрочное совпадение в нижнем регистре по полю `mitre_techniques`
   инцидента: правило `t1059` поймает `T1059.001`.
3. `keywords` — подстроки в `summary`, `description`, `status_description`,
   `attack_stage` и `mitre_tactics` (всё в нижнем регистре).
4. Если ничего не совпало — берётся `case_template_id` (фолбэк). Если и его нет —
   кейс создаётся без шаблона (пустой).
5. После правки конфига — `docker restart mdr-iris-sync`.

Добавить новый тип инцидента:

1. создать шаблон (раздел 2 или скрипт) и запомнить `id`;
2. добавить правило с этим `template_id` **в начало** `case_template_rules`
   (если оно должно перекрывать остальные);
3. `docker restart mdr-iris-sync`;
4. проверить на тестовом инциденте (ниже).

Проверка выбора без ожидания инцидента:

```bash
docker run --rm -v /opt/mdr-iris-sync:/app -w /app mdr-iris-sync:1.2 python - <<'PY'
import json
from mdr_iris_sync.mapping import select_case_template
cfg = json.load(open("/app/config.json"))
print(select_case_template({"summary": "LSASS dump", "mitre_techniques": ["T1003"]}, cfg["mapping"]))
PY
```

В логах контейнера при реальной работе: `incident <id> linked to IRIS case #<N>`.
Если шаблон не подошёл — проверь `mitre_techniques` в исходном инциденте MDR
(поле приходит не всегда, тогда работают ключевые слова).

Отключить автосоздание кейсов: `safety.allow_case_creation = false`, рестарт.

## 5. Автоназначение для KDP

Настройки в `/opt/kdp-iris-sync/config.json` (0600):

```json
"auto_escalate": {"enabled": true, "attack_template_id": 2, "anomaly_template_id": 1},
"auto_close": {"enabled": true, "closeable_status_ids": [2, 8]},
"kdp": {"status_map": {"active": 2, "in_progress": 4, "finished": 6}}
```

- `attack_template_id` / `anomaly_template_id` — шаблоны для атак и аномалий;
  `default_template_id` — фолбэк для прочих событий (bgp_down, сертификаты).
- Алерт создаётся и **сразу** эскалируется в кейс; в логах — `alert N escalated to case M`.
- `kdp.status_map` переводит статус события KDP в статус алерта IRIS; значения —
  id из таблицы `alert_status` конкретной инсталляции.
- `auto_close.closeable_status_ids` — какие статусы алерта разрешено закрывать
  (после эскалации IRIS ставит алерту `Escalated` = 8, поэтому 8 в списке обязателен).
- После правки — `docker restart kdp-iris-sync`, проверка `curl -s 127.0.0.1:8088/healthz`.

## 6. Типовые операции

| Задача | Действие |
|---|---|
| Добавить шаг в шаблон | GET шаблон → добавить элемент в `tasks` → PUT |
| Переименовать | PUT с новым `display_name` |
| Удалить шаблон | DELETE `/api/v2/manage/case-templates/<id>` (существующие кейсы не страдают) |
| Поменять приоритет | переставить элементы `case_template_rules` |
| Отключить автоэскалацию MDR | `safety.allow_case_creation=false` |
| Отключить автоэскалацию KDP | `auto_escalate.enabled=false` |
| Проверить, какой шаблон выберется | `select_case_template(...)` (раздел 4) |

## 7. Ограничения и грабли

- Идентификаторы статусов (`alert_status`, `severity`, `case_status`) зависят от
  инсталляции — сверяйся с БД:
  `docker exec iris3_db psql -U postgres -d iris_db -c "select * from alert_status"`.
- Задачи в `v3.0.0-beta.22` не обновлялись из-за бага API (`task_assignee_id ...`);
  на стенде стоит пропатченный образ `iris-backend:tasks-fix` (см. `/opt/iris3-fix`
  и `docker-compose.override.yml`). При обновлении IRIS патч нужно наложить заново,
  иначе клик по статусу задачи снова сломается.
- Шаблоны не влияют на уже созданные кейсы: задачи копируются в момент создания.
- Удаление шаблона не удаляет задачи существующих кейсов.
