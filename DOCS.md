# Документация

- [Шаблоны кейсов IRIS и автоназначение](docs/CASE_TEMPLATES.md) — как создавать и
  сопровождать шаблоны кейсов, как настраивать автоматический выбор шаблона для
  алертов MDR и KDP, типовые операции и грабли.
- `examples/case_templates/mdr_templates.json` — пример набора шаблонов для импорта.
- `scripts/apply_case_templates.py` — идемпотентный импорт/обновление шаблонов из JSON.

## Быстрый старт

```bash
# посмотреть, что будет сделано, без изменений
docker exec kdp-iris-sync python /app/scripts/apply_case_templates.py /app/templates.json --dry-run

# применить
docker exec kdp-iris-sync python /app/scripts/apply_case_templates.py /app/templates.json
```

После изменения правил маршрутизации в конфиге коннектора:

```bash
docker restart mdr-iris-sync   # MDR: mapping.case_template_rules
docker restart kdp-iris-sync   # KDP: auto_escalate.*
```
