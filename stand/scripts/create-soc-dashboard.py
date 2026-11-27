#!/usr/bin/env python3
"""Создать дашборд «SOC — открытые кейсы и алерты» на стенде IRIS v3.

Использование:
    IRIS_API_KEY=<ключ администратора> python3 create-soc-dashboard.py [https://127.0.0.1:8446]

Ключ можно взять из БД:  select api_key from "user" where "user"='administrator';
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1:8446"
KEY = os.environ.get("IRIS_API_KEY", "")
if not KEY:
    sys.exit("нужен IRIS_API_KEY")

HERE = os.path.dirname(os.path.abspath(__file__))
DASH = os.path.join(HERE, "..", "patches", "dashboard", "soc-dashboard.json")

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def call(path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


dashboard = json.load(open(DASH, encoding="utf-8"))
# API beta.1 не принимает operator=is_null — такие виджеты отбрасываем
for section in dashboard.get("sections", []):
    section["widgets"] = [
        w for w in section.get("widgets", [])
        if not any(f.get("operator") == "is_null" for f in (w.get("filters") or []))
    ]

status, result = call("/api/v2/custom-dashboards", "POST", dashboard)
if status >= 300:
    sys.exit("не удалось создать дашборд: %s %s" % (status, result))

uuid = result.get("dashboard_uuid") if isinstance(result, dict) else None
print("dashboard_uuid:", uuid)
if uuid:
    st, rendered = call("/api/v2/custom-dashboards/%s/render" % uuid, "POST", {"definition": dashboard, "filters": {}})
    print("render:", st)
    if st < 300 and isinstance(rendered, dict):
        for section in rendered.get("sections") or []:
            for widget in section.get("widgets", []):
                print(" -", widget.get("name"), "=>", widget.get("data", widget.get("error")))
