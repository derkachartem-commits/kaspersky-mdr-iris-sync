#!/usr/bin/env python3
"""Upsert IRIS case templates from a JSON file.

Usage:
    python scripts/apply_case_templates.py templates.json [--dry-run]

Template JSON: either a list of templates or {"templates": [...]}:
    {
      "name": "mdr_cryptomining",
      "display_name": "MDR — Криптомайнинг",
      "title_prefix": "[MDR]",
      "description": "…",
      "summary": "…",
      "tags": ["mdr", "mining"],
      "tasks": [{"title": "…", "description": "…"}],
      "note_directories": []
    }

Existing templates are matched by `name` and updated (PUT with the full object);
missing ones are created. Idempotent: safe to run repeatedly.

IRIS connection comes from the connector config (env KDP_CONFIG or /app/config.json):
iris.api_url and iris.api_key.
"""

from __future__ import annotations

import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings()

CONFIG_PATH = os.environ.get("KDP_CONFIG", "/app/config.json")


def load_api():
    cfg = json.load(open(CONFIG_PATH, encoding="utf-8"))
    api = cfg["iris"]["api_url"].rstrip("/")
    headers = {
        "Authorization": f"Bearer {cfg['iris']['api_key']}",
        "Accept": "application/json",
    }
    return api, headers


def normalize(tpl: dict) -> dict:
    tasks = tpl.get("tasks") or []
    return {
        "name": tpl["name"],
        "display_name": tpl["display_name"],
        "description": tpl.get("description", ""),
        "author": tpl.get("author", "Alter"),
        "title_prefix": tpl.get("title_prefix", ""),
        "summary": tpl.get("summary", ""),
        "tags": tpl.get("tags") or [],
        "tasks": [
            {"title": task["title"], "description": task.get("description", "")}
            for task in tasks
        ],
        "note_directories": tpl.get("note_directories") or [],
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    path = argv[1]
    dry_run = "--dry-run" in argv[2:]

    raw = json.load(open(path, encoding="utf-8"))
    templates = raw.get("templates") if isinstance(raw, dict) else raw
    if not isinstance(templates, list):
        print("ERROR: JSON must be a list of templates or {'templates': [...]}")
        return 2

    api, headers = load_api()
    response = requests.get(
        f"{api}/api/v2/manage/case-templates", headers=headers, verify=False, timeout=60
    )
    response.raise_for_status()
    existing = {item.get("name"): item for item in response.json().get("data", [])}

    for tpl in templates:
        body = normalize(tpl)
        name = body["name"]
        if name in existing:
            template_id = existing[name]["id"]
            if dry_run:
                print(f"would update {name} (id={template_id}), {len(body['tasks'])} tasks")
                continue
            r = requests.put(
                f"{api}/api/v2/manage/case-templates/{template_id}",
                json=body,
                headers=headers,
                verify=False,
                timeout=60,
            )
            print(f"update {name} (id={template_id}) -> {r.status_code}")
        else:
            if dry_run:
                print(f"would create {name}, {len(body['tasks'])} tasks")
                continue
            r = requests.post(
                f"{api}/api/v2/manage/case-templates",
                json=body,
                headers=headers,
                verify=False,
                timeout=60,
            )
            created_id = r.json().get("id") if r.content else None
            print(f"create {name} -> {r.status_code} id={created_id}")
        if r.status_code not in (200, 201):
            print(f"  body: {r.text[:300]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
