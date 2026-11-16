"""Configuration loading and validation."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict


DEFAULTS: Dict[str, Any] = {
    "log": {
        "file": "logs/mdr-iris-sync.log",
        "level": "INFO",
        "max_mb": 10,
        "backups": 5,
    },
    "interval_seconds": 180,
    "state_db": "state/sync.db",
    "safety": {
        "allow_alert_creation": True,
        "allow_case_creation": True,
        "allow_status_changes": False,
        "allow_comments": False,
    },
    "proxy": {
        "enabled": False,
        "url": "http://127.0.0.1:10808",
        "http": "",
        "https": "",
        "username": "",
        "password": "",
        "no_proxy": ["127.0.0.1", "localhost"],
    },
    "mdr": {
        "proxy": None,
        "api_url": "https://mdr.kaspersky.com/api/v1",
        "client_id": "",
        "refresh_token": "",
        "tokens_file": "state/mdr_tokens.json",
        "verify": True,
        "ca_bundle": None,
        "timeout": 60,
        "page_size": 100,
        "max_pages": 100,
        "initial_lookback_hours": 24,
        "include_statuses": [],
        "ignore_statuses": ["closed", "resolved"],
        "max_incidents_per_cycle": 100,
        "ignore_comment_authors": [],
        "token_refresh": {
            "refresh_before_seconds": 180,
            "retry_delay_seconds": 5,
            "max_delay_seconds": 300,
            "check_interval_seconds": 30,
        },
        "incident_fields": [
            "incident_id",
            "incident_number",
            "summary",
            "description",
            "priority",
            "status",
            "resolution",
            "status_description",
            "creation_time",
            "update_time",
            "tenant_name",
            "affected_hosts",
            "affected_hosts_mappings",
            "mitre_tactics",
            "mitre_techniques",
            "comments",
            "responses",
            "attachments",
        ],
    },
    "iris": {
        "proxy": None,
        "api_url": "https://127.0.0.1:8445",
        "api_key": "",
        "verify": False,
        "ca_bundle": None,
        "timeout": 60,
        "customer_id": 1,
        "classification_id": 1,
        "asset_type_id": None,
        "alert_status_id": 1,
        "case_status_id": 2,
        "closed_case_status_id": 3,
        "closed_alert_status_id": 3,
        "comments_object": "auto",
        "send_context": True,
        "ignore_comment_authors": [],
    },
    "mapping": {
        "mode": "escalate",
        "merge_target_case_id": None,
        "merge_target_by_tenant": {},
        "severity": {
            "LOW": 2,
            "NORMAL": 3,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5,
            "": 3,
        },
        "default_severity_id": 3,
        "status_to_iris": {
            "new": 1,
            "in progress": 2,
            "closed": 3,
            "resolved": 3,
            "escalated": 2,
        },
        "default_alert_status_id": 1,
        "close_mdr_resolution": "TRUE_POSITIVE",
        "close_mdr_summary": "Closed in DFIR-IRIS",
        "sync_case_status": True,
        "reopen_iris_case": False,
        "conflict_policy": "mdr_wins",
        "source_name": "Kaspersky MDR",
        "source_link_template": "https://mdr.kaspersky.com/incidents/{incident_id}",
        "tags": ["MDR", "Kaspersky"],
        "title_prefix": "[MDR]",
        "comment_prefix_mdr": "[MDR]",
        "comment_prefix_iris": "[IRIS]",
        "max_comments_per_cycle": 100,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _env_override(cfg: Dict[str, Any]) -> None:
    """Apply a handful of environment overrides (secrets stay out of files)."""
    env_map = {
        "MDR_API_URL": ("mdr", "api_url"),
        "MDR_CLIENT_ID": ("mdr", "client_id"),
        "MDR_REFRESH_TOKEN": ("mdr", "refresh_token"),
        "IRIS_API_URL": ("iris", "api_url"),
        "IRIS_API_KEY": ("iris", "api_key"),
        "SYNC_PROXY_URL": ("proxy", "url"),
    }

    if os.getenv("SYNC_PROXY_URL"):
        cfg["proxy"]["enabled"] = True
    for env_name, (section, key) in env_map.items():
        value = os.getenv(env_name)
        if value:
            cfg[section][key] = value

    interval = os.getenv("SYNC_INTERVAL_SECONDS")
    if interval:
        cfg["interval_seconds"] = int(interval)

    proxy_url = os.getenv("MDR_PROXY_URL")
    if proxy_url:
        cfg["mdr"]["proxy"] = {"enabled": True, "url": proxy_url}
    proxy_url = os.getenv("IRIS_PROXY_URL")
    if proxy_url:
        cfg["iris"]["proxy"] = {"enabled": True, "url": proxy_url}


def _absolutize(cfg: Dict[str, Any], base_dir: Path) -> None:
    for section, key in (
        ("log", "file"),
        ("state_db", None),
        ("mdr", "tokens_file"),
    ):
        if key is None:
            value = cfg.get(section)
            if isinstance(value, str):
                cfg[section] = str((base_dir / value).resolve())
        else:
            value = cfg.get(section, {}).get(key)
            if isinstance(value, str):
                cfg[section][key] = str((base_dir / value).resolve())


def load_config(path: str | os.PathLike[str]) -> Dict[str, Any]:
    config_path = Path(path).expanduser().resolve()
    with config_path.open("r", encoding="utf-8") as fh:
        user_cfg = json.load(fh)

    cfg = _deep_merge(DEFAULTS, user_cfg)
    _env_override(cfg)
    _absolutize(cfg, config_path.parent)
    validate_config(cfg)
    return cfg


def validate_config(cfg: Dict[str, Any]) -> None:
    errors = []

    if not cfg["mdr"].get("client_id"):
        errors.append("mdr.client_id is required")
    if not cfg["mdr"].get("refresh_token"):
        tokens_file = Path(cfg["mdr"]["tokens_file"])
        if not tokens_file.exists():
            errors.append(
                "mdr.refresh_token is empty and no saved token file exists "
                f"({tokens_file})"
            )

    if not cfg["iris"].get("api_url"):
        errors.append("iris.api_url is required")
    if not cfg["iris"].get("api_key"):
        errors.append("iris.api_key is required")

    mode = str(cfg["mapping"].get("mode", "escalate")).lower()
    if mode not in ("escalate", "merge"):
        errors.append("mapping.mode must be 'escalate' or 'merge'")
    if mode == "merge" and not (
        cfg["mapping"].get("merge_target_case_id")
        or cfg["mapping"].get("merge_target_by_tenant")
    ):
        errors.append(
            "mapping.mode=merge requires merge_target_case_id or "
            "merge_target_by_tenant"
        )

    if int(cfg["interval_seconds"]) < 30:
        errors.append("interval_seconds must be >= 30")

    for section in ("mdr", "iris"):
        proxy = cfg[section].get("proxy")
        if isinstance(proxy, dict) and proxy.get("enabled", True):
            proxy_url = proxy.get("url") or proxy.get("http") or proxy.get("https")
            if proxy_url and "://" not in str(proxy_url):
                errors.append(f"{section}.proxy.url must include a scheme, e.g. http://127.0.0.1:10808")

    global_proxy = cfg.get("proxy")
    if isinstance(global_proxy, dict) and global_proxy.get("enabled", True):
        proxy_url = (
            global_proxy.get("url")
            or global_proxy.get("http")
            or global_proxy.get("https")
        )
        if proxy_url and "://" not in str(proxy_url):
            errors.append(
                "proxy.url must include a scheme, e.g. http://127.0.0.1:10808"
            )

    if errors:
        raise ValueError("Invalid configuration:\n - " + "\n - ".join(errors))
