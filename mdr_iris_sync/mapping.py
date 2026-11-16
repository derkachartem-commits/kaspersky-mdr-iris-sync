"""Mapping between Kaspersky MDR incidents and DFIR-IRIS alerts/cases."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


def normalize(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def epoch_ms_to_iso(value: Any) -> Optional[str]:
    """Convert epoch milliseconds to an ISO-8601 UTC string."""
    milliseconds = as_int(value)
    if milliseconds is None:
        return None
    try:
        dt = datetime.fromtimestamp(milliseconds / 1000.0, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def priority_to_severity(priority: Any) -> int:
    mapping = {
        "low": 2,
        "normal": 3,
        "medium": 3,
        "high": 4,
        "critical": 5,
        "": 3,
    }
    return mapping.get(normalize(priority), 3)


def status_to_alert_status(status: Any, mapping: Dict[str, int], default: int) -> int:
    return int(mapping.get(normalize(status), default))


def fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", (text or "").strip()).casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def truncate(text: str, limit: int) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _dedupe(values: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        value = (value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def affected_hosts(incident: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return a normalized list of ``{"name": ..., "host_id": ...}``."""
    hosts: List[Dict[str, str]] = []

    mappings = incident.get("affected_hosts_mappings")
    mapped_ids = set()
    mapped_names = set()
    if isinstance(mappings, list):
        for item in mappings:
            if isinstance(item, dict):
                name = item.get("host_name") or item.get("name") or item.get("host_id")
                if name:
                    hosts.append(
                        {
                            "name": str(name),
                            "host_id": str(item.get("host_id") or ""),
                        }
                    )
                    mapped_names.add(str(name).lower())
                    if item.get("host_id"):
                        mapped_ids.add(str(item.get("host_id")))
            elif item:
                hosts.append({"name": str(item), "host_id": ""})
                mapped_names.add(str(item).lower())

    raw_hosts = incident.get("affected_hosts")
    if isinstance(raw_hosts, list):
        for item in raw_hosts:
            if isinstance(item, dict):
                name = item.get("host_name") or item.get("name")
                host_id = str(item.get("host_id") or "")
                if name and str(name).lower() not in mapped_names and host_id not in mapped_ids:
                    hosts.append({"name": str(name), "host_id": host_id})
            elif item:
                raw_name = str(item)
                name_part, _, id_part = raw_name.partition(":")
                if id_part and (id_part in mapped_ids or name_part.lower() in mapped_names):
                    continue
                if not id_part and raw_name.lower() in mapped_names:
                    continue
                hosts.append({"name": raw_name, "host_id": ""})

    deduped: List[Dict[str, str]] = []
    seen = set()
    for host in hosts:
        if host["name"] in seen:
            continue
        seen.add(host["name"])
        deduped.append(host)
    return deduped


def extract_iocs(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collect and deduplicate MDR IOCs from all supported fields."""
    raw: List[Dict[str, Any]] = []
    for key in ("iocs", "host_based_iocs", "network_based_iocs"):
        value = incident.get(key)
        if isinstance(value, list):
            raw.extend(item for item in value if isinstance(item, dict))

    result: List[Dict[str, Any]] = []
    seen = set()
    for ioc in raw:
        value = str(ioc.get("data") or ioc.get("value") or ioc.get("ioc") or "").strip()
        if not value:
            continue
        key = (value.lower(), normalize(ioc.get("type")))
        if key in seen:
            continue
        seen.add(key)
        result.append(ioc)
    return result


def ioc_type_id(ioc: Dict[str, Any]) -> int:
    """Map an MDR IOC type/value to an IRIS ioc_type id."""
    ioc_type = normalize(ioc.get("type"))
    value = str(ioc.get("data") or ioc.get("value") or "").strip().lower()
    if ioc_type in ("hash", "filehash", "file_hash"):
        digest = value[2:] if value.startswith("0x") else value
        return {32: 90, 40: 111, 64: 113}.get(len(digest), 96)  # md5, sha1, sha256, other
    return {
        "ip": 76,
        "ipv4": 76,
        "ipv6": 76,
        "ip-any": 76,
        "domain": 20,
        "hostname": 69,
        "url": 141,
        "uri": 140,
        "filename": 37,
        "file": 37,
        "file-path": 97,
        "file_path": 97,
        "path": 97,
        "email": 22,
        "md5": 90,
        "sha1": 111,
        "sha256": 113,
        "regkey": 109,
        "mutex": 94,
    }.get(ioc_type, 96)


def build_alert_payload(incident: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    mapping_cfg = cfg["mapping"]
    iris_cfg = cfg["iris"]

    incident_id = str(incident.get("incident_id") or "")
    incident_number = str(incident.get("incident_number") or incident_id)
    summary = (
        incident.get("summary")
        or incident.get("title")
        or incident.get("name")
        or f"MDR incident {incident_number}"
    )
    description = incident.get("description") or ""

    severity_map = mapping_cfg.get("severity", {})
    severity_id = int(
        severity_map.get(
            str(incident.get("priority") or "").upper(),
            severity_map.get("", mapping_cfg.get("default_severity_id", 3)),
        )
    )

    status_map = mapping_cfg.get("status_to_iris", {})
    status_id = status_to_alert_status(
        incident.get("status"),
        status_map,
        int(mapping_cfg.get("default_alert_status_id", iris_cfg.get("alert_status_id", 1))),
    )

    hosts = affected_hosts(incident)
    iocs = extract_iocs(incident)
    tags = list(mapping_cfg.get("tags", []))
    priority = incident.get("priority")
    if priority:
        tags.append(str(priority))
    for tactic in incident.get("mitre_tactics") or []:
        if tactic:
            tags.append(str(tactic))
    tags = [tag.replace(",", " ") for tag in _dedupe(tags)]

    lines = [
        f"**MDR incident:** #{incident_number} (`{incident_id}`)",
        f"**Priority:** {incident.get('priority') or 'unknown'}",
        f"**Status:** {incident.get('status') or 'unknown'}",
    ]
    if incident.get("tenant_name"):
        lines.append(f"**Tenant:** {incident['tenant_name']}")
    if incident.get("detection_technology"):
        lines.append(f"**Detection technology:** {incident['detection_technology']}")
    if incident.get("attack_stage"):
        lines.append(f"**Attack stage:** {incident['attack_stage']}")
    if hosts:
        lines.append(
            "**Affected hosts:** "
            + ", ".join(f"`{host['name']}`" for host in hosts)
        )
    if iocs:
        lines.append(f"**IOCs:** {len(iocs)}")
    tactics = incident.get("mitre_tactics") or []
    techniques = incident.get("mitre_techniques") or []
    if tactics:
        lines.append("**MITRE tactics:** " + ", ".join(str(item) for item in tactics))
    if techniques:
        lines.append(
            "**MITRE techniques:** " + ", ".join(str(item) for item in techniques)
        )
    if incident.get("recommendations"):
        lines.extend(["", "**Recommendations:**", str(incident["recommendations"])])
    source_link = ""
    template = mapping_cfg.get("source_link_template") or ""
    if template:
        source_link = template.format(
            incident_id=incident_id, incident_number=incident_number
        )
        lines.append(f"**MDR console:** {source_link}")

    if description:
        lines.extend(["", "---", "", description])

    payload: Dict[str, Any] = {
        "alert_title": truncate(
            f"{mapping_cfg.get('title_prefix', '[MDR]')} #{incident_number} {summary}",
            200,
        ),
        "alert_description": "\n".join(lines),
        "alert_source": mapping_cfg.get("source_name", "Kaspersky MDR"),
        "alert_source_ref": incident_id,
        "alert_severity_id": severity_id,
        "alert_status_id": status_id,
        "alert_customer_id": int(iris_cfg["customer_id"]),
        "alert_classification_id": int(iris_cfg["classification_id"]),
        "alert_tags": ",".join(tags),
    }
    if source_link:
        payload["alert_source_link"] = source_link

    recommendations = incident.get("recommendations")
    if recommendations:
        payload["alert_note"] = truncate(str(recommendations), 4000)

    event_time = epoch_ms_to_iso(incident.get("creation_time"))
    if event_time:
        payload["alert_source_event_time"] = event_time

    if hosts:
        asset_type_id = iris_cfg.get("asset_type_id")
        assets = []
        for host in hosts:
            asset: Dict[str, Any] = {
                "asset_name": host["name"],
                "asset_description": (
                    f"Kaspersky MDR host_id: {host['host_id']}"
                    if host["host_id"]
                    else "Kaspersky MDR affected host"
                ),
            }
            if asset_type_id is not None:
                asset["asset_type_id"] = int(asset_type_id)
            assets.append(asset)
        payload["alert_assets"] = assets

    if iocs:
        payload["alert_iocs"] = [
            {
                "ioc_value": str(ioc.get("data") or ioc.get("value") or ""),
                "ioc_description": str(
                    ioc.get("message") or ioc.get("description") or "Kaspersky MDR IOC"
                ),
                "ioc_type_id": ioc_type_id(ioc),
                "ioc_tags": "MDR",
            }
            for ioc in iocs
        ]

    if iris_cfg.get("send_context", True):
        payload["alert_context"] = {
            "mdr": {
                "incident_id": incident_id,
                "incident_number": incident_number,
                "priority": incident.get("priority"),
                "status": incident.get("status"),
                "tenant_name": incident.get("tenant_name"),
                "detection_technology": incident.get("detection_technology"),
                "attack_stage": incident.get("attack_stage"),
                "ioc_count": len(iocs),
                "asset_count": len(hosts),
                "creation_time": incident.get("creation_time"),
                "update_time": incident.get("update_time"),
            }
        }

    return payload


def build_escalation_payload(incident: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    mapping_cfg = cfg["mapping"]
    incident_id = str(incident.get("incident_id") or "")
    incident_number = str(incident.get("incident_number") or incident_id)
    summary = (
        incident.get("summary")
        or incident.get("title")
        or f"Kaspersky MDR incident {incident_number}"
    )
    tags = ",".join(
        tag.replace(",", " ") for tag in mapping_cfg.get("tags", ["MDR", "Kaspersky"])
    )
    return {
        "case_title": truncate(f"{mapping_cfg.get('title_prefix', '[MDR]')} #{incident_number} {summary}", 190),
        "case_tags": tags,
        "note": (
            f"Automatically escalated from Kaspersky MDR incident #{incident_number} "
            f"(`{incident_id}`)."
        ),
        "import_as_event": True,
        "iocs_import_list": [],
        "assets_import_list": [],
    }


def build_merge_payload(incident: Dict[str, Any], target_case_id: int) -> Dict[str, Any]:
    incident_id = str(incident.get("incident_id") or "")
    incident_number = str(incident.get("incident_number") or incident_id)
    return {
        "target_case_id": int(target_case_id),
        "note": (
            f"Automatically merged from Kaspersky MDR incident #{incident_number} "
            f"(`{incident_id}`)."
        ),
        "import_as_event": True,
        "iocs_import_list": [],
        "assets_import_list": [],
    }


# ---------------------------------------------------------------- comments
def comment_id(comment: Dict[str, Any]) -> Optional[str]:
    for key in ("comment_id", "id", "commentId"):
        value = comment.get(key)
        if value is not None:
            return str(value)
    return None


def comment_text(comment: Dict[str, Any]) -> str:
    for key in ("text", "comment_text", "comment", "comment_content", "content"):
        value = comment.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def comment_author(comment: Dict[str, Any]) -> str:
    for key in (
        "author_name",
        "comment_author",
        "author",
        "user_name",
        "username",
        "created_by",
    ):
        value = comment.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def comment_created(comment: Dict[str, Any]) -> str:
    for key in ("creation_time", "comment_date", "created_at", "date", "timestamp"):
        value = comment.get(key)
        if value is None:
            continue
        if isinstance(value, (int, float)):
            seconds = value / 1000.0 if value > 10_000_000_000 else value
            try:
                return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
            except (OverflowError, OSError, ValueError):
                return str(value)
        return str(value)
    return ""


def format_comment(
    prefix: str, author: str, created: str, text: str
) -> str:
    header = f"**{prefix} {author}**"
    if created:
        header += f" — {created}"
    return f"{header}\n\n{text}"


def status_name_from_case(case: Dict[str, Any]) -> str:
    for key in ("status_name", "case_status", "status"):
        value = case.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("state", "status"):
        nested = case.get(key)
        if isinstance(nested, dict):
            for nested_key in ("state_name", "status_name", "name"):
                value = nested.get(nested_key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def case_status_id(case: Dict[str, Any]) -> Optional[int]:
    """Case status id for both IRIS v2 (status_id) and v3 (state_id)."""
    for key in ("state_id", "status_id", "case_status_id"):
        value = as_int(case.get(key))
        if value is not None:
            return value
    for key in ("state", "status"):
        nested = case.get(key)
        if isinstance(nested, dict):
            for nested_key in ("state_id", "status_id", "id"):
                value = as_int(nested.get(nested_key))
                if value is not None:
                    return value
    return None


def case_is_closed(case: Dict[str, Any], closed_status_id: Optional[int]) -> bool:
    """Works with IRIS v2 (status_id/close date) and v3 (state_id/close_date)."""
    status_id = case_status_id(case)
    if closed_status_id is not None and status_id == int(closed_status_id):
        return True
    for key in ("close_date", "case_close_date"):
        if case.get(key):
            return True
    return normalize(status_name_from_case(case)) in ("closed", "resolved")
