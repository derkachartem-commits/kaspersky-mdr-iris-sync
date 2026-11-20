"""KDP webhook payload -> IRIS alert mapping."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

SOURCE_NAME = "Kaspersky KDP"

OPENING_TYPES = {"attack_start", "anomaly_start", "bgp_down", "ssl_certificate_expires"}
CLOSING_TYPES = {"attack_stop", "attack_short_term", "anomaly_stop"}


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _fmt_gbps(bps: float) -> str:
    return f"{bps / 1e9:.2f} Гбит/с" if bps else "н/д"


def _fmt_pps(pps: float) -> str:
    return f"{pps / 1e6:.2f} Mpps" if pps else "н/д"


def event_identity(payload: Dict[str, Any]) -> Tuple[str, str, str]:
    """Return (event_key, kind, external_id)."""
    msg = str(payload.get("msg_type") or "unknown")

    if msg.startswith("attack"):
        attack_id = str(payload.get("attack_id") or "unknown")
        return f"attack:{attack_id}", "attack", attack_id
    if msg.startswith("anomaly"):
        anomaly_id = str(payload.get("anomaly_id") or "unknown")
        return f"anomaly:{anomaly_id}", "anomaly", anomaly_id
    if msg == "bgp_down":
        peer = str(payload.get("peer_ip") or "unknown")
        ts = str(payload.get("timestamp") or "")
        return f"bgp:{peer}:{ts}", "bgp", peer
    if msg == "ssl_certificate_expires":
        subject = str(payload.get("certificate_subject") or "unknown")
        resource = str(payload.get("kdp_resource") or "")
        return f"cert:{resource}:{subject}", "certificate", subject
    return f"other:{msg}:{payload.get('timestamp')}", "other", msg


def severity_for(payload: Dict[str, Any], thresholds: Dict[str, Any]) -> str:
    msg = str(payload.get("msg_type") or "")
    if msg.startswith("attack"):
        bps = _num((payload.get("max_point_values") or {}).get("bps"))
        if bps >= _num(thresholds.get("attack_critical_bps", 5e9)):
            return "critical"
        if bps >= _num(thresholds.get("attack_high_bps", 1e9)):
            return "high"
        return "medium"
    if msg.startswith("anomaly"):
        excess = _num(payload.get("excess_percentage"))
        if excess >= _num(thresholds.get("anomaly_medium_excess_percent", 50)):
            return "medium"
        return "low"
    if msg == "bgp_down":
        return "high"
    if msg == "ssl_certificate_expires":
        return "medium"
    return "low"


def _context_lines(payload: Dict[str, Any]) -> list[str]:
    msg = str(payload.get("msg_type") or "")
    lines = [
        f"KDP msg_type: {msg}",
        f"Ресурс: {payload.get('resource_name')} (id={payload.get('resource_id')})",
        f"Группа: {payload.get('group_name')} (id={payload.get('group_id')})",
    ]
    if msg.startswith("attack"):
        mp = payload.get("max_point_values") or {}
        lines += [
            f"Тип атаки: {payload.get('attack_type')}",
            f"Начало: {payload.get('start_time')}",
            f"Конец: {payload.get('end_time') or '—'}",
            f"Пик: {_fmt_gbps(_num(mp.get('bps')))}, {_fmt_pps(_num(mp.get('pps')))}, "
            f"{_num(mp.get('rps')):.0f} rps",
            f"Атакованные IP: {', '.join(payload.get('attacked_ips') or []) or '—'}",
        ]
    elif msg.startswith("anomaly"):
        lines += [
            f"Параметр: {payload.get('check_name')}",
            f"Значение: {payload.get('max_value')} {payload.get('check_measurement') or ''}".strip(),
            f"Порог: {payload.get('threshold')}",
            f"Превышение: {payload.get('excess_percentage')} %",
            f"Метка времени: {payload.get('timestamp')}",
        ]
    elif msg == "bgp_down":
        lines += [f"Peer IP: {payload.get('peer_ip')}", f"Метка времени: {payload.get('timestamp')}"]
    elif msg == "ssl_certificate_expires":
        lines += [
            f"Сертификат: {payload.get('certificate_subject')}",
            f"Издатель: {payload.get('certificate_issuer')}",
            f"Действует до: {payload.get('valid_not_after')}",
            f"Ресурс: {payload.get('kdp_resource')}",
        ]
    else:
        lines += [f"Необработанный payload: {json.dumps(payload, ensure_ascii=False)[:1500]}"]
    return lines


def kdp_reference(payload: Dict[str, Any], kind: str, external_id: str) -> str:
    """Human reference to the KDP entity: the ID shown in the KDP cabinet."""
    if kind == "anomaly":
        anomaly_group_id = payload.get("resource_id") or external_id
        return f"KDP: аномалия ID {anomaly_group_id}"
    if kind == "attack":
        return f"KDP: атака ID {external_id}"
    if kind == "bgp":
        return f"KDP: BGP peer {payload.get('peer_ip')}"
    if kind == "certificate":
        return f"KDP: сертификат {payload.get('kdp_resource')}"
    return f"KDP: событие {external_id}"


def _kdp_link(payload: Dict[str, Any], config: Dict[str, Any], kind: str, external_id: str) -> str:
    """Deep link to the event in the KDP cabinet (portal.kdp.global)."""
    portal = str((config.get("kdp") or {}).get("portal_url") or "https://portal.kdp.global").rstrip("/")
    if kind == "attack" and external_id and external_id != "unknown":
        return f"{portal}/attacks/{external_id}"
    if kind == "anomaly":
        group_id = payload.get("group_id")
        resource_id = payload.get("resource_id")
        if group_id and resource_id:
            return f"{portal}/resources/{group_id}/{resource_id}"
        return f"{portal}/anomalies"
    if kind == "bgp":
        return f"{portal}/information"
    if kind == "certificate":
        return f"{portal}/tls"
    return portal


def build_alert(
    payload: Dict[str, Any],
    *,
    config: Dict[str, Any],
    event_key: str,
    kind: str,
    external_id: str,
) -> Dict[str, Any]:
    iris_cfg = config["iris"]
    severity_name = severity_for(payload, config.get("thresholds") or {})
    severity_id = int((iris_cfg.get("severity_ids") or {}).get(severity_name, 1))

    if kind == "attack":
        title = (
            f"[KDP] Атака — {payload.get('resource_name')} "
            f"({payload.get('attack_type')})"
        )
    elif kind == "anomaly":
        anomaly_id = payload.get("resource_id") or external_id
        title = (
            f"[KDP] Аномалия #{anomaly_id} — {payload.get('resource_name')} "
            f"({payload.get('check_name')})"
        )
    elif kind == "bgp":
        title = f"[KDP] BGP down — {payload.get('peer_ip')}"
    elif kind == "certificate":
        title = f"[KDP] Сертификат истекает — {payload.get('kdp_resource')}"
    else:
        title = f"[KDP] Событие {payload.get('msg_type')}"

    tags = ["kdp", f"kdp:{kind}", f"kdp-id:{kind}:{external_id}"]
    if payload.get("resource_name"):
        tags.append(f"svc:{payload['resource_name']}")

    return {
        "alert_title": title[:200],
        "alert_description": (
            "\n".join(_context_lines(payload))
            + "\n"
            + kdp_reference(payload, kind, external_id)
        )[:4000],
        "alert_source": SOURCE_NAME,
        "alert_source_ref": event_key,
        "alert_source_event_time": str(
            payload.get("start_time") or payload.get("timestamp") or ""
        ),
        "alert_severity_id": severity_id,
        "alert_status_id": int(iris_cfg.get("alert_status_new", 1)),
        "alert_owner_id": None,
        "alert_customer_id": int(iris_cfg.get("customer_id", 1)),
        "alert_tags": ",".join(tags),
    }


def close_comment(payload: Dict[str, Any], severity_name: Optional[str] = None) -> str:
    msg = str(payload.get("msg_type") or "")
    parts = [f"KDP: событие завершено ({msg})."]
    if payload.get("start_time") or payload.get("end_time"):
        parts.append(f"Начало: {payload.get('start_time')}; конец: {payload.get('end_time')}.")
    if msg.startswith("attack"):
        mp = payload.get("max_point_values") or {}
        parts.append(
            f"Пик: {_fmt_gbps(_num(mp.get('bps')))}, {_fmt_pps(_num(mp.get('pps')))}."
        )
    parts.append("Кейс не создавался: эскалация ручная.")
    return " ".join(parts)


def build_case_payload(
    payload: Dict[str, Any],
    *,
    config: Dict[str, Any],
    kind: str,
    external_id: str,
) -> Dict[str, Any]:
    """Payload for an automatic escalation of a KDP alert into a case."""
    auto = config.get("auto_escalate") or {}
    iris_cfg = config["iris"]
    resource = payload.get("resource_name") or payload.get("kdp_resource") or "unknown"

    if kind == "attack":
        title = f"[KDP] Атака — {resource} ({payload.get('attack_type')})"
        template_id = auto.get("attack_template_id")
    elif kind == "anomaly":
        anomaly_id = payload.get("resource_id") or external_id
        title = f"[KDP] Аномалия #{anomaly_id} — {resource} ({payload.get('check_name')})"
        template_id = auto.get("anomaly_template_id")
    else:
        title = f"[KDP] {kind} — {resource}"
        template_id = auto.get("default_template_id")

    start = str(payload.get("start_time") or payload.get("timestamp") or "")
    description = (
        "Автоматически создан из алерта KDP "
        f"(`{kind}:{external_id}`). {kdp_reference(payload, kind, external_id)}"
    )
    if start:
        description += f" Начало: {start}."

    body: Dict[str, Any] = {
        "case_title": title[:190],
        "case_description": description,
        "case_soc_id": f"KDP-{external_id}",
        "case_customer_id": int(iris_cfg.get("customer_id", 1)),
        "case_tags": f"kdp,{kind}",
    }
    if template_id:
        body["case_template_id"] = int(template_id)
    return body


def case_dates(payload: Dict[str, Any]) -> Dict[str, str]:
    """IRIS case date fields (YYYY-MM-DD) from the event timestamps."""
    out: Dict[str, str] = {}
    start = str(payload.get("start_time") or payload.get("timestamp") or "")
    end = str(payload.get("end_time") or "")
    if len(start) >= 10:
        out["open_date"] = start[:10]
    if len(end) >= 10:
        out["close_date"] = end[:10]
    return out


def status_id_for(payload: Dict[str, Any], config: Dict[str, Any]) -> Optional[int]:
    """Map a KDP event status ("active", "finished", ...) to an IRIS alert status."""
    raw = str(payload.get("_status") or "").strip().lower()
    if not raw:
        return None
    mapping = (config.get("kdp") or {}).get("status_map") or {}
    value = mapping.get(raw)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


CLOSED_STATUS_VALUES = {"finished", "closed", "ended", "stopped", "resolved"}


def is_closed_status(payload: Dict[str, Any]) -> bool:
    return str(payload.get("_status") or "").strip().lower() in CLOSED_STATUS_VALUES
