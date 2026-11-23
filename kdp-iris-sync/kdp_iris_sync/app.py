"""KDP -> DFIR-IRIS connector: API poller, outbox worker, active dashboard."""

from __future__ import annotations

import html
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from .iris_client import (
    IrisApiError,
    IrisClient,
    alert_id_from_response,
    case_id_from_response,
)
from .mapping import (
    CLOSING_TYPES,
    build_alert,
    build_case_payload,
    case_dates,
    close_comment,
    kdp_reference,
    event_identity,
    severity_for,
    status_id_for,
)
from .pull import KdpPuller
from .state import State, utcnow
from .token_refresh import TokenRefresher

LOG = logging.getLogger("kdp")
CONFIG_PATH = os.environ.get("KDP_CONFIG", "config.json")


def load_config(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


CONFIG = load_config(CONFIG_PATH)
STATE = State(CONFIG.get("state_db", "state/kdp.db"))
IRIS = IrisClient(
    api_url=CONFIG["iris"]["api_url"],
    api_key=CONFIG["iris"]["api_key"],
    verify=CONFIG["iris"].get("verify", False),
)


def setup_logging() -> None:
    log_cfg = CONFIG.get("log") or {}
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_cfg.get("file"):
        Path(log_cfg["file"]).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_cfg["file"], encoding="utf-8"))
    logging.basicConfig(
        level=getattr(logging, str(log_cfg.get("level", "INFO")).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
    )


# --------------------------------------------------------------- grouping
GROUP_PREFIX = "kdp_group:"


def _group_key(resource: str) -> str:
    return GROUP_PREFIX + resource


def _group_window_seconds() -> int:
    return int((CONFIG.get("dedupe") or {}).get("anomaly_group_minutes", 30)) * 60


def _remember_group(payload: Dict[str, Any], alert_id: int, case_id: Optional[int]) -> None:
    resource = str(payload.get("resource_name") or "")
    if not resource:
        return
    STATE.set_meta(
        _group_key(resource),
        json.dumps(
            {
                "alert_id": int(alert_id),
                "case_id": int(case_id) if case_id else None,
                "last_seen": utcnow(),
            }
        ),
    )


def _metric_note(payload: Dict[str, Any]) -> str:
    parts = ["KDP: новая метрика по тому же ресурсу."]
    parts.append(
        f"Значение: {payload.get('max_value')}, порог: {payload.get('threshold')}."
    )
    if payload.get("timestamp"):
        parts.append(f"Время: {payload.get('timestamp')}.")
    return " ".join(parts)


def _alert_is_closed(alert_id: int) -> bool:
    try:
        alert = IRIS.get_alert(alert_id)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("cannot read alert %s: %s", alert_id, exc)
        return False
    closed_id = int(CONFIG["iris"].get("alert_status_closed", 6))
    return alert.get("alert_status_id") == closed_id


def _try_group_anomaly(
    payload: Dict[str, Any], key: str, kind: str, external_id: str
) -> bool:
    """Attach a fresh anomaly to the open case/alert of the same resource."""
    window = _group_window_seconds()
    if window <= 0:
        return False
    resource = str(payload.get("resource_name") or "")
    raw = STATE.get_meta(_group_key(resource)) if resource else ""
    if not raw:
        return False
    try:
        group = json.loads(raw)
        last_seen = datetime.fromisoformat(str(group.get("last_seen") or ""))
    except (ValueError, TypeError):
        return False
    if (datetime.now(timezone.utc) - last_seen).total_seconds() > window:
        return False
    alert_id = int(group.get("alert_id") or 0)
    if not alert_id:
        return False
    if _alert_is_closed(alert_id):
        LOG.info(
            "group alert %s is closed - creating a new alert for %s", alert_id, resource
        )
        STATE.set_meta(_group_key(resource), "")
        return False
    case_id = group.get("case_id")

    STATE.open_event(key, kind, external_id, resource, payload)
    STATE.set_alert_id(key, alert_id)
    if case_id:
        STATE.set_case_id(key, int(case_id))

    note = _metric_note(payload)
    try:
        IRIS.add_comment("alerts", alert_id, note)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("cannot comment grouped alert %s: %s", alert_id, exc)
    if case_id:
        try:
            IRIS.append_case_description(int(case_id), note)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("cannot append to case %s: %s", case_id, exc)

    _remember_group(payload, alert_id, case_id)
    LOG.info("anomaly %s grouped into alert %s (resource=%s)", key, alert_id, resource)
    return True


# --------------------------------------------------------------- processing
def _create_alert(payload: Dict[str, Any], key: str, kind: str, external_id: str) -> Optional[int]:
    body = build_alert(
        payload, config=CONFIG, event_key=key, kind=kind, external_id=external_id
    )
    data = IRIS.add_alert(body)
    alert_id = alert_id_from_response(data)
    if alert_id is None:
        raise IrisApiError(f"IRIS не вернул alert_id: {data!r}")
    STATE.set_alert_id(key, alert_id)
    LOG.info("alert created: kdp=%s iris_alert=%s", key, alert_id)
    try:
        IRIS.add_comment("alerts", alert_id, kdp_reference(payload, kind, external_id))
    except Exception as exc:  # noqa: BLE001 - comment is informational
        LOG.warning("cannot add KDP reference comment to alert %s: %s", alert_id, exc)
    case_id = _maybe_escalate(payload, key, kind, external_id, alert_id)
    if kind == "anomaly":
        _remember_group(payload, alert_id, case_id)
    return alert_id


def _maybe_escalate(
    payload: Dict[str, Any],
    key: str,
    kind: str,
    external_id: str,
    alert_id: int,
) -> Optional[int]:
    """Create a case for a freshly created alert (auto-escalation)."""
    auto = CONFIG.get("auto_escalate") or {}
    if not auto.get("enabled"):
        return None
    try:
        body = build_case_payload(
            payload, config=CONFIG, kind=kind, external_id=external_id
        )
        data = IRIS.escalate_alert(alert_id, body)
        case_id = case_id_from_response(data)
        if case_id is None:
            LOG.warning("escalation returned no case_id for alert %s: %r", alert_id, data)
            return None
        STATE.set_case_id(key, int(case_id))
        dates = case_dates(payload)
        if dates.get("open_date"):
            try:
                IRIS.update_case(int(case_id), {"open_date": dates["open_date"]})
            except Exception as exc:  # noqa: BLE001
                LOG.warning("cannot set open_date on case %s: %s", case_id, exc)
        start = str(payload.get("start_time") or payload.get("timestamp") or "")
        if start:
            try:
                IRIS.append_case_description(int(case_id), f"Начало: {start}")
            except Exception as exc:  # noqa: BLE001
                LOG.warning("cannot append start time to case %s: %s", case_id, exc)
        LOG.info("alert %s escalated to case %s", alert_id, case_id)
        return int(case_id)
    except Exception as exc:  # noqa: BLE001 - escalation must not drop the alert
        LOG.error("auto-escalation failed for alert %s: %s", alert_id, exc)
        return None



_VOL_LAST: Dict[int, float] = {}


def _kdp_volume_bytes(resource_id, start, end):
    """Bytes moved by the resource between start and end (bps series)."""
    kdp = CONFIG.get("kdp") or {}
    base = str(kdp.get("api_url") or "").rstrip("/")
    token = kdp.get("token")
    if not base or not token or not resource_id or not start or not end:
        return None
    try:
        resp = requests.post(
            base + "/unit_checks/values/",
            json={"filter": {"check_ids": [1011], "date_from": start, "date_to": end,
                             "points_count": 480, "resource_id": int(resource_id)}},
            headers={"Authorization": f"Bearer {token}"},
            verify=kdp.get("verify", True),
            timeout=30,
        )
        if resp.status_code != 200:
            return None
        series = []
        for value in (resp.json() or {}).values():
            series = (value or {}).get("dirty") or (value or {}).get("values") or []
            if series:
                break
        total = 0.0
        prev = None
        for ts, val in series:
            if val is None:
                continue
            moment = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if prev is not None:
                seconds = (moment - prev[0]).total_seconds()
                if 0 < seconds <= 300:
                    total += (prev[1] + float(val)) / 2.0 * seconds
            prev = (moment, float(val))
        return (total / 8.0) if total else None
    except Exception as exc:  # noqa: BLE001
        LOG.warning("cannot compute volume for %s: %s", resource_id, exc)
        return None


def refresh_case_volumes() -> None:
    """Keep the traffic volume line in open KDP cases up to date (5 min throttle)."""
    now = datetime.now(timezone.utc)
    for row in STATE.list_events("open", limit=200):
        if not row["case_id"] or row["kind"] not in ("anomaly", "attack"):
            continue
        case_id = int(row["case_id"])
        if now.timestamp() - _VOL_LAST.get(case_id, 0) < 300:
            continue
        try:
            details = json.loads(row["details"] or "{}")
        except ValueError:
            continue
        rid = details.get("resource_id")
        start = details.get("start_time") or details.get("timestamp")
        if not rid or not start:
            continue
        size = _kdp_volume_bytes(rid, start, now.strftime("%Y-%m-%dT%H:%M:%SZ"))
        if not size:
            continue
        _VOL_LAST[case_id] = now.timestamp()
        line = "Объём трафика за период: %.2f ГБ (%.0f МБ), обновлено %s МСК" % (
            size / 1e9, size / 1e6, now.astimezone().strftime("%H:%M"))
        try:
            case = IRIS.get_case(case_id)
            desc = str(case.get("case_description") or "")
            cleaned = re.sub(r"Объём трафика за период:[^\n]*\n?", "", desc).rstrip()
            if line in cleaned:
                continue
            IRIS.update_case(case_id, {"case_description": (cleaned + "\n\n" + line)[:8000]})
        except Exception as exc:  # noqa: BLE001
            LOG.warning("cannot update case %s volume: %s", case_id, exc)

def _auto_close_reason(
    alert_id: int,
    *,
    kind: str = "событие",
    resource: str = "",
    start: str = "",
    end: str = "",
    why: str = "",
    volume_bytes: int = 0,
) -> str:
    """Human readable justification stored on the case when it is auto-closed."""
    lines = [f"Кейс закрыт автоматически коннектором KDP: {kind} {why or 'завершилась'}."]
    if resource:
        lines.append(f"Ресурс: {resource}")
    if start:
        lines.append(f"Начало: {start}")
    if end:
        lines.append(f"Конец: {end}")
    if volume_bytes:
        lines.append("Объём за период: %.2f ГБ (%.0f МБ)" % (volume_bytes / 1e9, volume_bytes / 1e6))
    lines.append(f"IRIS alert: #{alert_id}")
    lines.append(f"Закрыто: {utcnow()} (kdp-iris-sync)")
    return "\n".join(lines)


def _case_volume_line(case_id: int, end_iso: Optional[str] = None) -> str:
    """Final traffic volume for a case, derived from its description."""
    try:
        case = IRIS.get_case(int(case_id))
    except Exception:  # noqa: BLE001
        return ""
    desc = str(case.get("case_description") or "")
    m = re.search(r"Ресурс: .*?\(id=(\d+)\)", desc)
    s = re.search(r"Начало:\s*([0-9T:.+\-Z]+)", desc)
    if not m or not s:
        return ""
    size = _kdp_volume_bytes(int(m.group(1)), s.group(1), end_iso or utcnow())
    if not size:
        return ""
    return "Объём за период: %.2f ГБ (%.0f МБ)" % (size / 1e9, size / 1e6)

def _close_case_with_reason(case_id: int, state_id: int, reason: str) -> None:
    """Close a case and leave the reason both as a note and as closing_note."""
    if "Объём за период" not in reason:
        volume = _case_volume_line(case_id)
        if volume:
            reason = reason + "\n" + volume
    try:
        IRIS.add_case_note(case_id, "KDP: кейс закрыт автоматически", reason)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("cannot add close note to case %s: %s", case_id, exc)
        try:
            IRIS.append_case_description(case_id, reason)
        except Exception as exc2:  # noqa: BLE001
            LOG.warning("cannot append close text to case %s: %s", case_id, exc2)
    try:
        IRIS.close_case(case_id, state_id, resolution_note=reason)
        LOG.info("case %s closed (state=%s) with closing note", case_id, state_id)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("cannot close case %s: %s", case_id, exc)
        try:
            IRIS.update_case_state(case_id, state_id)
        except Exception as exc2:  # noqa: BLE001
            LOG.warning("cannot update state of case %s: %s", case_id, exc2)


def _close_alert(payload: Dict[str, Any], key: str, kind: str, external_id: str) -> None:
    if not (CONFIG.get("auto_close") or {}).get("enabled", True):
        LOG.info("auto_close disabled; skip close for %s", key)
        return

    row = STATE.get_event(key)
    alert_id = int(row["alert_id"]) if row and row["alert_id"] else None
    if alert_id is None:
        # Событие пришло только завершением: фиксируем как уже закрытое.
        alert_id = _create_alert(payload, key, kind, external_id)
        if alert_id is None:
            return

    closeable = (CONFIG.get("auto_close") or {}).get(
        "closeable_status_ids", [int(CONFIG["iris"].get("alert_status_new", 2)), 8]
    )
    closeable_ids = [int(item) for item in closeable]
    current = IRIS.get_alert(alert_id)
    status = current.get("alert_status_id")
    if status is not None and int(status) not in closeable_ids:
        LOG.info(
            "alert %s status=%s is not closeable (%s) — оставляю как есть",
            alert_id,
            status,
            closeable_ids,
        )
        STATE.close_event(key)
        return

    others = [
        item
        for item in STATE.list_events("open", limit=1000)
        if item["event_key"] != key
        and item["alert_id"]
        and int(item["alert_id"]) == alert_id
    ]
    if others:
        STATE.close_event(key)
        LOG.info(
            "alert %s still has %s open grouped event(s) - keep it open",
            alert_id,
            len(others),
        )
        return

    end_time = str(payload.get("end_time") or payload.get("timestamp") or utcnow())
    IRIS.add_comment("alerts", alert_id, close_comment(payload))
    IRIS.update_alert(
        alert_id, {"alert_status_id": int(CONFIG["iris"].get("alert_status_closed", 2))}
    )
    if row and row["case_id"]:
        case_id = int(row["case_id"])
        reason = _auto_close_reason(
            alert_id,
            kind="аномалия" if kind == "anomaly" else "атака",
            resource=str(payload.get("resource_name") or payload.get("kdp_resource") or ""),
            start=str(payload.get("start_time") or ""),
            end=end_time,
            why="больше не активна в KDP",
            volume_bytes=int(payload.get("volume_bytes") or 0),
        )
        try:
            IRIS.update_case(case_id, case_dates({"end_time": end_time}))
        except Exception as exc:  # noqa: BLE001
            LOG.warning("cannot set close date on case %s: %s", case_id, exc)
        if (CONFIG.get("auto_close") or {}).get("close_case", True):
            closed_state = int((CONFIG.get("auto_close") or {}).get("case_closed_state_id", 9))
            _close_case_with_reason(case_id, closed_state, reason)

    resource_key = str(payload.get("resource_name") or payload.get("kdp_resource") or "")
    if resource_key:
        STATE.set_meta(_group_key(resource_key), "")
    STATE.close_event(key)
    LOG.info("alert closed: kdp=%s iris_alert=%s", key, alert_id)


def process_payload(payload: Dict[str, Any]) -> None:
    key, kind, external_id = event_identity(payload)
    msg = str(payload.get("msg_type") or "")
    resource = str(payload.get("resource_name") or payload.get("kdp_resource") or "")

    if msg in CLOSING_TYPES:
        STATE.touch(key)
        _close_alert(payload, key, kind, external_id)
        return

    row = STATE.get_event(key)
    if row and row["alert_id"] and row["state"] == "open":
        STATE.touch(key)
        status_id = status_id_for(payload, CONFIG)
        if status_id is not None:
            try:
                IRIS.update_alert(int(row["alert_id"]), {"alert_status_id": status_id})
                LOG.info(
                    "alert %s status updated to %s (KDP state=%s)",
                    row["alert_id"],
                    status_id,
                    payload.get("_status"),
                )
            except Exception as exc:  # noqa: BLE001
                LOG.warning("cannot update alert %s status: %s", row["alert_id"], exc)
        LOG.info("duplicate open event ignored: %s", key)
        return

    if kind == "anomaly" and _try_group_anomaly(payload, key, kind, external_id):
        return

    STATE.open_event(key, kind, external_id, resource, payload)
    _create_alert(payload, key, kind, external_id)


def reconcile_groups() -> None:
    """Close alerts whose grouped KDP events are all finished.

    Safety net: a crash or an interrupted close can leave an escalated alert
    (and its case) open after every anomaly behind it has already ended.
    """
    auto = CONFIG.get("auto_close") or {}
    if not auto.get("enabled", True):
        return
    closeable = [int(item) for item in auto.get("closeable_status_ids", [2, 4, 8])]
    closed_status = int(CONFIG["iris"].get("alert_status_closed", 6))
    case_state = int(auto.get("case_closed_state_id", 9))
    open_by_alert = {}
    for row in STATE.list_events("open", limit=1000):
        if row["alert_id"]:
            open_by_alert.setdefault(int(row["alert_id"]), 0)
            open_by_alert[int(row["alert_id"])] += 1
    for meta in STATE.list_meta("kdp_group:"):
        try:
            group = json.loads(meta["value"] or "{}")
        except ValueError:
            continue
        alert_id = int(group.get("alert_id") or 0)
        if not alert_id or open_by_alert.get(alert_id):
            continue
        try:
            alert = IRIS.get_alert(alert_id)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("reconcile: cannot read alert %s: %s", alert_id, exc)
            continue
        status = alert.get("alert_status_id")
        if status is not None and int(status) not in closeable:
            continue
        try:
            IRIS.add_comment("alerts", alert_id, "KDP: аномалия завершена (авто-закрытие)")
            IRIS.update_alert(alert_id, {"alert_status_id": closed_status})
            LOG.info("reconcile: alert %s closed (no open events)", alert_id)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("reconcile: cannot close alert %s: %s", alert_id, exc)
            continue
        case_id = int(group.get("case_id") or 0)
        if case_id and auto.get("close_case", True):
            reason = _auto_close_reason(
                alert_id,
                kind="инцидент",
                why="завершился (в KDP не осталось активных событий, реконсиляция)",
            )
            _close_case_with_reason(case_id, case_state, reason)
        STATE.set_meta(meta["key"], "")


def reconcile_loop(stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            reconcile_groups()
            refresh_case_volumes()
        except Exception as exc:  # noqa: BLE001
            LOG.warning("reconcile failed: %s", exc)
        stop.wait(120)


def worker_loop(stop: threading.Event) -> None:
    delay = 0.5
    while not stop.is_set():
        rows = STATE.pending(limit=10)
        if not rows:
            stop.wait(1.0)
            continue
        for row in rows:
            try:
                payload = json.loads(row["payload"])
                process_payload(payload)
                STATE.mark_done(int(row["id"]))
                delay = 0.5
            except Exception as exc:  # noqa: BLE001 - outbox must survive anything
                attempts = int(row["attempts"]) + 1
                STATE.mark_error(int(row["id"]), f"{type(exc).__name__}: {exc}")
                LOG.warning("outbox %s attempt %s failed: %s", row["id"], attempts, exc)
                time.sleep(min(60.0, delay))
                delay = min(60.0, delay * 2)
                break


# --------------------------------------------------------------------- app
setup_logging()
app = FastAPI(title="KDP -> IRIS connector", docs_url=None, redoc_url=None)
_stop = threading.Event()
_thread = threading.Thread(target=worker_loop, args=(_stop,), daemon=True)
_thread.start()
_puller = KdpPuller(CONFIG, STATE, process_payload, _stop)
_refresher = TokenRefresher(CONFIG, CONFIG_PATH, _puller.update_token, _stop)
_puller.on_auth_error = _refresher.trigger
_puller.start()
_refresher.start()
_reconciler = threading.Thread(target=reconcile_loop, args=(_stop,), daemon=True)
_reconciler.start()


@app.on_event("shutdown")
def _shutdown() -> None:
    _stop.set()


@app.get("/healthz")
def healthz() -> Dict[str, Any]:
    stats = STATE.outbox_stats()
    open_events = STATE.list_events("open", limit=1000)
    pull_enabled = bool((CONFIG.get("kdp") or {}).get("enabled"))
    return {
        "status": "ok",
        "outbox": stats,
        "open_events": len(open_events),
        "iris_api": CONFIG["iris"]["api_url"],
        "pull": {
            "enabled": pull_enabled,
            "last_success": STATE.get_meta("pull_last_success"),
            "last_error": STATE.get_meta("pull_last_error"),
            "last_stats": STATE.get_meta("pull_last_stats"),
        },
    }


@app.get("/api/events")
def api_events(state: str = "open") -> Any:
    rows = STATE.list_events(None if state == "all" else state)
    return [
        {
            "event_key": r["event_key"],
            "kind": r["kind"],
            "resource": r["resource"],
            "alert_id": r["alert_id"],
            "state": r["state"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
        }
        for r in rows
    ]


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    rows = STATE.list_events(None, limit=300)
    body = []
    for r in rows:
        details = json.loads(r["details"] or "{}")
        msg = details.get("msg_type", "")
        extra = ""
        if r["kind"] == "attack":
            mp = details.get("max_point_values") or {}
            bps = mp.get("bps") or 0
            extra = f"{float(bps) / 1e9:.2f} Гбит/с"
        elif r["kind"] == "anomaly":
            extra = f"{details.get('check_name', '')} +{details.get('excess_percentage', '')}%"
        color = {"open": "#c62828", "closed": "#2e7d32"}.get(r["state"], "#555")
        body.append(
            "<tr>"
            f"<td>{html.escape(str(r['kind']))}</td>"
            f"<td>{html.escape(str(r['resource'] or ''))}</td>"
            f"<td>{html.escape(msg)}</td>"
            f"<td>{html.escape(extra)}</td>"
            f"<td style='color:{color}'>{html.escape(str(r['state']))}</td>"
            f"<td>{html.escape(str(r['alert_id'] or ''))}</td>"
            f"<td>{html.escape(str(r['first_seen']))}</td>"
            f"<td>{html.escape(str(r['last_seen']))}</td>"
            "</tr>"
        )
    stats = STATE.outbox_stats()
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="30">
<title>KDP — активные события</title>
<style>body{{font-family:system-ui,sans-serif;margin:24px}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:6px 10px;font-size:14px}}
th{{background:#f5f5f5;text-align:left}}</style></head><body>
<h2>KDP — события</h2>
<p>Активных в очереди: {stats['pending']}. Обновление каждые 30 с.</p>
<table><tr><th>Класс</th><th>Ресурс</th><th>msg_type</th><th>Пик/параметр</th>
<th>Статус</th><th>IRIS alert</th><th>Начало</th><th>Обновлено</th></tr>
{''.join(body)}</table></body></html>"""
