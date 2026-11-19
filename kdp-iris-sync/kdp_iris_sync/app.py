"""KDP -> DFIR-IRIS connector: API poller, outbox worker, active dashboard."""

from __future__ import annotations

import html
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

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
    close_comment,
    event_identity,
    severity_for,
    status_id_for,
)
from .pull import KdpPuller
from .state import State
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
    _maybe_escalate(payload, key, kind, external_id, alert_id)
    return alert_id


def _maybe_escalate(
    payload: Dict[str, Any],
    key: str,
    kind: str,
    external_id: str,
    alert_id: int,
) -> None:
    """Create a case for a freshly created alert (auto-escalation)."""
    auto = CONFIG.get("auto_escalate") or {}
    if not auto.get("enabled"):
        return
    try:
        body = build_case_payload(
            payload, config=CONFIG, kind=kind, external_id=external_id
        )
        data = IRIS.escalate_alert(alert_id, body)
        case_id = case_id_from_response(data)
        if case_id is None:
            LOG.warning("escalation returned no case_id for alert %s: %r", alert_id, data)
            return
        STATE.set_case_id(key, case_id)
        LOG.info("alert %s escalated to case %s", alert_id, case_id)
    except Exception as exc:  # noqa: BLE001 - escalation must not drop the alert
        LOG.error("auto-escalation failed for alert %s: %s", alert_id, exc)


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

    IRIS.add_comment("alerts", alert_id, close_comment(payload))
    IRIS.update_alert(
        alert_id, {"alert_status_id": int(CONFIG["iris"].get("alert_status_closed", 2))}
    )
    if row and row["case_id"]:
        try:
            IRIS.add_comment(
                "cases", int(row["case_id"]), close_comment(payload)
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning("cannot comment case %s: %s", row["case_id"], exc)
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

    STATE.open_event(key, kind, external_id, resource, payload)
    _create_alert(payload, key, kind, external_id)


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
