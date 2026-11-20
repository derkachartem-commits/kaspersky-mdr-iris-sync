"""Outbound polling of the KDP REST API.

Prod has no inbound ingress, so the connector can work in pull-only mode: it
periodically queries KDP (egress 443), synthesises the same payloads the
webhook would deliver, and closes events that disappeared from the active list.

Endpoint shapes differ between KDP deployments, therefore URLs, auth header and
field names are configurable; the mapper below accepts the documented webhook
field names first and falls back to common REST variants.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from .mapping import event_identity, is_closed_status
from .state import State, utcnow

LOG = logging.getLogger("kdp.pull")


def _pick(item: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
    return default


def _as_list(raw: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        for key in keys:
            value = raw.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if len(raw) == 1:
            value = next(iter(raw.values()))
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def attack_payload(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise an attack object from the REST API into a webhook payload."""
    max_point = item.get("max_point_values") or {}
    if not isinstance(max_point, dict):
        max_point = {}
    return {
        "msg_type": "attack_start",
        "attack_id": _pick(item, "attack_id", "id", "uuid", "attack_uuid"),
        "attack_type": _pick(item, "attack_type", "type", "vector", default="unknown"),
        "start_time": _pick(item, "start_time", "started_at", "start", "timestamp"),
        "resource_id": _pick(item, "resource_id", "target_id"),
        "resource_name": _pick(
            item, "resource_name", "resource", "target", "dst_ip", "host"
        ),
        "group_id": _pick(item, "group_id"),
        "group_name": _pick(item, "group_name"),
        "attacked_ips": item.get("attacked_ips") or [],
        "max_point_values": {
            "bps": _pick(max_point, "bps", default=_pick(item, "bps", "peak_bps", default=0)),
            "pps": _pick(max_point, "pps", default=_pick(item, "pps", "peak_pps", default=0)),
            "rps": _pick(max_point, "rps", default=_pick(item, "rps", default=0)),
        },
        "_status": _pick(item, "status", "state", "attack_status", default=""),
        "_source": "pull",
    }


def anomaly_payload(item: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise an anomaly object from the REST API into a webhook payload."""
    return {
        "msg_type": "anomaly_start",
        "anomaly_id": _pick(item, "anomaly_id", "id", "uuid"),
        "timestamp": _pick(item, "timestamp", "start_time", "started_at"),
        "resource_id": _pick(item, "resource_id"),
        "resource_name": _pick(item, "resource_name", "resource", "target", "host"),
        "group_id": _pick(item, "group_id"),
        "group_name": _pick(item, "group_name"),
        "check_name": _pick(
            item, "check_short_name", "check_name", "metric", "name", default="metric"
        ),
        "check_measurement": _pick(item, "check_measurement", "unit", default=""),
        "max_value": _pick(item, "max_value", "value", default=0),
        "threshold": _pick(item, "threshold", default=0),
        "excess_percentage": _pick(item, "excess_percentage", "excess", default=0),
        "_status": _pick(item, "status", "state", "anomaly_status", default=""),
        "_source": "pull",
    }


def stop_payload(kind: str, event_key: str, details: Dict[str, Any]) -> Dict[str, Any]:
    external_id = event_key.split(":", 1)[1] if ":" in event_key else event_key
    if kind == "attack":
        return {
            "msg_type": "attack_stop",
            "attack_id": external_id,
            "attack_type": details.get("attack_type") or "unknown",
            "start_time": details.get("start_time"),
            "end_time": utcnow(),
            "resource_name": details.get("resource_name"),
            "max_point_values": details.get("max_point_values") or {},
            "_source": "pull",
        }
    if kind == "anomaly":
        return {
            "msg_type": "anomaly_stop",
            "anomaly_id": external_id,
            "timestamp": utcnow(),
            "resource_name": details.get("resource_name"),
            "check_name": details.get("check_name"),
            "_source": "pull",
        }
    return {"msg_type": f"{kind}_stop", "_source": "pull"}


class KdpPuller(threading.Thread):
    """Poll KDP REST API and feed the same pipeline as the webhook."""

    def __init__(
        self,
        config: Dict[str, Any],
        state: State,
        process_payload: Callable[[Dict[str, Any]], None],
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="kdp-puller", daemon=True)
        self.cfg = config.get("kdp") or {}
        self.state = state
        self.process = process_payload
        self.stop_event = stop_event
        self.interval = max(15, int(self.cfg.get("poll_interval_seconds", 60)))
        self.grace_seconds = max(0, int(self.cfg.get("close_grace_seconds", 90)))
        self.session = requests.Session()
        # Called on 401/403 so the token refresher can re-login immediately.
        self.on_auth_error: Optional[Callable[[], None]] = None
        self.session.headers.update(self._headers())

    # ------------------------------------------------------------------ http
    def _headers(self) -> Dict[str, str]:
        token = str(self.cfg.get("token") or "")
        if not token:
            return {}
        header = str(self.cfg.get("auth_header") or "Authorization")
        scheme = str(self.cfg.get("auth_scheme") or "Bearer").strip()
        return {header: f"{scheme} {token}".strip(), "Accept": "application/json"}

    def _query_params(self) -> Optional[Dict[str, Any]]:
        """Query window for the anomalies feed (the cabinet hides inactive ones)."""
        state = str(self.cfg.get("anomalies_state") or "").strip()
        if not state:
            return None
        hours = max(1, int(self.cfg.get("anomalies_window_hours", 24)))
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        fmt = "%Y-%m-%dT%H:%M:%S.000Z"
        return {
            "locale_id": int(self.cfg.get("locale_id", 10)),
            "anomaly_state": state,
            "color": "all",
            "start": start.strftime(fmt),
            "end": end.strftime(fmt),
        }

    def _get(
        self,
        url: Optional[str],
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if not url:
            return []
        kwargs: Dict[str, Any] = {
            "verify": self.cfg.get("verify", True),
            "timeout": int(self.cfg.get("timeout", 30)),
        }
        if self.cfg.get("ca_bundle"):
            kwargs["verify"] = self.cfg["ca_bundle"]
        if self.cfg.get("proxy"):
            kwargs["proxies"] = {"http": self.cfg["proxy"], "https": self.cfg["proxy"]}
        method = (method or "GET").upper()
        if method == "GET":
            response = self.session.get(url, params=params, **kwargs)
        else:
            response = self.session.request(method, url, json={}, **kwargs)
        if response.status_code in (401, 403) and self.on_auth_error:
            LOG.warning("%s %s HTTP %s - asking for a token refresh", method, url, response.status_code)
            self.on_auth_error()
        if response.status_code != 200:
            raise RuntimeError(f"{method} {url} HTTP {response.status_code}: {response.text[:300]}")
        payload = response.json()
        return _as_list(payload, "data", "items", "attacks", "anomalies", "result", "events")

    def update_token(self, token: str) -> None:
        """Apply a freshly issued session token without restarting the poller."""
        self.cfg["token"] = token
        self.session.headers.update(self._headers())
        LOG.info("KDP puller switched to the refreshed token")

    # ------------------------------------------------------------------ poll
    def poll_once(self) -> Dict[str, int]:
        base = str(self.cfg.get("api_url") or "").rstrip("/")
        attacks_url = self.cfg.get("attacks_url") or (base + self.cfg.get("attacks_path", "") if base else None)
        anomalies_url = self.cfg.get("anomalies_url") or (base + self.cfg.get("anomalies_path", "") if base else None)

        stats = {"attacks": 0, "anomalies": 0, "closed": 0}
        polled: List[Tuple[str, Dict[str, str]]] = []

        if attacks_url:
            items = self._get(attacks_url, self.cfg.get("attacks_method", "GET"))
            active = {}
            for item in items:
                payload = attack_payload(item)
                key, kind, _ = event_identity(payload)
                if not payload.get("attack_id"):
                    LOG.warning("attack without id skipped: %s", json.dumps(item)[:300])
                    continue
                if is_closed_status(payload):
                    self.process(stop_payload(kind, key, payload))
                    continue
                active[key] = payload
                self.process(payload)
            stats["attacks"] = len(active)
            polled.append(("attack", active))

        if anomalies_url:
            items = self._get(
                anomalies_url,
                self.cfg.get("anomalies_method", "GET"),
                self._query_params(),
            )
            active = {}
            for item in items:
                payload = anomaly_payload(item)
                key, kind, _ = event_identity(payload)
                if not payload.get("anomaly_id"):
                    LOG.warning("anomaly without id skipped: %s", json.dumps(item)[:300])
                    continue
                if is_closed_status(payload):
                    self.process(stop_payload(kind, key, payload))
                    continue
                active[key] = payload
                self.process(payload)
            stats["anomalies"] = len(active)
            polled.append(("anomaly", active))

        if self.cfg.get("close_missing", True):
            stats["closed"] = self._close_missing(polled)

        self.state.set_meta("pull_last_success", utcnow())
        self.state.set_meta("pull_last_stats", json.dumps(stats))
        self.state.set_meta("pull_last_error", "")
        return stats

    def _close_missing(self, polled: List[Tuple[str, Dict[str, Any]]]) -> int:
        closed = 0
        now = datetime.now(timezone.utc)
        for kind, active in polled:
            for row in self.state.list_events("open", limit=500):
                if row["kind"] != kind or row["event_key"] in active:
                    continue
                try:
                    last_seen = datetime.fromisoformat(row["last_seen"])
                except ValueError:
                    continue
                if (now - last_seen).total_seconds() < self.grace_seconds:
                    continue
                details = json.loads(row["details"] or "{}")
                self.process(stop_payload(kind, row["event_key"], details))
                closed += 1
                LOG.info("closed %s: absent from KDP active list", row["event_key"])
        return closed

    def run(self) -> None:
        if not self.cfg.get("enabled"):
            LOG.info("KDP pull disabled (kdp.enabled=false)")
            return
        if not (self.cfg.get("api_url") or self.cfg.get("attacks_url") or self.cfg.get("anomalies_url")):
            LOG.error("KDP pull enabled but no api_url/attacks_url/anomalies_url configured")
            return
        LOG.info("KDP pull started (every %ss)", self.interval)
        while not self.stop_event.is_set():
            try:
                stats = self.poll_once()
                LOG.info("KDP pull: %s", stats)
            except Exception as exc:  # noqa: BLE001 - poller must survive
                self.state.set_meta("pull_last_error", f"{type(exc).__name__}: {exc}")
                LOG.warning("KDP pull failed: %s", exc)
            self.stop_event.wait(self.interval)
