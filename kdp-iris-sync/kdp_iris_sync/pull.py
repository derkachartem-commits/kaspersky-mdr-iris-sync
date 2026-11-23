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
        "attacked_ports": item.get("attacked_ports") or item.get("dst_ports") or item.get("ports") or [],
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
        "check_id": _pick(item, "check_id", default=""),
        "check_measurement": _pick(item, "check_measurement", "check_measure_units", "unit", default=""),
        "max_value": _pick(item, "max_value", "value", default=0),
        "threshold": _pick(item, "threshold", default=0),
        "excess_percentage": _pick(item, "excess_percentage", "excess", "percentage", default=0),
        "_status": _pick(item, "status", "state", "anomaly_status", default=""),
        "_last": _pick(item, "last", "last_seen", "timestamp", "start_time", default=""),
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
            "resource_id": details.get("resource_id"),
            "check_id": details.get("check_id"),
            "start_time": details.get("start_time") or details.get("timestamp"),
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
        # resource_id -> [ips]; refreshed periodically from /resources/
        self.resources: Dict[int, List[str]] = {}
        self._resources_loaded_at: Optional[datetime] = None
        # resource_id -> {"ports": str, "geo": str, "at": datetime}
        self.resource_meta: Dict[int, Dict[str, Any]] = {}

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
            "locale_id": int(self.cfg.get("anomalies_locale_id", 10)),
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

    def _load_resources(self) -> None:
        """Cache resource_id -> IP list from the KDP cabinet."""
        base = str(self.cfg.get("api_url") or "").rstrip("/")
        if not base:
            return
        url = str(self.cfg.get("resources_url") or (base + "/resources/"))
        body = {"locale_id": int(self.cfg.get("resources_locale_id", 10))}
        try:
            resp = self.session.post(
                url,
                json=body,
                verify=self.cfg.get("ca_bundle") or self.cfg.get("verify", True),
                timeout=int(self.cfg.get("timeout", 30)),
            )
            if resp.status_code != 200:
                LOG.warning("resources HTTP %s: %s", resp.status_code, resp.text[:200])
                return
            items = resp.json()
            if isinstance(items, dict):
                items = items.get("data") or []
            cache: Dict[int, List[str]] = {}
            for item in items or []:
                try:
                    rid = int(item.get("id"))
                except (TypeError, ValueError):
                    continue
                ips = [str(x) for x in (item.get("ips") or []) if x]
                cache[rid] = ips
            self.resources = cache
            self._resources_loaded_at = datetime.now(timezone.utc)
            LOG.info("KDP resources loaded: %s", len(cache))
        except Exception as exc:  # noqa: BLE001
            LOG.warning("cannot load KDP resources: %s", exc)

    def _volume_bytes(self, resource_id, check_id, start, end):
        """Bytes transferred between start and end (bps series, trapezoid)."""
        base = str(self.cfg.get("api_url") or "").rstrip("/")
        if not base or not resource_id or not check_id or not start or not end:
            return None
        try:
            resp = self.session.post(
                base + "/unit_checks/values/",
                json={"filter": {"check_ids": [int(check_id)], "date_from": start, "date_to": end,
                                  "points_count": 480, "resource_id": int(resource_id)}},
                verify=self.cfg.get("ca_bundle") or self.cfg.get("verify", True),
                timeout=int(self.cfg.get("timeout", 30)),
            )
            if resp.status_code != 200:
                return None
            data = resp.json() or {}
            series = []
            for value in data.values():
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
            LOG.warning("cannot compute volume for %s/%s: %s", resource_id, check_id, exc)
            return None

    def _stop_event(self, kind: str, key: str, details: Dict[str, Any]) -> None:
        payload = stop_payload(kind, key, details)
        if kind == "anomaly":
            # volume is always derived from the bps series of the resource
            size = self._volume_bytes(
                payload.get("resource_id"), 1011, payload.get("start_time"), payload.get("end_time")
            )
            if size:
                payload["volume_bytes"] = int(size)
        self.process(payload)
    def _load_resource_meta(self, rid: int) -> None:
        """Fetch ports/protocols and the geo-filter state of one resource."""
        base = str(self.cfg.get("api_url") or "").rstrip("/")
        if not base:
            return
        locale = int(self.cfg.get("anomalies_locale_id", 10))
        kwargs = {
            "verify": self.cfg.get("ca_bundle") or self.cfg.get("verify", True),
            "timeout": int(self.cfg.get("timeout", 30)),
        }
        meta: Dict[str, Any] = {"ports": "", "geo": "", "at": datetime.now(timezone.utc)}
        try:
            resp = self.session.get(f"{base}/resource/{rid}/", params={"locale_id": locale}, **kwargs)
            if resp.status_code == 200:
                detail = resp.json() or {}
                parts = []
                for item in detail.get("fprofiles") or []:
                    proto = str(item.get("protocol") or "").strip()
                    port = item.get("port") or 0
                    if proto and int(port or 0) > 0:
                        parts.append(f"{proto}/{port}")
                    elif proto:
                        parts.append(proto)
                meta["ports"] = ", ".join(parts)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("cannot load resource %s detail: %s", rid, exc)
        try:
            resp = self.session.get(f"{base}/resource/{rid}/geo_filter/", params={"locale_id": locale}, **kwargs)
            if resp.status_code == 200:
                filters = resp.json() or []
                if isinstance(filters, dict):
                    filters = filters.get("data") or []
                geo = "не настроен"
                for item in filters:
                    if str(item.get("system_name") or "") != "geofilter":
                        continue
                    if item.get("enabled"):
                        countries = []
                        for opt in item.get("options") or []:
                            if opt.get("enabled"):
                                countries.append(str(opt.get("short_name")))
                        countries_text = ", ".join(countries)
                        geo = "включён" + (f" ({countries_text})" if countries else "")
                    else:
                        geo = "выключен"
                    break
                meta["geo"] = geo
        except Exception as exc:  # noqa: BLE001
            LOG.warning("cannot load resource %s geo filter: %s", rid, exc)
        self.resource_meta[rid] = meta

    def _resource_meta(self, rid: int) -> Dict[str, Any]:
        hours = max(1, int(self.cfg.get("resources_refresh_hours", 6)))
        meta = self.resource_meta.get(rid)
        if meta and (datetime.now(timezone.utc) - meta["at"]) <= timedelta(hours=hours):
            return meta
        self._load_resource_meta(rid)
        return self.resource_meta.get(rid) or {}
    def _resources_stale(self) -> bool:
        hours = max(1, int(self.cfg.get("resources_refresh_hours", 6)))
        if not self._resources_loaded_at:
            return True
        return (datetime.now(timezone.utc) - self._resources_loaded_at) > timedelta(hours=hours)

    def _enrich(self, payload: Dict[str, Any]) -> None:
        """Attach the resource addresses (and keep the cache fresh)."""
        try:
            rid = int(payload.get("resource_id"))
        except (TypeError, ValueError):
            return
        if rid not in self.resources:
            self._load_resources()
        ips = self.resources.get(rid)
        if ips:
            payload["_ips"] = ips
        meta = self._resource_meta(rid)
        if meta.get("ports"):
            payload["_ports"] = meta["ports"]
        if meta.get("geo"):
            payload["_geo"] = meta["geo"]
    # ------------------------------------------------------------------ poll
    def poll_once(self) -> Dict[str, int]:
        base = str(self.cfg.get("api_url") or "").rstrip("/")
        attacks_url = self.cfg.get("attacks_url") or (base + self.cfg.get("attacks_path", "") if base else None)
        anomalies_url = self.cfg.get("anomalies_url") or (base + self.cfg.get("anomalies_path", "") if base else None)

        if self._resources_stale():
            self._load_resources()

        stats = {"attacks": 0, "anomalies": 0, "closed": 0}
        polled: List[Tuple[str, Dict[str, str]]] = []

        if attacks_url:
            items = self._get(attacks_url, self.cfg.get("attacks_method", "GET"))
            active = {}
            for item in items:
                payload = attack_payload(item)
                self._enrich(payload)
                key, kind, _ = event_identity(payload)
                if not payload.get("attack_id"):
                    LOG.warning("attack without id skipped: %s", json.dumps(item)[:300])
                    continue
                if is_closed_status(payload):
                    self._stop_event(kind, key, payload)
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
                if is_closed_status(payload) or self._is_stale(payload):
                    if self._has_open_event(key):
                        self.process(stop_payload(kind, key, payload))
                        stats["closed"] += 1
                    continue
                active[key] = payload
                self.process(payload)
            stats["anomalies"] = len(active)
            polled.append(("anomaly", active))

        if self.cfg.get("close_missing", True):
            stats["closed"] += self._close_missing(polled)

        self.state.set_meta("pull_last_success", utcnow())
        self.state.set_meta("pull_last_stats", json.dumps(stats))
        self.state.set_meta("pull_last_error", "")
        return stats

    def _is_stale(self, payload: Dict[str, Any]) -> bool:
        """An anomaly is over when KDP stopped refreshing its last-seen tick."""
        limit = max(60, int(self.cfg.get("anomaly_stale_seconds", 600)))
        raw = str(payload.get("_last") or "").strip()
        if not raw:
            return False
        text = raw.replace("Z", "+00:00")
        try:
            seen = datetime.fromisoformat(text)
        except ValueError:
            return False
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - seen).total_seconds() > limit

    def _has_open_event(self, key: str) -> bool:
        for row in self.state.list_events("open", limit=500):
            if row["event_key"] == key:
                return True
        return False

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
                self._stop_event(kind, row["event_key"], details)
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
