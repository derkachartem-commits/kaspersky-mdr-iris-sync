"""DFIR-IRIS REST API v2 client (alerts, cases, comments)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

import requests


class IrisApiError(RuntimeError):
    def __init__(self, message: str, status_code: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class IrisClient:
    def __init__(
        self,
        *,
        api_url: str,
        api_key: str,
        verify: Any = False,
        timeout: int = 60,
        proxies: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.verify = verify
        self.timeout = timeout
        self.proxies = proxies
        self.log = logger or logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            }
        )

    # ------------------------------------------------------------- helpers
    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        expected: Tuple[int, ...] = (200, 201),
    ) -> Any:
        url = f"{self.api_url}{path}"
        try:
            response = self.session.request(
                method,
                url,
                json=json_body,
                params=params,
                verify=self.verify,
                timeout=self.timeout,
                proxies=self.proxies,
            )
        except requests.RequestException as exc:
            raise IrisApiError(f"{method} {path} failed: {exc}") from exc

        if response.status_code not in expected:
            raise IrisApiError(
                f"{method} {path} HTTP {response.status_code}: {response.text[:800]}",
                status_code=response.status_code,
                body=response.text,
            )

        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    @staticmethod
    def _data(payload: Any) -> Any:
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    # -------------------------------------------------------------- alerts
    def add_alert(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw = self._request("POST", "/api/v2/alerts", json_body=payload, expected=(200, 201))
        data = self._data(raw)
        if not isinstance(data, dict):
            raise IrisApiError(f"unexpected add_alert response: {raw!r}")
        return data

    def get_alert(self, alert_id: int) -> Dict[str, Any]:
        raw = self._request("GET", f"/api/v2/alerts/{int(alert_id)}")
        data = self._data(raw)
        if not isinstance(data, dict):
            raise IrisApiError(f"unexpected get_alert response: {raw!r}")
        return data

    def update_alert(self, alert_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw = self._request(
            "PUT", f"/api/v2/alerts/{int(alert_id)}", json_body=payload
        )
        data = self._data(raw)
        return data if isinstance(data, dict) else {}

    def escalate_alert(self, alert_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw = self._request(
            "POST",
            f"/api/v2/alerts/escalate/{int(alert_id)}",
            json_body=payload,
            expected=(200, 201),
        )
        data = self._data(raw)
        if not isinstance(data, dict):
            raise IrisApiError(f"unexpected escalate_alert response: {raw!r}")
        return data

    def merge_alert(self, alert_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw = self._request(
            "POST",
            f"/api/v2/alerts/merge/{int(alert_id)}",
            json_body=payload,
            expected=(200, 201),
        )
        data = self._data(raw)
        return data if isinstance(data, dict) else {}

    # --------------------------------------------------------------- cases
    def get_case(self, case_id: int) -> Dict[str, Any]:
        raw = self._request("GET", f"/api/v2/cases/{int(case_id)}")
        data = self._data(raw)
        if not isinstance(data, dict):
            raise IrisApiError(f"unexpected get_case response: {raw!r}")
        return data

    def update_case(self, case_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw = self._request(
            "PUT", f"/api/v2/cases/{int(case_id)}", json_body=payload
        )
        data = self._data(raw)
        return data if isinstance(data, dict) else {}

    def update_case_state(self, case_id: int, status_id: int) -> Dict[str, Any]:
        """Set a case status across IRIS v2 and v3.

        v2 uses ``status_id``; v3 uses ``state_id``. Sending both is safe on
        both versions because their schemas ignore unknown fields.
        """
        status_id = int(status_id)
        payloads = [
            {"state_id": status_id, "status_id": status_id},
            {"status_id": status_id},
            {"state_id": status_id},
        ]
        last_error: Optional[IrisApiError] = None
        for payload in payloads:
            try:
                return self.update_case(case_id, payload)
            except IrisApiError as exc:
                if exc.status_code not in (400, 422):
                    raise
                last_error = exc
        if last_error:
            raise last_error
        raise IrisApiError(f"cannot update status of IRIS case {case_id}")

    def close_case(
        self, case_id: int, status_id: int, resolution_note: Optional[str] = None
    ) -> Dict[str, Any]:
        """Close a case.

        IRIS v3.0.0-beta.1 exposes ``POST /api/v2/cases/<id>/close``; v2.4
        used ``status_id`` on ``PUT /api/v2/cases/<id>`` and the legacy
        ``/case/close/<id>`` route. All three are tried for compatibility.
        """
        body: Dict[str, Any] = {
            "state_id": int(status_id),
            "status_id": int(status_id),
        }
        if resolution_note:
            body["case_resolution_note"] = resolution_note

        try:
            raw = self._request(
                "POST",
                f"/api/v2/cases/{int(case_id)}/close",
                json_body=body,
                expected=(200, 201),
            )
            data = self._data(raw)
            return data if isinstance(data, dict) else {}
        except IrisApiError as exc:
            if exc.status_code not in (404, 405):
                self.log.warning(
                    "POST /api/v2/cases/%s/close failed (%s); trying PUT status",
                    case_id,
                    exc,
                )

        try:
            return self.update_case_state(case_id, status_id)
        except IrisApiError as exc:
            self.log.warning(
                "PUT status for IRIS case %s failed (%s); falling back to /case/close",
                case_id,
                exc,
            )

        raw = self._request(
            "POST",
            f"/case/close/{int(case_id)}",
            json_body=body,
            expected=(200, 201),
        )
        data = self._data(raw)
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------ comments
    def list_comments(
        self,
        object_type: str,
        object_id: int,
        *,
        per_page: int = 100,
        max_pages: int = 100,
    ) -> List[Dict[str, Any]]:
        path = f"/api/v2/{object_type}/{int(object_id)}/comments"
        collected: List[Dict[str, Any]] = []
        seen = set()
        page = 1

        while page <= max_pages:
            raw = self._request(
                "GET", path, params={"page": page, "per_page": per_page}
            )
            data = self._data(raw)
            items: List[Dict[str, Any]] = []

            if isinstance(data, list):
                items = [item for item in data if isinstance(item, dict)]
            elif isinstance(data, dict):
                for key in ("comments", "data", "items"):
                    nested = data.get(key)
                    if isinstance(nested, list):
                        items = [item for item in nested if isinstance(item, dict)]
                        break

            new_items = 0
            for item in items:
                key = item.get("comment_id") or item.get("id")
                if key is not None:
                    if key in seen:
                        continue
                    seen.add(key)
                collected.append(item)
                new_items += 1

            if len(items) < per_page or new_items == 0:
                break
            page += 1

        return collected

    def add_comment(
        self, object_type: str, object_id: int, text: str
    ) -> Dict[str, Any]:
        path = f"/api/v2/{object_type}/{int(object_id)}/comments"
        raw = self._request(
            "POST", path, json_body={"comment_text": text}, expected=(200, 201)
        )
        data = self._data(raw)
        return data if isinstance(data, dict) else {}


def case_id_from_response(data: Dict[str, Any]) -> Optional[int]:
    for key in ("case_id", "id"):
        value = data.get(key)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                pass
    nested = data.get("case")
    if isinstance(nested, dict):
        return case_id_from_response(nested)
    return None


def alert_id_from_response(data: Dict[str, Any]) -> Optional[int]:
    for key in ("alert_id", "id"):
        value = data.get(key)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                pass
    nested = data.get("alert")
    if isinstance(nested, dict):
        return alert_id_from_response(nested)
    return None


def comment_id_from_response(data: Dict[str, Any]) -> Optional[str]:
    for key in ("comment_id", "id"):
        value = data.get(key)
        if value is not None:
            return str(value)
    nested = data.get("comment")
    if isinstance(nested, dict):
        return comment_id_from_response(nested)
    return None
