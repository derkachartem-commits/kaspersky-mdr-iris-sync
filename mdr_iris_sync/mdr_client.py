"""Kaspersky MDR Web Console REST API client.

Key points
---------
* All calls are ``POST https://mdr.kaspersky.com/api/v1/<client_id>/<method>``.
* Authentication uses a pair of JWTs: ``refresh_token`` (long-lived, rotated on
  every use) and ``access_token`` (30 minutes).
* The refresh procedure is deliberately restartable: on any failure it backs
  off and tries again instead of leaving the integration without a token.
  Concurrent refreshes are serialized because every refresh invalidates the
  previous refresh token.
"""

from __future__ import annotations

import base64
import errno
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

try:  # POSIX only: used to serialize refreshes across processes
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]


class MDRApiError(RuntimeError):
    def __init__(self, message: str, status_code: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class MDRTokenError(MDRApiError):
    pass


def jwt_exp(token: Optional[str]) -> Optional[int]:
    """Return the ``exp`` claim of a JWT without verifying the signature."""
    if not token:
        return None
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
        exp = data.get("exp")
        return int(exp) if exp is not None else None
    except Exception:  # noqa: BLE001 - malformed token must not crash the app
        return None


def _fmt_ts(ts: Optional[int]) -> str:
    if not ts:
        return "unknown"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


class _InterProcessLock:
    """Best-effort ``flock`` based mutex around the token file.

    Token rotation is destructive: every successful ``session/confirm``
    invalidates the previous refresh token. Two processes (the service and a
    manual ``--once`` run, or two hosts sharing a mounted state dir) must not
    refresh concurrently, otherwise one of them gets ``409 Already changed``
    and the new pair is never persisted.
    """

    def __init__(self, path: Path, timeout: float = 60.0) -> None:
        self.path = path
        self.timeout = timeout
        self._fh = None

    def __enter__(self) -> "_InterProcessLock":
        if fcntl is None:
            return self
        deadline = time.monotonic() + self.timeout
        self._fh = open(self.path, "a+")
        while True:
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise MDRTokenError(
                        f"cannot acquire token lock {self.path} within {self.timeout}s"
                    ) from exc
                time.sleep(0.1)

    def __exit__(self, *_exc: Any) -> None:
        if self._fh is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None


class MDRTokenStore:
    """Thread-safe rotating token store persisted to a 0600 JSON file."""

    def __init__(
        self,
        path: str,
        *,
        api_url: str,
        client_id: str,
        refresh_token: str = "",
        verify: Any = True,
        timeout: int = 60,
        refresh_before_seconds: int = 180,
        retry_delay_seconds: int = 5,
        max_delay_seconds: int = 300,
        proxies: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.api_url = api_url.rstrip("/")
        self.client_id = client_id
        self.verify = verify
        self.timeout = timeout
        self.refresh_before_seconds = max(30, int(refresh_before_seconds))
        self.retry_delay_seconds = max(1, int(retry_delay_seconds))
        self.max_delay_seconds = max(self.retry_delay_seconds, int(max_delay_seconds))
        self.proxies = proxies
        self.log = logger or logging.getLogger(__name__)

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._seed_refresh_token = refresh_token.strip()
        self._lock_path = Path(str(self.path) + ".lock")
        self._file_mtime: Optional[float] = None
        self._dirty = False
        self._load()

    # ------------------------------------------------------------- storage
    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._access_token = data.get("access_token") or None
                self._refresh_token = data.get("refresh_token") or None
                self._file_mtime = self.path.stat().st_mtime
            except Exception:  # noqa: BLE001
                self.log.exception("cannot read token file %s; ignoring it", self.path)

        # A manually generated token in config may supersede an expired token
        # left in the state file.
        if self._seed_refresh_token:
            file_token = self._refresh_token
            file_exp = jwt_exp(file_token)
            seed_exp = jwt_exp(self._seed_refresh_token)
            now = time.time()
            should_use_seed = (
                not file_token
                or (file_exp is not None and file_exp <= now + 60)
                or (
                    seed_exp is not None
                    and (file_exp is None or seed_exp > file_exp + 60)
                )
            )
            if should_use_seed and self._seed_refresh_token != file_token:
                self.log.info("using the refresh token from configuration")
                self._refresh_token = self._seed_refresh_token
                self._access_token = None
                self._save()

        if not self._refresh_token and self._seed_refresh_token:
            self._refresh_token = self._seed_refresh_token
            self._save()

        if self._refresh_token:
            self.log.info(
                "MDR refresh token loaded; expires %s",
                _fmt_ts(jwt_exp(self._refresh_token)),
            )
        else:
            self.log.error("MDR refresh token is not configured")

    def _reload_from_disk(self) -> None:
        """Pick up a token pair rotated by another process.

        Called while the inter-process lock is held, so the file cannot change
        between the read and the following refresh call.
        """
        try:
            st = self.path.stat()
        except OSError:
            return
        if self._file_mtime is not None and st.st_mtime == self._file_mtime:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            self.log.warning("cannot re-read token file %s", self.path)
            return

        file_refresh = data.get("refresh_token") or None
        file_access = data.get("access_token") or None
        if file_refresh and file_refresh != self._refresh_token:
            self.log.info("token file was rotated by another process; reloading it")
            self._refresh_token = file_refresh
            self._access_token = file_access
        self._file_mtime = st.st_mtime

    def _save(self) -> bool:
        """Atomically persist the pair; returns False if the write failed.

        The write is fsynced before the pair is handed back to callers, so a
        crash right after a successful ``session/confirm`` cannot lose the new
        refresh token (the old one is already invalid on the MDR side).
        """
        payload = {
            "access_token": self._access_token,
            "refresh_token": self._refresh_token,
            "updated_at": int(time.time()),
        }
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
            os.replace(tmp, self.path)
            try:
                dir_fd = os.open(str(self.path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
            try:
                self._file_mtime = self.path.stat().st_mtime
            except OSError:
                pass
            self._dirty = False
            return True
        except Exception:  # noqa: BLE001
            self.log.exception("cannot persist tokens to %s", self.path)
            self._dirty = True
            return False

    # ------------------------------------------------------------- tokens
    def stop(self) -> None:
        self._stop.set()

    def _access_is_valid(self) -> bool:
        if not self._access_token:
            return False
        exp = jwt_exp(self._access_token)
        if exp is None:
            return True
        return exp - self.refresh_before_seconds > time.time()

    def access_token(self, max_attempts: int = 3) -> str:
        with self._lock:
            if self._dirty:
                self._save()
            if self._access_is_valid():
                return self._access_token  # type: ignore[return-value]
            return self._refresh_locked(max_attempts=max_attempts)

    def force_refresh(self, max_attempts: int = 3) -> str:
        with self._lock:
            return self._refresh_locked(max_attempts=max_attempts)

    def refresh_after_auth_error(self, failed_access_token: Optional[str]) -> str:
        """Refresh only if the rejected token is still the current one.

        A 401/403 usually means the access token expired, and several threads
        (or the keeper and the sync loop) can hit it at the same time. If a
        concurrent refresh already produced a new pair, reusing it is correct;
        rotating again would invalidate the pair the other caller just saved
        and produce ``409 Already changed``.
        """
        with self._lock:
            if self._dirty:
                self._save()
            if (
                failed_access_token
                and self._access_token
                and self._access_token != failed_access_token
                and self._access_is_valid()
            ):
                self.log.info("access token was already refreshed; reusing it")
                return self._access_token
            return self._refresh_locked(
                max_attempts=3, failed_token=failed_access_token
            )

    def _refresh_locked(
        self, max_attempts: int, failed_token: Optional[str] = None
    ) -> str:
        """Refresh the token pair.

        ``max_attempts=0`` means retry forever with exponential backoff. That
        mode is used by the background keeper, so the refresh procedure is
        automatically restarted after any error.

        The network call runs under an inter-process lock and the new pair is
        fsynced to disk before it is returned. Both steps are required: the
        old refresh token is invalidated by ``session/confirm`` even if the
        process dies before persisting the new one.
        """
        attempt = 0
        delay = self.retry_delay_seconds
        ipc_lock = _InterProcessLock(self._lock_path)

        while not self._stop.is_set():
            attempt += 1
            try:
                with ipc_lock:
                    self._reload_from_disk()
                    if (
                        failed_token
                        and self._access_token
                        and self._access_token != failed_token
                        and self._access_is_valid()
                    ):
                        self.log.info("another process already refreshed the token")
                        return self._access_token

                    refresh_token = self._refresh_token or self._seed_refresh_token
                    if not refresh_token:
                        raise MDRTokenError(
                            "refresh_token is empty; generate a new token in "
                            "MDR Web Console -> Settings -> API"
                        )

                    url = f"{self.api_url}/{self.client_id}/session/confirm"
                    response = requests.post(
                        url,
                        json={"refresh_token": refresh_token},
                        verify=self.verify,
                        timeout=self.timeout,
                        proxies=self.proxies,
                    )

                    if response.status_code == 409:
                        # Someone else rotated the token between our read and
                        # this call. If their pair is on disk we can just use
                        # it; otherwise both tokens are dead and only a new
                        # manually generated token helps.
                        self._reload_from_disk()
                        if (
                            self._access_token
                            and self._access_is_valid()
                            and self._refresh_token != refresh_token
                        ):
                            self.log.warning(
                                "session/confirm returned 409 but a newer token "
                                "pair is on disk; using it"
                            )
                            return self._access_token
                        raise MDRTokenError(
                            "session/confirm HTTP 409: refresh token already used "
                            "by another session; generate a new token in MDR Web "
                            "Console -> Settings -> API",
                            status_code=409,
                            body=response.text,
                        )

                    if response.status_code != 200:
                        raise MDRTokenError(
                            f"session/confirm HTTP {response.status_code}: {response.text[:500]}",
                            status_code=response.status_code,
                            body=response.text,
                        )
                    data = response.json()
                    access_token = data.get("access_token")
                    new_refresh_token = data.get("refresh_token")
                    if not access_token or not new_refresh_token:
                        raise MDRTokenError(
                            "session/confirm response does not contain access_token "
                            "and refresh_token"
                        )

                    self._access_token = access_token
                    self._refresh_token = new_refresh_token
                    # Save before handing the pair to the caller: the previous
                    # refresh token is already invalid on the MDR side.
                    if not self._save():
                        self.log.critical(
                            "new MDR token pair is not persisted; keeping it in "
                            "memory and retrying the write"
                        )

                    self.log.info(
                        "MDR tokens refreshed; access expires %s, refresh expires %s",
                        _fmt_ts(jwt_exp(access_token)),
                        _fmt_ts(jwt_exp(new_refresh_token)),
                    )
                    return access_token

            except Exception as exc:  # noqa: BLE001 - retry any failure
                if isinstance(exc, MDRTokenError) and exc.status_code == 409:
                    raise
                if max_attempts and attempt >= max_attempts:
                    raise MDRTokenError(
                        f"token refresh failed after {attempt} attempt(s): {exc}"
                    ) from exc
                self.log.error(
                    "MDR token refresh failed (attempt %s): %s; retrying in %ss",
                    attempt,
                    exc,
                    delay,
                )
                if self._stop.wait(delay):
                    break
                delay = min(delay * 2, self.max_delay_seconds)

        raise MDRTokenError("token refresh stopped")


class TokenKeeper(threading.Thread):
    """Background thread that keeps the access token fresh.

    It calls :meth:`MDRTokenStore.access_token` with ``max_attempts=0`` so the
    refresh procedure never gives up: errors only cause a backoff and restart.
    """

    def __init__(self, tokens: MDRTokenStore, interval_seconds: int = 30) -> None:
        super().__init__(name="mdr-token-keeper", daemon=True)
        self.tokens = tokens
        self.interval_seconds = max(5, int(interval_seconds))
        self.log = logging.getLogger("mdr_iris_sync.token_keeper")
        self._stop = threading.Event()

    def run(self) -> None:
        self.log.info("token keeper started (check every %ss)", self.interval_seconds)
        while not self._stop.is_set():
            try:
                self.tokens.access_token(max_attempts=0)
            except Exception:  # noqa: BLE001
                self.log.exception("unexpected error in token keeper; restarting")
            self._stop.wait(self.interval_seconds)
        self.log.info("token keeper stopped")

    def stop(self) -> None:
        self._stop.set()
        self.tokens.stop()


class MDRClient:
    def __init__(
        self,
        *,
        api_url: str,
        client_id: str,
        tokens: MDRTokenStore,
        verify: Any = True,
        timeout: int = 60,
        page_size: int = 100,
        max_pages: int = 100,
        proxies: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.client_id = client_id
        self.tokens = tokens
        self.verify = verify
        self.timeout = timeout
        self.page_size = page_size
        self.max_pages = max_pages
        self.proxies = proxies
        self.log = logger or logging.getLogger(__name__)
        self.session = requests.Session()

    def _url(self, path: str) -> str:
        return f"{self.api_url}/{self.client_id}/{path.lstrip('/')}"

    def _post(
        self,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        auth: bool = True,
        retry_auth: int = 1,
    ) -> Any:
        headers: Dict[str, str] = {}
        last_error: Optional[Exception] = None

        for attempt in range(retry_auth + 1):
            if auth:
                token = self.tokens.access_token(max_attempts=3)
                headers["Authorization"] = f"Bearer {token}"
            try:
                response = self.session.post(
                    self._url(path),
                    json=payload or {},
                    headers=headers,
                    verify=self.verify,
                    timeout=self.timeout,
                    proxies=self.proxies,
                )
            except requests.RequestException as exc:
                raise MDRApiError(f"POST {path} failed: {exc}") from exc

            if response.status_code == 200:
                if not response.content:
                    return {}
                try:
                    return response.json()
                except ValueError:
                    return {"raw": response.text}

            if response.status_code in (401, 403) and auth and attempt < retry_auth:
                self.log.warning(
                    "MDR auth error on %s (HTTP %s); forcing token refresh",
                    path,
                    response.status_code,
                )
                try:
                    self.tokens.refresh_after_auth_error(token)
                    continue
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                    break

            raise MDRApiError(
                f"POST {path} HTTP {response.status_code}: {response.text[:800]}",
                status_code=response.status_code,
                body=response.text,
            )

        raise MDRApiError(f"POST {path} failed: {last_error}")

    # ------------------------------------------------------------- methods
    def incidents_count(self, **filters: Any) -> int:
        payload = {k: v for k, v in filters.items() if v is not None}
        result = self._post("incidents/count", payload)
        if isinstance(result, dict):
            return int(result.get("count", 0) or 0)
        return 0

    def list_incidents(
        self,
        *,
        min_update_time: Optional[int] = None,
        fields: Optional[List[str]] = None,
        **filters: Any,
    ) -> List[Dict[str, Any]]:
        collected: List[Dict[str, Any]] = []
        seen = set()
        page = 1

        while page <= self.max_pages:
            payload: Dict[str, Any] = {
                k: v for k, v in filters.items() if v is not None
            }
            payload.setdefault("sort", "update_time:asc")
            payload["page"] = page
            payload["page_size"] = self.page_size
            if min_update_time is not None:
                payload["min_update_time"] = int(min_update_time)
            if fields:
                payload["fields"] = fields

            raw = self._post("incidents/list", payload)
            items = _as_list(raw, "incidents", "items", "data")

            new_items = 0
            for item in items:
                if not isinstance(item, dict):
                    continue
                incident_id = item.get("incident_id")
                if incident_id and incident_id in seen:
                    continue
                if incident_id:
                    seen.add(incident_id)
                collected.append(item)
                new_items += 1

            self.log.debug(
                "incidents/list page=%s received=%s new=%s", page, len(items), new_items
            )
            if len(items) < self.page_size:
                break
            page += 1

        return collected

    def incident_details(
        self, incident_id: str, *, fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "incident_id": incident_id,
            "markdown_to_html": True,
        }
        if fields:
            payload["fields"] = fields
        raw = self._post("incidents/details", payload)
        if isinstance(raw, dict):
            incident = raw.get("incident")
            if isinstance(incident, dict):
                return incident
            data = raw.get("data")
            if isinstance(data, dict):
                return data
            return raw
        raise MDRApiError(f"unexpected incidents/details response: {type(raw)!r}")

    def list_comments(self, incident_id: str) -> List[Dict[str, Any]]:
        payload = {
            "incident_id": incident_id,
            "fields": [
                "author_name",
                "comment_id",
                "creation_time",
                "origin",
                "text",
                "was_read",
            ],
            "markdown_to_html": True,
        }
        raw = self._post("comments/list", payload)
        return _as_list(raw, "comments", "items", "data")

    def create_comment(self, incident_id: str, text: str) -> Any:
        return self._post(
            "comments/create",
            {
                "incident_id": incident_id,
                "text": text,
                "markdown_to_html": True,
            },
        )

    def close_incident(
        self, incident_id: str, resolution_status: str, summary: str
    ) -> Any:
        return self._post(
            "incidents/close",
            {
                "incident_id": incident_id,
                "resolution_status": resolution_status,
                "summary": summary,
            },
        )


def _as_list(value: Any, *keys: str) -> List[Dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        for key in keys:
            nested = value.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
        if len(value) == 1:
            nested = next(iter(value.values()))
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
    return []
