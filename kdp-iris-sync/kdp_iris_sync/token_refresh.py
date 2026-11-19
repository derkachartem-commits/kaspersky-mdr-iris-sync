"""Refresh the KDP cabinet session token (portal.kdp.global).

The KDP cabinet has no long-lived API tokens: after sign-in it returns an
opaque session token (localStorage.token in the SPA) which the connector sends
as "Authorization: Bearer <token>". The token lives for about a day, so the
connector re-authenticates every kdp.token_refresh_hours hours (12 by default)
and rewrites the token into config.json (mode 0600).

Credentials never live in the repository: they are read from the deployed
config file (kdp.login / kdp.password) or, taking precedence, from the
KDP_LOGIN / KDP_PASSWORD environment variables.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import requests

LOG = logging.getLogger("kdp.auth")

DEFAULT_PORTAL_URL = "https://portal.kdp.global"
DEFAULT_SIGNIN_PATH = "/api/auth/signin/"
# login_type 1 = email login (2 = phone, 3 = telegram, 4 = legacy login)
DEFAULT_LOGIN_TYPE = 1
DEFAULT_LOCALE_ID = 10


def credentials(cfg: Dict[str, Any]) -> tuple[str, str]:
    """Login/password from the environment first, then from the config file."""
    login = os.environ.get("KDP_LOGIN") or str(cfg.get("login") or "")
    password = os.environ.get("KDP_PASSWORD") or str(cfg.get("password") or "")
    return login.strip(), password


def fetch_token(cfg: Dict[str, Any], timeout: int = 30) -> str:
    """Sign in to the cabinet and return a fresh session token."""
    portal = str(cfg.get("portal_url") or DEFAULT_PORTAL_URL).rstrip("/")
    signin_path = str(cfg.get("signin_path") or DEFAULT_SIGNIN_PATH)
    login, password = credentials(cfg)
    if not login or not password:
        raise RuntimeError(
            "KDP credentials are not configured "
            "(kdp.login/kdp.password in config or KDP_LOGIN/KDP_PASSWORD env)"
        )
    body = {
        "login": login,
        "password": password,
        "login_type": int(cfg.get("login_type", DEFAULT_LOGIN_TYPE)),
        "locale_id": int(cfg.get("locale_id", DEFAULT_LOCALE_ID)),
    }
    response = requests.post(
        portal + signin_path,
        json=body,
        timeout=timeout,
        verify=bool(cfg.get("verify", True)),
    )
    if response.status_code != 200:
        raise RuntimeError(f"signin HTTP {response.status_code}: {response.text[:200]}")
    token = (response.json() or {}).get("token")
    if not token:
        raise RuntimeError("signin returned no token")
    return str(token)


def save_token(config_path: str, token: str) -> None:
    """Atomically rewrite config.json with the new token (keeps mode 0600)."""
    path = Path(config_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("kdp", {})["token"] = token
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".config-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except Exception:  # noqa: BLE001 - never leave a temp file behind
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


class TokenRefresher(threading.Thread):
    """Re-login every N hours (and on demand after a 401/403 from the API)."""

    def __init__(
        self,
        config: Dict[str, Any],
        config_path: str,
        apply_token: Callable[[str], None],
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name="kdp-token-refresher", daemon=True)
        self.cfg = config.get("kdp") or {}
        self.config_path = config_path
        self.apply = apply_token
        self.stop_event = stop_event
        self.interval = max(1, int(self.cfg.get("token_refresh_hours", 12))) * 3600
        self.timeout = int(self.cfg.get("timeout", 30))
        self._wake = threading.Event()

    def trigger(self) -> None:
        """Ask for an immediate refresh (called after API auth errors)."""
        self._wake.set()

    def refresh_once(self) -> Optional[str]:
        token = fetch_token(self.cfg, self.timeout)
        save_token(self.config_path, token)
        self.cfg["token"] = token
        self.apply(token)
        LOG.info(
            "KDP token refreshed (len=%s), next refresh in %s h",
            len(token),
            self.interval // 3600,
        )
        return token

    def run(self) -> None:
        if not self.cfg.get("refresh_token", True):
            LOG.info("KDP token refresh disabled (kdp.refresh_token=false)")
            return
        login, _ = credentials(self.cfg)
        if not login:
            LOG.warning(
                "KDP token refresh: no login configured "
                "(kdp.login or KDP_LOGIN) - refresher stays idle"
            )
            return
        LOG.info("KDP token refresher started (every %s h)", self.interval // 3600)
        while not self.stop_event.is_set():
            try:
                self.refresh_once()
            except Exception as exc:  # noqa: BLE001 - refresher must survive
                LOG.warning("KDP token refresh failed: %s", exc)
            self._wake.wait(self.interval)
            self._wake.clear()
