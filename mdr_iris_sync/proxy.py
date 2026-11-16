"""Proxy configuration helpers.

Proxy settings can be global and/or per service. Example::

    "proxy": {
        "enabled": true,
        "url": "http://127.0.0.1:10808",
        "no_proxy": ["127.0.0.1", "localhost"]
    }

    "mdr":  {"proxy": {"url": "socks5h://127.0.0.1:1080"}}
    "iris": {"proxy": {"enabled": false}}

A per-service ``"proxy": null`` (or omitted key) inherits the global setting,
``"proxy": false`` disables it for that service.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlsplit, urlunsplit


def _with_credentials(url: str, username: Any, password: Any = None) -> str:
    """Inject proxy credentials into a proxy URL."""
    if not url or not username:
        return url
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parts.port:
            host = f"{host}:{parts.port}"
        userinfo = quote(str(username), safe="")
        if password not in (None, ""):
            userinfo += ":" + quote(str(password), safe="")
        return urlunsplit(
            (parts.scheme, f"{userinfo}@{host}", parts.path, parts.query, parts.fragment)
        )
    except ValueError:
        return url


def _mask_proxy_url(url: str) -> str:
    """Hide credentials in log output."""
    try:
        parts = urlsplit(url)
        if parts.username or parts.password:
            host = parts.hostname or ""
            if parts.port:
                host = f"{host}:{parts.port}"
            netloc = f"***:***@{host}"
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except ValueError:
        pass
    return url


def resolve_proxy_config(
    global_cfg: Optional[Any], service_cfg: Optional[Any] = None
) -> Optional[Dict[str, Any]]:
    """Merge global and per-service proxy settings."""
    if service_cfg is False:
        return None
    if service_cfg is None:
        merged = global_cfg
    elif isinstance(service_cfg, str):
        merged = {"enabled": True, "url": service_cfg}
    elif isinstance(service_cfg, dict):
        base = global_cfg if isinstance(global_cfg, dict) else {}
        merged = {**base, **service_cfg}
    else:
        merged = global_cfg

    if not merged:
        return None
    if isinstance(merged, str):
        merged = {"enabled": True, "url": merged}
    if not merged.get("enabled", True):
        return None

    http_proxy = merged.get("http") or merged.get("url")
    https_proxy = merged.get("https") or merged.get("url")
    if not http_proxy and not https_proxy:
        return None

    username = merged.get("username")
    password = merged.get("password")
    if username:
        http_proxy = _with_credentials(http_proxy, username, password)
        https_proxy = _with_credentials(https_proxy, username, password)

    no_proxy = merged.get("no_proxy") or []
    if isinstance(no_proxy, str):
        no_proxy = [item.strip() for item in no_proxy.split(",") if item.strip()]

    return {
        "http": http_proxy or https_proxy,
        "https": https_proxy or http_proxy,
        "no_proxy": no_proxy,
    }


def _host_matches_no_proxy(host: str, no_proxy: List[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for entry in no_proxy:
        entry = str(entry).strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("."):
            entry = entry[1:]
        if host == entry or host.endswith("." + entry):
            return True
    return False


def proxies_for_url(
    proxy_cfg: Optional[Dict[str, Any]], target_url: str
) -> Optional[Dict[str, str]]:
    """Return a ``requests`` proxies dict, or ``None`` if the proxy is bypassed."""
    if not proxy_cfg:
        return None

    no_proxy = proxy_cfg.get("no_proxy") or []
    if no_proxy:
        try:
            # Imported lazily so config/proxy helpers can be tested without
            # the runtime dependency installed.
            from requests.utils import should_bypass_proxies

            bypass = should_bypass_proxies(target_url, ",".join(no_proxy))
        except ImportError:
            bypass = _host_matches_no_proxy(
                urlsplit(target_url).hostname or "", list(no_proxy)
            )
        except Exception:  # noqa: BLE001 - never fail on a no_proxy check
            bypass = False
        if bypass:
            return None

    proxies: Dict[str, str] = {}
    if proxy_cfg.get("http"):
        proxies["http"] = proxy_cfg["http"]
    if proxy_cfg.get("https"):
        proxies["https"] = proxy_cfg["https"]
    return proxies or None


def describe_proxies(proxies: Optional[Dict[str, str]]) -> str:
    if not proxies:
        return "disabled"
    parts: List[str] = []
    for scheme in ("http", "https"):
        if proxies.get(scheme):
            parts.append(f"{scheme}={_mask_proxy_url(proxies[scheme])}")
    return ", ".join(parts) if parts else "disabled"
