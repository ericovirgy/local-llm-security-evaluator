"""Minimal JSON-over-HTTP client with conservative defaults.

* loopback hosts only, unless the caller explicitly allows remote endpoints;
* environment proxy variables are ignored, so prompts never transit a proxy
  the user did not configure for this tool;
* redirects are refused;
* response bodies are size-limited and must be JSON objects.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from llmsec.adapters.base import AdapterError

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]  # noqa: ARG002
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not followed", headers, fp)


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def is_loopback_host(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def validate_base_url(url: str, allow_remote: bool) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise AdapterError(f"unsupported URL scheme {parts.scheme!r}; use http or https")
    if not parts.hostname:
        raise AdapterError("endpoint URL has no host")
    if parts.username or parts.password:
        raise AdapterError("credentials in the endpoint URL are not supported")
    if parts.query or parts.fragment:
        raise AdapterError("endpoint URL must not contain a query string or fragment")
    if not allow_remote and not is_loopback_host(parts.hostname):
        raise AdapterError(
            f"endpoint host {parts.hostname!r} is not a loopback address. Prompts and model "
            "outputs would leave this machine; pass --allow-remote to permit this explicitly."
        )
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def request_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)  # noqa: S310 - scheme validated
    req.add_header("Accept", "application/json")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    label = redact_url(url)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read(2048).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001 - best effort diagnostics only
            detail = ""
        raise AdapterError(f"HTTP {exc.code} from {label}: {detail[:300]}") from None
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise AdapterError(f"cannot reach {label}: {reason}") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AdapterError(f"response from {label} exceeds {MAX_RESPONSE_BYTES} bytes")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise AdapterError(f"response from {label} is not valid JSON") from None
    if not isinstance(data, dict):
        raise AdapterError(f"response from {label} is not a JSON object")
    return data
