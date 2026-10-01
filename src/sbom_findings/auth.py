"""Veracode HMAC-SHA-256 request signing.

The scheme is the one documented for every Veracode REST API
(VERACODE-HMAC-SHA-256). The signed URL is the path plus the query string,
with no scheme or host. API id and key are the hex segments of the
credentials file values.
"""

from __future__ import annotations

import hmac
import os
from hashlib import sha256

_SCHEME = "VERACODE-HMAC-SHA-256"
_VERSION = b"vcode_request_version_1"


def credential_hex(value: str) -> str:
    """Return the trailing hex segment of a Veracode API id or key."""
    text = (value or "").strip()
    if not text:
        raise ValueError("empty Veracode credential")
    segment = text.rsplit("-", 1)[-1].strip()
    try:
        bytes.fromhex(segment)
    except ValueError as exc:
        raise ValueError("Veracode credential is not hex") from exc
    return segment.lower()


def authorization_header(
    api_id: str,
    api_key: str,
    host: str,
    url: str,
    method: str = "GET",
    *,
    nonce_bytes: bytes | None = None,
    timestamp_ms: int | None = None,
) -> str:
    """Build the Authorization header for one request.

    ``url`` is the request path, including a leading slash and the query
    string when one is present. ``nonce_bytes`` and ``timestamp_ms`` exist
    so tests can pin the signature.
    """
    api_id_hex = credential_hex(api_id)
    api_key_hex = credential_hex(api_key)
    if not url.startswith("/"):
        raise ValueError("signed URL must start with /")
    host = host.strip().lower()
    method = method.upper()
    nonce = nonce_bytes if nonce_bytes is not None else os.urandom(16)
    if len(nonce) != 16:
        raise ValueError("HMAC nonce must be 16 bytes")
    timestamp = str(timestamp_ms if timestamp_ms is not None else _now_ms())
    signing_data = f"id={api_id_hex}&host={host}&url={url}&method={method}"
    key = bytes.fromhex(api_key_hex)
    k_nonce = hmac.new(key, nonce, sha256).digest()
    k_time = hmac.new(k_nonce, timestamp.encode("utf-8"), sha256).digest()
    k_sig = hmac.new(k_time, _VERSION, sha256).digest()
    signature = hmac.new(k_sig, signing_data.encode("utf-8"), sha256).hexdigest()
    nonce_hex = nonce.hex()
    return (
        f"{_SCHEME} id={api_id_hex},ts={timestamp},nonce={nonce_hex},sig={signature}"
    )


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)
