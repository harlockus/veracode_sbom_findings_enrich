"""Authenticated JSON client for api.veracode.com.

Pagination accepts both HAL shapes Veracode actually returns and the shapes
described in the Swagger documents: ``_embedded`` as an object or a list,
``_links`` as a map or a list, and ``page.total_pages``.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from sbom_findings.auth import authorization_header
from sbom_findings.config import Settings, _header_value

log = logging.getLogger("sbom_findings.client")

MAX_ATTEMPTS = 5
DEFAULT_TIMEOUT = 180
MAX_RESPONSE_BYTES = 80 * 1024 * 1024

Sender = Callable[[str, dict[str, str], int], tuple[int, Mapping[str, str], bytes]]


class VeracodeError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, path: str | None = None):
        super().__init__(message)
        self.status = status
        self.path = path


class VeracodeClient:
    def __init__(
        self,
        settings: Settings,
        *,
        sender: Sender | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        sleeper: Callable[[float], None] | None = None,
    ):
        self.settings = settings
        self._sender = sender or _urllib_sender
        self._timeout = timeout
        self._sleep = sleeper or time.sleep

    def get_json(self, path: str, query: Mapping[str, Any] | None = None) -> dict[str, Any]:
        url_path = join_query(path, query)
        status, body = self._request(url_path)
        if not body:
            return {}
        try:
            payload = json.loads(body.decode("utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise VeracodeError(
                f"Veracode returned non-JSON for {url_path} (HTTP {status})",
                status=status,
                path=url_path,
            ) from exc
        if not isinstance(payload, dict):
            return {"_value": payload}
        return payload

    def paginate(
        self,
        path: str,
        query: Mapping[str, Any] | None = None,
        *,
        keys: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        """Follow HAL next links, then page numbers, and return every item."""
        base_query = {k: v for k, v in dict(query or {}).items() if v is not None}
        current = path
        current_query: dict[str, Any] | None = dict(base_query)
        seen: set[str] = set()
        items: list[dict[str, Any]] = []
        for _ in range(10_000):
            signature = join_query(current, current_query)
            if signature in seen:
                break
            seen.add(signature)
            payload = self.get_json(current, current_query)
            batch = [row for row in extract_collection(payload, keys) if isinstance(row, dict)]
            items.extend(batch)
            nxt = next_href(payload)
            page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
            number = _as_int(page.get("number") if page else None)
            total_pages = _as_int(
                (page or {}).get("total_pages") if page else None
            )
            if total_pages is None and page:
                total_pages = _as_int(page.get("totalPages"))
            if nxt:
                current = same_host_path(nxt, self.settings.host)
                current_query = None
                continue
            if number is None or total_pages is None or number + 1 >= total_pages:
                break
            current = path
            current_query = dict(base_query)
            current_query["page"] = number + 1
        return items

    def _request(self, url_path: str) -> tuple[int, bytes]:
        url_path = assert_api_path(url_path)
        url = f"{self.settings.base_url}{url_path}"
        last_error: Exception | None = None
        for attempt in range(MAX_ATTEMPTS):
            headers = {
                "Authorization": authorization_header(
                    self.settings.api_id,
                    self.settings.api_key,
                    self.settings.host,
                    url_path,
                    "GET",
                ),
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
                "User-Agent": _header_value(self.settings.user_agent, fallback="SBOM-Findings/1.0"),
            }
            try:
                status, response_headers, raw = self._sender(url, headers, self._timeout)
            except TimeoutError as exc:
                last_error = exc
                self._backoff(attempt, None)
                continue
            except urllib.error.URLError as exc:
                last_error = exc
                self._backoff(attempt, None)
                continue
            body = maybe_decompress(raw, response_headers)
            if status in {429, 500, 502, 503, 504} and attempt + 1 < MAX_ATTEMPTS:
                self._backoff(attempt, _header(response_headers, "Retry-After"))
                continue
            if status < 200 or status >= 300:
                detail = _safe_error_detail(body)
                raise VeracodeError(
                    f"Veracode HTTP {status} for {url_path}{detail}",
                    status=status,
                    path=url_path,
                )
            return status, body
        raise VeracodeError(
            f"Veracode request failed after {MAX_ATTEMPTS} attempts for {url_path}: {last_error}"
        )

    def _backoff(self, attempt: int, retry_after: str | None) -> None:
        delay = _retry_delay(attempt, retry_after)
        log.warning("retrying Veracode request in %.1fs", delay)
        self._sleep(delay)


def join_query(path: str, query: Mapping[str, Any] | None) -> str:
    if query is None:
        return path
    encoded = encode_query(query)
    if not encoded:
        return path.split("?", 1)[0]
    base = path.split("?", 1)[0]
    return f"{base}?{encoded}"


def encode_query(query: Mapping[str, Any]) -> str:
    pairs: list[tuple[str, str]] = []
    for key, value in query.items():
        if value is None:
            continue
        if isinstance(value, bool):
            text = "true" if value else "false"
        else:
            text = str(value)
        pairs.append((str(key), text))
    return urlencode(pairs, doseq=True, quote_via=quote, safe="")


def extract_collection(payload: Any, keys: tuple[str, ...]) -> list[Any]:
    if not isinstance(payload, dict):
        return []
    embedded = payload.get("_embedded")
    if isinstance(embedded, dict):
        for key in keys:
            value = embedded.get(key)
            if isinstance(value, list):
                return value
        lists = [value for value in embedded.values() if isinstance(value, list)]
        if len(lists) == 1:
            return lists[0]
    if isinstance(embedded, list):
        return embedded
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def next_href(payload: dict[str, Any]) -> str | None:
    for key in ("_links", "_link"):
        href = _href_from_links(payload.get(key), rel="next")
        if href:
            return href
    return None


def same_host_path(href: str, host: str) -> str:
    if href.startswith("/"):
        return assert_api_path(href)
    parsed = urlparse(href)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() != host.lower():
        raise VeracodeError("refusing a pagination link that leaves the Veracode API host")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return assert_api_path(path)


def assert_api_path(path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or "\\" in path or "@" in path.split("?", 1)[0]:
        raise VeracodeError("refusing an unexpected Veracode path")
    lowered = path.lower()
    if "%2e%2e" in lowered or "%00" in lowered or "%5c" in lowered:
        raise VeracodeError("refusing an encoded Veracode path")
    path_only = path.split("?", 1)[0]
    if ".." in path_only.split("/"):
        raise VeracodeError("refusing a Veracode path that contains ..")
    return path


def quote_path_segment(value: str, *, safe: str = "") -> str:
    return quote(value, safe=safe)


def maybe_decompress(raw: bytes, headers: Mapping[str, str]) -> bytes:
    if not raw:
        return raw
    if len(raw) > MAX_RESPONSE_BYTES:
        raise VeracodeError("Veracode response exceeded the size limit")
    encoding = (_header(headers, "Content-Encoding") or "").lower()
    if "gzip" in encoding or raw[:2] == b"\x1f\x8b":
        return _gunzip_limited(raw)
    return raw


def _gunzip_limited(raw: bytes, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    """Inflate gzip and stop once the output passes ``limit``."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        produced = decompressor.decompress(raw, limit + 1)
    except zlib.error as exc:
        raise VeracodeError("Veracode response was not valid gzip") from exc
    if len(produced) > limit or not decompressor.eof:
        if len(produced) > limit or decompressor.unconsumed_tail:
            raise VeracodeError("Veracode response exceeded the size limit")
        raise VeracodeError("Veracode response was not valid gzip")
    return produced


def _href_from_links(links: Any, *, rel: str) -> str | None:
    if isinstance(links, dict):
        if rel in links:
            return _href_value(links.get(rel))
        for value in links.values():
            if isinstance(value, dict) and str(value.get("rel") or "").lower() == rel:
                return _href_value(value)
        return None
    if isinstance(links, list):
        for item in links:
            if isinstance(item, dict) and str(item.get("rel") or "").lower() == rel:
                return _href_value(item)
        return None
    if isinstance(links, str) and rel == "next":
        return links or None
    return None


def _href_value(value: Any) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        href = value.get("href")
        return str(href) if href else None
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface 3xx as an HTTP error instead of following it.

    The default opener copies the Authorization header onto a redirected
    request. Veracode responses are read from the signed host only.
    """

    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _opener() -> urllib.request.OpenerDirector:
    # A subclass of HTTPRedirectHandler suppresses the default redirect handler.
    return urllib.request.build_opener(
        urllib.request.ProxyHandler,
        urllib.request.HTTPSHandler,
        _NoRedirect,
    )


def _urllib_sender(url: str, headers: dict[str, str], timeout: int):
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" and not (parsed.scheme == "http" and host in {"127.0.0.1", "localhost"}):
        raise VeracodeError("refusing a URL that is not HTTPS")
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _opener().open(request, timeout=timeout) as response:
            return response.status, response.headers, _read_limited(response)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, _read_limited(exc)


def read_https(url: str, headers: dict[str, str], timeout: float) -> bytes | None:
    """GET one HTTPS URL. Redirects and transport errors return no body."""
    try:
        status, response_headers, body = _urllib_sender(url, headers, timeout)
        body = maybe_decompress(body, response_headers)
    except (urllib.error.URLError, TimeoutError, OSError, VeracodeError):
        return None
    if status != 200:
        return None
    return body


def _read_limited(stream, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = stream.read(64 * 1024)
        if not block:
            break
        total += len(block)
        if total > limit:
            raise VeracodeError("Veracode response exceeded the size limit")
        chunks.append(block)
    return b"".join(chunks)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value)
    return None


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), 60.0)
        except ValueError:
            pass
    return float(min(2**attempt, 30))


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_error_detail(body: bytes) -> str:
    if not body:
        return ""
    text = body.decode("utf-8", errors="replace").strip().replace("\n", " ")
    if len(text) > 300:
        text = text[:300] + "..."
    lowered = text.lower()
    markers = (
        "veracode-hmac",
        "api_key",
        "api-key",
        "authorization",
        "bearer ",
        "sig=",
        "secret",
    )
    if any(marker in lowered for marker in markers):
        return ""
    return f": {text}"
