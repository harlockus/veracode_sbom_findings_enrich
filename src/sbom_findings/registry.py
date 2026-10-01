"""Resolve a Maven coordinate when Veracode did not return one.

Upload findings identify a Java library by filename and version. The
SourceClear component-activity call needs ``group:artifact:version``.
Maven Central is used only to discover that group id, and only when the
artifact and version match exactly one group. Safe versions still come
from the SourceClear registry.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlencode

from sbom_findings.client import read_https

_SEARCH = "https://search.maven.org/solrsearch/select"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,127}$")


def unique_maven_ref(artifact: str, version: str, documents: list[dict]) -> str | None:
    """Build a library reference when every exact hit shares one group id."""
    groups: list[str] = []
    for document in documents:
        if str(document.get("a") or "") != artifact:
            continue
        if str(document.get("v") or "") != version:
            continue
        group = str(document.get("g") or "").strip()
        if not _TOKEN.fullmatch(group) or ".." in group:
            continue
        if group not in groups:
            groups.append(group)
    if len(groups) != 1 or not artifact or not version:
        return None
    return f"maven:{groups[0]}:{artifact}:{version}:"


def search_maven_ref(artifact: str, version: str, *, timeout: float = 20) -> str | None:
    """Query Maven Central. Network errors return no coordinate.

    The artifact and version are sent only when they are a single Maven
    token. Characters that would change the Solr query are rejected, and
    the request does not follow redirects.
    """
    if not _TOKEN.fullmatch(artifact or "") or not _TOKEN.fullmatch(version or ""):
        return None
    query = urlencode(
        {
            "q": f'a:"{artifact}" AND v:"{version}"',
            "rows": 20,
            "wt": "json",
        }
    )
    body = read_https(
        f"{_SEARCH}?{query}",
        {"User-Agent": "SBOM-Findings/1.0", "Accept": "application/json"},
        timeout,
    )
    if body is None:
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    documents = payload.get("response", {}).get("docs", [])
    if not isinstance(documents, list):
        return None
    return unique_maven_ref(artifact, version, documents)
