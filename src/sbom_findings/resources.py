"""Veracode resource calls used by the collector.

Endpoints and query names are taken from:

* Applications API 1.0 — ``GET /appsec/v1/applications``
* Findings API 2.1 — ``GET /appsec/v2/applications/{guid}/findings``
  with ``scan_type=SCA``. ``include_annot`` and ``violates_policy`` are
  rejected for SCA, so they are never sent.
* SCA Agent API 3.0 — workspaces, projects, issues, issue detail,
  component activity, and ``/sbom/v1/targets/{uuid}/{cyclonedx|spdx}``
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from sbom_findings.client import VeracodeClient, VeracodeError

FINDINGS_PAGE_SIZE = 500
SCA_PAGE_SIZE = 100


def list_applications(
    client: VeracodeClient,
    *,
    name: str | None = None,
    page_size: int = SCA_PAGE_SIZE,
) -> list[dict[str, Any]]:
    query: dict[str, Any] = {"size": page_size}
    if name:
        query["name"] = name
    return client.paginate("/appsec/v1/applications", query, keys=("applications",))


def get_application(client: VeracodeClient, guid: str) -> dict[str, Any]:
    return client.get_json(f"/appsec/v1/applications/{quote(guid, safe='')}")


def list_sca_findings(
    client: VeracodeClient,
    application_guid: str,
    *,
    sca_scan_mode: str = "BOTH",
    sca_dep_mode: str | None = None,
    context: str | None = None,
    page_size: int = FINDINGS_PAGE_SIZE,
) -> list[dict[str, Any]]:
    query: dict[str, Any] = {
        "scan_type": "SCA",
        "sca_scan_mode": sca_scan_mode,
        "size": page_size,
    }
    if sca_dep_mode:
        query["sca_dep_mode"] = sca_dep_mode
    if context:
        query["context"] = context
    return client.paginate(
        f"/appsec/v2/applications/{quote(application_guid, safe='')}/findings",
        query,
        keys=("findings",),
    )


def list_workspaces(
    client: VeracodeClient,
    *,
    name: str | None = None,
    page_size: int = SCA_PAGE_SIZE,
) -> list[dict[str, Any]]:
    query: dict[str, Any] = {"size": page_size, "include_metrics": "false"}
    if name:
        query["filter[workspace]"] = name
    return client.paginate("/srcclr/v3/workspaces", query, keys=("workspaces",))


def list_projects(
    client: VeracodeClient,
    workspace_id: str,
    *,
    page_size: int = SCA_PAGE_SIZE,
) -> list[dict[str, Any]]:
    return client.paginate(
        f"/srcclr/v3/workspaces/{quote(workspace_id, safe='')}/projects",
        {"size": page_size},
        keys=("projects",),
    )


def list_linked_projects(client: VeracodeClient, application_guid: str) -> list[dict[str, Any]]:
    payload = client.get_json(
        f"/srcclr/v3/applications/{quote(application_guid, safe='')}/projects"
    )
    projects = payload.get("linked_projects")
    if isinstance(projects, list):
        return [item for item in projects if isinstance(item, dict)]
    return []


def list_libraries(
    client: VeracodeClient,
    workspace_id: str,
    *,
    page_size: int = SCA_PAGE_SIZE,
) -> list[dict[str, Any]]:
    """Libraries in one workspace. ``id`` is the SourceClear library reference."""
    return client.paginate(
        f"/srcclr/v3/workspaces/{quote(workspace_id, safe='')}/libraries",
        {"size": page_size},
        keys=("libraries",),
    )


def list_issues(
    client: VeracodeClient,
    workspace_id: str,
    *,
    status: str = "open",
    page_size: int = SCA_PAGE_SIZE,
) -> list[dict[str, Any]]:
    query: dict[str, Any] = {
        "type": "vulnerability",
        "size": page_size,
        "vuln_methods": "false",
    }
    if status:
        query["status"] = status
    return client.paginate(
        f"/srcclr/v3/workspaces/{quote(workspace_id, safe='')}/issues",
        query,
        keys=("issues",),
    )


def get_issue(client: VeracodeClient, issue_id: str) -> dict[str, Any]:
    return client.get_json(f"/srcclr/v3/issues/{quote(issue_id, safe='')}")


def get_component_activity(client: VeracodeClient, library_ref: str) -> dict[str, Any]:
    """GET /srcclr/v3/component-activity/{libraryRef}.

    The path segment is percent-encoded. A 400 or 404 is retried once with
    colons left literal, because gateway deployments differ on that detail.
    """
    last: VeracodeError | None = None
    for safe in ("", ":"):
        encoded = quote(library_ref, safe=safe)
        try:
            return client.get_json(f"/srcclr/v3/component-activity/{encoded}")
        except VeracodeError as exc:
            last = exc
            if exc.status not in {400, 404}:
                raise
    if last is None:
        raise VeracodeError("component activity was not requested")
    raise last


def get_sbom(
    client: VeracodeClient,
    target_uuid: str,
    *,
    fmt: str,
    scan_type: str,
    linked: bool = False,
) -> dict[str, Any]:
    if fmt not in {"cyclonedx", "spdx"}:
        raise ValueError(f"unsupported SBOM format {fmt}")
    if scan_type not in {"application", "agent"}:
        raise ValueError(f"unsupported SBOM type {scan_type}")
    query: dict[str, Any] = {
        "type": scan_type,
        "vulnerability": "true",
    }
    if fmt == "cyclonedx" and scan_type == "application":
        query["linked"] = "true" if linked else "false"
    if fmt == "spdx":
        query["dependency"] = "true"
    return client.get_json(
        f"/srcclr/sbom/v1/targets/{quote(target_uuid, safe='')}/{fmt}",
        query,
    )
