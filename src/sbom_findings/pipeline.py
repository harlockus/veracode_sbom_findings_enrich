"""Collect upload and agent SCA results, then write JSON and Excel."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sbom_findings.client import VeracodeClient, VeracodeError
from sbom_findings.coordinates import looks_like_library_ref
from sbom_findings.enrich import (
    SafeVersionEnricher,
    attach_library_refs,
    component_identity,
    merge_sources,
    scope_mode,
)
from sbom_findings.export import (
    utc_now,
    write_findings_workbook,
    write_json,
    write_sbom_workbook,
)
from sbom_findings.normalize import (
    components_from_cyclonedx,
    components_from_spdx,
    dependencies_from_cyclonedx,
    dependencies_from_spdx,
    finding_from_api,
    finding_from_issue,
    finding_from_sbom_vulnerability,
    is_open_status,
    vulnerabilities_from_cyclonedx,
)
from sbom_findings.resources import (
    get_application,
    get_sbom,
    list_applications,
    list_issues,
    list_libraries,
    list_linked_projects,
    list_projects,
    list_sca_findings,
    list_workspaces,
)

log = logging.getLogger("sbom_findings")

_SLUG = re.compile(r"[^A-Za-z0-9._-]+")
_WINDOWS_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
)


@dataclass
class CollectRequest:
    app_names: list[str] = field(default_factory=list)
    app_guids: list[str] = field(default_factory=list)
    workspace_names: list[str] = field(default_factory=list)
    workspace_guids: list[str] = field(default_factory=list)
    project_guids: list[str] = field(default_factory=list)
    all_apps: bool = False
    all_workspaces: bool = False
    sca_scan_mode: str = "BOTH"
    sca_dep_mode: str | None = None
    context: str | None = None
    sbom_formats: tuple[str, ...] = ("cyclonedx",)
    include_linked_sbom: bool = True
    enrich: bool = True
    out_dir: Path = Path("output")


@dataclass
class CollectResult:
    out_dir: Path
    findings_json: Path
    findings_xlsx: Path
    sbom_json: Path
    sbom_xlsx: Path
    manifest_json: Path
    finding_count: int
    component_count: int
    warnings: list[str]


def collect(client: VeracodeClient, request: CollectRequest) -> CollectResult:
    warnings: list[str] = []
    apps = _resolve_apps(client, request, warnings)
    workspaces = _resolve_workspaces(client, request, warnings)
    explicit_agent = bool(workspaces) or bool(request.project_guids)
    include_agent = request.sca_scan_mode in {"AGENT", "BOTH"} or explicit_agent
    include_upload = request.sca_scan_mode in {"UPLOAD", "BOTH"}

    findings: list[dict[str, Any]] = []
    components: list[dict[str, Any]] = []
    library_catalog: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    documents: list[dict[str, Any]] = []

    seen_projects: set[str] = set()
    seen_issue_workspaces: set[str] = set()

    for app in apps:
        guid = _text(app.get("guid"))
        name = _app_name(app)
        _safe(
            warnings,
            f"findings for {name or guid}",
            lambda g=guid, n=name: findings.extend(_app_findings(client, g, n, request)),
        )
        if include_upload:
            for fmt in request.sbom_formats:
                _safe(
                    warnings,
                    f"{fmt} upload SBOM for {name or guid}",
                    lambda g=guid, n=name, f=fmt: _take_sbom(
                        client,
                        request,
                        target_uuid=g,
                        fmt=f,
                        scan_type="application",
                        linked=False,
                        target=_target(application_name=n, application_guid=g, scan_mode="UPLOAD"),
                        documents=documents,
                        components=components,
                        vulnerabilities=vulnerabilities,
                        dependencies=dependencies,
                    ),
                )
        if include_agent and request.include_linked_sbom and "cyclonedx" in request.sbom_formats:
            _safe(
                warnings,
                f"linked CycloneDX SBOM for {name or guid}",
                lambda g=guid, n=name: _take_sbom(
                    client,
                    request,
                    target_uuid=g,
                    fmt="cyclonedx",
                    scan_type="application",
                    linked=True,
                    target=_target(application_name=n, application_guid=g, scan_mode="UPLOAD+AGENT"),
                    documents=documents,
                    components=components,
                    vulnerabilities=vulnerabilities,
                    dependencies=dependencies,
                ),
            )
        if include_agent:
            linked = _safe_value(
                warnings,
                f"linked projects for {name or guid}",
                lambda g=guid: list_linked_projects(client, g),
                default=[],
            )
            for project in linked:
                project_id = _text(project.get("id"))
                if not project_id or project_id in seen_projects:
                    continue
                seen_projects.add(project_id)
                workspace = project.get("workspace") if isinstance(project.get("workspace"), dict) else {}
                workspace_id = _text(workspace.get("id"))
                workspace_name = _text(workspace.get("name"))
                _collect_project(
                    client,
                    request,
                    warnings,
                    project_id=project_id,
                    project_name=_text(project.get("name")),
                    workspace_id=workspace_id,
                    workspace_name=workspace_name,
                    application_name=name,
                    application_guid=guid,
                    documents=documents,
                    components=components,
                    vulnerabilities=vulnerabilities,
                    dependencies=dependencies,
                )
                if workspace_id and workspace_id not in seen_issue_workspaces:
                    seen_issue_workspaces.add(workspace_id)
                    _safe(
                        warnings,
                        f"agent issues for workspace {workspace_name or workspace_id}",
                        lambda w=workspace_id, wn=workspace_name: findings.extend(
                            _workspace_issues(client, w, wn)
                        ),
                    )

    for workspace in workspaces:
        workspace_id = _text(workspace.get("id"))
        workspace_name = _text(workspace.get("name"))
        projects = _safe_value(
            warnings,
            f"projects for workspace {workspace_name or workspace_id}",
            lambda w=workspace_id: list_projects(client, w),
            default=[],
        )
        for project in projects:
            project_id = _text(project.get("id"))
            if not project_id or project_id in seen_projects:
                continue
            seen_projects.add(project_id)
            linked_app = project.get("linked_application") if isinstance(project.get("linked_application"), dict) else {}
            _collect_project(
                client,
                request,
                warnings,
                project_id=project_id,
                project_name=_text(project.get("name")),
                workspace_id=workspace_id,
                workspace_name=workspace_name,
                application_name=_text(linked_app.get("name")),
                application_guid=_text(linked_app.get("guid")),
                documents=documents,
                components=components,
                vulnerabilities=vulnerabilities,
                dependencies=dependencies,
            )
        if workspace_id and workspace_id not in seen_issue_workspaces:
            seen_issue_workspaces.add(workspace_id)
            _safe(
                warnings,
                f"agent issues for workspace {workspace_name or workspace_id}",
                lambda w=workspace_id, wn=workspace_name: findings.extend(
                    _workspace_issues(client, w, wn)
                ),
            )
        if workspace_id:
            _safe(
                warnings,
                f"libraries for workspace {workspace_name or workspace_id}",
                lambda w=workspace_id, wn=workspace_name: library_catalog.extend(
                    _library_catalog(client, w, wn)
                ),
            )

    for project_id in request.project_guids:
        if project_id in seen_projects:
            continue
        seen_projects.add(project_id)
        _collect_project(
            client,
            request,
            warnings,
            project_id=project_id,
            project_name=project_id,
            workspace_id="",
            workspace_name="",
            application_name="",
            application_guid="",
            documents=documents,
            components=components,
            vulnerabilities=vulnerabilities,
            dependencies=dependencies,
        )

    _link_apps_onto_agent_findings(findings, components)
    attach_library_refs(findings, [*components, *library_catalog])
    findings.extend(_sbom_only_findings(findings, vulnerabilities, components))
    findings = merge_sources(findings)
    if request.enrich and findings:
        enricher = SafeVersionEnricher(client)
        for index, finding in enumerate(findings, start=1):
            if index == 1 or index % 25 == 0:
                log.info("enriching finding %s of %s", index, len(findings))
            enricher.enrich(finding)
        log.info("SourceClear enrichment calls: %s", enricher.calls)

    generated_at = utc_now()
    out = request.out_dir
    out.mkdir(parents=True, exist_ok=True)
    _write_raw_sboms(out, documents)

    finding_summary = _finding_summary(findings, warnings)
    sbom_summary = _sbom_summary(documents, components, vulnerabilities, dependencies, warnings)
    findings_payload = {
        "generated_at": generated_at,
        "scan_mode": request.sca_scan_mode,
        "counts": {row["metric"]: row["value"] for row in finding_summary},
        "warnings": warnings,
        "findings": findings,
    }
    sbom_payload = {
        "generated_at": generated_at,
        "formats": list(request.sbom_formats),
        "documents": [_public_document(doc) for doc in documents],
        "components": components,
        "vulnerabilities": vulnerabilities,
        "dependencies": dependencies,
        "warnings": warnings,
    }
    findings_json = out / "findings.json"
    findings_xlsx = out / "findings.xlsx"
    sbom_json = out / "sbom.json"
    sbom_xlsx = out / "sbom.xlsx"
    manifest_json = out / "manifest.json"
    write_json(findings_json, findings_payload)
    write_json(sbom_json, sbom_payload)
    write_findings_workbook(findings_xlsx, findings, finding_summary)
    write_sbom_workbook(
        sbom_xlsx,
        components=components,
        vulnerabilities=vulnerabilities,
        dependencies=dependencies,
        summary=sbom_summary,
    )
    manifest = {
        "generated_at": generated_at,
        "host": client.settings.host,
        "applications": [{"guid": _text(app.get("guid")), "name": _app_name(app)} for app in apps],
        "workspaces": [{"id": _text(ws.get("id")), "name": _text(ws.get("name"))} for ws in workspaces],
        "project_ids": sorted(seen_projects),
        "finding_count": len(findings),
        "component_count": len(components),
        "vulnerability_count": len(vulnerabilities),
        "warnings": warnings,
        "files": {
            "findings_json": findings_json.name,
            "findings_xlsx": findings_xlsx.name,
            "sbom_json": sbom_json.name,
            "sbom_xlsx": sbom_xlsx.name,
        },
    }
    write_json(manifest_json, manifest)
    return CollectResult(
        out_dir=out,
        findings_json=findings_json,
        findings_xlsx=findings_xlsx,
        sbom_json=sbom_json,
        sbom_xlsx=sbom_xlsx,
        manifest_json=manifest_json,
        finding_count=len(findings),
        component_count=len(components),
        warnings=warnings,
    )


def _resolve_apps(client: VeracodeClient, request: CollectRequest, warnings: list[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if request.all_apps:
        found.extend(list_applications(client))
    for guid in request.app_guids:
        try:
            found.append(get_application(client, guid))
        except VeracodeError as exc:
            warnings.append(f"application {guid}: {exc}")
    for name in request.app_names:
        matches = list_applications(client, name=name)
        exact = [app for app in matches if _app_name(app).lower() == name.lower()]
        if exact:
            found.extend(exact)
        elif matches:
            found.extend(matches)
            warnings.append(
                f"application name {name!r} was not an exact match; using {len(matches)} API matches"
            )
        else:
            warnings.append(f"no application named {name!r}")
    return _dedupe(found, "guid")


def _resolve_workspaces(
    client: VeracodeClient, request: CollectRequest, warnings: list[str]
) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if request.all_workspaces:
        found.extend(list_workspaces(client))
    for guid in request.workspace_guids:
        found.append({"id": guid, "name": guid})
    for name in request.workspace_names:
        matches = list_workspaces(client, name=name)
        exact = [row for row in matches if _text(row.get("name")).lower() == name.lower()]
        chosen = exact or matches
        if chosen:
            found.extend(chosen)
            if not exact:
                warnings.append(
                    f"workspace name {name!r} was not an exact match; using {len(matches)} API matches"
                )
        else:
            warnings.append(f"no workspace named {name!r}")
    return _dedupe(found, "id")


def _app_findings(
    client: VeracodeClient, guid: str, name: str, request: CollectRequest
) -> list[dict[str, Any]]:
    raw_rows = list_sca_findings(
        client,
        guid,
        sca_scan_mode=request.sca_scan_mode,
        sca_dep_mode=request.sca_dep_mode,
        context=request.context,
    )
    return [
        row
        for row in (finding_from_api(raw, application_name=name, application_guid=guid) for raw in raw_rows)
        if is_open_status(row.get("issue_status"))
    ]


def _workspace_issues(
    client: VeracodeClient, workspace_id: str, workspace_name: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in list_issues(client, workspace_id, status="open"):
        if _text(raw.get("issue_type")) not in {"", "vulnerability"}:
            continue
        row = finding_from_issue(raw, workspace_id=workspace_id, workspace_name=workspace_name)
        if is_open_status(row.get("issue_status")):
            rows.append(row)
    return rows


def _collect_project(client, request, warnings, **kwargs) -> None:
    documents = kwargs["documents"]
    components = kwargs["components"]
    vulnerabilities = kwargs["vulnerabilities"]
    dependencies = kwargs["dependencies"]
    target = _target(
        application_name=kwargs["application_name"],
        application_guid=kwargs["application_guid"],
        workspace_id=kwargs["workspace_id"],
        workspace_name=kwargs["workspace_name"],
        project_id=kwargs["project_id"],
        project_name=kwargs["project_name"],
        scan_mode="AGENT",
    )
    for fmt in request.sbom_formats:
        label = f"{fmt} agent SBOM for {kwargs['project_name'] or kwargs['project_id']}"
        _safe(
            warnings,
            label,
            lambda f=fmt, t=target, pid=kwargs["project_id"]: _take_sbom(
                client,
                request,
                target_uuid=pid,
                fmt=f,
                scan_type="agent",
                linked=False,
                target=t,
                documents=documents,
                components=components,
                vulnerabilities=vulnerabilities,
                dependencies=dependencies,
            ),
        )


def _take_sbom(
    client,
    request,
    *,
    target_uuid,
    fmt,
    scan_type,
    linked,
    target,
    documents,
    components,
    vulnerabilities,
    dependencies,
) -> None:
    document = get_sbom(
        client,
        target_uuid,
        fmt=fmt,
        scan_type=scan_type,
        linked=linked,
    )
    record = {
        **target,
        "format": fmt,
        "linked": linked,
        "target_uuid": target_uuid,
        "document": document,
    }
    documents.append(record)
    if fmt == "cyclonedx":
        components.extend(components_from_cyclonedx(document, target=target))
        vulnerabilities.extend(vulnerabilities_from_cyclonedx(document, target=target))
        dependencies.extend(dependencies_from_cyclonedx(document, target=target))
    else:
        components.extend(components_from_spdx(document, target=target))
        dependencies.extend(dependencies_from_spdx(document, target=target))


def _sbom_only_findings(findings, vulnerabilities, components) -> list[dict[str, Any]]:
    existing = {}
    for row in findings:
        existing.setdefault(_sbom_key(row), row)
    extra = []
    for vuln in vulnerabilities:
        for row in finding_from_sbom_vulnerability(vuln, components):
            key = _sbom_key(row)
            if not key[0]:
                continue
            current = existing.get(key)
            if current is not None:
                sources = list(dict.fromkeys([*(current.get("sources") or []), "sbom"]))
                current["sources"] = sources
                if not current.get("library_ref") and row.get("library_ref"):
                    current["library_ref"] = row["library_ref"]
                    current["library_ref_source"] = row.get("library_ref_source") or "sbom"
                continue
            existing[key] = row
            extra.append(row)
    return extra


def _library_catalog(client: VeracodeClient, workspace_id: str, workspace_name: str) -> list[dict[str, Any]]:
    rows = []
    for library in list_libraries(client, workspace_id):
        ref = _text(library.get("id"))
        if not looks_like_library_ref(ref):
            continue
        rows.append(
            {
                "name": _text(library.get("name")),
                "version": _text(library.get("version")),
                "library_ref": ref,
                "library_ref_source": "workspace_library",
                "workspace_id": workspace_id,
                "workspace_name": workspace_name,
                "application_guid": "",
                "project_id": "",
            }
        )
    return rows


def _sbom_key(row: dict[str, Any]) -> tuple[str, ...]:
    cve, name, version = component_identity(row)
    return (
        cve,
        name,
        version,
        scope_mode(row),
        row.get("application_guid") or "",
        row.get("project_id") or "",
    )


def _link_apps_onto_agent_findings(findings, components) -> None:
    """Agent issues do not carry the application GUID. Copy it from SBOM rows."""
    by_project = {}
    for component in components:
        project_id = component.get("project_id")
        if project_id and component.get("application_guid"):
            by_project[project_id] = component
    for finding in findings:
        project_id = finding.get("project_id")
        if project_id and not finding.get("application_guid") and project_id in by_project:
            source = by_project[project_id]
            finding["application_guid"] = source.get("application_guid") or ""
            finding["application_name"] = finding.get("application_name") or source.get("application_name") or ""


def _write_raw_sboms(out: Path, documents: list[dict[str, Any]]) -> None:
    folder = out / "sbom"
    folder.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    for document in documents:
        label = document.get("project_name") or document.get("application_name") or document.get("target_uuid")
        mode = "agent" if document.get("scan_mode") == "AGENT" else "upload"
        if document.get("linked"):
            mode = "linked"
        stem = _slug(f"{label}-{mode}-{document.get('format')}")
        name = stem
        suffix = 2
        while name in used:
            name = f"{stem}-{suffix}"
            suffix += 1
        used.add(name)
        path = folder / f"{name}.json"
        if path.parent != folder:
            name = "sbom"
            path = folder / f"{name}.json"
        write_json(path, document["document"])
        document["file"] = path.relative_to(out).as_posix()


def _public_document(document: dict[str, Any]) -> dict[str, Any]:
    raw = document.get("document") or {}
    component_count = len(raw.get("components") or raw.get("packages") or [])
    vulnerability_count = len(raw.get("vulnerabilities") or [])
    return {
        "format": document.get("format"),
        "scan_mode": document.get("scan_mode"),
        "linked": document.get("linked"),
        "application_name": document.get("application_name"),
        "application_guid": document.get("application_guid"),
        "workspace_name": document.get("workspace_name"),
        "project_name": document.get("project_name"),
        "project_id": document.get("project_id"),
        "target_uuid": document.get("target_uuid"),
        "file": document.get("file"),
        "component_count": component_count,
        "vulnerability_count": vulnerability_count,
    }


def _finding_summary(findings: list[dict[str, Any]], warnings: list[str]) -> list[dict[str, Any]]:
    def count(predicate) -> int:
        return sum(1 for row in findings if predicate(row))

    return [
        {"metric": "findings", "value": len(findings)},
        {"metric": "upload_scan_mode", "value": count(lambda row: row.get("scan_mode") == "UPLOAD")},
        {"metric": "agent_scan_mode", "value": count(lambda row: row.get("scan_mode") == "AGENT")},
        {"metric": "with_recommended_safe_version", "value": count(lambda row: row.get("recommended_safe_version"))},
        {"metric": "enrichment_gaps", "value": count(lambda row: row.get("enrichment_status") not in {"enriched", ""})},
        {"metric": "exploit_observed", "value": count(lambda row: row.get("exploit_observed") is True)},
        {"metric": "warnings", "value": len(warnings)},
    ]


def _sbom_summary(documents, components, vulnerabilities, dependencies, warnings) -> list[dict[str, Any]]:
    return [
        {"metric": "sbom_documents", "value": len(documents)},
        {"metric": "components", "value": len(components)},
        {"metric": "vulnerabilities", "value": len(vulnerabilities)},
        {"metric": "dependencies", "value": len(dependencies)},
        {"metric": "warnings", "value": len(warnings)},
    ]


def _target(**values: str) -> dict[str, str]:
    base = {
        "application_name": "",
        "application_guid": "",
        "workspace_id": "",
        "workspace_name": "",
        "project_id": "",
        "project_name": "",
        "scan_mode": "",
    }
    base.update({key: value or "" for key, value in values.items()})
    return base


def _safe(warnings: list[str], label: str, action) -> None:
    try:
        action()
    except VeracodeError as exc:
        if exc.status == 401:
            raise
        if exc.status == 404:
            warnings.append(f"{label}: not found (no scan in range, or the id is unknown)")
            log.warning("%s", warnings[-1])
            return
        if exc.status == 403:
            warnings.append(
                f"{label}: access denied. SBOM generation allows a Results API user. "
                "Workspace, issue, and safe-version calls require a UI user API credential."
            )
            log.warning("%s", warnings[-1])
            return
        warnings.append(f"{label}: {exc}")
        log.warning("%s", warnings[-1])


def _safe_value(warnings: list[str], label: str, action, default):
    box: dict[str, Any] = {}

    def run() -> None:
        box["value"] = action()

    _safe(warnings, label, run)
    return box.get("value", default)


def _dedupe(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen = set()
    unique = []
    for row in rows:
        ident = _text(row.get(key))
        if not ident or ident in seen:
            continue
        seen.add(ident)
        unique.append(row)
    return unique


def _app_name(app: dict[str, Any]) -> str:
    profile = app.get("profile") if isinstance(app.get("profile"), dict) else {}
    return _text(profile.get("name") or app.get("name"))


def _slug(value: str) -> str:
    """File stem that is legal on Windows, macOS, and Linux."""
    cleaned = _SLUG.sub("-", str(value))
    cleaned = re.sub(r"\.{2,}", ".", cleaned).strip(" .-_")
    cleaned = cleaned[:80].rstrip(" .-_")
    if not cleaned or cleaned.upper() in _WINDOWS_RESERVED:
        cleaned = "sbom" if not cleaned else f"file-{cleaned}"
    return cleaned[:80].rstrip(" .-_") or "sbom"


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
