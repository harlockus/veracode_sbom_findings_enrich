"""Turn Veracode payloads into flat records for JSON and Excel.

Field names follow the Findings API 2.1 schemas (``ScaFinding``,
``ScaFindingCve``) and the SCA Agent API 3.0 schemas (``IssueSummary``,
``LibrarySummary``, ``VulnerabilitySummary``, CycloneDX ``component``,
SPDX ``packages``). The Findings example returns ``metadata`` as an object
and ``component_path`` as a list, while the schema text says otherwise, so
both shapes are accepted.
"""

from __future__ import annotations

from typing import Any

from sbom_findings.coordinates import find_library_ref, library_ref_from_purl, looks_like_library_ref


def is_open_status(value: object) -> bool:
    """True when a finding is open.

    The Findings API has no status query parameter. It returns open and
    closed findings, and ``finding_status.status`` is ``OPEN`` or ``CLOSED``.
    Agent issues use ``open`` and ``fixed``. A missing status is kept.
    """
    text = str(value or "").strip().upper()
    if not text:
        return True
    return text == "OPEN"


def sca_metadata(details: dict[str, Any]) -> dict[str, Any]:
    meta = details.get("metadata")
    if isinstance(meta, dict):
        return meta
    if isinstance(meta, str):
        text = meta.strip()
        if text.startswith("{") and text.endswith("}"):
            import json

            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
            if isinstance(parsed, dict):
                return parsed
        if text:
            return {"raw": text}
    return {}


def component_paths(details: dict[str, Any]) -> list[str]:
    raw = (
        details.get("component_path")
        or details.get("component_paths")
        or details.get("component_path(s)")
        or []
    )
    if isinstance(raw, str):
        return [raw] if raw else []
    paths: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item:
                paths.append(item)
            elif isinstance(item, dict) and item.get("path"):
                paths.append(str(item["path"]))
    return paths


def finding_from_api(raw: dict[str, Any], *, application_name: str, application_guid: str) -> dict[str, Any]:
    details = raw.get("finding_details") if isinstance(raw.get("finding_details"), dict) else {}
    meta = sca_metadata(details)
    cve = details.get("cve") if isinstance(details.get("cve"), dict) else {}
    cwe = details.get("cwe") if isinstance(details.get("cwe"), dict) else {}
    cvss3 = cve.get("cvss3") if isinstance(cve.get("cvss3"), dict) else {}
    exploit = cve.get("exploitability") if isinstance(cve.get("exploitability"), dict) else {}
    status = raw.get("finding_status") if isinstance(raw.get("finding_status"), dict) else {}
    paths = component_paths(details)
    licenses = _license_ids(details.get("licenses"))
    filename = _text(details.get("component_filename"))
    return {
        "source": "findings_api",
        "sources": ["findings_api"],
        "scan_type": _text(raw.get("scan_type")) or "SCA",
        "scan_mode": _upper(meta.get("sca_scan_mode")),
        "dependency_mode": _upper(meta.get("sca_dep_mode")),
        "application_name": application_name,
        "application_guid": application_guid,
        "workspace_id": "",
        "workspace_name": "",
        "project_id": "",
        "project_name": "",
        "project_branch": "",
        "issue_id": _text(raw.get("issue_id")),
        "issue_status": _text(status.get("status")),
        "resolution": _text(status.get("resolution")),
        "resolution_status": _text(status.get("resolution_status")),
        "first_found_date": _text(status.get("first_found_date")),
        "last_seen_date": _text(status.get("last_seen_date")),
        "is_new": status.get("new"),
        "violates_policy": raw.get("violates_policy"),
        "policy_severity": details.get("severity"),
        "cve": _text(cve.get("name")),
        "cve_href": _text(cve.get("href")),
        "cvss2_score": cve.get("cvss"),
        "cvss2_severity": _text(cve.get("severity")),
        "cvss2_vector": _text(cve.get("vector")),
        "cvss3_score": cvss3.get("score"),
        "cvss3_severity": _text(cvss3.get("severity")),
        "cvss3_vector": _text(cvss3.get("vector")),
        "cwe_id": _text(cwe.get("id")),
        "cwe_name": _text(cwe.get("name")),
        "title": "",
        "description": _text(raw.get("description")),
        "component_id": _text(details.get("component_id")),
        "component_filename": filename,
        "component_name": filename,
        "component_version": _text(details.get("version")),
        "language": _text(details.get("language")),
        "component_paths": paths,
        "licenses": licenses,
        "product_id": _text(details.get("product_id")),
        "library_id": "",
        "library_ref": "",
        "library_ref_source": "",
        "direct": _dependency_flag(meta.get("sca_dep_mode"), direct=True),
        "transitive": _dependency_flag(meta.get("sca_dep_mode"), direct=False),
        "vulnerable_method": None,
        "epss_score": exploit.get("epss_score"),
        "epss_percentile": exploit.get("epss_percentile"),
        "epss_score_date": _text(exploit.get("epss_score_date")),
        "exploit_observed": exploit.get("exploit_observed"),
        "exploit_source": _text(exploit.get("exploit_source")),
        "exploit_note": _text(exploit.get("exploit_note")),
        "fixed_version": "",
        "latest_safe_version": "",
        "safe_versions": [],
        "latest_release_version": "",
        "recommended_safe_version": "",
        "enrichment_status": "",
        "enrichment_detail": "",
    }


def finding_from_issue(
    raw: dict[str, Any],
    *,
    workspace_id: str,
    workspace_name: str,
) -> dict[str, Any]:
    library = raw.get("library") if isinstance(raw.get("library"), dict) else {}
    vuln = raw.get("vulnerability") if isinstance(raw.get("vulnerability"), dict) else {}
    exploit = vuln.get("exploitability") if isinstance(vuln.get("exploitability"), dict) else {}
    license_obj = raw.get("license") if isinstance(raw.get("license"), dict) else {}
    library_id = _text(library.get("id"))
    library_ref = library_id if looks_like_library_ref(library_id) else ""
    fix = raw.get("fix_info") if isinstance(raw.get("fix_info"), dict) else {}
    direct = library.get("direct")
    transitive = library.get("transitive")
    if direct is True:
        dep = "DIRECT"
    elif transitive is True:
        dep = "TRANSITIVE"
    else:
        dep = ""
    return {
        "source": "sca_agent",
        "sources": ["sca_agent"],
        "scan_type": "SCA",
        "scan_mode": "AGENT",
        "dependency_mode": dep,
        "application_name": "",
        "application_guid": "",
        "workspace_id": workspace_id,
        "workspace_name": workspace_name,
        "project_id": _text(raw.get("project_id")),
        "project_name": _text(raw.get("project_name")),
        "project_branch": _text(raw.get("project_branch")),
        "issue_id": _text(raw.get("id")),
        "issue_status": _text(raw.get("issue_status")),
        "issue_type": _text(raw.get("issue_type")),
        "resolution": "",
        "resolution_status": "",
        "first_found_date": _text(raw.get("created_date")),
        "last_seen_date": "",
        "is_new": None,
        "violates_policy": None,
        "policy_severity": raw.get("severity"),
        "cve": _text(vuln.get("cve")),
        "cve_href": "",
        "cvss2_score": vuln.get("cvss2_score"),
        "cvss2_severity": "",
        "cvss2_vector": _text(vuln.get("cvss2_vector")),
        "cvss3_score": vuln.get("cvss3_score"),
        "cvss3_severity": "",
        "cvss3_vector": _text(vuln.get("cvss3_vector")),
        "cwe_id": _text(vuln.get("cwe_id")),
        "cwe_name": "",
        "title": _text(vuln.get("title")) or _text(license_obj.get("name")),
        "description": _text(vuln.get("title")),
        "component_id": "",
        "component_filename": _text(library.get("name")),
        "component_name": _text(library.get("name")),
        "component_version": _text(library.get("version")),
        "language": "",
        "component_paths": _paths_from_issue(raw),
        "licenses": [license_obj.get("name")] if license_obj.get("name") else [],
        "product_id": "",
        "library_id": library_id,
        "library_ref": library_ref,
        "library_ref_source": "library_id" if library_ref else "",
        "direct": direct,
        "transitive": transitive,
        "vulnerable_method": raw.get("vulnerable_method"),
        "ignored": raw.get("ignored"),
        "epss_score": exploit.get("epss_score"),
        "epss_percentile": exploit.get("epss_percentile"),
        "epss_score_date": _text(exploit.get("epss_score_date")),
        "exploit_observed": exploit.get("exploit_observed"),
        "exploit_source": _text(exploit.get("exploit_source")),
        "exploit_note": _text(exploit.get("exploit_note")),
        "fixed_version": _text(fix.get("fixed_version")),
        "latest_safe_version": _text(fix.get("latest_safe_version")),
        "safe_versions": [],
        "latest_release_version": _text(library.get("latest_version")),
        "recommended_safe_version": "",
        "enrichment_status": "",
        "enrichment_detail": "",
    }


def components_from_cyclonedx(document: dict[str, Any], *, target: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for component in document.get("components") or []:
        if not isinstance(component, dict):
            continue
        rows.append(_component_row(component, target=target, sbom_format="cyclonedx"))
    return rows


def vulnerabilities_from_cyclonedx(document: dict[str, Any], *, target: dict[str, Any]) -> list[dict[str, Any]]:
    by_ref = {}
    for component in document.get("components") or []:
        if isinstance(component, dict) and component.get("bom-ref"):
            by_ref[str(component["bom-ref"])] = component
    rows = []
    for vuln in document.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        ratings = vuln.get("ratings") if isinstance(vuln.get("ratings"), list) else []
        score = ""
        severity = ""
        vector = ""
        if ratings and isinstance(ratings[0], dict):
            score = ratings[0].get("score", "")
            severity = _text(ratings[0].get("severity"))
            vector = _text(ratings[0].get("vector"))
        affects = []
        for item in vuln.get("affects") or []:
            if isinstance(item, dict) and item.get("ref"):
                affects.append(str(item["ref"]))
            elif isinstance(item, str):
                affects.append(item)
        cwes = []
        for cwe in vuln.get("cwes") or []:
            if isinstance(cwe, dict) and cwe.get("id") is not None:
                cwes.append(str(cwe["id"]))
            elif isinstance(cwe, (str, int)):
                cwes.append(str(cwe))
        source = vuln.get("source") if isinstance(vuln.get("source"), dict) else {}
        rows.append(
            {
                **target,
                "sbom_format": "cyclonedx",
                "vulnerability_id": _text(vuln.get("id")),
                "source_name": _text(source.get("name")),
                "source_url": _text(source.get("url")),
                "description": _text(vuln.get("description")),
                "score": score,
                "severity": severity,
                "vector": vector,
                "cwes": cwes,
                "affects": affects,
                "affected_components": [_component_label(by_ref.get(ref), ref) for ref in affects],
            }
        )
    return rows


def dependencies_from_cyclonedx(document: dict[str, Any], *, target: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in document.get("dependencies") or []:
        if not isinstance(item, dict):
            continue
        parent = _text(item.get("ref"))
        depends = item.get("dependsOn") or item.get("depends_on") or []
        if isinstance(depends, str):
            depends = [depends]
        for child in depends:
            rows.append({**target, "sbom_format": "cyclonedx", "ref": parent, "depends_on": _text(child)})
    return rows


def components_from_spdx(document: dict[str, Any], *, target: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for package in document.get("packages") or []:
        if not isinstance(package, dict):
            continue
        description = _text(package.get("description"))
        library_ref = description if looks_like_library_ref(description) else ""
        version = _text(package.get("versionInfo") or package.get("version"))
        if not version and library_ref:
            version = _version_from_ref(library_ref)
        licenses = [
            item
            for item in (
                _text(package.get("licenseConcluded")),
                _text(package.get("licenseDeclared")),
            )
            if item and item.upper() not in {"NOASSERTION", "NONE"}
        ]
        rows.append(
            {
                **target,
                "sbom_format": "spdx",
                "bom_ref": _text(package.get("SPDXID")),
                "name": _text(package.get("name")),
                "group": "",
                "version": version,
                "purl": "",
                "type": "library",
                "licenses": licenses,
                "hashes": [],
                "library_ref": library_ref,
                "library_ref_source": "spdx_description" if library_ref else "",
                "description": description,
            }
        )
    return rows


def dependencies_from_spdx(document: dict[str, Any], *, target: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in document.get("relationships") or []:
        if not isinstance(item, dict):
            continue
        relationship = _text(item.get("relationshipType")).upper()
        if relationship and relationship not in {"DEPENDS_ON", "DEPENDENCY_OF"}:
            continue
        left = _text(item.get("spdxElementId"))
        right = _text(item.get("relatedSpdxElement"))
        if relationship == "DEPENDENCY_OF":
            left, right = right, left
        if left or right:
            rows.append({**target, "sbom_format": "spdx", "ref": left, "depends_on": right})
    return rows


def finding_from_sbom_vulnerability(
    vuln: dict[str, Any],
    components: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """One findings row per affected component of an SBOM vulnerability."""
    by_label = {}
    by_ref = {}
    for component in components:
        by_ref[component.get("bom_ref") or ""] = component
        by_ref[component.get("purl") or ""] = component
        by_label[_component_label(component, "")] = component
    affects = vuln.get("affects") or [""]
    rows = []
    for ref in affects:
        component = by_ref.get(ref) or by_label.get(ref) or {}
        rows.append(
            {
                "source": "sbom",
                "sources": ["sbom"],
                "scan_type": "SCA",
                "scan_mode": _upper(vuln.get("scan_mode")),
                "dependency_mode": "",
                "application_name": _text(vuln.get("application_name")),
                "application_guid": _text(vuln.get("application_guid")),
                "workspace_id": _text(vuln.get("workspace_id")),
                "workspace_name": _text(vuln.get("workspace_name")),
                "project_id": _text(vuln.get("project_id")),
                "project_name": _text(vuln.get("project_name")),
                "project_branch": "",
                "issue_id": "",
                "issue_status": "OPEN",
                "resolution": "",
                "resolution_status": "",
                "first_found_date": "",
                "last_seen_date": "",
                "is_new": None,
                "violates_policy": None,
                "policy_severity": vuln.get("severity"),
                "cve": _text(vuln.get("vulnerability_id")),
                "cve_href": _text(vuln.get("source_url")),
                "cvss2_score": vuln.get("score"),
                "cvss2_severity": _text(vuln.get("severity")),
                "cvss2_vector": _text(vuln.get("vector")),
                "cvss3_score": "",
                "cvss3_severity": "",
                "cvss3_vector": "",
                "cwe_id": ", ".join(vuln.get("cwes") or []),
                "cwe_name": "",
                "title": _text(vuln.get("vulnerability_id")),
                "description": _text(vuln.get("description")),
                "component_id": "",
                "component_filename": _text(component.get("name")),
                "component_name": _text(component.get("name")),
                "component_version": _text(component.get("version")),
                "language": "",
                "component_paths": [],
                "licenses": list(component.get("licenses") or []),
                "product_id": "",
                "library_id": "",
                "library_ref": _text(component.get("library_ref")),
                "library_ref_source": _text(component.get("library_ref_source")),
                "direct": None,
                "transitive": None,
                "vulnerable_method": None,
                "epss_score": "",
                "epss_percentile": "",
                "epss_score_date": "",
                "exploit_observed": "",
                "exploit_source": "",
                "exploit_note": "",
                "fixed_version": "",
                "latest_safe_version": "",
                "safe_versions": [],
                "latest_release_version": "",
                "recommended_safe_version": "",
                "enrichment_status": "",
                "enrichment_detail": "",
            }
        )
    return rows


def _component_row(component: dict[str, Any], *, target: dict[str, Any], sbom_format: str) -> dict[str, Any]:
    properties = component.get("properties") if isinstance(component.get("properties"), list) else []
    property_map = {}
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name"):
            property_map[str(prop["name"])] = prop.get("value")
    purl = _text(component.get("purl"))
    library_ref = (
        find_library_ref(property_map, component.get("description"), component.get("bom-ref"))
        or library_ref_from_purl(purl)
        or ""
    )
    source = "purl" if library_ref and library_ref == library_ref_from_purl(purl) else ""
    if library_ref and not source:
        source = "component_property"
    hashes = []
    for item in component.get("hashes") or []:
        if isinstance(item, dict) and item.get("content"):
            hashes.append(f"{item.get('alg') or ''}:{item.get('content')}")
    return {
        **target,
        "sbom_format": sbom_format,
        "bom_ref": _text(component.get("bom-ref")),
        "name": _text(component.get("name")),
        "group": _text(component.get("group")),
        "version": _text(component.get("version")),
        "purl": purl,
        "type": _text(component.get("type")),
        "licenses": _license_names(component.get("licenses")),
        "hashes": hashes,
        "library_ref": library_ref,
        "library_ref_source": source,
        "description": "",
    }


def _license_names(value: Any) -> list[str]:
    names: list[str] = []
    if not isinstance(value, list):
        return names
    for item in value:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            license_obj = item.get("license") if isinstance(item.get("license"), dict) else item
            name = license_obj.get("id") or license_obj.get("name") or item.get("expression")
            if name:
                names.append(str(name))
    return names


def _license_ids(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    names = []
    for item in value:
        if isinstance(item, dict) and item.get("license_id"):
            names.append(str(item["license_id"]))
        elif isinstance(item, str):
            names.append(item)
    return names


def _paths_from_issue(raw: dict[str, Any]) -> list[str]:
    paths = []
    for key in ("component_file_path",):
        if raw.get(key):
            paths.append(str(raw[key]))
    extra = raw.get("component_file_paths")
    if isinstance(extra, list):
        paths.extend(str(item) for item in extra if item)
    return paths


def _component_label(component: dict[str, Any] | None, fallback: str) -> str:
    if not component:
        return fallback
    name = component.get("name") or ""
    version = component.get("version") or ""
    if name and version:
        return f"{name}@{version}"
    return str(name or component.get("purl") or fallback)


def _version_from_ref(library_ref: str) -> str:
    parts = library_ref.split(":")
    if len(parts) < 5:
        return ""
    return ":".join(parts[3:-1])


def _dependency_flag(mode: Any, *, direct: bool) -> bool | None:
    text = _upper(mode)
    if text == "DIRECT":
        return direct
    if text == "TRANSITIVE":
        return not direct
    if text == "BOTH":
        return True
    return None


def _upper(value: Any) -> str:
    return str(value or "").strip().upper()


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()
