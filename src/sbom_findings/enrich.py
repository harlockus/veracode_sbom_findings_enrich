"""Add SourceClear safe versions to each vulnerability row.

Two registry calls are used, both from SCA Agent API 3.0:

* ``GET /srcclr/v3/issues/{id}`` returns ``fix_info.fixed_version`` and
  ``fix_info.latest_safe_version`` for that vulnerability.
* ``GET /srcclr/v3/component-activity/{libraryRef}`` returns
  ``safe_versions`` and ``library.latest_release_version`` for the
  library instance. Upload findings have no issue id, so they use this
  call after the library reference is recovered from the SBOM.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from sbom_findings.client import VeracodeClient, VeracodeError
from sbom_findings.coordinates import artifact_name, library_ref_from_purl, looks_like_library_ref
from sbom_findings.registry import search_maven_ref
from sbom_findings.resources import get_component_activity, get_issue

log = logging.getLogger("sbom_findings.enrich")

_LANGUAGE_TYPE = {
    "JAVASCRIPT": "npm",
    "JS": "npm",
    "NODE": "npm",
    "PYTHON": "pypi",
    "RUBY": "gem",
    "CSHARP": "nuget",
    "DOTNET": "nuget",
    "GO": "go",
    "GOLANG": "go",
    "PHP": "composer",
}


class SafeVersionEnricher:
    def __init__(self, client: VeracodeClient):
        self.client = client
        self._issues: dict[str, dict[str, Any] | Exception] = {}
        self._activity: dict[str, dict[str, Any] | Exception] = {}
        self._maven: dict[tuple[str, str], str] = {}
        self.calls = 0

    def enrich(self, finding: dict[str, Any]) -> dict[str, Any]:
        fix_fixed = finding.get("fixed_version") or ""
        fix_latest = finding.get("latest_safe_version") or ""
        issue_id = finding.get("issue_id") or ""
        # Findings API issue ids are integers and are not SourceClear issue UUIDs.
        sources = finding.get("sources") or [finding.get("source")]
        if "sca_agent" in sources and _looks_uuid(issue_id):
            detail = self._issue(issue_id)
            if isinstance(detail, dict):
                fix = detail.get("fix_info") if isinstance(detail.get("fix_info"), dict) else {}
                fix_fixed = fix_fixed or _text(fix.get("fixed_version"))
                fix_latest = fix_latest or _text(fix.get("latest_safe_version"))
                library = detail.get("library") if isinstance(detail.get("library"), dict) else {}
                library_id = _text(library.get("id"))
                if looks_like_library_ref(library_id) and not finding.get("library_ref"):
                    finding["library_ref"] = library_id
                    finding["library_ref_source"] = "issue_detail"
                if library.get("latest_version") and not finding.get("latest_release_version"):
                    finding["latest_release_version"] = _text(library.get("latest_version"))
                methods = detail.get("vulnerable_methods")
                if methods and not finding.get("vulnerable_methods"):
                    finding["vulnerable_methods"] = _method_summaries(methods)
            elif isinstance(detail, VeracodeError) and detail.status == 403:
                finding["enrichment_status"] = "forbidden"
                finding["enrichment_detail"] = (
                    "SourceClear issue detail requires a UI user API credential"
                )

        library_ref = finding.get("library_ref") or ""
        if not library_ref:
            guessed = _guess_ref(finding)
            if guessed:
                library_ref = guessed
                finding["library_ref"] = guessed
                finding["library_ref_source"] = finding.get("library_ref_source") or "language_guess"
        if not library_ref and _is_jvm(finding):
            resolved = self._resolve_jvm(finding)
            if resolved:
                library_ref = resolved
                finding["library_ref"] = resolved
                finding["library_ref_source"] = "registry"

        safe_versions: list[str] = list(finding.get("safe_versions") or [])
        latest_release = finding.get("latest_release_version") or ""
        activity_error = ""
        if library_ref:
            activity = self._activity_for(library_ref)
            if isinstance(activity, dict):
                safe_versions = _string_list(activity.get("safe_versions")) or safe_versions
                library = activity.get("library") if isinstance(activity.get("library"), dict) else {}
                latest_release = latest_release or _text(library.get("latest_release_version"))
            elif isinstance(activity, VeracodeError):
                if activity.status == 403 and finding.get("enrichment_status") != "forbidden":
                    finding["enrichment_status"] = "forbidden"
                    finding["enrichment_detail"] = (
                        "SourceClear component activity requires a UI user API credential"
                    )
                elif activity.status == 404:
                    activity_error = "component not in the SourceClear registry"
                else:
                    activity_error = f"component activity HTTP {activity.status}"

        recommended = _recommended_version(fix_latest, fix_fixed, safe_versions, latest_release)
        finding["fixed_version"] = fix_fixed
        finding["latest_safe_version"] = fix_latest
        finding["safe_versions"] = safe_versions
        finding["latest_release_version"] = latest_release
        finding["recommended_safe_version"] = recommended
        if finding.get("enrichment_status") == "forbidden":
            return finding
        if recommended or safe_versions:
            finding["enrichment_status"] = "enriched"
            finding["enrichment_detail"] = activity_error
        elif not library_ref and "sca_agent" not in (finding.get("sources") or []):
            finding["enrichment_status"] = "missing_coordinates"
            finding["enrichment_detail"] = "No library reference in the issue, SBOM, or package URL"
        elif activity_error:
            finding["enrichment_status"] = "not_in_registry"
            finding["enrichment_detail"] = activity_error
        else:
            finding["enrichment_status"] = "no_safe_version"
            finding["enrichment_detail"] = "Registry returned no safe version for this library"
        return finding

    def _issue(self, issue_id: str) -> dict[str, Any] | Exception:
        cached = self._issues.get(issue_id)
        if cached is not None:
            return cached if not isinstance(cached, Exception) else cached
        self.calls += 1
        try:
            payload = get_issue(self.client, issue_id)
        except VeracodeError as exc:
            self._issues[issue_id] = exc
            log.warning("issue %s enrichment failed: HTTP %s", issue_id, exc.status)
            return exc
        self._issues[issue_id] = payload
        return payload

    def _resolve_jvm(self, finding: dict[str, Any]) -> str:
        """Find a Maven library reference and keep it only when the registry agrees."""
        artifact = artifact_name(
            finding.get("component_filename") or finding.get("component_name"),
            finding.get("component_version"),
        )
        version = str(finding.get("component_version") or "").strip()
        if not artifact or not version:
            return ""
        cache_key = (artifact, version)
        cached = self._maven.get(cache_key)
        if cached is not None:
            return cached
        conventional = f"maven:{artifact}:{artifact}:{version}:"
        activity = self._activity_for(conventional)
        if isinstance(activity, dict) and _library_matches(activity, artifact):
            self._maven[cache_key] = conventional
            return conventional
        discovered = search_maven_ref(artifact, version)
        if discovered and discovered != conventional:
            activity = self._activity_for(discovered)
            if isinstance(activity, dict) and _library_matches(activity, artifact):
                self._maven[cache_key] = discovered
                return discovered
        self._maven[cache_key] = ""
        return ""

    def _activity_for(self, library_ref: str) -> dict[str, Any] | Exception:
        cached = self._activity.get(library_ref)
        if cached is not None:
            return cached
        self.calls += 1
        try:
            payload = get_component_activity(self.client, library_ref)
        except VeracodeError as exc:
            self._activity[library_ref] = exc
            log.warning("component activity failed for %s: HTTP %s", library_ref, exc.status)
            return exc
        self._activity[library_ref] = payload
        return payload


def attach_library_refs(findings: list[dict[str, Any]], components: list[dict[str, Any]]) -> None:
    """Copy library references from SBOMs and workspace libraries onto findings.

    Match the package name and version. A finding filename such as
    ``commons-io-2.4.jar`` matches a component named ``commons-io``.
    """
    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    global_refs: dict[tuple[str, str], set[str]] = defaultdict(set)
    for component in components:
        ref = component.get("library_ref") or ""
        if not looks_like_library_ref(ref):
            continue
        target = component.get("project_id") or component.get("application_guid") or ""
        by_target[target].append(component)
        name = artifact_name(component.get("name") or component.get("filename"), component.get("version")).lower()
        version = str(component.get("version") or "")
        if name:
            global_refs[(name, version)].add(ref)
    for finding in findings:
        if finding.get("library_ref"):
            continue
        name = artifact_name(
            finding.get("component_filename") or finding.get("component_name"),
            finding.get("component_version"),
        ).lower()
        version = str(finding.get("component_version") or "")
        if not name:
            continue
        pool: list[dict[str, Any]] = []
        for key in (finding.get("project_id"), finding.get("application_guid")):
            if key:
                pool.extend(by_target.get(key, []))
        matched = [
            component["library_ref"]
            for component in pool
            if artifact_name(component.get("name") or component.get("filename"), component.get("version")).lower()
            == name
            and str(component.get("version") or "") == version
        ]
        chosen = _choose_ref(matched)
        if chosen:
            finding["library_ref"] = chosen
            finding["library_ref_source"] = _ref_source(pool, chosen)
            continue
        everywhere = _choose_ref(list(global_refs.get((name, version)) or []))
        if everywhere:
            finding["library_ref"] = everywhere
            finding["library_ref_source"] = "catalog"


def merge_sources(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold duplicate CVE rows that describe the same component and scan mode.

    Upload and agent rows stay separate. Rows with the same project id fold
    together. A Findings API row has no project id; it folds into the agent
    issue only when that application has one matching project row. Two agent
    projects stay separate.
    """
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        groups[_loose(finding)].append(finding)
    merged: list[dict[str, Any]] = []
    for rows in groups.values():
        with_project = [row for row in rows if row.get("project_id")]
        without_project = [row for row in rows if not row.get("project_id")]
        if len(with_project) == 1 and without_project:
            base = with_project[0]
            for extra in without_project:
                _prefer(base, extra)
            merged.append(base)
            continue
        by_project: dict[str, dict[str, Any]] = {}
        for row in with_project + without_project:
            key = str(row.get("project_id") or "")
            current = by_project.get(key)
            if current is None:
                by_project[key] = row
                merged.append(row)
                continue
            _prefer(current, row)
    return merged


def _loose(finding: dict[str, Any]) -> tuple[str, ...]:
    return _identity(finding)[:-1]


def component_identity(finding: dict[str, Any]) -> tuple[str, str, str]:
    """CVE, package name, and version used to fold the same vulnerability."""
    name = artifact_name(
        finding.get("component_filename") or finding.get("component_name"),
        finding.get("component_version"),
    ).lower()
    return (
        (finding.get("cve") or "").upper(),
        name,
        str(finding.get("component_version") or ""),
    )


def scope_mode(finding: dict[str, Any]) -> str:
    """Treat an application linked SBOM as the same scope as the upload scan.

    ``UPLOAD+AGENT`` is the application CycloneDX document with linked agent
    projects folded in. It is not a separate agent project.
    """
    mode = (finding.get("scan_mode") or "").upper()
    if mode in {"UPLOAD+AGENT", "BOTH"} and not finding.get("project_id"):
        return "UPLOAD"
    return mode


def _identity(finding: dict[str, Any]) -> tuple[str, ...]:
    cve, name, version = component_identity(finding)
    return (
        cve,
        name,
        version,
        scope_mode(finding),
        finding.get("application_guid") or "",
        finding.get("project_id") or "",
    )


def _prefer(left: dict[str, Any], right: dict[str, Any]) -> None:
    sources = list(dict.fromkeys([*(left.get("sources") or []), *(right.get("sources") or [])]))
    left["sources"] = sources
    left["source"] = "+".join(sources)
    for field in (
        "library_ref",
        "library_ref_source",
        "fixed_version",
        "latest_safe_version",
        "latest_release_version",
        "workspace_id",
        "workspace_name",
        "project_id",
        "project_name",
        "project_branch",
        "description",
        "title",
        "cwe_name",
        "exploit_source",
        "exploit_note",
    ):
        if field == "project_id" and left.get(field):
            continue
        if not left.get(field) and right.get(field):
            left[field] = right[field]
    if not left.get("safe_versions") and right.get("safe_versions"):
        left["safe_versions"] = right["safe_versions"]
    if left.get("epss_score") in (None, "") and right.get("epss_score") not in (None, ""):
        left["epss_score"] = right["epss_score"]
        left["epss_percentile"] = right.get("epss_percentile")
    if left.get("vulnerable_method") is None and right.get("vulnerable_method") is not None:
        left["vulnerable_method"] = right["vulnerable_method"]
    if _looks_uuid(str(right.get("issue_id") or "")) and not _looks_uuid(str(left.get("issue_id") or "")):
        left["issue_id"] = right["issue_id"]


def _ref_source(pool: list[dict[str, Any]], chosen: str) -> str:
    for component in pool:
        if component.get("library_ref") != chosen:
            continue
        if component.get("application_guid") or component.get("project_id"):
            return "sbom"
        if component.get("workspace_id"):
            return "workspace_library"
    return "sbom"


def _choose_ref(refs: list[str]) -> str:
    """Pick one reference. Ignore a coordinate that only differs by a trailing dot."""
    ordered = list(dict.fromkeys(ref for ref in refs if ref))
    clean = [ref for ref in ordered if not any(part.endswith(".") for part in ref.split(":"))]
    pool = clean or ordered
    if len(pool) == 1:
        return pool[0]
    return ""


def _recommended_version(
    latest_safe: str,
    fixed: str,
    safe_versions: list[str],
    latest_release: str,
) -> str:
    """Choose the safe version to show.

    ``latest_safe_version`` from the issue wins. Otherwise use the registry
    latest release when that release is one of the safe versions. The
    ``safe_versions`` list is not ordered, so the last entry is not used.
    """
    if latest_safe:
        return latest_safe
    if latest_release and latest_release in safe_versions:
        return latest_release
    releases = [version for version in safe_versions if not _timestamp_version(version)]
    if releases:
        return releases[0]
    if safe_versions:
        return safe_versions[0]
    return fixed


def _timestamp_version(version: str) -> bool:
    digits = version.replace(".", "")
    return digits.isdigit() and len(digits) >= 8


def _library_matches(activity: dict[str, Any], artifact: str) -> bool:
    library = activity.get("library") if isinstance(activity.get("library"), dict) else {}
    expected = artifact.lower()
    names = {
        _text(library.get("name")).lower(),
        _text(library.get("coordinate1")).lower(),
        _text(library.get("coordinate2")).lower(),
    }
    names.discard("")
    return expected in names


def _is_jvm(finding: dict[str, Any]) -> bool:
    language = (finding.get("language") or "").upper()
    if language in {"JAVA", "SCALA", "KOTLIN"}:
        return True
    filename = (finding.get("component_filename") or finding.get("component_name") or "").lower()
    return filename.endswith(".jar")


def _guess_ref(finding: dict[str, Any]) -> str:
    """Guess a registry id when the SBOM did not supply one.

    Maven and Go are skipped: the Findings API does not return the Maven
    group id or the Go module path, and a wrong guess would attach a safe
    version from a different component.
    """
    language = (finding.get("language") or "").upper()
    if language in {"JAVA", "SCALA", "KOTLIN", "GO", "GOLANG"}:
        return ""
    coord_type = _LANGUAGE_TYPE.get(language)
    name = finding.get("component_filename") or finding.get("component_name") or ""
    version = finding.get("component_version") or ""
    if not coord_type or not name or not version:
        return ""
    return library_ref_from_purl(f"pkg:{coord_type}/{name}@{version}") or ""


def _method_summaries(methods: Any) -> list[str]:
    if not isinstance(methods, list):
        return []
    lines = []
    for method in methods:
        if not isinstance(method, dict):
            continue
        summary = method.get("method") if isinstance(method.get("method"), dict) else method
        name = ""
        if isinstance(summary, dict):
            name = _text(summary.get("name") or summary.get("method_name") or summary.get("descriptor"))
        line = method.get("line_number") or method.get("line")
        if name and line:
            lines.append(f"{name}:{line}")
        elif name:
            lines.append(name)
    return lines


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item not in (None, "")]


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _looks_uuid(value: str) -> bool:
    parts = value.split("-")
    return len(parts) == 5 and all(part.isalnum() for part in parts)
