from sbom_findings.client import VeracodeError
from sbom_findings.enrich import SafeVersionEnricher, attach_library_refs, merge_sources
from sbom_findings.registry import unique_maven_ref


def test_jar_filename_takes_the_sbom_coordinate():
    finding = {
        "component_filename": "commons-collections4-4.0.jar",
        "component_name": "commons-collections4-4.0.jar",
        "component_version": "4.0",
        "application_guid": "app",
        "library_ref": "",
    }
    attach_library_refs(
        [finding],
        [
            {
                "name": "commons-collections4",
                "version": "4.0",
                "library_ref": "maven:org.apache.commons:commons-collections4:4.0:",
                "application_guid": "app",
            }
        ],
    )
    assert finding["library_ref"] == "maven:org.apache.commons:commons-collections4:4.0:"
    assert finding["library_ref_source"] == "sbom"


def test_workspace_library_id_is_used_when_no_sbom_exists():
    finding = {
        "component_filename": "log4j-1.2.8.jar",
        "component_name": "log4j-1.2.8.jar",
        "component_version": "1.2.8",
        "application_guid": "old-app",
        "library_ref": "",
    }
    attach_library_refs(
        [finding],
        [
            {
                "name": "log4j",
                "version": "1.2.8",
                "library_ref": "maven:log4j:log4j:1.2.8:",
                "workspace_id": "ws",
                "application_guid": "",
                "project_id": "",
            }
        ],
    )
    assert finding["library_ref"] == "maven:log4j:log4j:1.2.8:"
    assert finding["library_ref_source"] == "catalog"


def test_trailing_dot_coordinate_loses_to_the_clean_one():
    finding = {
        "component_name": "spring-web",
        "component_version": "5.2.7.RELEASE",
        "application_guid": "app",
        "library_ref": "",
    }
    attach_library_refs(
        [finding],
        [
            {
                "name": "spring-web",
                "version": "5.2.7.RELEASE",
                "library_ref": "maven:org.springframework.:spring-web:5.2.7.RELEASE:",
                "application_guid": "app",
            },
            {
                "name": "spring-web",
                "version": "5.2.7.RELEASE",
                "library_ref": "maven:org.springframework:spring-web:5.2.7.RELEASE:",
                "application_guid": "app",
            },
        ],
    )
    assert finding["library_ref"] == "maven:org.springframework:spring-web:5.2.7.RELEASE:"


def test_linked_sbom_row_folds_into_the_upload_finding():
    upload = {
        "source": "findings_api",
        "sources": ["findings_api"],
        "cve": "CVE-2015-7501",
        "component_name": "commons-collections4-4.0.jar",
        "component_filename": "commons-collections4-4.0.jar",
        "component_version": "4.0",
        "scan_mode": "UPLOAD",
        "application_guid": "app",
        "project_id": "",
        "library_ref": "",
    }
    linked = {
        "source": "sbom",
        "sources": ["sbom"],
        "cve": "CVE-2015-7501",
        "component_name": "commons-collections4",
        "component_filename": "commons-collections4",
        "component_version": "4.0",
        "scan_mode": "UPLOAD+AGENT",
        "application_guid": "app",
        "project_id": "",
        "library_ref": "maven:org.apache.commons:commons-collections4:4.0:",
    }
    folded = merge_sources([upload, linked])
    assert len(folded) == 1
    assert folded[0]["library_ref"].endswith("commons-collections4:4.0:")
    assert "sbom" in folded[0]["sources"]


def test_registry_confirms_a_maven_coordinate(monkeypatch):
    calls = []

    def activity(client, library_ref):
        calls.append(library_ref)
        if library_ref == "maven:org.springframework:spring-webmvc:4.3.10.RELEASE:":
            return {
                "safe_versions": ["5.3.27"],
                "library": {
                    "name": "spring-webmvc",
                    "coordinate1": "org.springframework",
                    "coordinate2": "spring-webmvc",
                    "latest_release_version": "6.1.0",
                },
            }
        raise VeracodeError("missing", status=404, path=library_ref)

    monkeypatch.setattr("sbom_findings.enrich.get_component_activity", activity)
    monkeypatch.setattr(
        "sbom_findings.enrich.search_maven_ref",
        lambda artifact, version: "maven:org.springframework:spring-webmvc:4.3.10.RELEASE:",
    )
    finding = {
        "sources": ["findings_api"],
        "source": "findings_api",
        "language": "JAVA",
        "component_filename": "spring-webmvc-4.3.10.RELEASE.jar",
        "component_name": "spring-webmvc-4.3.10.RELEASE.jar",
        "component_version": "4.3.10.RELEASE",
        "library_ref": "",
        "issue_id": "12",
    }
    SafeVersionEnricher(client=None).enrich(finding)
    assert finding["library_ref"] == "maven:org.springframework:spring-webmvc:4.3.10.RELEASE:"
    assert finding["recommended_safe_version"] == "5.3.27"
    assert finding["enrichment_status"] == "enriched"
    assert calls[0] == "maven:spring-webmvc:spring-webmvc:4.3.10.RELEASE:"


def test_recommended_version_prefers_the_latest_release_over_a_timestamp():
    from sbom_findings.enrich import _recommended_version

    safe = ["3.2.2", "20031027.000000", "20040102.233541"]
    assert _recommended_version("", "", safe, "3.2.2") == "3.2.2"
    assert _recommended_version("2.5.1", "2.4.2", ["2.4.2", "2.5.1"], "2.5.1") == "2.5.1"


def test_unique_maven_ref_requires_one_group():
    docs = [{"g": "log4j", "a": "log4j", "v": "1.2.8"}]
    assert unique_maven_ref("log4j", "1.2.8", docs) == "maven:log4j:log4j:1.2.8:"
    docs.append({"g": "org.apache.logging.log4j", "a": "log4j", "v": "1.2.8"})
    assert unique_maven_ref("log4j", "1.2.8", docs) is None
    assert unique_maven_ref("log4j", "1.2.8", [{"g": "../evil", "a": "log4j", "v": "1.2.8"}]) is None
