from sbom_findings.enrich import merge_sources
from sbom_findings.normalize import (
    components_from_spdx,
    finding_from_api,
    finding_from_issue,
    is_open_status,
)


FINDING = {
    "scan_type": "SCA",
    "description": "console-io auth bypass",
    "violates_policy": False,
    "issue_id": 42,
    "finding_status": {"status": "OPEN", "resolution": "UNRESOLVED", "first_found_date": "2023-04-20T16:35:49.354Z"},
    "finding_details": {
        "severity": 5,
        "component_filename": "console-io",
        "version": "2.6.3",
        "language": "JAVASCRIPT",
        "metadata": {"sca_scan_mode": "UPLOAD", "sca_dep_mode": "UNKNOWN"},
        "cve": {
            "name": "CVE-2016-10532",
            "cvss": 10,
            "cvss3": {"score": 9.8, "severity": "Very High", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "exploitability": {"epss_score": 0.38, "exploit_observed": True, "exploit_source": "KEV"},
        },
        "cwe": {"id": 287, "name": "Improper Authentication"},
        "component_path": [{"path": "node_modules/console-io"}],
        "licenses": [{"license_id": "mit", "risk_rating": "2"}],
    },
}


def test_open_status_keeps_open_and_blank_only():
    assert is_open_status("OPEN")
    assert is_open_status("open")
    assert is_open_status("")
    assert is_open_status(None)
    assert not is_open_status("CLOSED")
    assert not is_open_status("fixed")


def test_findings_api_sca_example_shape():
    row = finding_from_api(FINDING, application_name="verademo", application_guid="app")
    assert row["scan_mode"] == "UPLOAD"
    assert row["cve"] == "CVE-2016-10532"
    assert row["cvss3_score"] == 9.8
    assert row["component_paths"] == ["node_modules/console-io"]
    assert row["exploit_observed"] is True
    assert row["licenses"] == ["mit"]
    assert row["application_name"] == "verademo"


def test_agent_issue_keeps_coordinate_id_and_fix_info():
    row = finding_from_issue(
        {
            "id": "44444444-4444-4444-4444-444444444444",
            "issue_status": "open",
            "issue_type": "vulnerability",
            "project_name": "verademo-src",
            "library": {
                "id": "maven:net.minidev:json-smart:1.3.1:",
                "name": "json-smart",
                "version": "1.3.1",
                "direct": True,
                "latest_version": "2.5.1",
            },
            "vulnerability": {"cve": "CVE-2023-1370", "cvss3_score": 7.5, "title": "stack overflow"},
            "fix_info": {"fixed_version": "2.4.2", "latest_safe_version": "2.5.1"},
        },
        workspace_id="ws",
        workspace_name="demo",
    )
    assert row["library_ref"] == "maven:net.minidev:json-smart:1.3.1:"
    assert row["fixed_version"] == "2.4.2"
    assert row["dependency_mode"] == "DIRECT"
    assert row["scan_mode"] == "AGENT"


def test_findings_api_agent_row_folds_into_the_single_project_issue():
    api = {
        "source": "findings_api",
        "sources": ["findings_api"],
        "cve": "CVE-2023-1370",
        "component_name": "json-smart",
        "component_version": "1.3.1",
        "scan_mode": "AGENT",
        "application_guid": "app",
        "project_id": "",
        "issue_id": 42,
        "description": "from findings",
    }
    issue = {
        "source": "sca_agent",
        "sources": ["sca_agent"],
        "cve": "CVE-2023-1370",
        "component_name": "json-smart",
        "component_version": "1.3.1",
        "scan_mode": "AGENT",
        "application_guid": "app",
        "project_id": "project-1",
        "issue_id": "44444444-4444-4444-4444-444444444444",
        "fixed_version": "2.4.2",
    }
    other_project = dict(issue, project_id="project-2", issue_id="55555555-5555-5555-5555-555555555555")
    folded = merge_sources([api, issue])
    assert len(folded) == 1
    assert folded[0]["issue_id"] == issue["issue_id"]
    assert folded[0]["fixed_version"] == "2.4.2"
    assert folded[0]["sources"] == ["sca_agent", "findings_api"]
    assert len(merge_sources([api, issue, other_project])) == 3


def test_spdx_description_is_the_library_reference():
    rows = components_from_spdx(
        {"packages": [{"SPDXID": "SPDXRef-Package-1", "name": "win32", "description": "npm:win32::0.9.12:", "licenseConcluded": "MIT"}]},
        target={"scan_mode": "AGENT", "application_name": "", "application_guid": "", "workspace_id": "", "workspace_name": "", "project_id": "p", "project_name": "proj"},
    )
    assert rows[0]["library_ref"] == "npm:win32::0.9.12:"
    assert rows[0]["version"] == "0.9.12"
    assert rows[0]["licenses"] == ["MIT"]
