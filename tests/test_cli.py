from sbom_findings.cli import main
from sbom_findings.pipeline import CollectResult


def test_collect_with_no_target_covers_apps_and_workspaces(monkeypatch, tmp_path):
    monkeypatch.setenv("VERACODE_API_KEY_ID", "abcd")
    monkeypatch.setenv("VERACODE_API_KEY_SECRET", "abcd")
    monkeypatch.setenv("VERACODE_APP", "")
    monkeypatch.setenv("VERACODE_WORKSPACE", "")
    captured = {}

    def fake_collect(client, request):
        captured["request"] = request
        out = request.out_dir
        out.mkdir(parents=True, exist_ok=True)
        return CollectResult(
            out_dir=out,
            findings_json=out / "findings.json",
            findings_xlsx=out / "findings.xlsx",
            sbom_json=out / "sbom.json",
            sbom_xlsx=out / "sbom.xlsx",
            manifest_json=out / "manifest.json",
            finding_count=1,
            component_count=1,
            warnings=[],
        )

    monkeypatch.setattr("sbom_findings.cli.collect", fake_collect)
    assert main(["collect", "--out", str(tmp_path)]) == 0
    request = captured["request"]
    assert request.all_apps is True
    assert request.all_workspaces is True
    assert request.sca_scan_mode == "BOTH"


def test_missing_credentials_exit_2(monkeypatch, tmp_path):
    monkeypatch.setattr("sbom_findings.config.PROJECT_ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    for name in (
        "VERACODE_API_KEY_ID",
        "VERACODE_API_ID",
        "VERACODE_API_KEY_SECRET",
        "VERACODE_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    assert main(["doctor"]) == 2


def test_region_host_is_rejected(monkeypatch):
    monkeypatch.setenv("VERACODE_API_KEY_ID", "abcd")
    monkeypatch.setenv("VERACODE_API_KEY_SECRET", "abcd")
    monkeypatch.setenv("VERACODE_API_HOST", "example.com")
    assert main(["doctor"]) == 2
