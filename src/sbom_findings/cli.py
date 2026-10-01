"""Command line for Veracode SCA SBOM and findings export."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from sbom_findings import __version__
from sbom_findings.client import VeracodeClient, VeracodeError
from sbom_findings.config import PROJECT_ROOT, ConfigError, load_settings
from sbom_findings.pipeline import CollectRequest, collect
from sbom_findings.resources import list_applications, list_workspaces

log = logging.getLogger("sbom_findings")


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )
    try:
        settings = load_settings(args.env_file)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    client = VeracodeClient(settings)
    try:
        if args.command == "doctor":
            return _doctor(client)
        if args.command == "list-apps":
            return _list_apps(client)
        if args.command == "list-workspaces":
            return _list_workspaces(client)
        return _collect(client, args, settings)
    except VeracodeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbom-findings",
        description=(
            "Export Veracode SCA SBOMs and findings for upload scans and "
            "agent scans, and add SourceClear safe versions."
        ),
    )
    parser.add_argument("--version", action="version", version=f"sbom-findings {__version__}")
    parser.add_argument("--env-file", type=Path, help="Credentials file. Defaults to .env in this project.")
    parser.add_argument("--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)

    collect_parser = commands.add_parser(
        "collect",
        help="Write SBOM and findings for every application and every SCA workspace.",
    )
    collect_parser.add_argument("--app", action="append", default=[], help="Application name. Repeatable.")
    collect_parser.add_argument("--app-guid", action="append", default=[], help="Application GUID. Repeatable.")
    collect_parser.add_argument("--workspace", action="append", default=[], help="SCA workspace name. Repeatable.")
    collect_parser.add_argument("--workspace-guid", action="append", default=[], help="SCA workspace GUID. Repeatable.")
    collect_parser.add_argument("--project-guid", action="append", default=[], help="SCA agent project GUID. Repeatable.")
    collect_parser.add_argument("--all-apps", action="store_true", help="Every application visible to this credential.")
    collect_parser.add_argument("--all-workspaces", action="store_true", help="Every SCA workspace visible to this credential.")
    collect_parser.add_argument(
        "--scan-mode",
        choices=("UPLOAD", "AGENT", "BOTH"),
        default="BOTH",
        help="Findings API sca_scan_mode. Default BOTH. An explicit workspace is still collected as agent.",
    )
    collect_parser.add_argument(
        "--dependency",
        choices=("DIRECT", "TRANSITIVE", "BOTH", "UNKNOWN"),
        help="Findings API sca_dep_mode. Default is every dependency mode.",
    )
    collect_parser.add_argument("--context", help="Sandbox GUID for Findings API results. Policy findings are the default.")
    collect_parser.add_argument(
        "--sbom-format",
        choices=("cyclonedx", "spdx", "both"),
        default="cyclonedx",
        help="Official SBOM document format. Flattened JSON and Excel are always written.",
    )
    collect_parser.add_argument(
        "--no-linked",
        action="store_true",
        help="Skip the application CycloneDX SBOM that includes linked agent projects.",
    )
    collect_parser.add_argument("--no-enrich", action="store_true", help="Skip SourceClear safe-version lookups.")
    collect_parser.add_argument(
        "--out",
        type=Path,
        help="Output directory. Default is output/<UTC timestamp> under this project.",
    )

    commands.add_parser("list-apps", help="Print application names and GUIDs.")
    commands.add_parser("list-workspaces", help="Print SCA workspace names and GUIDs.")
    commands.add_parser("doctor", help="Check credentials and both API families.")
    return parser


def _collect(client: VeracodeClient, args, settings) -> int:
    app_names = list(args.app)
    workspace_names = list(args.workspace)
    all_apps, all_workspaces = _account_scope(args)
    if settings.default_app and not app_names and not args.app_guid and not all_apps:
        app_names.append(settings.default_app)
    if settings.default_workspace and not workspace_names and not args.workspace_guid and not all_workspaces:
        workspace_names.append(settings.default_workspace)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.out or (PROJECT_ROOT / "output" / stamp)
    formats = ("cyclonedx", "spdx") if args.sbom_format == "both" else (args.sbom_format,)
    result = collect(
        client,
        CollectRequest(
            app_names=app_names,
            app_guids=list(args.app_guid),
            workspace_names=workspace_names,
            workspace_guids=list(args.workspace_guid),
            project_guids=list(args.project_guid),
            all_apps=all_apps,
            all_workspaces=all_workspaces,
            sca_scan_mode=args.scan_mode,
            sca_dep_mode=args.dependency,
            context=args.context,
            sbom_formats=formats,
            include_linked_sbom=not args.no_linked,
            enrich=not args.no_enrich,
            out_dir=out,
        ),
    )
    print(f"Findings: {result.finding_count}  ({result.findings_json})")
    print(f"          {result.findings_xlsx}")
    print(f"SBOM:     {result.component_count} components  ({result.sbom_json})")
    print(f"          {result.sbom_xlsx}")
    print(f"Manifest: {result.manifest_json}")
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if result.finding_count == 0 and result.component_count == 0 and result.warnings:
        return 3
    return 0


def _account_scope(args) -> tuple[bool, bool]:
    """Every run covers upload scans and SCA agent workspaces.

    A named application limits the upload set. A named workspace or project
    limits the agent set. With neither, or with ``--all-apps`` / ``--all-workspaces``,
    both sets are the whole account. ``--scan-mode UPLOAD`` skips workspaces.
    ``--scan-mode AGENT`` skips applications.
    """
    named_app = bool(args.app or args.app_guid)
    named_workspace = bool(args.workspace or args.workspace_guid or args.project_guid)
    all_apps = bool(args.all_apps) or (args.scan_mode != "AGENT" and not named_app)
    all_workspaces = bool(args.all_workspaces) or (args.scan_mode != "UPLOAD" and not named_workspace)
    if args.all_apps and args.scan_mode != "UPLOAD":
        all_workspaces = True
    if args.all_workspaces and args.scan_mode != "AGENT":
        all_apps = True
    return all_apps, all_workspaces


def _list_apps(client: VeracodeClient) -> int:
    apps = list_applications(client)
    for app in apps:
        profile = app.get("profile") if isinstance(app.get("profile"), dict) else {}
        name = profile.get("name") or app.get("name") or ""
        print(f"{app.get('guid')}\t{name}")
    print(f"{len(apps)} applications", file=sys.stderr)
    return 0


def _list_workspaces(client: VeracodeClient) -> int:
    rows = list_workspaces(client)
    for row in rows:
        print(f"{row.get('id')}\t{row.get('name')}")
    print(f"{len(rows)} workspaces", file=sys.stderr)
    return 0


def _doctor(client: VeracodeClient) -> int:
    settings = client.settings
    print(f"host: {settings.host}")
    print(f"region: {settings.region}")
    print(f"api id length: {len(settings.api_id)}")
    print(f"api key length: {len(settings.api_key)}")
    print(f"user agent: {settings.user_agent}")
    failures = 0
    failures += _probe(client, "Applications API", "/appsec/v1/applications", {"page": 0, "size": 1})
    failures += _probe(
        client,
        "SCA workspace API",
        "/srcclr/v3/workspaces",
        {"page": 0, "size": 1, "include_metrics": "false"},
    )
    if failures:
        print("doctor: one or more probes failed", file=sys.stderr)
        return 1
    print("doctor: both APIs authenticated")
    return 0


def _probe(client: VeracodeClient, label: str, path: str, query: dict) -> int:
    try:
        client.get_json(path, query)
    except VeracodeError as exc:
        print(f"{label}: HTTP {exc.status}")
        if exc.status == 403 and path.startswith("/srcclr"):
            print(
                "  The SCA REST API requires a UI user API credential. "
                "An API service account can still call Findings and, with the Results API role, SBOM."
            )
        return 1
    print(f"{label}: ok")
    return 0


def _configure_stdio() -> None:
    """Keep non-ASCII application names printable on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


if __name__ == "__main__":
    raise SystemExit(main())
