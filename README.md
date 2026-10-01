# SBOM Findings

SBOM Findings exports Veracode Software Composition Analysis for upload (policy) scans and SCA agent workspaces. One run writes an SBOM and an open-findings report, each as JSON and Excel, and adds a recommended safe version from the SourceClear registry.

The package is a command-line program. It runs on macOS, Windows, and Linux with Python 3.11 or newer. It uses the Python standard library for HTTP and HMAC, plus `python-dotenv` and `openpyxl`.

## What a run produces

| File | Contents |
| --- | --- |
| `findings.json` | Open SCA findings from the Findings API, SCA agent issues, and vulnerabilities that appear only in the SBOM, with safe-version fields |
| `findings.xlsx` | Sheets: Findings, Safe versions, Enrichment gaps, Summary |
| `sbom.json` | Index of SBOM documents plus flat components, vulnerabilities, dependencies, and licenses |
| `sbom.xlsx` | Sheets: Components, Vulnerabilities, Dependencies, Licenses, Summary |
| `sbom/*.json` | Raw CycloneDX 1.4 or SPDX 2.3 documents returned by Veracode |
| `manifest.json` | Applications, workspaces, project ids, counts, warnings, and file names |

Files are written to `output/<UTC timestamp>/` inside the project directory. `--out` selects another directory. JSON is UTF-8 with LF newlines. Excel headers are frozen, filtered, and wrapped. A cell whose text begins with `=`, `+`, `-`, or `@` is stored as text.

## Requirements

- Python 3.11, 3.12, 3.13, or 3.14
- pip 26.2 or newer (`python -m pip install --upgrade "pip>=26.2"`)
- Network access to the Veracode API for the account region, and to `https://search.maven.org` when a Java coordinate has to be discovered
- A Veracode API id and key

Create the id and key in the Veracode Platform from a UI user: **My Account > API Credentials**. Workspace issues and safe-version lookups require that UI user credential. An API service account with the Results API role can call the Findings API and SBOM generation. When that service account is used, SourceClear calls are recorded as access denied and the Findings and SBOM files are still written.

## Install

Clone or copy this directory, then create a virtual environment inside it. The commands below install the package and the test runner. Use a normal install. An editable install (`pip install -e`) can fail on macOS with Python 3.14 when the environment directory is flagged hidden, because that interpreter skips hidden `.pth` files.

### macOS and Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade "pip>=26.2"
python -m pip install ".[dev]"
test -f .env || cp .env.example .env
```

On Linux, `python3` is the usual command. On macOS, `python3` from python.org or Homebrew both work.

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade "pip>=26.2"
python -m pip install ".[dev]"
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

If activation is blocked by execution policy, call the environment Python directly and skip activation:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade "pip>=26.2"
.\.venv\Scripts\python.exe -m pip install ".[dev]"
.\.venv\Scripts\python.exe -m sbom_findings doctor
```

The `sbom-findings` command is also installed on the environment's script path: `.venv\Scripts\sbom-findings.exe` on Windows, and `.venv/bin/sbom-findings` on macOS and Linux. `python -m sbom_findings` works on all three and does not depend on that script being on `PATH`.

## Credentials

Edit `.env`. Leave the key file out of git. `.gitignore` already excludes `.env`.

```text
VERACODE_API_KEY_ID=
VERACODE_API_KEY_SECRET=
VERACODE_API_REGION=us
```

| Variable | Required | Meaning |
| --- | --- | --- |
| `VERACODE_API_KEY_ID` | Yes | API id. `VERACODE_API_ID` is an accepted alias. |
| `VERACODE_API_KEY_SECRET` | Yes | API secret key. `VERACODE_API_KEY` is an accepted alias. |
| `VERACODE_API_REGION` | No | `us` (default), `eu`, or `federal`. `us-federal` is accepted as an alias of `federal`. |
| `VERACODE_API_HOST` | No | Overrides the region. The only accepted hosts are `api.veracode.com`, `api.veracode.eu`, and `api.veracode.us`. |
| `VERACODE_APP` | No | Application name used when `collect` is given no application target. Ignored when the run already covers every application. |
| `VERACODE_WORKSPACE` | No | Workspace name used when `collect` is given no workspace target. Ignored when the run already covers every workspace. |
| `VERACODE_USER_AGENT` | No | User-Agent for the SCA API. Default `SBOM-Findings/1.0`. Control characters are removed. |

Values stay on one line. A variable already set in the process environment wins over the file. Files are read in this order, and a later file fills only the names that are still empty: the project `.env`, a `.env` in the current directory when that path is different, then `--env-file`.

`doctor` prints the host, the region, the length of each credential, and the User-Agent. It does not print the id or the key.

## Check the credential

```bash
python -m sbom_findings doctor
```

Exit 0 means both the Applications API and the SCA workspace API authenticated. Exit 2 means the configuration is incomplete or the host is not a Veracode host. Exit 1 means a probe failed. HTTP 401 stops the run. HTTP 403 on the workspace API means the credential is not a UI user API credential. Findings and SBOM generation can still succeed with a Results API service account.

```bash
python -m sbom_findings list-apps
python -m sbom_findings list-workspaces
```

Each line is a GUID, a tab, and the name. The count is written to stderr.

## Collect

```bash
python -m sbom_findings collect
```

With no target flags, `collect` reads every application and every SCA agent workspace the credential can see. Upload scans and agent workspaces are both included. That is the normal run. A full account can take several minutes. Progress is written to stderr when `--verbose` is set, and enrichment progress is logged every 25 findings.

Limit the run when you need a slice of the account:

```bash
python -m sbom_findings collect --app verademo
python -m sbom_findings collect --app-guid <guid>
python -m sbom_findings collect --workspace "My Workspace"
python -m sbom_findings collect --project-guid <guid> --sbom-format both
python -m sbom_findings collect --app verademo --scan-mode UPLOAD
python -m sbom_findings collect --scan-mode AGENT
python -m sbom_findings collect --app verademo --context <sandbox-guid>
python -m sbom_findings collect --out reports/verademo
```

| Flag | Effect |
| --- | --- |
| `--app` | Application name. Repeat the flag for more than one name. |
| `--app-guid` | Application GUID. Repeatable. |
| `--workspace` | SCA workspace name. Repeatable. |
| `--workspace-guid` | SCA workspace GUID. Repeatable. |
| `--project-guid` | SCA agent project GUID. Repeatable. The workspace list is skipped for that project. |
| `--all-apps` | Every visible application. This is already the default when no application is named and the scan mode is not `AGENT`. |
| `--all-workspaces` | Every visible workspace. This is already the default when no workspace or project is named and the scan mode is not `UPLOAD`. |
| `--scan-mode` | `UPLOAD`, `AGENT`, or `BOTH` (default). Sent as the Findings API `sca_scan_mode`. `UPLOAD` skips workspaces. `AGENT` skips applications. |
| `--dependency` | `DIRECT`, `TRANSITIVE`, `BOTH`, or `UNKNOWN`. Sent as `sca_dep_mode`. Omit it to keep every dependency mode. |
| `--context` | Sandbox GUID for the Findings API. Policy findings are the default. The SBOM API returns the latest policy scan. A sandbox scan is included there after it is promoted. |
| `--sbom-format` | `cyclonedx` (default), `spdx`, or `both`. The flat JSON and Excel SBOM are written either way. |
| `--no-linked` | Skip the second application CycloneDX document that includes agent projects linked to the application. |
| `--no-enrich` | Skip SourceClear safe-version lookups. |
| `--out` | Output directory. |
| `--env-file` | Credentials file other than the project `.env`. |
| `--verbose` | Debug logging. |
| `--version` | Print `sbom-findings` and the version. |

`--all-apps` together with a scan mode other than `UPLOAD` also collects every workspace. `--all-workspaces` together with a scan mode other than `AGENT` also collects every application.

## Open findings

The findings files contain open findings.

- A row whose status is empty is kept.
- A row whose status is `OPEN`, in any letter case, is kept. Agent issues arrive as `open` and are kept.
- A mitigated finding that is still open is kept.
- `CLOSED` and `fixed` rows are dropped before the reports are merged.
- Vulnerabilities that come only from the current SBOM are recorded as open, because that document is the current component set.

The Findings API has no status query parameter, so the program downloads the SCA page and applies this rule locally. Agent issues are requested with `status=open`. There is no switch that asks for closed or fixed findings.

## How the two scan types are collected

`BOTH` is the default and does all of the following.

1. Findings API, `scan_type=SCA` and `sca_scan_mode` set to the requested mode, for each selected application. SCA is never combined with static, dynamic, or manual scan types. `include_annot` and `violates_policy` are not sent, because the Findings API rejects them for SCA.
2. CycloneDX (and SPDX, when requested) for the application, `type=application`. The CycloneDX call asks for the upload scan with `linked=false`, then a second document with `linked=true` when agent data is in scope. SPDX has no `linked` parameter. SPDX requests dependencies. Vulnerability data is requested on every SBOM call.
3. For each agent project linked to the application, an SBOM with `type=agent`.
4. For each selected workspace: projects, open vulnerability issues, and the workspace library catalog. Each project receives an agent SBOM. The library catalog is used to recover coordinates. It is not copied into `sbom.json` as extra components.

A 404 on an SBOM means Veracode has no scan for that target in the last 13 months. The warning is recorded and the run continues. A 403 on a SourceClear call is recorded the same way. A 401 stops the run.

Regions and hosts:

| Region | Host |
| --- | --- |
| `us` | `api.veracode.com` |
| `eu` | `api.veracode.eu` |
| `federal` | `api.veracode.us` |

Every Veracode request is signed with HMAC-SHA-256 (`VERACODE-HMAC-SHA-256`). The signed string is the lowercased host plus the path and query. The nonce is 16 random bytes.

Official references used for the calls:

| API | Use |
| --- | --- |
| [Applications API](https://docs.veracode.com/r/c_apps_intro), SwaggerHub `veracode-applications-api-specification` 1.0 | Resolve an application name to a GUID |
| [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro), SwaggerHub `veracode-findings_api_specification` 2.1 | `GET /appsec/v2/applications/{guid}/findings?scan_type=SCA` |
| [Create an SBOM with the REST API](https://docs.veracode.com/r/Generate_an_SBOM_with_the_REST_API) | CycloneDX 1.4 JSON and SPDX 2.3 JSON |
| [SCA REST API](https://docs.veracode.com/r/c_sourceclear_intro), SwaggerHub `veracode-sca_agent_api_specification` 3.0 | Workspaces, projects, issues, libraries, component activity |

Page size is 500 for findings and 100 for SCA collections. HAL `next` links are followed when they stay on the same Veracode host. Otherwise the page number is incremented until the last page.

## Safe versions

Every open finding is offered to the enricher unless `--no-enrich` is set. The enricher fills:

| Field | Source |
| --- | --- |
| `fixed_version`, `latest_safe_version` | `fix_info` on `GET /srcclr/v3/issues/{id}` |
| `safe_versions`, `latest_release_version` | `GET /srcclr/v3/component-activity/{libraryRef}` |
| `recommended_safe_version` | Chosen from those values, as described below |
| `library_ref` | Coordinate used for the component-activity call |
| `library_ref_source` | Where that coordinate was found |
| `enrichment_status`, `enrichment_detail` | Outcome of the lookup |

Issue detail is requested only for an agent issue whose id is a UUID. A Findings API `issue_id` is an integer and is not a SourceClear issue id. `GET /srcclr/v3/vulnerabilities/{id}` does not return fix versions, so it is not called.

`recommended_safe_version` uses the first of these that exists:

1. `latest_safe_version` from the issue.
2. The registry latest release, when that release is one of the `safe_versions`.
3. The first safe version that is not a Maven timestamp (eight or more digits).
4. The first safe version.
5. `fixed_version`.

`safe_versions` is not treated as a sorted list. The last entry is not assumed to be the newest.

Library reference shape, from the SCA API: `coordinateType:coordinate1:coordinate2:version:platform`.

| Ecosystem | Example |
| --- | --- |
| Maven | `maven:net.minidev:json-smart:1.3.1:` |
| npm | `npm:win32::0.9.12:` |
| PyPI, RubyGems, NuGet, Composer, CocoaPods, Cargo, Go | The same colon form, with an empty second coordinate when the ecosystem has none |

The reference is recovered in this order:

1. The agent issue or its issue detail, when it already carries a library id.
2. The same application or project: SBOM package URL, SPDX package description, or workspace library id, matched on artifact name and version. Archive suffixes (`.jar`, `.war`, `.ear`, `.whl`, `.gem`, and the other common suffixes) and a trailing `-<version>` are removed before the name is compared, so `commons-collections4-4.0.jar` matches the SBOM artifact `commons-collections4`.
3. The same pair matched once in the whole catalog for the run. A coordinate whose segment ends with a dot loses to the clean coordinate. Two different groups for the same name and version are left unmatched.
4. For a remaining Java, Scala, or Kotlin component: `maven:<artifact>:<artifact>:<version>:` is accepted only when component activity returns that same artifact. If it does not, Maven Central is asked for `a:"<artifact>" AND v:"<version>"`. The group is used only when every exact hit shares one group, and component activity confirms the artifact again.

Maven group ids and Go module paths are taken from those sources. A filename alone is not turned into a group id or a module path. npm, PyPI, RubyGems, NuGet, and Composer can use a language hint when the coordinate is just the package name and version.

| `enrichment_status` | Meaning |
| --- | --- |
| `enriched` | A recommended safe version, or a list of safe versions, was stored. |
| `no_safe_version` | The registry knows the library and returned no safe release. |
| `not_in_registry` | Component activity did not return a record for the coordinate. |
| `missing_coordinates` | No library reference could be built. |
| `forbidden` | The credential cannot call SourceClear. The rest of the export is kept. |

`no_safe_version` is a registry answer. It means the lookup ran. Libraries in that state in a typical account include older `mysql-connector-java`, `axis` 1.2, `jstl` 1.2, and coordinates SourceClear does not publish a fix for.

## Findings columns

The Findings sheet and `findings.json` use one row per open vulnerability after duplicates are merged. Rows that share the same CVE, normalized component name, version, scope, application, and project are one row. An application-level `UPLOAD+AGENT` row with no project id is folded into the upload row. Two agent projects stay as two rows. Sources are combined, so a row can list `findings_api`, `sbom`, and `sca_agent` together.

Columns: Sources, Scan mode, Dependency, Application, Application GUID, Workspace, Project, Branch, Issue id, Status, Resolution, First found, Last seen, Violates policy, Severity, CVE, CWE, CWE name, CVSS v2, CVSS v3, CVSS v3 severity, CVSS v3 vector, EPSS, EPSS percentile, Exploit observed, Exploit source, Component, Version, Language, Licenses, Paths, Vulnerable method, Vulnerable methods, Library reference, Fixed version, Latest safe version, Safe versions, Recommended safe version, Latest release, Enrichment, Enrichment detail, Description.

The Safe versions sheet keeps rows that have a CVE or are vulnerability issues. The Enrichment gaps sheet keeps rows whose enrichment status is present and is not `enriched`.

## SBOM columns

Components: Scan mode, Format, Application, Workspace, Project, Component, Group, Version, Package URL, Type, Licenses, Library reference, Reference source, BOM ref, Hashes.

Vulnerabilities: Scan mode, Format, Application, Project, Vulnerability, Severity, Score, Vector, CWEs, Affected components, Source, URL, Description.

Dependencies: Scan mode, Format, Application, Project, Component, Depends on.

Licenses: one row per license on a component, with the component, version, application, project, and scan mode.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The reports were written. Warnings may still be listed on stderr. |
| 1 | The API call failed, including HTTP 401, or `doctor` saw a failed probe. |
| 2 | Configuration is missing or invalid, or the host is not a Veracode host. |
| 3 | The run finished with warnings, and both the finding count and the component count are zero. |

## Tests

The tests use the published Findings example shape, the Swagger library-reference examples, and a scripted API. They do not call Veracode or Maven Central.

```bash
python -m pytest
```

From a source tree, without installing:

```bash
PYTHONPATH=src python -m pytest
```

On Windows PowerShell, set the path for that command only:

```powershell
$env:PYTHONPATH = "src"
python -m pytest
```

GitHub Actions runs that test suite on `ubuntu-latest`, `windows-latest`, and `macos-latest` for Python 3.11, 3.12, 3.13, and 3.14. The Ubuntu 3.12 job also runs `pip-audit`. Dependabot checks pip and GitHub Actions weekly. See [SECURITY.md](SECURITY.md) for the controls and the dependency floors.

## Repository contents

Track the source, the tests, `pyproject.toml`, `.env.example`, this README, and `SECURITY.md`. Leave these untracked:

| Path | Why |
| --- | --- |
| `.env` | API credentials |
| `.venv/` | Local environment |
| `output/` | Account SBOMs and findings |
| `build/`, `dist/`, `*.egg-info/` | Build artifacts |

`output/.gitkeep` is the only file under `output/` that belongs in git. Reports from a live run contain customer vulnerability data.

This directory does not include a license file. Add the license you want to grant before you publish the repository for other people to reuse.

## Publishing on GitHub

The workflow file is `.github/workflows/ci.yml`. After the repository exists on GitHub, a push or a pull request runs the three operating systems. Create the repository as private when the history or the README should stay inside your organization. Do not add `.env` or `output/` in the first commit. Confirm `git status` shows neither before you commit.

```bash
git init
git add .
git status
git commit -m "Initial import of SBOM Findings."
git branch -M main
git remote add origin git@github.com:<owner>/sbom-findings.git
git push -u origin main
```

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `Missing VERACODE_API_KEY_ID` | Fill `.env`, or export the variables in the shell before the command. |
| `VERACODE_API_HOST must be one of` | Use `us`, `eu`, or `federal`, or one of the three official hosts. |
| `doctor` reports HTTP 401 | The id or key is wrong, revoked, or from a different region than `VERACODE_API_REGION`. |
| Workspace probe reports HTTP 403 | Generate the credential from a UI user. A Results API service account cannot list workspaces or resolve safe versions. |
| Many `no scan in range` warnings | Those applications have no SBOM in the 13-month window. Findings for them are still exported when the Findings API has them. |
| `ModuleNotFoundError: sbom_findings` after an editable install on macOS | Reinstall without editable mode: `python -m pip install --force-reinstall --no-deps .` |
| Excel opens a component name as a formula | Re-run with this version. Formula-leading text is stored as text. |
| Windows cannot create the virtual environment | Install Python from python.org and run `py -3 -m venv .venv`. |

## Program layout

| Path | Role |
| --- | --- |
| `src/sbom_findings/cli.py` | Commands, default scope, exit codes |
| `src/sbom_findings/pipeline.py` | Collect, merge, and write |
| `src/sbom_findings/resources.py` | Veracode paths and query parameters |
| `src/sbom_findings/auth.py` | HMAC-SHA-256 |
| `src/sbom_findings/client.py` | HTTPS, pagination, retries, response limits |
| `src/sbom_findings/normalize.py` | API and SBOM rows, open-status rule |
| `src/sbom_findings/enrich.py` | Safe versions |
| `src/sbom_findings/coordinates.py` | Package URLs and filename normalization |
| `src/sbom_findings/registry.py` | Maven Central group discovery |
| `src/sbom_findings/export.py` | JSON and Excel |
| `src/sbom_findings/config.py` | `.env` and the host allow list |
| `tests/` | Scripted API and security checks |
