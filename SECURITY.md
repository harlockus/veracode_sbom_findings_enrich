# Security

SBOM Findings calls the Veracode API with HMAC credentials and writes the account's SBOM and open SCA findings to local files. Treat `.env` and `output/` as secret.

## Reporting a vulnerability

Report a vulnerability in this program privately to the repository owner. Include the version, the platform, and a description that lets the owner reproduce it. Leave API credentials, customer findings, and exploit detail out of a public issue.

## What the program does to limit risk

- The API host is one of `api.veracode.com`, `api.veracode.eu`, or `api.veracode.us`. Any other host is rejected before a request is sent.
- Requests use HTTPS. Certificate verification stays at the Python default. The program does not install a custom trust store and does not disable verification.
- Redirects are not followed. A 3xx response is an error, so the `Authorization` header is not sent to a second host.
- A pagination link that leaves the Veracode host is refused. Paths that contain `..`, an encoded `..`, a backslash, or a NUL are refused.
- Response bodies are capped at 80 MiB, including gzip expansion.
- Credential values are read from the environment or `.env`. They are not accepted on the command line, and they are not written to the log. An error body that contains an authorization header, a signature, or a key field is omitted from the message.
- `VERACODE_USER_AGENT` is reduced to a single header line. Control characters are removed.
- Maven Central is used only to discover a Maven group id. The artifact and version must each be one token of letters, digits, and `._+-`. The query is not sent when the token check fails. Safe versions still come from SourceClear.
- Excel cells whose text begins with `=`, `+`, `-`, or `@` are stored with a leading apostrophe so the spreadsheet application treats them as text.
- Output file names are restricted to a portable stem. Windows reserved device names are prefixed, and the raw SBOM file is written under the run's `sbom` directory.
- `.env`, virtual environments, build output, and `output/` are listed in `.gitignore`.

## Dependencies

Runtime dependencies are `python-dotenv` and `openpyxl`. The floors in `pyproject.toml` are versions audited with no known advisory at release:

| Package | Floor | Note |
| --- | --- | --- |
| python-dotenv | 1.2.4 | CVE-2026-28684 is fixed in 1.2.2. This program reads `.env` with `dotenv_values` and does not call `set_key` or `unset_key`. |
| openpyxl | 3.1.5 | Workbooks are written by this program. It does not open workbooks from the network. |
| pip | 26.2 | Used only to install. Older pip releases have published advisories. |
| setuptools | 84 | Build backend only. |
| pytest | 9.1.1 | Tests only. |

Continuous integration installs the package on Ubuntu, Windows, and macOS and runs `pip-audit` on Ubuntu with Python 3.12. Dependabot is configured for pip and GitHub Actions.

## Data handling

A collect run downloads the SCA findings and SBOMs visible to the API credential. The JSON and Excel files contain component names, versions, CVEs, paths, and safe-version recommendations. Store them where the rest of that account's security data is stored. Do not commit them.
