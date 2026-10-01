"""Runtime settings loaded from the environment and an optional .env file."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _project_root() -> Path:
    """Directory that contains this project's pyproject.toml.

    A source checkout lives two levels above ``src/sbom_findings``. An
    installed copy lives under ``site-packages``, so walk upward until the
    project file is found. The working directory is the fallback, which keeps
    reports out of the interpreter directory on every platform.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if _is_project(parent):
            return parent
    cwd = Path.cwd()
    if _is_project(cwd):
        return cwd
    return cwd


def _is_project(directory: Path) -> bool:
    marker = directory / "pyproject.toml"
    if not marker.is_file():
        return False
    try:
        text = marker.read_text(encoding="utf-8")
    except OSError:
        return False
    return "sbom-findings" in text


PROJECT_ROOT = _project_root()

REGIONS = {
    "us": "api.veracode.com",
    "eu": "api.veracode.eu",
    "federal": "api.veracode.us",
    "us-federal": "api.veracode.us",
}

ALLOWED_HOSTS = frozenset(REGIONS.values())


class ConfigError(ValueError):
    """Raised when required settings are missing or invalid."""


@dataclass(frozen=True)
class Settings:
    api_id: str
    api_key: str
    host: str
    region: str
    user_agent: str
    default_app: str
    default_workspace: str

    @property
    def base_url(self) -> str:
        return f"https://{self.host}"


def load_settings(env_file: Path | None = None) -> Settings:
    """Load credentials.

    Files are applied in order: the project ``.env``, a ``.env`` in the
    current directory, then ``--env-file``. A variable already set in the
    process environment is left alone. Later files override earlier files.
    """
    paths = [PROJECT_ROOT / ".env"]
    cwd_env = Path.cwd() / ".env"
    if cwd_env.resolve() != (PROJECT_ROOT / ".env").resolve():
        paths.append(cwd_env)
    if env_file is not None:
        paths.append(env_file)
    for key, value in _merged_env(paths).items():
        os.environ.setdefault(key, value)

    api_id = _first("VERACODE_API_KEY_ID", "VERACODE_API_ID")
    api_key = _first("VERACODE_API_KEY_SECRET", "VERACODE_API_KEY")
    region = _plain(os.environ.get("VERACODE_API_REGION") or "us").lower()
    host = _plain(os.environ.get("VERACODE_API_HOST") or "").lower()
    if not host:
        if region not in REGIONS:
            known = ", ".join(sorted(set(REGIONS)))
            raise ConfigError(
                f"VERACODE_API_REGION must be one of {known}, or set VERACODE_API_HOST"
            )
        host = REGIONS[region]
    if host not in ALLOWED_HOSTS:
        known = ", ".join(sorted(ALLOWED_HOSTS))
        raise ConfigError(f"VERACODE_API_HOST must be one of {known}")
    user_agent = _header_value(os.environ.get("VERACODE_USER_AGENT") or "", fallback="SBOM-Findings/1.0")
    return Settings(
        api_id=api_id,
        api_key=api_key,
        host=host,
        region=region if host == REGIONS.get(region) else "custom",
        user_agent=user_agent,
        default_app=_plain(os.environ.get("VERACODE_APP") or ""),
        default_workspace=_plain(os.environ.get("VERACODE_WORKSPACE") or ""),
    )


def _merged_env(paths: list[Path]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for path in paths:
        if not path.is_file():
            continue
        for key, value in dotenv_values(path).items():
            if value is not None:
                merged[key] = value
    return merged


def _first(*names: str) -> str:
    for name in names:
        value = _plain(os.environ.get(name) or "")
        if value:
            return value
    joined = " or ".join(names)
    raise ConfigError(
        f"Missing {joined}. Put them in {PROJECT_ROOT / '.env'} and keep that file out of git."
    )


def _plain(value: str) -> str:
    """Drop control characters so a pasted value stays a single field."""
    return _CONTROL.sub("", value).strip()


def _header_value(value: str, *, fallback: str, limit: int = 180) -> str:
    text = " ".join(_CONTROL.sub(" ", value).split())
    if len(text) > limit:
        text = text[:limit].rstrip()
    return text or fallback
