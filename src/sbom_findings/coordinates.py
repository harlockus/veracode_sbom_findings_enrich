"""Library instance references used by the SourceClear registry.

Swagger documents the component-activity id as
``coordinateType:coordinate1:coordinate2:version:platform``.
The published examples are ``maven:net.minidev:json-smart:1.3.1:`` and
``npm:win32::0.9.12:``. SPDX package descriptions from the SBOM API use
that same string.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

# Five colon-separated fields. Version may itself contain colons; platform
# is the final field and is often empty, so the reference ends with ":".
_REF = re.compile(r"^[A-Za-z0-9]+:[^:\s]*:[^:\s]*:.+:[^:\s]*$")

_PURL_TYPE = {
    "maven": "maven",
    "npm": "npm",
    "pypi": "pypi",
    "gem": "gem",
    "golang": "go",
    "go": "go",
    "nuget": "nuget",
    "composer": "composer",
    "cocoapods": "cocoapods",
    "cargo": "cargo",
    "hackage": "hackage",
    "hex": "hex",
    "pub": "pub",
}

# Types whose package name lives in coordinate1 and whose coordinate2 is empty.
_NAME_IN_COORD1 = {"npm", "pypi", "gem", "go", "nuget", "cargo", "cocoapods", "hackage", "hex", "pub", "composer"}


_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".jar",
    ".war",
    ".ear",
    ".aar",
    ".dll",
    ".nupkg",
    ".whl",
    ".gem",
    ".tgz",
    ".zip",
    ".pom",
)


def artifact_name(filename: str | None, version: str | None = "") -> str:
    """Return the package name inside a scan filename.

    Upload findings name the file, for example ``commons-collections4-4.0.jar``.
    SBOM components and SourceClear libraries use ``commons-collections4``.
    """
    name = (filename or "").strip()
    lower = name.lower()
    for suffix in _ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            name = name[: -len(suffix)]
            lower = name.lower()
            break
    version_text = str(version or "").strip()
    if version_text and lower.endswith("-" + version_text.lower()):
        name = name[: -(len(version_text) + 1)]
    return name.strip()


def looks_like_library_ref(value: str | None) -> bool:
    if not value or "://" in value or value.startswith("pkg:"):
        return False
    return _REF.fullmatch(value.strip()) is not None


def library_ref_from_purl(purl: str | None) -> str | None:
    """Convert a Package URL into a SourceClear library instance reference."""
    if not purl:
        return None
    text = purl.strip()
    if not text.startswith("pkg:"):
        return None
    body = text[4:]
    body = body.split("?", 1)[0].split("#", 1)[0]
    if "@" not in body or "/" not in body:
        return None
    type_and_name, version = body.rsplit("@", 1)
    type_name, remainder = type_and_name.split("/", 1)
    coord_type = _PURL_TYPE.get(type_name.lower())
    if not coord_type or not version:
        return None
    remainder = unquote(remainder)
    version = unquote(version)
    if coord_type == "maven":
        if "/" not in remainder:
            return None
        group, artifact = remainder.rsplit("/", 1)
        if not group or not artifact:
            return None
        return f"maven:{group}:{artifact}:{version}:"
    if coord_type in _NAME_IN_COORD1:
        name = remainder
        if coord_type == "npm" and name.startswith("@") and "/" not in name:
            return None
        return f"{coord_type}:{name}::{version}:"
    return None


def library_ref_from_parts(
    coordinate_type: str | None,
    coordinate1: str | None,
    coordinate2: str | None,
    version: str | None,
    platform: str | None = "",
) -> str | None:
    if not coordinate_type or version is None or version == "":
        return None
    ctype = coordinate_type.strip().lower()
    c1 = coordinate1 or ""
    c2 = coordinate2 or ""
    plat = platform or ""
    ref = f"{ctype}:{c1}:{c2}:{version}:{plat}"
    return ref if looks_like_library_ref(ref) else None


def find_library_ref(*values: object) -> str | None:
    """Return the first string that already is a library instance reference."""
    for value in values:
        if isinstance(value, str) and looks_like_library_ref(value.strip()):
            return value.strip()
        if isinstance(value, dict):
            nested = find_library_ref(*value.values())
            if nested:
                return nested
        if isinstance(value, list):
            nested = find_library_ref(*value)
            if nested:
                return nested
    return None
