#!/usr/bin/env python3
"""Verify VERSION and CHANGELOG are semver-aligned."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def _die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        _die(f"Failed to read {path}: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SemVer alignment.")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    version_path = root / "VERSION"
    changelog_path = root / "CHANGELOG.md"

    version = _read_text(version_path)
    if not version:
        _die("VERSION is empty.")
    if not SEMVER_RE.fullmatch(version):
        _die(f"VERSION '{version}' is not valid SemVer.")

    changelog = _read_text(changelog_path)
    pattern = re.compile(rf"^## \[{re.escape(version)}\](?:\s|$)", re.MULTILINE)
    if not pattern.search(changelog):
        _die(f"CHANGELOG.md is missing an entry for version {version}.")

    print(f"OK: VERSION {version} is valid and CHANGELOG is aligned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
