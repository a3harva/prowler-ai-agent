#!/usr/bin/env python3
"""Scan the public source tree for data that must never leave the project.

This check is deliberately generic so that the checker itself can be public:
it looks for credential shapes, personal absolute paths, non-reserved public
IP addresses, and the dockerignore guarantees that keep local environment
files out of image build contexts.

Organization-specific names, internal hostnames, customer identifiers, and
employee emails do NOT belong in this file — publishing them here would leak
exactly what we are trying to catch. Put them in an external denylist supplied
through the ``OSS_DENYLIST_FILE`` environment variable (one regular expression
per line; blank lines and ``#`` comments are ignored). The file is read from
the working tree but is never committed, so a public checkout simply runs the
generic checks.

Exit status is non-zero if any violation is found.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

# Credential shapes that are unambiguous enough to flag without a provider
# context. Kept in sync with the token families the project can actually see.
SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("private key block", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ("google api key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("aws access key id", r"AKIA[0-9A-Z]{16}"),
    ("github token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("gitlab token", r"glpat-[A-Za-z0-9_\-]{20,}"),
    ("slack token", r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    ("langfuse secret key", r"sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
)

# A personal absolute path leaks an employee's name and workstation layout.
# Container-internal service users are legitimate and therefore allowed.
PERSONAL_PATH = re.compile(r"/(?:Users|home)/([A-Za-z0-9][A-Za-z0-9._-]*)")
ALLOWED_PATH_USERS = frozenset({"prowler", "appuser", "nonroot", "node", "app", "runner"})

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

# Reviewed synthetic vectors that exist only to prove the redaction logic in
# backend/tests/test_observability.py. They are intentionally fake and must be
# the only literal credential shapes allowed to appear in the tree.
SYNTHETIC_ALLOWLIST: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-lf-11111111-2222-3333-4444-555555555555"),
    re.compile(r"BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBg"),
)

DOCKERIGNORE_REQUIRED = (".env", ".env.*")

def tracked_files() -> list[Path]:
    """Tracked files plus untracked-but-not-ignored files.

    The extra set makes the check useful before a commit: an ignored
    ``.env.local`` or ``reports/`` file is still excluded, but a newly created
    source file is scanned immediately rather than after `git add`.
    """
    out = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [Path(name) for name in out.split("\0") if name]


def load_external_denylist() -> list[tuple[str, re.Pattern[str]]]:
    path = os.environ.get("OSS_DENYLIST_FILE", "scripts/oss-denylist.local")
    if not path or not os.path.isfile(path):
        return []
    patterns: list[tuple[str, re.Pattern[str]]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append((f"denylist:{line}", re.compile(line, re.IGNORECASE)))
    return patterns


def build_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return [
        (f"secret:{label}", re.compile(pattern))
        for label, pattern in SECRET_PATTERNS
    ] + load_external_denylist()


def scan_text(
    label: str,
    text: str,
    patterns: list[tuple[str, re.Pattern[str]]],
    suffix: str = "",
) -> list[str]:
    findings: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern_label, pattern in patterns:
            if not pattern.search(line):
                continue
            # Synthetic fixtures may suppress the matching generic secret
            # detector, never an organization-specific denylist hit.
            allowed = pattern_label.startswith("secret:") and any(
                allowlist_pattern.search(line) for allowlist_pattern in SYNTHETIC_ALLOWLIST
            )
            if not allowed:
                findings.append(f"{label}:{number}: {pattern_label}")
        for match in PERSONAL_PATH.finditer(line):
            if match.group(1).lower() not in ALLOWED_PATH_USERS:
                findings.append(f"{label}:{number}: personal absolute path")
                break
        if suffix != ".lock":
            for match in IPV4.finditer(line):
                try:
                    address = ipaddress.ip_address(match.group(0))
                except ValueError:
                    continue
                if address.is_global:
                    findings.append(f"{label}:{number}: public IP address {address}")
    return findings


def scan_file(path: Path, patterns: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    if b"\x00" in raw:
        return []
    return scan_text(str(path), raw.decode("utf-8", "replace"), patterns, path.suffix)


def check_dockerignore(root: Path) -> list[str]:
    findings: list[str] = []
    for relative in ("backend/.dockerignore", "frontend/.dockerignore"):
        path = root / relative
        if not path.is_file():
            findings.append(f"{relative}: missing")
            continue
        entries = {line.strip() for line in path.read_text(encoding="utf-8").splitlines()}
        for required in DOCKERIGNORE_REQUIRED:
            if required not in entries:
                findings.append(f"{relative}: must ignore {required}")
    return findings


def scan_tree(root: Path, patterns: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    findings: list[str] = []
    for path in tracked_files():
        full = root / path
        if full.is_file():
            findings.extend(scan_file(full, patterns))
    findings.extend(check_dockerignore(root))
    return findings


def main() -> int:
    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
        ).stdout.strip()
    )
    patterns = build_patterns()
    findings = scan_tree(root, patterns)

    if findings:
        print("OSS safety check failed:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1

    print("OSS safety check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
