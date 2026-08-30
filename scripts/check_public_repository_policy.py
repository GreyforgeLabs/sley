#!/usr/bin/env python3
"""Fail closed when public-repository doctrine and tracked content diverge."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "repository-policy.json"
MAX_TEXT_BYTES = 2 * 1024 * 1024

HOME_PREFIX = "/" + "home/"
PRIVATE_TEXT = (
    re.compile(re.escape(HOME_PREFIX) + r"(?!example(?:/|$))[^/\s`\"]+/", re.IGNORECASE),
    re.compile(r"[A-Za-z]:\\Users\\(?!Example\\)[^\\\s`\"]+\\", re.IGNORECASE),
    re.compile("greyforge" + r"lab(?!s)", re.IGNORECASE),
)
SECRET_TEXT = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
)
FORBIDDEN_NAMES = {".env", "credentials.json", "secrets.json"}
FORBIDDEN_SUFFIXES = {".key", ".p12", ".pfx", ".pem"}


def fail(message: str) -> None:
    raise AssertionError(message)


def tracked_paths() -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return sorted(
        item.decode("utf-8", "strict")
        for item in completed.stdout.split(b"\0")
        if item
    )


policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
expected = {
    "schema": "sley2.repository-policy.v1",
    "source_repository": "GreyforgeLabs/sley",
    "source_visibility": "public",
    "source_hosting_authorized": True,
    "releases_authorized": False,
    "tags_authorized": False,
    "package_publication_authorized": False,
    "deployment_authorized": False,
    "provider_spend_authorized": False,
    "product_claims_authorized": False,
}
for key, value in expected.items():
    if policy.get(key) != value:
        fail(f"repository policy mismatch: {key}")

actual_visibility = os.environ.get("SLEY2_ACTUAL_VISIBILITY", "")
if actual_visibility and actual_visibility != "public":
    fail(f"GitHub visibility is {actual_visibility!r}, expected 'public'")

paths = tracked_paths()
problems: list[str] = []
for relative in paths:
    pure = PurePosixPath(relative)
    lower_name = pure.name.lower()
    if lower_name in FORBIDDEN_NAMES or pure.suffix.lower() in FORBIDDEN_SUFFIXES:
        problems.append(f"forbidden tracked filename: {relative}")
        continue
    path = ROOT / relative
    try:
        data = path.read_bytes()
    except OSError as error:
        problems.append(f"unreadable tracked file: {relative}: {error.__class__.__name__}")
        continue
    if len(data) > MAX_TEXT_BYTES or b"\0" in data:
        continue
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        continue
    if any(pattern.search(text) for pattern in PRIVATE_TEXT):
        problems.append(f"machine-local path or peer identity: {relative}")
    if any(pattern.search(text) for pattern in SECRET_TEXT):
        problems.append(f"high-confidence credential material: {relative}")

if problems:
    fail("; ".join(problems))

print(
    json.dumps(
        {
            "schema": "sley2.repository-policy-check.v1",
            "tracked_files": len(paths),
            "declared_visibility": policy["source_visibility"],
            "observed_visibility": actual_visibility or "not-supplied-local-check",
            "release_authorized": policy["releases_authorized"],
            "result": "PASS",
        },
        sort_keys=True,
    )
)
