#!/usr/bin/env python3
"""Validate the bounded S20-710 pre-release audit without claiming release PASS."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "evidence/security/T52/pre-release-inventory.json"
SECRET_SCAN_PATH = ROOT / "evidence/security/T54/secret-scan.json"
EXPECTED_BLOCKERS = ["workspace-license-text:missing-operator-approved-root-license"]
EXPECTED_ANCHOR = "51863f7b93271bd7a73f9b7b3b02eeca93447d9a"
EXPECTED_COUNTS = {
    ("cargo", False): 22,
    ("cargo", True): 14,
    ("pypi", False): 2,
    ("pypi", True): 1,
}
REQUIRED_IGNORES = {
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "credentials/",
    "secrets/",
    ".aws/",
    ".gnupg/",
}


def fail(message: str) -> None:
    raise AssertionError(message)


def strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from strings(item)


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load {path.relative_to(ROOT)}: {error}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def check_generated_files() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/generate_supply_chain_evidence.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"generated audit evidence drifted: {completed.stdout.strip() or completed.stderr.strip()}")


def check_inventory(inventory: dict[str, Any]) -> None:
    if inventory.get("contract") != "s20-710-pre-release-inventory-v1":
        fail("unexpected inventory contract")
    if inventory.get("history_anchor_commit") != EXPECTED_ANCHOR:
        fail("unexpected inventory history anchor")
    if inventory.get("result") != "BLOCKED" or inventory.get("blockers") != EXPECTED_BLOCKERS:
        fail("inventory must be blocked only on the operator-approved root license text")
    if inventory.get("full_release_sbom") is not False:
        fail("pre-release inventory must not claim to be a full release SBOM")
    if inventory.get("standards_sbom_deferred") is not True:
        fail("standards SBOM must remain deferred while the root license is blocked")
    if inventory.get("python_lock_freshness") != "uv lock --check --offline --no-python-downloads:PASS":
        fail("Python lock freshness assertion is missing")
    if inventory.get("license_text_files") != []:
        fail("an unreviewed root license file appeared; operator disposition is required")

    packages = inventory.get("packages")
    if not isinstance(packages, list):
        fail("inventory packages must be a list")
    counts = Counter((package.get("ecosystem"), package.get("workspace")) for package in packages)
    if counts != Counter(EXPECTED_COUNTS):
        fail(f"unexpected package inventory counts: {dict(counts)}")
    refs = {package.get("bom_ref") for package in packages}
    if None in refs or len(refs) != len(packages):
        fail("package BOM references must be present and unique")

    for package in packages:
        workspace = package["workspace"]
        if workspace:
            if package.get("license_declared") != "LicenseRef-Proprietary":
                fail(f"workspace license metadata mismatch: {package['bom_ref']}")
            expected_evidence = (
                "cargo-metadata-declared-expression"
                if package["ecosystem"] == "cargo"
                else "pyproject-declared-expression"
            )
            if package.get("license_evidence") != expected_evidence:
                fail(f"workspace license evidence mismatch: {package['bom_ref']}")
            if package.get("license_disposition") != "BLOCKED_MISSING_APPROVED_PROPRIETARY_LICENSE_TEXT":
                fail(f"workspace license disposition mismatch: {package['bom_ref']}")
            continue
        if package.get("license_disposition") != "DECLARED_PERMISSIVE_PRE_RELEASE_REVIEW":
            fail(f"registry dependency license is not dispositioned: {package['bom_ref']}")
        if package["ecosystem"] == "cargo":
            if package.get("license_evidence") != "cargo-metadata-declared-expression":
                fail(f"cargo dependency license evidence mismatch: {package['bom_ref']}")
            checksum = package.get("checksum_sha256")
            if not isinstance(checksum, str) or len(checksum) != 64:
                fail(f"cargo dependency lacks a lock checksum: {package['bom_ref']}")
            if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                fail(f"cargo dependency has an unexpected source: {package['bom_ref']}")
        elif package["ecosystem"] == "pypi":
            if package.get("license_evidence") != "curated-offline-pre-release-review":
                fail(f"Python dependency license evidence mismatch: {package['bom_ref']}")
            hashes = package.get("artifact_hashes")
            if not isinstance(hashes, list) or not hashes or any(
                not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71
                for value in hashes
            ):
                fail(f"Python dependency lacks locked artifact hashes: {package['bom_ref']}")
            if package.get("source") != "https://pypi.org/simple":
                fail(f"Python dependency has an unexpected source: {package['bom_ref']}")

    relationships = inventory.get("relationships")
    if not isinstance(relationships, list) or not relationships:
        fail("dependency relationships must be non-empty")
    for relationship in relationships:
        if relationship.get("from") not in refs or relationship.get("to") not in refs:
            fail("dependency relationship refers to an unknown package")


def check_secret_scan(scan: dict[str, Any]) -> None:
    if scan.get("contract") != "s20-710-secret-scan-v1":
        fail("unexpected secret-scan contract")
    if scan.get("history_anchor_commit") != EXPECTED_ANCHOR:
        fail("unexpected secret-scan history anchor")
    if scan.get("result") != "PASS_NO_HIGH_CONFIDENCE_FINDINGS":
        fail("high-confidence secret scan did not pass")
    if scan.get("blockers") != [] or scan.get("findings") != []:
        fail("secret scan contains unresolved blockers or findings")
    if scan.get("matched_secret_values_emitted") is not False:
        fail("secret scan must never emit matched secret values")
    for field in ("candidate_files_scanned", "candidate_bytes_scanned", "history_blobs_scanned", "history_bytes_scanned"):
        if not isinstance(scan.get(field), int) or scan[field] <= 0:
            fail(f"secret-scan coverage counter is invalid: {field}")

    ignore_lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if not REQUIRED_IGNORES.issubset(ignore_lines):
        fail("required secret-bearing ignore patterns are missing")


def check_no_host_paths(*documents: dict[str, Any]) -> None:
    for document in documents:
        for value in strings(document):
            if value.startswith("/") or "file://" in value or "/home/" in value:
                fail(f"host-specific path leaked into audit evidence: {value}")


def main() -> int:
    try:
        check_generated_files()
        inventory = load(INVENTORY_PATH)
        scan = load(SECRET_SCAN_PATH)
        check_inventory(inventory)
        check_secret_scan(scan)
        check_no_host_paths(inventory, scan)
    except AssertionError as error:
        print(json.dumps({"result": "FAIL", "reason": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "release_sbom": False,
                "result": "DEFERRED",
                "root_license_text_approved": False,
                "t52_local_lock_inventory": "PASS",
                "t54_high_confidence_scan": "PASS",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
