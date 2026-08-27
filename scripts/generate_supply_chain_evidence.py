#!/usr/bin/env python3
"""Generate deterministic, offline S20-710 pre-release audit evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HISTORY_ANCHOR = "51863f7b93271bd7a73f9b7b3b02eeca93447d9a"
MAX_SCANNED_BLOB_BYTES = 64 * 1024 * 1024
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"

INVENTORY_PATH = ROOT / "evidence/security/T52/pre-release-inventory.json"
SECRET_SCAN_PATH = ROOT / "evidence/security/T54/secret-scan.json"
OUTPUT_PATHS = {INVENTORY_PATH.relative_to(ROOT), SECRET_SCAN_PATH.relative_to(ROOT)}

PYTHON_LICENSES = {
    ("blake3", "1.0.9"): "CC0-1.0 OR Apache-2.0",
    ("unicodedata2", "16.0.0"): "Apache-2.0",
}

PERMISSIVE_CARGO_LICENSES = {
    "BSD-2-Clause",
    "MIT OR Apache-2.0",
    "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception",
    "CC0-1.0 OR MIT-0 OR Apache-2.0",
    "Unlicense OR MIT",
    "Apache-2.0 OR BSL-1.0",
    "Zlib OR Apache-2.0 OR MIT",
    "MIT OR Apache-2.0 OR Zlib",
    "(MIT OR Apache-2.0) AND Unicode-3.0",
    "MIT/Apache-2.0",
}

SECRET_PATTERNS = {
    "PRIVATE_KEY_PEM": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS_ACCESS_KEY": re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "GITHUB_TOKEN": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})"),
    "SLACK_TOKEN": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "OPENAI_KEY": re.compile(rb"sk-[A-Za-z0-9]{20,}"),
    "STRIPE_LIVE_KEY": re.compile(rb"(?:sk|rk)_live_[A-Za-z0-9]{20,}"),
    "GOOGLE_API_KEY": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "URL_CREDENTIAL": re.compile(rb"https?://[^/\s:@]{1,128}:[^/\s@]{1,256}@"),
}

REQUIRED_IGNORE_PATTERNS = {
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


def run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        input=input_bytes,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"deterministic command failed: {command[0]}: {message}")
    return completed.stdout


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def package_ref(ecosystem: str, name: str, version: str, *, workspace: bool = False) -> str:
    suffix = "?workspace=true" if workspace else ""
    return f"pkg:{ecosystem}/{name}@{version}{suffix}"


def license_disposition(expression: str | None, *, workspace: bool) -> tuple[str, str | None]:
    if workspace:
        if expression != "LicenseRef-Proprietary":
            return "BLOCKED_LICENSE_METADATA_MISMATCH", expression
        return "BLOCKED_MISSING_APPROVED_PROPRIETARY_LICENSE_TEXT", expression
    if expression in PERMISSIVE_CARGO_LICENSES:
        normalized = "MIT OR Apache-2.0" if expression == "MIT/Apache-2.0" else expression
        return "DECLARED_PERMISSIVE_PRE_RELEASE_REVIEW", normalized
    return "BLOCKED_UNREVIEWED_LICENSE_EXPRESSION", expression


def cargo_inventory() -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    metadata = json.loads(
        run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1"])
    )
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    lock_entries = {
        (package["name"], package["version"], package.get("source")): package
        for package in lock["package"]
    }
    packages: list[dict[str, Any]] = []
    id_to_ref: dict[str, str] = {}
    blockers: list[str] = []
    for package in metadata["packages"]:
        workspace = package.get("source") is None
        source = "workspace" if workspace else package["source"]
        reference = package_ref("cargo", package["name"], package["version"], workspace=workspace)
        id_to_ref[package["id"]] = reference
        lock_entry = lock_entries.get((package["name"], package["version"], package.get("source")))
        checksum = None if workspace else (lock_entry or {}).get("checksum")
        if not workspace:
            if source != REGISTRY_SOURCE:
                blockers.append(f"cargo-source:{package['name']}@{package['version']}")
            if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
                blockers.append(f"cargo-checksum:{package['name']}@{package['version']}")
        disposition, normalized = license_disposition(package.get("license"), workspace=workspace)
        if disposition.startswith("BLOCKED_") and not workspace:
            blockers.append(f"cargo-license:{package['name']}@{package['version']}:{disposition}")
        packages.append(
            {
                "bom_ref": reference,
                "checksum_sha256": checksum,
                "ecosystem": "cargo",
                "license_declared": package.get("license"),
                "license_evidence": "cargo-metadata-declared-expression",
                "license_normalized_for_review": normalized,
                "license_disposition": disposition,
                "name": package["name"],
                "source": source,
                "version": package["version"],
                "workspace": workspace,
            }
        )
    relationships: list[dict[str, str]] = []
    for node in metadata["resolve"]["nodes"]:
        for dependency in node["dependencies"]:
            relationships.append({"from": id_to_ref[node["id"]], "to": id_to_ref[dependency]})
    packages.sort(key=lambda item: item["bom_ref"])
    relationships = sorted({(item["from"], item["to"]) for item in relationships})
    return packages, [{"from": source, "to": target} for source, target in relationships], blockers


def python_inventory() -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    run(
        [
            "uv",
            "lock",
            "--check",
            "--offline",
            "--no-python-downloads",
            "--project",
            "oracle/scb1",
        ]
    )
    lock = tomllib.loads((ROOT / "oracle/scb1/uv.lock").read_text(encoding="utf-8"))
    project = tomllib.loads((ROOT / "oracle/scb1/pyproject.toml").read_text(encoding="utf-8"))
    packages: list[dict[str, Any]] = []
    blockers: list[str] = []
    name_to_ref: dict[str, str] = {}
    for package in lock["package"]:
        workspace = package.get("source", {}).get("editable") == "."
        name = package["name"]
        version = package["version"]
        reference = package_ref("pypi", name, version, workspace=workspace)
        name_to_ref[name] = reference
        if workspace:
            declared = project["project"].get("license")
            disposition, normalized = license_disposition(declared, workspace=True)
            license_evidence = "pyproject-declared-expression"
            hashes: list[str] = []
            source = "workspace:oracle/scb1"
        else:
            declared = PYTHON_LICENSES.get((name, version))
            normalized = declared
            license_evidence = "curated-offline-pre-release-review"
            disposition = (
                "DECLARED_PERMISSIVE_PRE_RELEASE_REVIEW"
                if declared in {"CC0-1.0 OR Apache-2.0", "Apache-2.0"}
                else "BLOCKED_UNREVIEWED_LICENSE_EXPRESSION"
            )
            hashes = []
            if "sdist" in package:
                hashes.append(package["sdist"]["hash"])
            hashes.extend(wheel["hash"] for wheel in package.get("wheels", []))
            hashes.sort()
            source = package.get("source", {}).get("registry")
            if source != "https://pypi.org/simple":
                blockers.append(f"python-source:{name}@{version}")
            if not hashes or any(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in hashes):
                blockers.append(f"python-hash:{name}@{version}")
        if disposition.startswith("BLOCKED_") and not workspace:
            blockers.append(f"python-license:{name}@{version}:{disposition}")
        packages.append(
            {
                "artifact_hashes": hashes,
                "bom_ref": reference,
                "ecosystem": "pypi",
                "license_declared": declared,
                "license_evidence": license_evidence,
                "license_normalized_for_review": normalized,
                "license_disposition": disposition,
                "name": name,
                "source": source,
                "version": version,
                "workspace": workspace,
            }
        )
    relationships: list[dict[str, str]] = []
    for package in lock["package"]:
        source = name_to_ref[package["name"]]
        for dependency in package.get("dependencies", []):
            target_name = dependency["name"] if isinstance(dependency, dict) else dependency
            relationships.append({"from": source, "to": name_to_ref[target_name]})
    packages.sort(key=lambda item: item["bom_ref"])
    relationships.sort(key=lambda item: (item["from"], item["to"]))
    return packages, relationships, blockers


def license_text_files() -> list[str]:
    names = []
    for path in ROOT.iterdir():
        if path.is_file() and re.match(r"(?i)^(license|copying|notice)(\..*)?$", path.name):
            names.append(path.name)
    return sorted(names)


def candidate_files() -> list[Path]:
    raw = run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    paths = []
    for value in raw.split(b"\0"):
        if not value:
            continue
        relative = Path(os.fsdecode(value))
        if relative in OUTPUT_PATHS:
            continue
        paths.append(relative)
    return sorted(paths, key=lambda path: path.as_posix().encode("utf-8"))


def scan_blob(data: bytes) -> list[str]:
    return sorted(name for name, pattern in SECRET_PATTERNS.items() if pattern.search(data))


def current_candidate_scan() -> tuple[list[dict[str, str]], list[str], int, int, str]:
    findings: list[dict[str, str]] = []
    blockers: list[str] = []
    count = 0
    byte_count = 0
    manifest = hashlib.sha256()
    for relative in candidate_files():
        path = ROOT / relative
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            blockers.append(f"candidate-nonregular:{relative.as_posix()}")
            continue
        size = path.stat().st_size
        if size > MAX_SCANNED_BLOB_BYTES:
            blockers.append(f"candidate-oversize:{relative.as_posix()}:{size}")
            continue
        data = path.read_bytes()
        digest = sha256(data)
        encoded_path = relative.as_posix().encode("utf-8")
        manifest.update(len(encoded_path).to_bytes(8, "big"))
        manifest.update(encoded_path)
        manifest.update(bytes.fromhex(digest))
        count += 1
        byte_count += len(data)
        for pattern in scan_blob(data):
            findings.append({"pattern": pattern, "path": relative.as_posix(), "scope": "candidate"})
    return findings, blockers, count, byte_count, manifest.hexdigest()


def history_objects() -> tuple[list[str], dict[str, list[str]]]:
    lines = run(["git", "rev-list", "--objects", HISTORY_ANCHOR]).decode("utf-8").splitlines()
    object_paths: dict[str, list[str]] = {}
    for line in lines:
        fields = line.split(" ", 1)
        object_paths.setdefault(fields[0], [])
        if len(fields) == 2:
            object_paths[fields[0]].append(fields[1])
    return sorted(object_paths), object_paths


def history_scan() -> tuple[list[dict[str, str]], list[str], int, int]:
    object_ids, object_paths = history_objects()
    batch = run(["git", "cat-file", "--batch"], input_bytes=("\n".join(object_ids) + "\n").encode())
    position = 0
    findings: list[dict[str, str]] = []
    blockers: list[str] = []
    blobs = 0
    byte_count = 0
    for expected_object in object_ids:
        newline = batch.find(b"\n", position)
        if newline < 0:
            raise RuntimeError("truncated git cat-file batch header")
        header = batch[position:newline].decode("ascii")
        position = newline + 1
        fields = header.split()
        if len(fields) != 3 or fields[0] != expected_object:
            raise RuntimeError("unexpected git cat-file batch header")
        object_type, size = fields[1], int(fields[2])
        data = batch[position : position + size]
        position += size
        if batch[position : position + 1] != b"\n":
            raise RuntimeError("truncated git cat-file batch payload")
        position += 1
        if object_type != "blob":
            continue
        if size > MAX_SCANNED_BLOB_BYTES:
            blockers.append(f"history-oversize:{expected_object}:{size}")
            continue
        blobs += 1
        byte_count += size
        patterns = scan_blob(data)
        for pattern in patterns:
            paths = sorted(object_paths.get(expected_object) or ["<unresolved-history-path>"])
            for path in paths:
                findings.append(
                    {
                        "blob_oid": expected_object,
                        "path": path,
                        "pattern": pattern,
                        "scope": "history",
                    }
                )
    if position != len(batch):
        raise RuntimeError("surplus git cat-file batch bytes")
    return findings, blockers, blobs, byte_count


def build_outputs() -> dict[Path, bytes]:
    cargo_packages, cargo_relationships, cargo_blockers = cargo_inventory()
    python_packages, python_relationships, python_blockers = python_inventory()
    licenses = license_text_files()
    blockers = sorted(set(cargo_blockers + python_blockers))
    if not licenses:
        blockers.append("workspace-license-text:missing-operator-approved-root-license")
    ignore_lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing_ignores = sorted(REQUIRED_IGNORE_PATTERNS - ignore_lines)
    blockers.extend(f"secret-ignore-pattern:missing:{pattern}" for pattern in missing_ignores)
    inventory = {
        "blockers": sorted(set(blockers)),
        "cargo_lock_sha256": sha256((ROOT / "Cargo.lock").read_bytes()),
        "contract": "s20-710-pre-release-inventory-v1",
        "full_release_sbom": False,
        "history_anchor_commit": HISTORY_ANCHOR,
        "license_text_files": licenses,
        "packages": cargo_packages + python_packages,
        "relationships": sorted(
            cargo_relationships + python_relationships,
            key=lambda item: (item["from"], item["to"]),
        ),
        "result": "BLOCKED" if blockers else "PASS",
        "sources": {
            "cargo_registry": REGISTRY_SOURCE,
            "python_registry": "https://pypi.org/simple",
        },
        "python_lock_freshness": "uv lock --check --offline --no-python-downloads:PASS",
        "standards_sbom_deferred": bool(blockers),
        "uv_lock_sha256": sha256((ROOT / "oracle/scb1/uv.lock").read_bytes()),
    }

    current_findings, current_blockers, current_files, current_bytes, candidate_digest = (
        current_candidate_scan()
    )
    history_findings, history_blockers, history_blobs, history_bytes = history_scan()
    secret_findings = sorted(
        current_findings + history_findings,
        key=lambda item: (item["scope"], item["path"], item["pattern"], item.get("blob_oid", "")),
    )
    secret_blockers = sorted(set(current_blockers + history_blockers))
    if secret_findings:
        secret_blockers.append("high-confidence-secret-findings-require-disposition")
    secret_scan = {
        "blockers": secret_blockers,
        "candidate_bytes_scanned": current_bytes,
        "candidate_file_manifest_sha256": candidate_digest,
        "candidate_files_scanned": current_files,
        "contract": "s20-710-secret-scan-v1",
        "findings": secret_findings,
        "history_anchor_commit": HISTORY_ANCHOR,
        "history_blobs_scanned": history_blobs,
        "history_bytes_scanned": history_bytes,
        "limitations": [
            "high-confidence patterns only; no entropy or semantic credential validation",
            "history is frozen through the pre-audit anchor; later release audit must re-anchor",
            "generated T52/T54 reports are excluded from their own candidate scan",
            "no ignored local files, reflogs, remotes, provider stores, or external secret managers scanned",
        ],
        "matched_secret_values_emitted": False,
        "patterns": sorted(SECRET_PATTERNS),
        "result": "BLOCKED" if secret_blockers else "PASS_NO_HIGH_CONFIDENCE_FINDINGS",
    }
    return {
        INVENTORY_PATH: canonical_json(inventory),
        SECRET_SCAN_PATH: canonical_json(secret_scan),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    outputs = build_outputs()
    drift: list[str] = []
    for path, expected in outputs.items():
        if arguments.check:
            if not path.exists() or path.read_bytes() != expected:
                drift.append(path.relative_to(ROOT).as_posix())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
    if drift:
        print(json.dumps({"result": "FAIL", "drift": drift}, sort_keys=True))
        return 1
    if arguments.check:
        print(json.dumps({"result": "PASS", "outputs": len(outputs)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
