#!/usr/bin/env python3
"""Check the scoped S20-600 frozen legacy artifact adapter."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bench.legacy.runner import (  # noqa: E402
    FROZEN_CONTRACT,
    LegacyRunnerError,
    verify_frozen_artifact,
)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


runner = read("bench/legacy/runner.py")
tests = read("bench/legacy/tests/test_runner.py")
spec = read("docs/spec/LEGACY_ARTIFACT_ADAPTER_V1.md")
adr = read("docs/adr/ADR-0018-frozen-legacy-artifact-adapter.md")
legacy_readme = read("bench/legacy/README.md")
bench_readme = read("bench/README.md")
work_packages = read("docs/WORK_PACKAGES.md")
makefile = read("Makefile")
problems: list[str] = []

for token in [
    "Status: S20-600 verified-artifact and version-smoke contract only.",
    "b24f19c6a348751c93c9cf63f6f4154f6132796112c26f9d8c0e71324080dbc7",
    "1,568 members",
    "1,067 sorted payload entries",
    "NOT_ENFORCED_VERSION_ONLY",
    "Numeric codes 60000 through 60014",
    "Full S20-600 remains open",
]:
    if token not in spec:
        problems.append(f"legacy adapter spec missing {token!r}")

for token in [
    "class LegacyErrorCode(IntEnum)",
    "class LegacyArtifactContract",
    "def verify_frozen_artifact",
    "def staged_frozen_artifact",
    "def run_version_smoke",
    "def record_smoke_evidence",
    'VERSION_ARGUMENTS = ("--version",)',
    "O_NOFOLLOW",
    "subprocess.Popen(",
    "shell=False",
    "start_new_session=True",
    '"SLEY_SOURCE_CACHE_DIR"',
    '"network_isolation": "NOT_ENFORCED_VERSION_ONLY"',
    '"stage_write_bits_removed": True',
    '"read_only_mount_enforced": False',
    '"benchmark_trials_executed": 0',
    '"full_s20_600_complete": False',
]:
    if token not in runner:
        problems.append(f"legacy adapter implementation missing {token!r}")

for forbidden in [
    "extractall(",
    ".extract(",
    "shell=True",
    "os.system",
    "os.popen",
    '"/home/',
]:
    if forbidden in runner:
        problems.append(f"legacy adapter contains forbidden surface {forbidden!r}")

tree = ast.parse(runner)
imports: set[str] = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.update(alias.name.split(".")[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imports.add(node.module.split(".")[0])
for forbidden in {"socket", "requests", "urllib", "http", "ftplib"}:
    if forbidden in imports:
        problems.append(f"legacy adapter imports network module {forbidden!r}")

for token in [
    "test_valid_artifact_is_verified_stage_write_bits_removed_and_smoked",
    "test_outer_identity_drift_fails_before_archive_use",
    "test_traversal_links_and_duplicates_fail_closed",
    "test_payload_tamper_fails_manifest_inventory_check",
    "test_timeout_is_returned_as_retained_failure",
    "test_nonzero_exit_and_stderr_are_retained",
    "test_output_limit_kills_and_retains_prefix",
    "test_nonfinite_timeout_fails_closed",
    "test_evidence_records_are_create_only",
]:
    if token not in tests:
        problems.append(f"legacy adapter tests missing {token!r}")

if "scoped frozen-artifact adapter" not in bench_readme:
    problems.append("benchmark README omits scoped S20-600 adapter")
if "verified frozen-artifact/version-smoke adapter" not in work_packages:
    problems.append("S20-600 work-package checkpoint is absent")
if "python3 scripts/check_legacy_runner.py" not in makefile:
    problems.append("routine quick gate omits legacy adapter checker")
if "legacy-runner-smoke:" not in makefile:
    problems.append("Makefile omits explicit real legacy smoke target")
if "never reads or writes" not in legacy_readme:
    problems.append("legacy README omits live-checkout boundary")
if "successful longer smoke" not in adr:
    problems.append("legacy ADR omits retained negative and positive evidence")
if runner.count("60_0") < 15:
    problems.append("fewer than fifteen frozen legacy-adapter numeric codes")

unit = subprocess.run(
    [sys.executable, "-m", "unittest", "discover", "-s", "bench/legacy/tests"],
    cwd=ROOT,
    check=False,
    capture_output=True,
    text=True,
)
if unit.returncode != 0:
    problems.append(
        f"synthetic legacy adapter tests failed: {(unit.stderr or unit.stdout).strip()}"
    )

verified = None
try:
    verified = verify_frozen_artifact()
except LegacyRunnerError as error:
    problems.append(f"frozen artifact verification failed: {error}")

result = {
    "contract": "s20-600-frozen-legacy-artifact-adapter-v1",
    "artifact_sha256": FROZEN_CONTRACT.artifact_sha256,
    "artifact_size_bytes": FROZEN_CONTRACT.artifact_size_bytes,
    "artifact_bytes_verified": verified is not None,
    "archive_members_verified": verified.archive_member_count if verified else None,
    "payload_files_verified": verified.payload_file_count if verified else None,
    "payload_bytes_verified": verified.payload_total_bytes if verified else None,
    "stable_error_codes": 15,
    "synthetic_smoke_tests": 9,
    "manual_real_smoke_target": "make legacy-runner-smoke",
    "real_smoke_in_routine_quick": False,
    "provider_or_model_execution": False,
    "benchmark_trials_executed": 0,
    "network_isolation_claimed": False,
    "live_legacy_checkout_interaction": False,
    "full_s20_600_complete": False,
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
