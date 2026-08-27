#!/usr/bin/env python3
"""Check the offline-only S20-610 raw baseline runner contract."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


runner = read("bench/raw/runner.py")
tests = read("bench/raw/tests/test_runner.py")
spec = read("docs/spec/RAW_BASELINE_RUNNER_V1.md")
adr = read("docs/adr/ADR-0017-offline-raw-baseline-runner.md")
bench_readme = read("bench/README.md")
raw_readme = read("bench/raw/README.md")
work_packages = read("docs/WORK_PACKAGES.md")
makefile = read("Makefile")
problems: list[str] = []

for token in [
    "Status: S20-610 offline-only normative runner contract.",
    "sley2.raw-run-manifest.v1",
    "sley2.raw-trial-digest-claim.v1",
    "all seventeen controls",
    "accepted_change_tokens",
    "Numeric codes 61000 through 61015",
    "The raw fixture remains pending",
]:
    if token not in spec:
        problems.append(f"raw runner spec missing {token!r}")

for token in [
    "class RawErrorCode(IntEnum)",
    "class AgentAdapter(Protocol)",
    "class ToolAdapter(Protocol)",
    "class OracleAdapter(Protocol)",
    "class WorkspaceAdapter(Protocol)",
    "class AccountingClock(Protocol)",
    "def validate_run_manifest",
    "def assert_fair_shared_controls",
    "def write_run_manifest",
    "def append_trial_digest_claim",
    "def verify_digest_claim_directory",
    "os.O_EXCL",
    "os.O_APPEND",
    "fcntl.LOCK_EX",
    "os.fsync",
    'EXTERNAL_COMMAND_POLICY = "forbidden"',
    'EVIDENCE_STATUS = "UNVERIFIED_INJECTED_DIGEST_CLAIMS"',
    'VERIFICATION_STATUS = "UNVERIFIED_ADAPTER_CLAIM"',
    "ACT is derived only by S20-630",
]:
    if token not in runner:
        problems.append(f"raw runner implementation missing {token!r}")

tree = ast.parse(runner)
imports: set[str] = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.update(alias.name.split(".")[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imports.add(node.module.split(".")[0])
for forbidden in {"subprocess", "socket", "requests", "urllib", "http"}:
    if forbidden in imports:
        problems.append(f"runner imports forbidden live execution/network module {forbidden!r}")
for forbidden in [
    "os.system",
    "os.popen",
    "Popen",
    "run_command",
    "<LOCAL_HOME>/sley",
]:
    if forbidden in runner:
        problems.append(f"runner contains forbidden execution/Sley1 surface {forbidden!r}")

for token in [
    "test_success_and_timeout_are_chained_and_complete",
    "test_control_drift_and_external_execution_fail_closed",
    "test_duplicate_and_trial_limit_preserve_existing_chain",
    "test_tamper_and_noncanonical_manifest_are_detected",
]:
    if token not in tests:
        problems.append(f"raw runner smoke missing {token!r}")

if "offline-only, injected-adapter evidence runner" not in raw_readme:
    problems.append("raw runner README omits offline-only boundary")
if "offline-only raw-file runner contract" not in bench_readme:
    problems.append("benchmark README omits S20-610 closeout")
if "offline raw digest-claim contract" not in work_packages:
    problems.append("S20-610 work-package closeout is absent")
if "python3 scripts/check_raw_baseline_runner.py" not in makefile:
    problems.append("routine quick gate omits raw baseline checker")
if "ships no external command" not in adr:
    problems.append("raw runner ADR omits the no-execution decision")
if runner.count("61_0") < 16:
    problems.append("fewer than sixteen frozen raw-runner numeric codes")

smoke = subprocess.run(
    [sys.executable, "-m", "unittest", "discover", "-s", "bench/raw/tests"],
    cwd=ROOT,
    check=False,
    capture_output=True,
    text=True,
)
if smoke.returncode != 0:
    problems.append(f"offline smoke failed: {(smoke.stderr or smoke.stdout).strip()}")

result = {
    "contract": "s20-610-offline-raw-baseline-runner-v1",
    "stable_error_codes": 16,
    "run_freeze_controls": 17,
    "benchmark_metrics": 25,
    "offline_smoke_tests": 4,
    "external_command_adapter": False,
    "provider_or_model_execution": False,
    "sley_1_2_interaction": False,
    "actual_trials": 0,
    "artifact_bytes_verified": False,
    "oracle_claims_verified": False,
    "accounting_claims_verified": False,
    "act_derived": False,
    "nabu_review": "REVISE_TO_OFFLINE_APPEND_ONLY_CONTRACT",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
