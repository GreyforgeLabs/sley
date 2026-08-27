#!/usr/bin/env python3
"""Validate the explicit S20-650 optional-arm unavailable state."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "bench/benchmark-plan.json"
CORPUS_PATH = ROOT / "bench/corpus/v1/tasks.json"
RECORD_PATH = ROOT / "bench/external/availability.json"
SPEC_PATH = ROOT / "docs/spec/EXTERNAL_COMPARISON_AVAILABILITY_V1.md"

EXPECTED_REASONS = [
    "NO_REGISTERED_EXACT_VERSION",
    "NO_REGISTERED_RUNNABLE_ARTIFACT_DIGEST",
    "NO_REGISTERED_EQUIVALENT_FIXTURE",
    "NO_REGISTERED_TOOL_DESCRIPTION_DIGEST",
    "NO_REGISTERED_ENVIRONMENT_DIGEST",
    "NO_REGISTERED_ORACLE_DIGEST",
]
NULL_REGISTRATION_FIELDS = [
    "registered_artifact_sha256",
    "registered_artifact_size_bytes",
    "registered_environment_digest",
    "registered_exact_version",
    "registered_fixture_digest",
    "registered_oracle_digest",
    "registered_tool_description_digest",
]
FALSE_CLAIM_FIELDS = [
    "acquisition_or_network_search_performed",
    "global_project_availability_claimed",
    "performance_claim",
    "public_claim_authorized",
    "required_arm",
    "superiority_claim",
]
EXPECTED_RECORD_FIELDS = {
    "acquisition_or_network_search_performed",
    "arm_id",
    "availability_status",
    "benchmark_plan_arm_status",
    "benchmark_plan_sha256",
    "comparison_trials_executed",
    "contract",
    "corpus_sha256",
    "global_project_availability_claimed",
    "performance_claim",
    "public_claim_authorized",
    "reason_codes",
    *NULL_REGISTRATION_FIELDS,
    "required_arm",
    "result",
    "scope",
    "superiority_claim",
    "work_package",
}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} is not an object")
    return value


problems: list[str] = []
try:
    plan = load(PLAN_PATH)
    corpus = load(CORPUS_PATH)
    record = load(RECORD_PATH)
    spec = SPEC_PATH.read_text(encoding="utf-8")
except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
    problems.append(str(error))
    plan = {}
    corpus = {}
    record = {}
    spec = ""

optional_arms = [
    arm
    for arm in plan.get("arms", [])
    if isinstance(arm, dict) and arm.get("id") == "zerolang"
]
if optional_arms != [
    {"id": "zerolang", "required": False, "fixture_status": "UNESTABLISHED"}
]:
    problems.append("frozen benchmark plan optional arm drifted")
if corpus.get("version") != 1 or corpus.get("status") != "FROZEN":
    problems.append("frozen corpus identity drifted")

plan_digest = (
    hashlib.sha256(PLAN_PATH.read_bytes()).hexdigest() if PLAN_PATH.exists() else None
)
corpus_digest = (
    hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    if CORPUS_PATH.exists()
    else None
)
expected_identity = {
    "arm_id": "zerolang",
    "availability_status": "UNAVAILABLE_NO_FROZEN_COMPARISON_PACKAGE",
    "benchmark_plan_arm_status": "UNESTABLISHED",
    "benchmark_plan_sha256": plan_digest,
    "comparison_trials_executed": 0,
    "contract": "sley2.external-arm-availability.v1",
    "corpus_sha256": corpus_digest,
    "result": "EXPLICIT_UNAVAILABLE",
    "scope": "REPOSITORY_REGISTERED_EVIDENCE_ONLY",
    "work_package": "S20-650",
}
for field, expected in expected_identity.items():
    if record.get(field) != expected:
        problems.append(f"availability record identity mismatch: {field}")
if set(record) != EXPECTED_RECORD_FIELDS:
    problems.append("availability record field set drifted")
if (
    type(record.get("comparison_trials_executed")) is not int
):  # bool is not a trial count
    problems.append("comparison trial count is not an integer")
for field in NULL_REGISTRATION_FIELDS:
    if field not in record or record[field] is not None:
        problems.append(f"unavailable registration field is not null: {field}")
for field in FALSE_CLAIM_FIELDS:
    if record.get(field) is not False:
        problems.append(f"unavailable claim field is not false: {field}")
if record.get("reason_codes") != EXPECTED_REASONS:
    problems.append("unavailable reason codes drifted")

allowed_external_files = {"README.md", "availability.json"}
actual_external_files = {
    path.relative_to(RECORD_PATH.parent).as_posix()
    for path in RECORD_PATH.parent.rglob("*")
    if path.is_file()
}
if actual_external_files != allowed_external_files:
    problems.append(
        f"unexpected external adapter/artifact files: {sorted(actual_external_files)}"
    )
if any(path.is_symlink() for path in RECORD_PATH.parent.rglob("*")):
    problems.append("external availability directory contains a symbolic link")

for token in [
    "Status: S20-650 complete as an explicit repository-scoped unavailable state.",
    "AVAILABLE_FROZEN",
    "EXPLICIT_UNAVAILABLE",
    "makes no global availability statement",
    "zero comparison trials",
    "cannot be treated as a poor score",
]:
    if token not in spec:
        problems.append(f"availability spec missing {token!r}")

result = {
    "contract": "s20-650-external-comparison-availability-v1",
    "arm_id": "zerolang",
    "availability": "EXPLICIT_UNAVAILABLE",
    "scope": "REPOSITORY_REGISTERED_EVIDENCE_ONLY",
    "missing_prerequisites": len(EXPECTED_REASONS),
    "comparison_trials_executed": 0,
    "global_project_availability_claimed": False,
    "network_or_acquisition_performed": False,
    "public_claim_authorized": False,
    "full_s20_650_complete": not problems,
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
