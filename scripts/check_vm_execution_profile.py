#!/usr/bin/env python3
"""Check the restricted S20-270 deterministic VM execution profile."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/VM_EXECUTION_PROFILE_V1.md")
execution_code = read("crates/sley-vm/src/execute.rs")
library_code = read("crates/sley-vm/src/lib.rs")
work_packages = read("docs/WORK_PACKAGES.md")

problems: list[str] = []

required_spec = [
    "Status: S20-270 restricted epoch-1 normative specification.",
    '"SLEYOBS1"',
    '"sley2.observation.v1"',
    "all five frozen terminators",
    "262,144 ordered inputs",
    "67,108,864",
    "aggregate validated input",
    "Full S20-270 GA",
    "S20-290 owns",
]
for token in required_spec:
    if token not in spec:
        problems.append(f"profile missing {token!r}")

if "250,260" not in work_packages:
    problems.append("S20-270 does not declare its S20-250 value-hash dependency")
if "execute_function" not in execution_code or "execute_function" not in library_code:
    problems.append("integrated execution API is missing or not exported")
if "lower_function(input)?" not in execution_code:
    problems.append("execution does not preserve the integrated lowering boundary")
if "hash_validated_value" not in execution_code or "require_hashable" not in execution_code:
    problems.append("canonical input/result value-hash gate is incomplete")
if (
    "MAX_EXECUTION_INPUTS" not in execution_code
    or "MAX_EXECUTION_INPUT_VALUE_UNITS" not in execution_code
):
    problems.append("hard aggregate input bounds are missing")
if "MAX_OBSERVATION_PREIMAGE_BYTES" not in execution_code:
    problems.append("observation preimage cap is missing")
if "Arc<ConstValue>" not in execution_code or "payload_view" not in execution_code:
    problems.append("immutable selected-payload reference views are missing")

codes = [
    "VM_EXEC_INPUT_COUNT_MISMATCH",
    "VM_EXEC_INPUT_TYPE_MISMATCH",
    "VM_EXEC_RESOURCE_LIMIT",
    "VM_EXEC_CANCELLED",
    "VM_EXEC_TRAP",
    "VM_EXEC_INTERNAL_INVARIANT",
]
for code in codes:
    if code not in execution_code or code not in spec:
        problems.append(f"execution code drift: {code}")

unit_tests = execution_code.count("#[test]")
if unit_tests < 10:
    problems.append("fewer than ten restricted execution tests")
if "observation_preimage_and_id_are_exact" not in execution_code:
    problems.append("literal observation preimage fixture is missing")
if "for _ in 0..128" not in execution_code:
    problems.append("128-repeat determinism fixture is missing")

result = {
    "contract": "s20-270-restricted-vm-execution-profile-v1",
    "supported_terminators": 5,
    "supported_opcodes": [102, 103, 104],
    "stable_error_codes": len(codes),
    "execution_unit_tests": unit_tests,
    "max_inputs": 262_144,
    "max_input_value_units": 67_108_864,
    "max_observation_preimage_bytes": 67_108_864,
    "full_ga_complete": False,
    "nabu_review": "PASS_RESTRICTED_FAIL_CLOSED_PROFILE",
    "ariadne_review": "PASS_AFTER_RESOURCE_AND_PAYLOAD_ACCOUNTING_FIXES",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
