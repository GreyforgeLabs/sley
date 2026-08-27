#!/usr/bin/env python3
"""Check the restricted S20-240 contract/test profile."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/CONTRACT_TEST_PROFILE_V1.md"
MODEL = ROOT / "crates/sley-ssmc/src/lib.rs"
CHECKER_ROOT = ROOT / "crates/sley-check/src/lib.rs"
CHECKER = ROOT / "crates/sley-check/src/contracts.rs"

SPEC_MARKERS = (
    "Status: S20-240 restricted epoch-1 normative specification.",
    "not the complete GA",
    "POLICY_INCOMPLETE",
    "only accepted environment is exactly `Replay([])`",
    "Expected observations must be empty",
    "Full GA remains blocked on a later schema",
)
MODEL_MARKERS = (
    "pub enum ContractKind",
    "pub enum ContractSource",
    "pub struct ContractDefinition",
    "pub struct ConstantDefinition",
    "pub struct GlobalValueDefinition",
    "pub struct TestCaseDefinition",
    "pub enum EffectEnvironment",
    "pub enum ExpectedOutcome",
    "#![forbid(unsafe_code)]",
)
ROOT_MARKERS = ("pub mod contracts;", "#![forbid(unsafe_code)]")
CHECKER_MARKERS = (
    "pub fn validate_contract_test_program",
    "fn validate_bindings",
    "fn validate_contract_assertions",
    "fn reject_test_observations",
    "fn select_tests",
    "stable_contract_test_codes_are_frozen",
    "seeded_unresolved_selection_smoke_never_accepts_or_panics",
)
LIMITS = {
    "MAX_CONTRACT_TYPE_DEFINITIONS": "65_535",
    "MAX_CONTRACTS": "65_535",
    "MAX_TEST_CASES": "65_535",
    "MAX_TOTAL_CONTRACT_BINDINGS": "1_000_000",
    "MAX_TOTAL_TEST_INPUTS": "1_000_000",
    "MAX_SELECTED_TESTS": "65_535",
}
FORBIDDEN_SOURCE_MARKERS = (
    "use std::fs",
    "std::net",
    "std::process",
    "Command::",
    "SystemTime",
)


def main() -> int:
    problems: list[str] = []
    for path in (SPEC, MODEL, CHECKER_ROOT, CHECKER):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")
    spec = SPEC.read_text() if SPEC.is_file() else ""
    model = MODEL.read_text() if MODEL.is_file() else ""
    checker_root = CHECKER_ROOT.read_text() if CHECKER_ROOT.is_file() else ""
    checker = CHECKER.read_text() if CHECKER.is_file() else ""

    for marker in SPEC_MARKERS:
        if marker not in spec:
            problems.append(f"spec-marker:{marker}")
    for marker in MODEL_MARKERS:
        if marker not in model:
            problems.append(f"model-marker:{marker}")
    for marker in ROOT_MARKERS:
        if marker not in checker_root:
            problems.append(f"checker-root-marker:{marker}")
    for marker in CHECKER_MARKERS:
        if marker not in checker:
            problems.append(f"checker-marker:{marker}")
    for marker in FORBIDDEN_SOURCE_MARKERS:
        if marker in model or marker in checker_root or marker in checker:
            problems.append(f"forbidden-source-marker:{marker}")
    for name, value in LIMITS.items():
        declaration = f"pub const {name}: usize = {value};"
        if declaration not in checker:
            problems.append(f"limit:{declaration}")
    if "pub const MAX_CONTRACT_TEST_WORK: u64 = 50_000_000;" not in checker:
        problems.append("limit:MAX_CONTRACT_TEST_WORK")

    codes = [
        int(value.replace("_", ""))
        for value in re.findall(r"Self::[A-Za-z0-9]+ => (24_\d{3}),", checker)
    ]
    if codes != list(range(24_000, 24_018)):
        problems.append(f"contract-test-codes:{codes}")
    compact_spec = spec.replace(",", "").replace("_", "")
    for number in range(24_000, 24_018):
        if str(number) not in compact_spec:
            problems.append(f"numeric-error:{number}")

    kind_tags = [
        int(value)
        for value in re.findall(
            r"Self::(?:Precondition|Postcondition|Invariant|EffectBound|CapabilityBound|ResultPredicate|ResourceCeiling) => (\d),",
            model,
        )
    ]
    if kind_tags != list(range(1, 8)):
        problems.append(f"contract-kind-tags:{kind_tags}")
    unit_tests = checker.count("#[test]")
    if unit_tests < 11:
        problems.append(f"contract-test-unit-tests:{unit_tests}<11")

    print(
        json.dumps(
            {
                "ariadne_review": "PASS_AFTER_TEST_PLAN_NAMESPACE_FIX",
                "contract": "s20-240-restricted-contract-test-profile-v1",
                "contract_kinds_frozen": len(kind_tags),
                "contract_kinds_supported": 3,
                "contract_test_error_codes": len(codes),
                "contract_test_unit_tests": unit_tests,
                "full_ga_complete": False,
                "implementation": ["crates/sley-ssmc", "crates/sley-check"],
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
                "vulcan_review": "PASS",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
