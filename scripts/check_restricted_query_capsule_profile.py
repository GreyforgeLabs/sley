#!/usr/bin/env python3
"""Check the restricted S20-320 complete-query capsule profile."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/RESTRICTED_QUERY_CAPSULE_PROFILE_V1.md")
ids = read("crates/sley-id/src/lib.rs")
code = read("crates/sley-query/src/capsule.rs")
api = read("crates/sley-query/src/lib.rs")
work_packages = read("docs/WORK_PACKAGES.md")
problems: list[str] = []

for token in [
    "Status: S20-320 restricted epoch-1 normative specification.",
    '"SLEYRQC1"',
    '"sley2.restricted-query-capsule.v1"',
    "CompleteRestrictedResult",
    "Truncation = False(1)",
    "Continuation = None(1)",
    "33,554,432",
    "67,108,864",
    "not unblock S20-330, S20-400, S20-620, M3, M5, or GA",
]:
    if token not in spec:
        problems.append(f"capsule profile missing {token!r}")

if "restricted complete-query evidence capsule" not in work_packages:
    problems.append("S20-320 work-package row does not declare restricted scope")
if "RestrictedQueryCapsuleId" not in ids or "sley2.restricted-query-capsule.v1" not in ids:
    problems.append("restricted capsule identifier domain/type is absent")
if "mod capsule;" not in api or "pub use capsule::*;" not in api:
    problems.append("restricted capsule implementation is not exported")

for token in [
    "pub fn build_restricted_query_capsule",
    "response: &RestrictedQueryResponse",
    "RestrictedQueryCapsuleId::derive(&record)",
    "derive_dictionary",
    "derive_relationships",
    "MAX_CAPSULE_SOURCE_RESPONSE_BYTES: u64 = 33_554_432",
    "MAX_RESTRICTED_CAPSULE_BYTES: u64 = 67_108_864",
    "MAX_RESTRICTED_CAPSULE_WORK: u64 = 100_000_000",
    "pub const fn is_truncated(&self) -> bool",
    "pub const fn has_continuation(&self) -> bool",
]:
    if token not in code:
        problems.append(f"capsule implementation missing {token!r}")

for forbidden in [
    "pub fn decode_capsule",
    "pub fn import_capsule",
    "ContextCapsuleId::derive",
    "std::fs",
    "std::env",
    "std::process",
    "std::net",
    "SystemTime",
]:
    if forbidden in code:
        problems.append(f"forbidden capsule/ambient surface present: {forbidden}")

codes = [f"32_{value:03d}" for value in range(8)]
for stable_code in codes:
    if stable_code not in code:
        problems.append(f"stable capsule code missing: {stable_code}")

required_tests = [
    "all_four_query_capsule_vectors_are_fixed",
    "dictionary_and_relationship_projection_are_exact",
    "completeness_is_fixed_without_truncation_or_continuation",
    "repeated_equal_capsules_are_byte_identical",
    "dictionary_duplicates_and_missing_relationship_endpoints_fail",
    "resource_limits_fail_without_partial_capsule",
    "failed_or_omitted_queries_produce_no_capsule_input",
]
for test in required_tests:
    if test not in code:
        problems.append(f"restricted capsule fixture missing: {test}")

unit_tests = code.count("#[test]")
if unit_tests < 8:
    problems.append("fewer than eight restricted capsule tests")

result = {
    "contract": "s20-320-restricted-complete-query-capsule-profile-v1",
    "magic": "SLEYRQC1",
    "query_kinds": 4,
    "result_variants": 3,
    "stable_error_codes": len(codes),
    "capsule_unit_tests": unit_tests,
    "complete_only": True,
    "truncation": False,
    "continuation": False,
    "uses_master_context_capsule_id": False,
    "full_s20_320_complete": False,
    "nabu_review": "REVISE_TO_DISTINCT_RESTRICTED_EVIDENCE_ENVELOPE",
    "ariadne_review": "PASS_AFTER_SIZE_FEASIBILITY_AND_RESULT_KIND_FIX",
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2_P3_P4",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
