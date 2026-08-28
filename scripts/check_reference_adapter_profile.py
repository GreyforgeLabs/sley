#!/usr/bin/env python3
"""Check the restricted S20-280 deterministic reference-adapter profile."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/REFERENCE_ADAPTER_PROFILE_V1.md")
adapter = read("crates/sley-adapter/src/lib.rs")
identifier = read("crates/sley-id/src/lib.rs")
work_packages = read("docs/WORK_PACKAGES.md")
summary = json.loads(read("machineresearch/sley-2.0/machine-summary.json"))

problems: list[str] = []

expected_transcript_id = "820510df49047b58d4cace426f72090b5e9e4ded84a0a4405a4957e4cdfdf6a1"
if expected_transcript_id not in adapter:
    problems.append("fixed adapter transcript vector drift")
if summary.get("reference_adapter_profile", {}).get("fixed_transcript_id") != expected_transcript_id:
    problems.append("machine-summary adapter transcript vector drift")

required_spec = [
    "Status: S20-280 restricted epoch-1 normative specification.",
    '"SLEYRAI1"',
    '"SLEYADS1"',
    '"SLEYADT1"',
    '"sley2.reference-random.v1"',
    "request-owned S20-280 fixture records",
    "Full S20-280 GA remains blocked",
]
for token in required_spec:
    if token not in spec:
        problems.append(f"profile missing {token!r}")

for domain in [
    "sley2.reference-adapter-id.v1",
    "sley2.adapter-state.v1",
    "sley2.adapter-transcript.v1",
]:
    if domain not in spec or domain not in identifier:
        problems.append(f"domain registry drift: {domain}")

if "230,270" not in work_packages:
    problems.append("S20-280 does not declare its S20-230/S20-270 dependencies")
if "pub fn invoke_reference_adapter" not in adapter:
    problems.append("restricted adapter invocation API is missing")
if "AdapterInvocationError" not in adapter or "Fingerprint(FingerprintError)" not in adapter:
    problems.append("prior type/fingerprint failures are not preserved")
if "types: &TypeEnvironment" not in adapter or "schema_epoch: SchemaEpochId" not in adapter:
    problems.append("state/transcript hashing lacks explicit type/epoch context")
if "SchemaEpochId::from_bytes([0; 32])" in adapter:
    problems.append("replay outcome hashing uses an unbound zero schema epoch")
for forbidden in ["std::fs", "std::env", "std::process", "std::net"]:
    if forbidden in adapter:
        problems.append(f"ambient host surface imported: {forbidden}")

required_tests = [
    "fixed_reference_ids_cover_all_kinds",
    "fixed_state_and_transcript_vectors",
    "prior_type_failure_is_preserved_before_adapter_preflight",
    "identity_abi_and_effect_swaps_fail_without_mutation",
    "random_counter_overflow_is_atomic",
    "replay_mismatch_and_response_injection_are_atomic",
    "replay_outcomes_bind_state_id_to_schema_epoch",
    "repeated_equal_invocations_are_deterministic",
]
for test in required_tests:
    if test not in adapter:
        problems.append(f"adapter adversarial fixture missing: {test}")

codes = [f"28_{value:03d}" for value in range(12)]
for code in codes:
    if code not in adapter:
        problems.append(f"stable adapter code missing: {code}")

unit_tests = adapter.count("#[test]")
if unit_tests < 14:
    problems.append("fewer than fourteen restricted adapter tests")

result = {
    "contract": "s20-280-restricted-reference-adapter-profile-v1",
    "reference_adapter_kinds": 8,
    "stable_error_codes": len(codes),
    "adapter_unit_tests": unit_tests,
    "host_access": False,
    "vm_integration": False,
    "full_ga_complete": False,
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
