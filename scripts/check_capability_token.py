#!/usr/bin/env python3
"""Check the narrow local S20-380 capability-token package."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


policy = read("crates/sley-policy/src/lib.rs")
adapter = read("crates/sley-adapter/src/lib.rs")
policy_cargo = read("crates/sley-policy/Cargo.toml")
adapter_cargo = read("crates/sley-adapter/Cargo.toml")
spec = read("docs/spec/CAPABILITY_TOKEN_V1.md")
adr = read("docs/adr/ADR-0016-capability-tokens.md")
threats = read("docs/THREAT_REGISTER.md")
work_packages = read("docs/WORK_PACKAGES.md")
makefile = read("Makefile")
summary = json.loads(read("machineresearch/sley-2.0/machine-summary.json"))
problems: list[str] = []

for token in [
    "Status: S20-380 narrow local-only normative profile.",
    '"SLEYCAPD"',
    '"SLEYCAPM"',
    '"sley2.capability-token.v1"',
    "authenticator = keyed-BLAKE3-256(host_secret[32], mac_preimage)",
    "max_virtual_files * 4368",
    "Failures before charge mutate neither ledger nor fixture.",
    "does not complete candidate admission",
]:
    if token not in spec:
        problems.append(f"capability spec missing {token!r}")

for token in [
    "pub struct CapabilityTokenBody",
    "pub struct CapabilityToken",
    "pub struct CapabilityTrustedKey",
    "pub struct CapabilityLedger",
    "pub fn issue_capability_token",
    "pub fn import_capability_token",
    "pub fn verify_capability_token",
    "pub fn verify_and_charge_capability",
    'b"SLEYCAPD"',
    'b"SLEYCAPM"',
    "Hasher::new_keyed",
    "CapabilitySecret(..redacted..)",
    "constant_time_eq",
    "fd9248cd3f1e46ed013e97c985c8e9e45eb58277b0d8dd126f5cbfeb1698d616",
    "7c4c590e61b186cd399b7cfcb3abc6481c0dc77b542fd50f6f7f3c4aebcec7ac",
    "f7a00e1e9eb35d6b66445c47c8426d5792078b9a9de9b165d7b7c697d3c92acb",
    "t22_capability_forgery_fails_closed",
    "t23_capability_replay_expiry_and_budget_fail_closed",
    "t24_capability_scope_workspace_effect_and_adapter_confusion_fail_closed",
]:
    if token not in policy:
        problems.append(f"capability implementation missing {token!r}")

for token in [
    "pub fn capability_budget_for_adapter_limits",
    "MAX_CANONICAL_PATH_BYTES: u64 = 4_352",
    "pub fn invoke_authorized_reference_adapter",
    "verify_and_charge_capability",
    "authorized_adapter_resource_dimensions_fail_closed_before_charge",
    "authorized_adapter_request_binding_confusion_fails_before_charge",
    "capability_budget_reserves_the_maximum_canonical_path",
    "authorized_adapter_success_charges_once_then_mutates_fixture",
    "authorized_adapter_failure_before_charge_mutates_neither_ledger_nor_fixture",
    "authorized_adapter_failure_after_charge_consumes_ledger_without_fixture_mutation",
    "conformance-only fixture API",
]:
    if token not in adapter:
        problems.append(f"authorized adapter boundary missing {token!r}")

for forbidden in [
    "SystemTime",
    "std::fs",
    "std::env",
    "std::net",
    "std::process",
    "thread_rng",
    "rand::",
]:
    if forbidden in policy or forbidden in adapter:
        problems.append(f"ambient capability/runtime surface present: {forbidden}")

for token in ["T22", "T23", "T24", "S20-380 unit coverage present"]:
    if token not in threats:
        problems.append(f"threat register missing {token!r}")
if "local capability token and authorized reference-adapter wrapper" not in work_packages:
    problems.append("S20-380 work-package closeout is absent")
if 'blake3 = "=1.8.2"' not in policy_cargo:
    problems.append("sley-policy lacks the pinned BLAKE3 dependency")
if 'sley-policy = { path = "../sley-policy" }' not in adapter_cargo:
    problems.append("sley-adapter lacks the one-way sley-policy dependency")
if "sley-adapter" in policy_cargo:
    problems.append("forbidden reverse sley-policy -> sley-adapter dependency present")
if "python3 scripts/check_capability_token.py" not in makefile:
    problems.append("routine quick gate omits capability-token checker")
if "There is no reverse dependency." not in adr:
    problems.append("capability ADR omits the one-way dependency decision")
if (
    summary.get("adversarial", {}).get("vulcan_adapter_binding_review")
    != "PASS_NO_OPEN_P0_P1_P2"
):
    problems.append("S20-700 adapter-binding review disposition is absent")
summary_profile = summary.get("capability_token_profile", {})
expected_summary = {
    "status": "S20_380_COMPLETE_NARROW_LOCAL_PROFILE",
    "contract": "docs/spec/CAPABILITY_TOKEN_V1.md",
    "implementation": ["crates/sley-policy", "crates/sley-adapter"],
    "token_fields": 16,
    "budget_fields": 6,
    "stable_error_codes": 20,
    "policy_capability_unit_tests": 6,
    "authorized_adapter_unit_tests": 6,
    "policy_total_unit_tests": 25,
    "adapter_total_unit_tests": 20,
    "workspace_total_rust_unit_tests": 347,
    "token_digest": "fd9248cd3f1e46ed013e97c985c8e9e45eb58277b0d8dd126f5cbfeb1698d616",
    "authenticator": "7c4c590e61b186cd399b7cfcb3abc6481c0dc77b542fd50f6f7f3c4aebcec7ac",
    "stored_token_blake3": "f7a00e1e9eb35d6b66445c47c8426d5792078b9a9de9b165d7b7c697d3c92acb",
    "host_secret_serialized": False,
    "host_time_ambient": False,
    "replay_and_budget_ledger": True,
    "authorized_reference_adapter_wrapper": True,
    "precharge_failure_atomic": True,
    "postcharge_fixture_failure_atomic": True,
    "t22_forgery_covered": True,
    "t23_replay_expiry_budget_covered": True,
    "t24_binding_confusion_covered": True,
    "policy_transition_authority": False,
    "vm_integration": False,
    "live_host_confinement": False,
    "candidate_or_commit_authority": False,
    "full_ga_complete": False,
    "implementation_complete": True,
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2",
    "s20_700_binding_review": "PASS_NO_OPEN_P0_P1_P2",
}
summary_registered = True
for field, expected in expected_summary.items():
    if summary_profile.get(field) != expected:
        summary_registered = False
        problems.append(f"capability machine summary mismatch: {field}")
if policy.count("38_0") < 20:
    problems.append("fewer than twenty frozen capability numeric codes")
if policy.count("#[test]") != 25:
    problems.append("policy test inventory differs from the registered twenty-five")
if adapter.count("#[test]") != 20:
    problems.append("adapter test inventory differs from the registered twenty")

result = {
    "contract": "s20-380-capability-token-v1",
    "token_fields": 16,
    "budget_fields": 6,
    "stable_error_codes": 20,
    "adapter_limit_path_bytes": 4352,
    "adapter_file_entry_reservation_bytes": 4368,
    "host_time_ambient": False,
    "host_secret_serialized": False,
    "live_host_authority": False,
    "vm_integration": False,
    "candidate_or_commit_authority": False,
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2",
    "s20_700_binding_review": "PASS_NO_OPEN_P0_P1_P2",
    "machine_summary_registered": summary_registered,
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
