#!/usr/bin/env python3
"""Check the S20-370 protected policy-root package."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/POLICY_ROOT_V1.md")
code = read("crates/sley-policy/src/lib.rs")
readme = read("crates/sley-policy/README.md")
ids = read("crates/sley-id/src/lib.rs")
work_packages = read("docs/WORK_PACKAGES.md")
cargo = read("Cargo.toml")
makefile = read("Makefile")
problems: list[str] = []

for token in [
    "Status: S20-370 normative protected-policy contract.",
    'contract_tag      = 370',
    'contract_domain   = "sley2.policy-root.v1"',
    "18c124c267de228e79936a01e589aedafe576b8d0fdf611f12d517f0378aa335",
    "ca84d0b5c4911bff88c6f5ed7c93e8f1eb6ef16b9193f53020a5649c01306725",
    "ExternalHigherAuthorityOnly = 1",
    "transitions remain unapproved",
    "does not complete S20-350, S20-360, S20-380, S20-390",
]:
    if token not in spec:
        problems.append(f"policy spec missing {token!r}")

for token in [
    "PrincipalId",
    "Host-supplied opaque 32-byte principal identity",
]:
    if token not in ids:
        problems.append(f"principal identity surface missing {token!r}")

for token in [
    "pub struct PolicyRootRecord",
    "pub struct AcceptedPolicyRoot",
    "pub struct PrincipalGrant",
    "pub struct PolicyTransitionMode",
    "EXTERNAL_HIGHER_AUTHORITY_ONLY",
    "pub fn import_policy_root",
    "pub fn validate_ordinary_program_isolation",
    "pub fn finalize_mandatory_contract_tests",
    "POLICY_ROOT_DUPLICATE_INPUT",
    "POLICY_FINAL_REQUIRED_TEST_NOT_SELECTED",
    "unordered_inputs_have_identical_root_for_128_repeats",
    "policy_self_oracle_and_protected_entity_isolation_is_pure",
    "finalization_rejects_forged_or_omitted_contract_test_inputs",
    "invalid_transition_tag_preserves_the_frozen_policy_error",
]:
    if token not in code:
        problems.append(f"policy implementation missing {token!r}")

for forbidden in [
    "pub root:",
    "pub stored_bytes:",
    "pub fn issue_capability",
    "pub fn authorize_transition",
    "pub fn apply",
    "pub fn commit",
    "CandidateId",
    "CapabilityTokenDigest",
    "std::fs",
    "std::env",
    "std::net",
    "std::process",
    "SystemTime",
]:
    if forbidden in code:
        problems.append(f"forbidden mutable/ambient/authority surface present: {forbidden}")

if code.count("#[test]") < 19:
    problems.append("fewer than nineteen policy-root tests")
if code.count("37_0") < 19:
    problems.append("fewer than nineteen frozen policy numeric codes")
if '"crates/sley-policy"' not in cargo:
    problems.append("sley-policy is absent from the Cargo workspace")
if "python3 scripts/check_policy_root.py" not in makefile:
    problems.append("routine quick gate omits policy-root checker")
if "protected policy root" not in work_packages:
    problems.append("S20-370 work-package closeout is absent")
if "does not issue capability tokens" not in readme:
    problems.append("policy README omits the no-token boundary")

result = {
    "contract": "s20-370-protected-policy-root-v1",
    "contract_tag": 370,
    "digest_domain_tag": 8,
    "record_fields": 11,
    "principal_grant_fields": 4,
    "resource_ceiling_fields": 6,
    "stable_error_codes": 19,
    "policy_unit_tests": code.count("#[test]"),
    "capability_tokens": False,
    "policy_transition_authority": False,
    "candidate_or_commit_authority": False,
    "nabu_review": "REVISE_TO_NARROW_PROTECTED_POLICY_ROOT",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
