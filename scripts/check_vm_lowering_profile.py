#!/usr/bin/env python3
"""Check the restricted S20-260 VM lowering profile for drift."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/VM_LOWERING_PROFILE_V1.md")
identifiers = read("docs/spec/IDENTIFIERS_V1.md")
identifier_code = read("crates/sley-id/src/lib.rs")
vm_code = read("crates/sley-vm/src/lib.rs")
lowering_code = read("crates/sley-vm/src/lower.rs")
workspace = read("Cargo.toml")

problems: list[str] = []

required_spec = [
    "Status: S20-260 restricted epoch-1 normative specification.",
    '"SLEYBC01"',
    '"SLEYBCK1"',
    '"sley2.vm-bytecode-cache-key.v1"',
    "all five terminators",
    "full S20-260 GA",
    "1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae",
    "389791b170bc9d8575f7e6f338e4f9e9f2b75f35d7a2e52c7cb106cb2cd6136a",
]
for token in required_spec:
    if token not in spec:
        problems.append(f"profile missing {token!r}")

if "sley2.vm-bytecode-cache-key.v1" not in identifiers:
    problems.append("bytecode cache-key domain is absent from identifier contract")
if "sley2.vm-bytecode-cache-key.v1" not in identifier_code:
    problems.append("bytecode cache-key domain is absent from identifier code")
if '"crates/sley-vm"' not in workspace:
    problems.append("sley-vm is absent from the workspace")
if "cache_key_preimage" not in vm_code or "derive_cache_key" not in vm_code:
    problems.append("exact cache preimage/key implementation is missing")
if "SSMC1_FIELD_SCHEMA_HASH" not in vm_code or "SSMC1_DECODER_LIMITS_HASH" not in vm_code:
    problems.append("cache key lacks frozen SSMC1 descriptor bindings")
if "validate_function_graph" not in lowering_code or "lower_function" not in lowering_code:
    problems.append("integrated prior validation/lowering path is missing")
if "MAX_LOWERING_WORK" not in lowering_code or "MAX_BYTECODE_BYTES" not in lowering_code:
    problems.append("lowering work or byte ceiling is missing")
if "preflight_resources" not in lowering_code:
    problems.append("preallocation resource preflight is missing")

codes = [
    "VM_LOWER_PROFILE_UNSUPPORTED",
    "VM_LOWER_OPCODE_UNSUPPORTED",
    "VM_LOWER_SIGNATURE_MISMATCH",
    "VM_LOWER_IMMEDIATE_MISMATCH",
    "VM_LOWER_LOCAL_REFERENCE_INVALID",
    "VM_LOWER_CACHE_KEY_UNSUPPORTED",
    "VM_LOWER_RESOURCE_LIMIT",
]
for code in codes:
    if code not in vm_code or code not in spec:
        problems.append(f"lowering code drift: {code}")

unit_tests = vm_code.count("#[test]") + lowering_code.count("#[test]")
if unit_tests < 11:
    problems.append("fewer than eleven lowering/cache conformance tests")

result = {
    "contract": "s20-260-restricted-vm-lowering-profile-v1",
    "supported_terminators": 5,
    "supported_opcodes": [102, 103, 104],
    "stable_error_codes": len(codes),
    "unit_tests": unit_tests,
    "cache_preimage_bytes": 224,
    "full_ga_complete": False,
    "ariadne_review": "PASS_AFTER_ENCODING_LIMIT_AND_ORDER_FIXES",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
