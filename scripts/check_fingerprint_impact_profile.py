#!/usr/bin/env python3
"""Check the restricted S20-250 fingerprint/impact profile for drift."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/FINGERPRINT_IMPACT_PROFILE_V1.md")
identifiers = read("docs/spec/IDENTIFIERS_V1.md")
identifier_code = read("crates/sley-id/src/lib.rs")
fingerprint_code = read("crates/sley-ssmc/src/fingerprint.rs")
query_code = read("crates/sley-query/src/lib.rs")
workspace = read("Cargo.toml")

problems: list[str] = []

required_spec = [
    "Status: S20-250 restricted epoch-1 normative specification.",
    '"SLEYSFP1"',
    '"SLEYVHS1"',
    '"sley2.value-hash.v1"',
    "full S20-250 GA",
    "kinds 4 through 15",
    "Appendix A: exhaustive projection grammar",
    "replay request/response and config value",
]
for token in required_spec:
    if token not in spec:
        problems.append(f"profile missing {token!r}")

if "sley2.value-hash.v1" not in identifiers or "sley2.value-hash.v1" not in identifier_code:
    problems.append("dedicated value-hash domain is not frozen in docs and code")
if '"crates/sley-query"' not in workspace:
    problems.append("sley-query is absent from the workspace")
if "SSMC1_FIELD_SCHEMA_HASH" not in fingerprint_code:
    problems.append("fingerprint encoder lacks the frozen schema hash")
if "MAX_FINGERPRINT_WORK" not in fingerprint_code or "ensure_append" not in fingerprint_code:
    problems.append("fingerprint preappend work accounting is missing")
if "FunctionMaps" not in fingerprint_code or "encode_value_ref" not in fingerprint_code:
    problems.append("function local-slot normalization is missing")
if "ImpactIndex" not in query_code or "transitive_impact" not in query_code:
    problems.append("direct/reverse/transitive impact implementation is missing")
if "MAX_IMPACT_WORK" not in query_code or "charge_work" not in query_code:
    problems.append("impact extraction/traversal work accounting is missing")

fingerprint_codes = [
    "FINGERPRINT_ENTITY_UNSUPPORTED",
    "FINGERPRINT_INVENTORY_INVALID",
    "FINGERPRINT_LOCAL_REFERENCE_INVALID",
    "FINGERPRINT_CLAIM_MISSING",
    "FINGERPRINT_MISMATCH",
    "FINGERPRINT_RESOURCE_LIMIT",
    "VALUE_HASH_TYPE_UNSUPPORTED",
    "VALUE_HASH_VALUE_INVALID",
]
impact_codes = [
    "IMPACT_ENTITY_UNSUPPORTED",
    "IMPACT_SET_NOT_CANONICAL",
    "IMPACT_UNRESOLVED_ENTITY",
    "IMPACT_WRONG_ENTITY_KIND",
    "IMPACT_RESOURCE_LIMIT",
]
for code in fingerprint_codes:
    if code not in fingerprint_code or code not in spec:
        problems.append(f"fingerprint code drift: {code}")
for code in impact_codes:
    if code not in query_code or code not in spec:
        problems.append(f"impact code drift: {code}")

fingerprint_tests = fingerprint_code.count("#[test]")
impact_tests = query_code.count("#[test]")
if fingerprint_tests < 4:
    problems.append("fewer than four fingerprint/value fixed-property tests")
if impact_tests < 4:
    problems.append("fewer than four impact/value integration tests")

result = {
    "contract": "s20-250-restricted-fingerprint-impact-profile-v1",
    "fingerprint_entity_kinds": [4, 5],
    "impact_entity_kinds": list(range(4, 16)),
    "stable_error_codes": len(fingerprint_codes) + len(impact_codes),
    "fingerprint_tests": fingerprint_tests,
    "impact_tests": impact_tests,
    "full_ga_complete": False,
    "ariadne_review": "PASS_AFTER_EXHAUSTIVE_EDGE_MATRIX_FIX",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
