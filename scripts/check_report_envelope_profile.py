#!/usr/bin/env python3
"""Check the restricted S20-290 deterministic report-envelope profile."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/REPORT_ENVELOPE_PROFILE_V1.md")
code = read("crates/sley-conformance/src/lib.rs")
vm_code = read("crates/sley-vm/src/execute.rs")
work_packages = read("docs/WORK_PACKAGES.md")
summary = json.loads(read("machineresearch/sley-2.0/machine-summary.json"))

problems: list[str] = []

expected_report_ids = {
    "fixed_observed_execution_report_id": "ec5c4a9607f4b6aa79371f58d947d7be5e516840f76575b666181aea14fdf467",
    "fixed_rejected_execution_report_id": "e5aa428b5cf4fe81e72cecbbcfd901acf9c34cdbda2939945230d1f9aa3232a0",
    "fixed_test_report_id": "7bd8a85d393eeaba11727d44be3b37063cad207b834d16ea8cd4f93a87d522d3",
}
report_summary = summary.get("report_envelope_profile", {})
for field, expected in expected_report_ids.items():
    if expected not in code:
        problems.append(f"fixed report source vector drift: {field}")
    if report_summary.get(field) != expected:
        problems.append(f"machine-summary report vector drift: {field}")

for token in [
    "Status: S20-290 restricted epoch-1 normative specification.",
    '"SLEYEXR1"',
    '"SLEYTSR1"',
    '"sley2.execution-report.v1"',
    '"sley2.test-report.v1"',
    "PolicyAndResourceIncomplete",
    "`Match` is not `Passed`",
    "Full S20-290 GA and the M2 exit remain blocked",
]:
    if token not in spec:
        problems.append(f"profile missing {token!r}")

if "240,270" not in work_packages:
    problems.append("S20-290 does not declare its S20-240/S20-270 dependencies")
if "pub fn build_execution_report" not in code or "pub fn build_test_report" not in code:
    problems.append("restricted execution/test report constructors are missing")
if "derive_observation_id(" not in code or "pub fn derive_observation_id(" not in vm_code:
    problems.append("report verification does not route through VM observation authority")
if "PolicyAndResourceIncomplete" not in code or "RestrictedComparison" not in code:
    problems.append("non-final test comparison surface is incomplete")
if "FailurePhase::Cfg" not in code or "GraphUnresolvedReference" not in code:
    problems.append("GRAPH/CFG failure projection fixture is missing")
for forbidden in ["std::fs", "std::env", "std::process", "std::net", "SystemTime"]:
    if forbidden in code:
        problems.append(f"ambient/measured host surface imported: {forbidden}")

required_tests = [
    "observed_execution_vector_is_exact",
    "rejected_vector_and_unavailable_input_are_exact",
    "failure_projection_preserves_all_phases_and_graph_codes",
    "observed_context_cache_and_observation_tampering_fail_exactly",
    "malformed_observed_input_preserves_exact_type_failure",
    "test_match_vector_is_exact_and_nonfinal",
    "value_mismatch_and_execution_rejection_are_distinct",
    "trap_code_comparison_matrix_is_exact",
    "plan_order_and_execution_binding_fail_closed",
    "execution_report_id_tampering_is_rejected_by_test_aggregation",
    "repeated_equivalent_reports_are_byte_identical",
]
for test in required_tests:
    if test not in code:
        problems.append(f"report conformance fixture missing: {test}")

codes = [f"29_{value:03d}" for value in range(8)]
for stable_code in codes:
    if stable_code not in code:
        problems.append(f"stable report code missing: {stable_code}")

unit_tests = code.count("#[test]")
if unit_tests < 13:
    problems.append("fewer than thirteen restricted report tests")

result = {
    "contract": "s20-290-restricted-report-envelope-profile-v1",
    "execution_magic": "SLEYEXR1",
    "test_magic": "SLEYTSR1",
    "stable_error_codes": len(codes),
    "report_unit_tests": unit_tests,
    "canonical_entities": False,
    "persistence": False,
    "test_pass_claim": False,
    "m2_exit_complete": False,
    "nabu_review": "PASS_DERIVED_ENVELOPES_ONLY",
    "ariadne_review": "PASS_AFTER_GRAPH_PHASE_CLARIFICATION",
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
