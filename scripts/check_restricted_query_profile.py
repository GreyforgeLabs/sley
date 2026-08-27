#!/usr/bin/env python3
"""Check the restricted S20-310 modeled-snapshot query profile."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/RESTRICTED_QUERY_PROFILE_V1.md")
query_code = read("crates/sley-query/src/query.rs")
query_api = read("crates/sley-query/src/lib.rs")
snapshot_code = read("crates/sley-query/src/snapshot.rs")
work_packages = read("docs/WORK_PACKAGES.md")
identifiers = read("docs/spec/IDENTIFIERS_V1.md")

problems: list[str] = []

for token in [
    "Status: S20-310 restricted epoch-1 normative specification.",
    '"SLEYQRY1"',
    '"SLEYQRS1"',
    '"sley2.query.v1"',
    "GetModeledEntityKind",
    "ListDirectDependencies",
    "ListDirectDependents",
    "ReverseImpactClosure",
    "QUERY_REQUIRED_FACT_OMITTED",
    "no import/decoder API",
    "Full S20-310 and the M3 blocker remain open",
    "does not unblock S20-320, S20-400, or GA",
]:
    if token not in spec:
        problems.append(f"query profile missing {token!r}")

if "restricted modeled-snapshot typed queries" not in work_packages:
    problems.append("S20-310 work-package row does not declare restricted scope")
if "sley2.query.v1" not in identifiers:
    problems.append("typed query identifier domain is absent from identifier contract")
if "mod query;" not in query_api or "pub use query::*;" not in query_api:
    problems.append("restricted query implementation is not exported")
if "pub fn build_index_snapshot" not in snapshot_code:
    problems.append("fresh snapshot authority is absent")

for token in [
    "pub fn build_restricted_query_request",
    "pub fn execute_restricted_query",
    "pub fn run_restricted_query",
    "let snapshot = build_index_snapshot(context, entities)?",
    "QueryId::derive(&preimage)",
    "response_bytes > request.limits.max_response_bytes",
    "QueryErrorCode::RequiredFactOmitted",
    "QueryErrorCode::SnapshotMismatch",
    "checked_add(response_bytes)",
    "RESPONSE_HEADER_WITHOUT_ROOT: usize = 204",
    "RESPONSE_HEADER_WITH_ROOT: usize = 236",
]:
    if token not in query_code:
        problems.append(f"query implementation missing {token!r}")

for forbidden in [
    "pub fn decode_query",
    "pub fn decode_response",
    "free_form",
    "std::fs",
    "std::env",
    "std::process",
    "std::net",
    "SystemTime",
]:
    if forbidden in query_code:
        problems.append(f"forbidden query/ambient surface present: {forbidden}")

codes = [f"31_{value:03d}" for value in range(8)]
for stable_code in codes:
    if stable_code not in query_code:
        problems.append(f"stable query code missing: {stable_code}")

required_tests = [
    "all_four_query_id_and_response_vectors_are_exact",
    "direct_dependency_dependent_and_closure_results_are_exact",
    "repeated_equal_queries_are_byte_identical",
    "filters_and_seeds_must_be_nonempty_canonical_sets",
    "request_identity_and_snapshot_binding_fail_closed",
    "unresolved_entities_fail_before_empty_success",
    "applied_edge_entity_depth_and_byte_limits_omit_no_facts",
    "profile_and_work_limits_fail_as_resources_without_partial_payload",
    "fanout_cycle_and_work_precedence_are_bounded",
    "fresh_impact_failure_precedes_query_failure",
    "claimed_root_and_applied_limits_change_query_identity",
    "discarded_candidate_can_only_yield_the_same_fresh_query_surface",
]
for test in required_tests:
    if test not in query_code:
        problems.append(f"restricted query fixture missing: {test}")

unit_tests = query_code.count("#[test]")
if unit_tests < 13:
    problems.append("fewer than thirteen restricted query tests")

result = {
    "contract": "s20-310-restricted-modeled-snapshot-query-profile-v1",
    "request_magic": "SLEYQRY1",
    "response_magic": "SLEYQRS1",
    "query_kinds": 4,
    "stable_error_codes": len(codes),
    "query_unit_tests": unit_tests,
    "partial_results": False,
    "continuation": False,
    "root_provenance_proven": False,
    "full_s20_310_complete": False,
    "s20_320_unblocked": False,
    "nabu_review": "REVISE_TO_RESTRICTED_PROFILE",
    "ariadne_review": "PASS_AFTER_RESPONSE_LAYOUT_AND_TAG_PRECEDENCE_FIX",
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2_P3_P4",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
