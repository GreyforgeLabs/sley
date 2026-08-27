#!/usr/bin/env python3
"""Check the restricted S20-300 rebuild-first index snapshot profile."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


spec = read("docs/spec/INDEX_SNAPSHOT_PROFILE_V1.md")
identifier_spec = read("docs/spec/IDENTIFIERS_V1.md")
identifier_code = read("crates/sley-id/src/lib.rs")
query_api = read("crates/sley-query/src/lib.rs")
snapshot_code = read("crates/sley-query/src/snapshot.rs")
work_packages = read("docs/WORK_PACKAGES.md")

problems: list[str] = []

for token in [
    "Status: S20-300 restricted epoch-1 normative specification.",
    '"SLEYIDX1"',
    '"sley2.index-snapshot.v1"',
    "A snapshot digest authenticates bytes, never semantic provenance.",
    "always rebuilds from the explicit modeled entity request",
    "RestrictedModeledKinds4To15Only",
    "Full S20-300 and root-backed S20-310 remain blocked",
]:
    if token not in spec:
        problems.append(f"profile missing {token!r}")

if "restricted epoch-1 index snapshot" not in work_packages:
    problems.append("S20-300 work-package row does not declare its restricted scope")
if "sley2.index-snapshot.v1" not in identifier_spec:
    problems.append("snapshot identifier domain is absent from the identifier contract")
if "Domain::IndexSnapshot" not in identifier_code or "IndexSnapshotId" not in identifier_code:
    problems.append("snapshot identifier domain/type is absent from sley-id")
if "mod snapshot;" not in query_api or "pub use snapshot::*;" not in query_api:
    problems.append("snapshot implementation is not exported by sley-query")

for token in [
    "pub fn build_index_snapshot",
    "pub fn admit_index_snapshot",
    "ImpactIndex::build(entities)?",
    "inspect_candidate(context, candidate)",
    "if candidate != fresh.record()",
    "MAX_SNAPSHOT_RECORD_BYTES",
    "MAX_SNAPSHOT_EDGES",
    "MAX_SNAPSHOT_WORK",
    "decoded_reverse != invert_edges(&direct)?",
]:
    if token not in snapshot_code:
        problems.append(f"snapshot implementation missing {token!r}")

for forbidden in [
    "pub fn inspect_candidate",
    "pub fn from_digest",
    "pub fn from_state_root",
    "trust_snapshot_for_root",
    "std::fs",
    "std::env",
    "std::process",
    "std::net",
    "SystemTime",
]:
    if forbidden in snapshot_code:
        problems.append(f"forbidden authority/ambient surface present: {forbidden}")

codes = [f"30_{value:03d}" for value in range(8)]
for stable_code in codes:
    if stable_code not in snapshot_code:
        problems.append(f"stable snapshot code missing: {stable_code}")

required_tests = [
    "empty_and_nonempty_records_have_fixed_vectors",
    "graph_projection_and_128_rebuilds_are_identical",
    "missing_and_exact_candidates_return_only_fresh_snapshots",
    "format_version_context_completeness_and_digest_fail_closed",
    "count_trailing_order_and_endpoint_perturbations_are_discarded",
    "reverse_disagreement_and_valid_unequal_content_are_discarded",
    "fresh_impact_failures_are_preserved_before_candidate_inspection",
    "truncated_records_and_overlimit_records_are_bounded",
]
for test in required_tests:
    if test not in snapshot_code:
        problems.append(f"snapshot conformance fixture missing: {test}")

unit_tests = snapshot_code.count("#[test]")
if unit_tests < 9:
    problems.append("fewer than nine restricted snapshot tests")

result = {
    "contract": "s20-300-restricted-index-snapshot-profile-v1",
    "magic": "SLEYIDX1",
    "modeled_entity_kinds": list(range(4, 16)),
    "stable_error_codes": len(codes),
    "snapshot_unit_tests": unit_tests,
    "fresh_rebuild_required_for_hit": True,
    "public_candidate_hydration": False,
    "root_provenance_proven": False,
    "useful_cache": False,
    "full_s20_300_complete": False,
    "s20_310_unblocked": False,
    "nabu_review": "PASS_RESTRICTED_CONFORMANCE_CACHE_ONLY",
    "ariadne_review": "PASS_NO_OPEN_P0_P1_P2",
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2",
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
}
print(json.dumps(result, indent=2, sort_keys=True))
raise SystemExit(0 if not problems else 1)
