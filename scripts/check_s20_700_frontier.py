#!/usr/bin/env python3
"""Check the honest S20-700 persistent-fuzz frontier and blockers."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATION_VALUE = ROOT / "crates/sley-mutate/src/value.rs"
CANDIDATE = ROOT / "crates/sley-mutate/src/candidate.rs"
CANDIDATE_FUZZ = ROOT / "fuzz/targets/mutation_candidate.rs"
RESULT = ROOT / "crates/sley-policy/src/candidate_result.rs"
RESULT_FUZZ = ROOT / "fuzz/targets/candidate_result.rs"
MUTATION_MODEL = ROOT / "machineresearch/sley-2.0/09-mutation-and-transaction-model.md"
REPOSITORY_MODEL = ROOT / "machineresearch/sley-2.0/12-repository-branch-merge-model.md"
WORK_PACKAGES = ROOT / "docs/WORK_PACKAGES.md"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
AUDIT = ROOT / "docs/audits/S20_700_REMAINING_SURFACE_BLOCKERS.md"
MAKEFILE = ROOT / "Makefile"

problems: list[str] = []

mutation_value = MUTATION_VALUE.read_text(encoding="utf-8")
for marker in [
    "It supplies no binary codec, candidate",
    "construct a candidate",
    "establish authority",
    "mutate state",
]:
    if marker not in mutation_value:
        problems.append(f"mutation-boundary-marker-missing:{marker}")

candidate_source = CANDIDATE.read_text(encoding="utf-8")
for marker in [
    "pub struct CandidateRecord",
    "pub fn build_candidate",
    "pub fn import_candidate",
]:
    if marker not in candidate_source:
        problems.append(f"candidate-production-boundary-missing:{marker}")
candidate_fuzz = CANDIDATE_FUZZ.read_text(encoding="utf-8")
for marker in [
    "import_candidate(payload)",
    "build_candidate(&imported.record)",
    "decode_candidate_record(payload)",
    "encode_candidate_record(&record)",
]:
    if marker not in candidate_fuzz:
        problems.append(f"candidate-fuzz-boundary-missing:{marker}")

result_source = RESULT.read_text(encoding="utf-8")
for marker in ["pub fn import_candidate_result", "CandidateResultRecord"]:
    if marker not in result_source:
        problems.append(f"candidate-result-boundary-missing:{marker}")
result_fuzz = RESULT_FUZZ.read_text(encoding="utf-8")
for marker in [
    "import_candidate_result(input)",
    "CandidateResultId::derive(&first.preimage)",
    "record.phase_results.len(), 14",
]:
    if marker not in result_fuzz:
        problems.append(f"candidate-result-fuzz-boundary-missing:{marker}")

mutation_model = " ".join(MUTATION_MODEL.read_text(encoding="utf-8").split())
for marker in [
    "S20-350 proposal construction is complete",
    "restricted S20-360 candidate validation is complete",
    "S20-390 commit",
]:
    if marker not in mutation_model:
        problems.append(f"mutation-model-marker-missing:{marker}")

repository_model = REPOSITORY_MODEL.read_text(encoding="utf-8")
if "no native repository implementation" not in repository_model:
    problems.append("repository-merge-model-drift")
if (ROOT / "crates/sley-repo/src/merge.rs").exists():
    problems.append("merge-production-boundary-now-present:reaudit-required")
if (ROOT / "crates/sley-txn").exists():
    problems.append("transaction-production-boundary-now-present:reaudit-required")

work_packages = WORK_PACKAGES.read_text(encoding="utf-8")
for marker in [
    "ten persistent libFuzzer targets",
    "nine scoped persistent Make smoke gates",
    "merge production boundary remains absent",
]:
    if marker not in work_packages:
        problems.append(f"work-package-marker-missing:{marker}")

summary = json.loads(MACHINE_SUMMARY.read_text(encoding="utf-8"))
frontier = summary.get("s20_700_remaining_surface_audit", {})
expected = {
    "master_required_surface_count": 11,
    "scoped_target_count": 10,
    "scoped_landed_surface_count": 11,
    "remaining_required_surface_count": 1,
    "mutation_candidate_production_boundary": True,
    "mutation_candidate_persistent_fuzz_target": True,
    "mutation_candidate_independent_conformance": True,
    "candidate_result_production_boundary": True,
    "candidate_result_persistent_fuzz_target": True,
    "candidate_result_required_by_section_18_5": False,
    "candidate_result_vulcan_review": "PASS_P3_CORPUS_BREADTH_CLOSED_NO_OPEN_P0_P1_P2_P3_P4",
    "merge_engine_production_boundary": False,
    "no_parallel_harness_created": True,
    "full_s20_700_complete": False,
    "next_dependency_complete_package": "S20-390-ATOMIC-COMMIT-AND-RECEIPTS",
}
for key, value in expected.items():
    if frontier.get(key) != value:
        problems.append(f"machine-summary-drift:{key}")
if frontier.get("remaining_required_surfaces") != ["merge engine"]:
    problems.append("machine-summary-remaining-surface-drift")
if frontier.get("vulcan_review") != "DEFERRED_FORGE_OAUTH_401":
    problems.append("machine-summary-vulcan-review-drift")
if frontier.get("local_frontier_contract") != "docs/audits/S20_LOCAL_COMPLETION_FRONTIER.md":
    problems.append("machine-summary-local-frontier-drift")

for path, marker in [
    (RESULTS, "ten scoped persistent libFuzzer"),
    (GAPS, "S20-350 is complete as a proposal-only construction boundary"),
    (AUDIT, "No placeholder merge target is created"),
    (AUDIT, "S20-390 is now the next dependency-complete package"),
    (MAKEFILE, "python3 scripts/check_s20_700_frontier.py"),
]:
    if marker not in path.read_text(encoding="utf-8"):
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-persistent-fuzz-frontier-v1",
            "full_s20_700_complete": False,
            "remaining_required_surfaces": ["merge engine"],
            "result": "PASS",
        },
        indent=2,
        sort_keys=True,
    )
)
