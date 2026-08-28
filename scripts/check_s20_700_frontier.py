#!/usr/bin/env python3
"""Check the honest S20-700 persistent-fuzz frontier and blockers."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATION_VALUE = ROOT / "crates/sley-mutate/src/value.rs"
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

mutation_model = " ".join(MUTATION_MODEL.read_text(encoding="utf-8").split())
for marker in [
    "S20-350 remains a separate",
    "no candidate/value codec exists yet",
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
    "eight persistent libFuzzer targets",
    "seven scoped persistent Make smoke gates",
    "mutation-candidate and merge production boundaries remain absent",
]:
    if marker not in work_packages:
        problems.append(f"work-package-marker-missing:{marker}")

summary = json.loads(MACHINE_SUMMARY.read_text(encoding="utf-8"))
frontier = summary.get("s20_700_remaining_surface_audit", {})
expected = {
    "master_required_surface_count": 11,
    "scoped_target_count": 8,
    "scoped_landed_surface_count": 9,
    "remaining_required_surface_count": 2,
    "mutation_candidate_production_boundary": False,
    "merge_engine_production_boundary": False,
    "no_parallel_harness_created": True,
    "full_s20_700_complete": False,
    "next_dependency_complete_package": None,
}
for key, value in expected.items():
    if frontier.get(key) != value:
        problems.append(f"machine-summary-drift:{key}")
if frontier.get("remaining_required_surfaces") != [
    "mutation candidates",
    "merge engine",
]:
    problems.append("machine-summary-remaining-surface-drift")
if frontier.get("vulcan_review") != "DEFERRED_FORGE_OAUTH_401":
    problems.append("machine-summary-vulcan-review-drift")
if frontier.get("local_frontier_contract") != "docs/audits/S20_LOCAL_COMPLETION_FRONTIER.md":
    problems.append("machine-summary-local-frontier-drift")

for path, marker in [
    (RESULTS, "eight scoped persistent libFuzzer"),
    (GAPS, "persistent targets are still absent"),
    (GAPS, "S20-350 candidate construction remains blocked"),
    (AUDIT, "No placeholder target is created"),
    (AUDIT, "No next authority-safe package is registered"),
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
            "remaining_required_surfaces": ["mutation candidates", "merge engine"],
            "result": "PASS",
        },
        indent=2,
        sort_keys=True,
    )
)
