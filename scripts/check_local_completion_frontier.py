#!/usr/bin/env python3
"""Check the fail-closed local completion frontier for unfinished Sley 2 work."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
AUDIT = ROOT / "docs/audits/S20_LOCAL_COMPLETION_FRONTIER.md"
WORK_PACKAGES = ROOT / "docs/WORK_PACKAGES.md"
SCB1 = ROOT / "docs/spec/SCB1.md"
EPOCH_SCHEMA = ROOT / "docs/spec/SSMC1_EPOCH1_SCHEMA.txt"
SSMC = ROOT / "crates/sley-ssmc/src/lib.rs"
MAKEFILE = ROOT / "Makefile"


def fail(message: str) -> None:
    raise AssertionError(message)


def require_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        fail(f"frontier drift: {label}")


def check_fail_closed_gate(gate: str) -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/gate_status.py", gate],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    require_equal(completed.returncode, 2, f"{gate} return code")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{gate} did not emit JSON") from error
    require_equal(report.get("result"), "NOT_IMPLEMENTED", f"{gate} result")


def main() -> int:
    try:
        summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
        require_equal(summary.get("status"), "IN_PROGRESS", "project status")
        require_equal(summary.get("phase"), "M2", "project phase")
        require_equal(summary.get("publication_authorized"), False, "publication authority")
        require_equal(
            summary.get("artifact"),
            {"path": None, "sha256": None, "size_bytes": None, "reproducibility": None},
            "release artifact",
        )

        frontier = summary.get("local_completion_frontier", {})
        expected_frontier = {
            "status": "S20_360_RESTRICTED_COMPLETE_S20_390_READY",
            "goal_complete": False,
            "next_authority_safe_package": "S20-390-ATOMIC-COMMIT-AND-RECEIPTS",
            "blocked_lane_count": 6,
            "blocked_lanes": [
                "semantics_and_queries",
                "sessions_and_protocol",
                "repository",
                "succession_benchmark",
                "adversarial",
                "supply_chain_and_release",
            ],
            "p0_package_ready": True,
            "s20_250_schema_bodies_frozen": True,
            "s20_250_impact_semantics_frozen": False,
            "locked_option_canon_resolved": True,
            "const_value_canon_resolved": True,
            "s20_350_native_implementation_complete": True,
            "s20_350_independent_conformance_complete": True,
            "s20_350_implementation_complete": True,
            "s20_350_persistent_fuzz_complete": True,
            "s20_360_restricted_validation_complete": True,
            "s20_360_operation_analysis_complete": False,
            "s20_360_independent_conformance_complete": True,
            "s20_360_persistent_fuzz_complete": True,
            "session_authority_available": False,
            "transaction_boundary_available": False,
            "protocol_boundary_available": False,
            "merge_boundary_available": False,
            "real_benchmark_run_authorized": False,
            "root_license_text_approved": False,
            "release_artifact_available": False,
            "required_specialist_review": "PASS_S20_360_ARIADNE_VULCAN",
            "focused_semantic_security_review": "PASS_NO_OPEN_REPORT_GRADE_FINDINGS",
            "full_v2_eligible": False,
            "release_check_eligible": False,
        }
        require_equal(frontier, expected_frontier, "machine-summary frontier")

        session = summary.get("session_handle_profile", {})
        require_equal(session.get("implementation_started"), False, "S20-330 implementation")
        require_equal(
            session.get("unblocked_by_restricted_s20_320"), False, "S20-330 authority"
        )
        mutation = summary.get("mutation_value_profile", {})
        for field in ("aggregate_codecs", "candidate_construction"):
            require_equal(mutation.get(field), True, f"S20-350 {field}")
        for field in ("candidate_authority", "runtime_mutation"):
            require_equal(mutation.get(field), False, f"S20-350 {field}")
        for field in (
            "native_s20_350_implementation_complete",
            "independent_conformance_complete",
            "persistent_candidate_fuzz_harness",
            "full_s20_350_complete",
        ):
            require_equal(mutation.get(field), True, f"S20-350 {field}")
        for field in ("generic_option_canon_resolved", "const_value_canon_resolved"):
            require_equal(mutation.get(field), True, f"S20-350 {field}")
        require_equal(
            mutation.get("nabu_review"),
            "PASS_FROZEN_ARCHITECTURE_INTEGRATED",
            "S20-350 review",
        )
        require_equal(
            mutation.get("epoch1_reanchor_review"),
            "PASS_AFTER_P2_VECTOR_REANCHOR",
            "S20-350 epoch-1 re-anchor review",
        )
        require_equal(
            summary.get("candidate_contract_freeze", {}).get("s20_350_unblocked"),
            True,
            "S20-345 unblocks S20-350",
        )
        require_equal(
            summary.get("fingerprint_impact_profile", {}).get("unmodeled_entity_kinds"),
            [1, 2, 3, 16, 17, 18],
            "S20-250 modeled kinds",
        )
        require_equal(
            summary.get("s20_700_remaining_surface_audit", {}).get(
                "next_dependency_complete_package"
            ),
            "S20-390-ATOMIC-COMMIT-AND-RECEIPTS",
            "S20-700 next package",
        )
        validation = summary.get("s20_360_candidate_validation", {})
        require_equal(
            validation.get("status"),
            "COMPLETE_RESTRICTED_OPERATION_FREE_VALIDATION_BOUNDARY",
            "S20-360 restricted status",
        )
        require_equal(validation.get("validation_phases"), 14, "S20-360 phases")
        require_equal(validation.get("terminal_decisions"), 16, "S20-360 decisions")
        require_equal(
            validation.get("operation_success_subset"),
            "operation-free",
            "S20-360 success subset",
        )
        require_equal(
            validation.get("ariadne_review"),
            "PASS_AFTER_RESOURCE_LIMIT_DECISION_FIX",
            "S20-360 Ariadne review",
        )
        require_equal(
            validation.get("vulcan_review"),
            "PASS_P3_CORPUS_BREADTH_CLOSED_NO_OPEN_P0_P1_P2_P3_P4",
            "S20-360 Vulcan review",
        )
        for field in (
            "accepted_state_mutation",
            "capability_ledger_mutation",
            "candidate_authority",
            "commit_authority",
            "runtime_authority",
            "full_ga_operation_analysis_complete",
            "full_ga_fingerprint_requirement_complete",
        ):
            require_equal(validation.get(field), False, f"S20-360 {field}")
        require_equal(
            summary.get("s20_710_pre_release_audit", {}).get("full_s20_710_complete"),
            False,
            "S20-710 completion",
        )

        scb1 = " ".join(SCB1.read_text(encoding="utf-8").split())
        if (
            "`Option<T>` is a union with tag 0 and zero-length payload for `None`, or tag 1"
            not in scb1
        ):
            fail("SCB1 Option<T> tag marker changed")
        epoch_schema = EPOCH_SCHEMA.read_text(encoding="utf-8")
        if "generic union Option<T>(0:None,1:Some<T>)" not in epoch_schema:
            fail("epoch Option<T> tag marker changed")
        if "generic union Option<T>(1:None,2:Some<T>)" in epoch_schema:
            fail("provisional epoch Option<T> tags remain")

        ssmc = SSMC.read_text(encoding="utf-8")
        for type_name in (
            "WorkspaceDefinition",
            "PackageDefinition",
            "NamespaceDefinition",
            "EntryPointDefinition",
            "PolicyBindingDefinition",
            "DependencyBindingDefinition",
        ):
            if f"pub struct {type_name}" in ssmc:
                fail(f"S20-250 core body appeared; re-audit required: {type_name}")

        for relative in (
            "crates/sley-txn",
            "crates/sley-protocol",
            "crates/sley-json-bridge",
            "crates/sley-cli",
            "crates/sley-repo/src/merge.rs",
        ):
            if (ROOT / relative).exists():
                fail(f"production boundary appeared; re-audit required: {relative}")

        packages = WORK_PACKAGES.read_text(encoding="utf-8")
        for marker in (
            "| S20-330 | 320 |",
            "| S20-390 | 150,160,360,370 |",
            "| S20-400 | 310,350,390 |",
            "| S20-500 | 390 |",
            "| S20-620 | 320,420,430 |",
            "| S20-720 | all GA code |",
        ):
            if marker not in packages:
                fail(f"work-package dependency drift: {marker}")

        audit = AUDIT.read_text(encoding="utf-8")
        for marker in (
            "restricted S20-360 validation is complete",
            "S20-250 remains incomplete",
            "candidate construction is proposal-only",
            "S20-390 transaction work is next",
        ):
            if marker not in audit:
                fail(f"frontier audit marker missing: {marker}")
        if "python3 scripts/check_local_completion_frontier.py" not in MAKEFILE.read_text(
            encoding="utf-8"
        ):
            fail("quick gate omits local completion frontier")

        check_fail_closed_gate("v2")
        check_fail_closed_gate("release-check")
    except (AssertionError, OSError, json.JSONDecodeError) as error:
        print(json.dumps({"reason": str(error), "result": "FAIL"}, sort_keys=True))
        return 1

    print(
        json.dumps(
            {
                "blocked_lanes": 6,
                "full_gate_run": False,
                "goal_complete": False,
                "next_authority_safe_package": "S20-390-ATOMIC-COMMIT-AND-RECEIPTS",
                "result": "PASS",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
