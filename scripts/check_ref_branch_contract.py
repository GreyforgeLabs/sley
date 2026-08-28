#!/usr/bin/env python3
"""Validate the S20-500 native branch/ref contract and honest implementation state."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/NATIVE_REFS_BRANCHES_V1.md"
ADR = ROOT / "docs/adr/ADR-0022-native-branch-ref-boundary.md"
REPOSITORY_MODEL = ROOT / "docs/spec/REPOSITORY_MODEL_V1.md"
ERRORS = ROOT / "docs/spec/ERROR_CODES_V1.md"
WORK_PACKAGES = ROOT / "docs/WORK_PACKAGES.md"
SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
AUDIT = ROOT / "docs/audits/S20_500_REF_BRANCH_CONTRACT_FREEZE.md"
EVIDENCE = ROOT / "evidence/validation/s20-500-ref-branch-contract-freeze-v1.json"
CLOSEOUT = ROOT / "docs/audits/S20_500_NATIVE_REFS_BRANCHES_CLOSEOUT.md"
CLOSEOUT_EVIDENCE = (
    ROOT / "evidence/validation/s20-500-native-refs-branches-closeout-v1.json"
)
TXN_MANIFEST = ROOT / "crates/sley-txn/Cargo.toml"
REPO_MANIFEST = ROOT / "crates/sley-repo/Cargo.toml"
REF_IMPLEMENTATION = ROOT / "crates/sley-repo/src/refs.rs"
REPO_LIBRARY = ROOT / "crates/sley-repo/src/lib.rs"
TXN_LIBRARY = ROOT / "crates/sley-txn/src/lib.rs"
TXN_REPOSITORY = ROOT / "crates/sley-txn/src/repository.rs"

ERROR_CODES = (
    "REF_FORMAT_VERSION",
    "REF_NAME_INVALID",
    "REF_NAME_RESERVED",
    "REF_DIGEST_MISMATCH",
    "REF_FIELD_SHAPE",
    "REF_BRANCH_BINDING_MISMATCH",
    "REF_NOT_FOUND",
    "REF_ALREADY_EXISTS",
    "REF_NAME_COLLISION",
    "REF_TARGET_MISMATCH",
    "REF_NAMED_CAS_STALE",
    "BRANCH_RECORD_FORMAT_VERSION",
    "BRANCH_RECORD_DIGEST_MISMATCH",
    "BRANCH_RECORD_FIELD_SHAPE",
    "BRANCH_ORIGIN_MISMATCH",
    "BRANCH_NOT_FAST_FORWARD",
    "BRANCH_ANCESTRY_CYCLE",
    "BRANCH_RESOURCE_LIMIT",
    "RECOVERY_NAMED_REF_INCOMPLETE",
    "REF_IO",
    "REF_INTERNAL_INVARIANT",
)


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def require_markers(
    path: Path, markers: tuple[str, ...], label: str, problems: list[str]
) -> None:
    text = path.read_text(encoding="utf-8")
    for marker in markers:
        if marker not in text:
            problems.append(f"{label}-missing:{marker}")


def main() -> int:
    problems: list[str] = []
    for path in (
        SPEC,
        ADR,
        REPOSITORY_MODEL,
        ERRORS,
        WORK_PACKAGES,
        SUMMARY,
        AUDIT,
        EVIDENCE,
        CLOSEOUT,
        CLOSEOUT_EVIDENCE,
        TXN_MANIFEST,
        REPO_MANIFEST,
        REF_IMPLEMENTATION,
        REPO_LIBRARY,
        TXN_LIBRARY,
        TXN_REPOSITORY,
    ):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")
    if problems:
        print(json.dumps({"problems": problems, "result": "FAIL"}, indent=2))
        return 1

    require_markers(
        SPEC,
        (
            'name_key_preimage = "SLEYBNM1"',
            '"sley2.branch-name-path.v1"',
            'branch_preimage = "SLEYBR01"',
            '"sley2.branch-record.v1"',
            'ref_preimage = "SLEYRF01"',
            '"sley2.branch-ref.v1"',
            "exactly eight required fields",
            "exactly nine required fields",
            "locks/refs.lock",
            "direct parent",
            "`BRANCH_NOT_FAST_FORWARD`",
            "`TXN_PARENT_SHAPE`",
            "`BRANCH_ORIGIN_MISMATCH`",
            "`BranchUpdateStatus` enum",
            "| 1 | `CREATED` |",
            "| 2 | `ADVANCED` |",
            "| 3 | `PRESENT` |",
            "RECOVERY_NAMED_REF_INCOMPLETE",
            "REF_BRANCH_BINDING_MISMATCH",
            "65,536",
            "Raw branch-name bytes never become host path components",
            "branch deletion, rename, force movement",
        ),
        "ref-branch-spec",
        problems,
    )
    require_markers(
        ADR,
        (
            "sley-repo` owns S20-500",
            "independent of `sley-repo`",
            "repository metadata digests",
            "One repository-wide refs lock",
            "last-write-wins path",
            "cross-component",
            "S20-530",
            "clone-equivalent",
            "S20-540",
        ),
        "ref-branch-adr",
        problems,
    )

    spec = SPEC.read_text(encoding="utf-8")
    errors = ERRORS.read_text(encoding="utf-8")
    for numeric, symbol in enumerate(ERROR_CODES, start=50_000):
        marker = f"| {numeric} | `{symbol}` |"
        if spec.count(marker) != 1:
            problems.append(f"ref-branch-spec-error-drift:{numeric}:{symbol}")
        if errors.count(marker) != 1:
            problems.append(f"error-registry-drift:{numeric}:{symbol}")

    if "sley-repo" in TXN_MANIFEST.read_text(encoding="utf-8"):
        problems.append("dependency-inversion:sley-txn->sley-repo")

    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    profile = summary.get("s20_500_native_refs_branches", {})
    expected = {
        "status": "COMPLETE_NATIVE_REFS_BRANCHES_BOUNDARY",
        "contract": "docs/spec/NATIVE_REFS_BRANCHES_V1.md",
        "adr": "docs/adr/ADR-0022-native-branch-ref-boundary.md",
        "closeout_audit": "docs/audits/S20_500_NATIVE_REFS_BRANCHES_CLOSEOUT.md",
        "validation_evidence": "evidence/validation/s20-500-native-refs-branches-closeout-v1.json",
        "dependency_direction": "sley-repo -> sley-txn",
        "verified_revision_api_present": True,
        "branch_name_ascii_only": True,
        "raw_name_used_as_host_path": False,
        "immutable_origin_record_fields": 8,
        "mutable_ref_record_fields": 9,
        "error_codes_drafted": 21,
        "global_refs_lock": True,
        "idempotent_create": True,
        "branch_update_statuses": 3,
        "direct_parent_fast_forward_only": True,
        "bounded_ancestry_limit": 65_536,
        "maximum_branch_origins": 65_536,
        "maintenance_gc_coordination": True,
        "branch_delete": False,
        "force_move": False,
        "symbolic_refs": False,
        "named_branch_candidate_commit": False,
        "error_codes_implemented": 21,
        "native_ref_unit_tests": 28,
        "verified_revision_unit_tests": 5,
        "repository_crate_tests": 64,
        "transaction_crate_active_tests": 19,
        "tier_1_make_quick": True,
        "tier_2_repository_focus": True,
        "implementation_complete": True,
        "implementation_nabu_review": "PASS_FINAL_ARCHITECTURE_FRONTIER_NO_OPEN_P0_P1_P2_P3_P4",
        "implementation_ariadne_review": "PASS_FINAL_DIRECTORY_DURABILITY_NO_OPEN_P0_P1_P2_P3_P4",
        "implementation_vulcan_review": "PASS_DIRECTORY_DURABILITY_FINDING_CLOSED_NO_OPEN_P0_P1_P2_P3_P4",
    }
    for field, expected_value in expected.items():
        if profile.get(field) != expected_value:
            problems.append(f"machine-summary-drift:{field}")

    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    evidence_expected = {
        "contract": "s20-500-ref-branch-contract-freeze-v1",
        "implementation_complete": False,
        "result": "PASS_CONTRACT_FROZEN",
        "validation_tier": "TIER_1_CONTRACT_CHECKPOINT",
    }
    for field, expected_value in evidence_expected.items():
        if evidence.get(field) != expected_value:
            problems.append(f"contract-evidence-drift:{field}")
    command_expected = {
        "contract_checker": "PASS",
        "tier_1_make_quick": "PASS",
    }
    if evidence.get("commands") != command_expected:
        problems.append("contract-evidence-drift:commands")
    deterministic_expected = {
        "branch_origin_fields": 8,
        "branch_update_statuses": 3,
        "error_codes": 21,
        "maximum_ancestry_nodes": 65_536,
        "mutable_ref_fields": 9,
    }
    if evidence.get("deterministic_inputs") != deterministic_expected:
        problems.append("contract-evidence-drift:deterministic_inputs")
    review_expected = {
        "ariadne": "PASS_PRIOR_P2_P3_CLOSED_NO_NEW_P0_P1_P2_P3_P4",
        "nabu": "PASS_ONE_WAY_BOUNDARY_AND_DRAFT_REQUIREMENTS",
        "vulcan": "PASS_PRIOR_P1_P1_P2_CLOSED_NO_NEW_P0_P1_P2_P3_P4",
    }
    if evidence.get("reviews") != review_expected:
        problems.append("contract-evidence-drift:reviews")

    closeout_evidence = json.loads(CLOSEOUT_EVIDENCE.read_text(encoding="utf-8"))
    closeout_expected = {
        "claim": "NATIVE_NAMED_REFS_BRANCHES_AND_BOUNDED_ANCESTRY",
        "contract": "s20-500-native-refs-branches-closeout-v1",
        "result": "PASS_NATIVE_REFS_BRANCHES_BOUNDARY",
        "validation_tier": "TIER_2_SUBSYSTEM_HANDOFF",
    }
    for field, expected_value in closeout_expected.items():
        if closeout_evidence.get(field) != expected_value:
            problems.append(f"closeout-evidence-drift:{field}")
    closeout_commands = {
        "focused": {
            "cargo_clippy_sley_txn_sley_repo": "PASS_STRICT_ALL_TARGETS",
            "cargo_test_sley_repo": "PASS_64",
            "cargo_test_sley_txn": "PASS_19_ACTIVE_1_IGNORED",
            "directory_retry_regression": "PASS_LAYOUT_AND_DIGEST_FANOUT",
            "frontier_checkers": "PASS_LOCAL_AND_S20_700",
            "gc_checker": "PASS",
            "ref_branch_contract_checker": "PASS",
        },
        "tier_1_make_quick": "PASS",
        "tier_2_make_adversarial": "PASS",
        "tier_2_make_conformance": "PASS",
        "tier_2_make_core": "PASS",
    }
    if closeout_evidence.get("commands") != closeout_commands:
        problems.append("closeout-evidence-drift:commands")
    closeout_inputs = {
        "branch_origin_fields": 8,
        "branch_update_statuses": 3,
        "error_codes": 21,
        "maximum_ancestry_nodes": 65_536,
        "maximum_branch_origins": 65_536,
        "maximum_visible_branches": 4_096,
        "mutable_ref_fields": 9,
        "native_ref_unit_tests": 28,
        "repository_crate_tests": 64,
        "transaction_crate_active_tests": 19,
        "verified_revision_unit_tests": 5,
    }
    if closeout_evidence.get("deterministic_inputs") != closeout_inputs:
        problems.append("closeout-evidence-drift:deterministic_inputs")
    closeout_reviews = {
        "ariadne": "PASS_FINAL_DIRECTORY_DURABILITY_NO_OPEN_P0_P1_P2_P3_P4",
        "nabu": "PASS_FINAL_ARCHITECTURE_FRONTIER_NO_OPEN_P0_P1_P2_P3_P4",
        "vulcan": "PASS_DIRECTORY_DURABILITY_FINDING_CLOSED_NO_OPEN_P0_P1_P2_P3_P4",
    }
    if closeout_evidence.get("reviews") != closeout_reviews:
        problems.append("closeout-evidence-drift:reviews")
    if any(closeout_evidence.get("authority", {}).values()):
        problems.append("closeout-evidence-drift:authority")

    audit = normalized(AUDIT)
    for marker in (
        "PASS - contract frozen; implementation not yet present",
        "Tier 1 contract checkpoint plus independent architecture and adversarial review",
        "sley-repo -> sley-txn",
        "VerifiedRevision",
        "twenty-one exact S20-500 error codes",
        "PASS` with no new P0-P4",
        "No push, deploy, provider call, publication, spend, trading action",
    ):
        if marker not in audit:
            problems.append(f"contract-audit-drift:{marker}")

    closeout = normalized(CLOSEOUT)
    for marker in (
        "S20-500 native refs and branches complete",
        "Tier 2 subsystem handoff",
        "its parent is synced before use",
        "no open P0-P4",
        "S20-530 is the next dependency-complete local package",
        "no push, runtime deployment, provider call, publication, spend, trading action",
    ):
        if marker not in closeout:
            problems.append(f"closeout-audit-drift:{marker}")

    implementation_complete = REF_IMPLEMENTATION.is_file()
    if profile.get("implementation_complete") is not implementation_complete:
        problems.append("machine-summary-drift:implementation_complete")
    if implementation_complete:
        if 'sley-txn = { path = "../sley-txn" }' not in REPO_MANIFEST.read_text(
            encoding="utf-8"
        ):
            problems.append("implementation-dependency-missing:sley-repo->sley-txn")
        require_markers(
            TXN_LIBRARY,
            ("VerifiedRevision", "TransactionRepository"),
            "verified-revision-export",
            problems,
        )
        require_markers(
            TXN_REPOSITORY,
            (
                "pub struct VerifiedRevision",
                "pub fn verified_revision(",
                "let _lock = self.acquire_lock()?;",
                "fn load_verified_revision(",
                "fn receipt_path_readonly(",
                "verified_revision_rejects_symlinked_receipt_fanout",
                "verified_revision_does_not_consult_corrupt_accepted_head",
            ),
            "verified-revision-implementation",
            problems,
        )
        require_markers(
            REPO_LIBRARY,
            ("mod refs;", "pub use refs::*;"),
            "ref-branch-export",
            problems,
        )
        require_markers(
            REF_IMPLEMENTATION,
            (
                'const BRANCH_MAGIC: [u8; 8] = *b"SLEYBR01";',
                'const REF_MAGIC: [u8; 8] = *b"SLEYRF01";',
                'const NAME_KEY_MAGIC: [u8; 8] = *b"SLEYBNM1";',
                "pub struct BranchName",
                "pub struct BranchRepository",
                "pub fn create_branch(",
                "pub fn resolve_branch(",
                "pub fn list_branches(",
                "pub fn advance_branch(",
                "pub fn branch_ancestry(",
                "pub fn recover_refs(",
                "file.lock()?;",
                "fs::hard_link(&stage_path, final_path)",
                "fs::rename(&stage_path, path)?;",
                "checked_key_path(",
                "validate_recovery_tree(",
                "const MAX_BRANCH_ORIGINS: usize = 65_536;",
                "validate_new_origin_capacity(",
                "sync_dir(parent)?;",
                "exclusive_gc_ownership_serializes_transaction_and_ref_mutation",
                "concurrent_create_and_advance_have_one_mutating_winner",
                "directory_creation_retry_redurabilizes_layout_and_fanout_before_branch_success",
                "ancestry_is_head_first_bounded_convergent_and_cycle_checked",
                "recovery_removes_only_exact_owned_stages_and_reports_orphans",
            ),
            "ref-branch-implementation",
            problems,
        )
        ref_source = REF_IMPLEMENTATION.read_text(encoding="utf-8")
        if ref_source.count("#[test]") != 28:
            problems.append("ref-branch-unit-test-count-drift")
        for forbidden in (
            "pub fn delete_branch(",
            "pub fn force_branch(",
            "pub fn rename_branch(",
            "pub fn create_tag(",
            "pub fn commit_to_branch(",
        ):
            if forbidden in ref_source:
                problems.append(f"excluded-api-present:{forbidden}")
        if profile.get("status") != "COMPLETE_NATIVE_REFS_BRANCHES_BOUNDARY":
            problems.append("implementation-status-drift")
    elif profile.get("status") not in {
        "CONTRACT_DRAFT_PENDING_ARIADNE_VULCAN_REVIEW",
        "CONTRACT_FROZEN_IMPLEMENTATION_READY",
    }:
        problems.append("draft-status-drift")

    packages = normalized(WORK_PACKAGES)
    for marker in (
        "S20-500",
        "`VerifiedRevision` API",
        "direct-parent fast-forward CAS",
        "Complete native refs/branches boundary",
    ):
        if marker not in packages:
            problems.append(f"work-package-drift:{marker}")

    result = {
        "ariadne_review": profile.get("ariadne_review"),
        "contract": "s20-500-native-refs-branches-v1",
        "contract_frozen": profile.get("status")
        in {
            "CONTRACT_FROZEN_IMPLEMENTATION_READY",
            "IMPLEMENTED_VALIDATION_REVIEW_PENDING",
            "IMPLEMENTED_REVIEW_FINDINGS_PENDING",
            "COMPLETE_NATIVE_REFS_BRANCHES_BOUNDARY",
        },
        "error_codes": len(ERROR_CODES),
        "implementation_complete": implementation_complete,
        "nabu_review": profile.get("nabu_review"),
        "implementation_ariadne_review": profile.get("implementation_ariadne_review"),
        "implementation_nabu_review": profile.get("implementation_nabu_review"),
        "implementation_vulcan_review": profile.get("implementation_vulcan_review"),
        "problems": problems,
        "result": "PASS" if not problems else "FAIL",
        "vulcan_review": profile.get("vulcan_review"),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
