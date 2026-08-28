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
TXN_MANIFEST = ROOT / "crates/sley-txn/Cargo.toml"
REPO_MANIFEST = ROOT / "crates/sley-repo/Cargo.toml"
REF_IMPLEMENTATION = ROOT / "crates/sley-repo/src/refs.rs"

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
        TXN_MANIFEST,
        REPO_MANIFEST,
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
        "contract": "docs/spec/NATIVE_REFS_BRANCHES_V1.md",
        "adr": "docs/adr/ADR-0022-native-branch-ref-boundary.md",
        "dependency_direction": "sley-repo -> sley-txn",
        "verified_revision_api_present": False,
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
        "branch_delete": False,
        "force_move": False,
        "symbolic_refs": False,
        "named_branch_candidate_commit": False,
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

    implementation_complete = REF_IMPLEMENTATION.is_file()
    if profile.get("implementation_complete") is not implementation_complete:
        problems.append("machine-summary-drift:implementation_complete")
    if implementation_complete:
        if 'sley-txn = { path = "../sley-txn" }' not in REPO_MANIFEST.read_text(
            encoding="utf-8"
        ):
            problems.append("implementation-dependency-missing:sley-repo->sley-txn")
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
        "Contract frozen; implementation ready",
    ):
        if marker not in packages:
            problems.append(f"work-package-drift:{marker}")

    result = {
        "ariadne_review": profile.get("ariadne_review"),
        "contract": "s20-500-native-refs-branches-v1",
        "contract_frozen": profile.get("status")
        == "CONTRACT_FROZEN_IMPLEMENTATION_READY",
        "error_codes": len(ERROR_CODES),
        "implementation_complete": implementation_complete,
        "nabu_review": profile.get("nabu_review"),
        "problems": problems,
        "result": "PASS" if not problems else "FAIL",
        "vulcan_review": profile.get("vulcan_review"),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
