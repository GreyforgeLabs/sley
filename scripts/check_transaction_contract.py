#!/usr/bin/env python3
"""Check the restricted S20-390 transaction, receipt, and fixed-head contract."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/TRANSACTION_MODEL_V1.md"
REPOSITORY_SPEC = ROOT / "docs/spec/REPOSITORY_MODEL_V1.md"
IDENTIFIERS = ROOT / "docs/spec/IDENTIFIERS_V1.md"
ERRORS = ROOT / "docs/spec/ERROR_CODES_V1.md"
ADR = ROOT / "docs/adr/ADR-0021-transaction-receipt-and-accepted-head-boundary.md"
THREATS = ROOT / "docs/THREAT_REGISTER.md"
WORK_PACKAGES = ROOT / "docs/WORK_PACKAGES.md"
CRATE_MANIFEST = ROOT / "crates/sley-txn/Cargo.toml"
LIBRARY = ROOT / "crates/sley-txn/src/lib.rs"
CODEC = ROOT / "crates/sley-txn/src/codec.rs"
REPOSITORY = ROOT / "crates/sley-txn/src/repository.rs"
VALIDATOR = ROOT / "crates/sley-policy/src/candidate_validation.rs"
ORACLE = ROOT / "oracle/scb1/src/sley2_scb1_oracle/transaction_receipt.py"
ACCEPTED = ROOT / "conformance/transaction-receipt/v1/accepted.json"
REJECTED = ROOT / "conformance/transaction-receipt/v1/rejected.json"
SUMS = ROOT / "conformance/transaction-receipt/v1/SHA256SUMS"
GENERATOR = ROOT / "scripts/generate_transaction_receipt_fixtures.py"
FUZZ_TARGET = ROOT / "fuzz/targets/transaction_receipt.rs"
FUZZ_CHECK = ROOT / "scripts/check_transaction_receipt_persistent_fuzz_slice.py"
CLOSEOUT = ROOT / "docs/audits/S20_390_ATOMIC_COMMIT_CLOSEOUT.md"
EVIDENCE = ROOT / "evidence/validation/s20-390-atomic-commit-closeout-v1.json"
MASTER = ROOT.parent / "machineresearch/sley/in-progress/2.0/Sley2.0mastergoal.md"


ERROR_CODES = (
    "TXN_FORMAT_VERSION",
    "TXN_KIND_INVALID",
    "TXN_PARENT_SHAPE",
    "TXN_FIELD_SHAPE",
    "TXN_CHANGED_BINDING_INVALID",
    "TXN_TOMBSTONE_INVALID",
    "TXN_RESULT_NOT_VALID",
    "TXN_RESULT_BINDING_MISMATCH",
    "TXN_TEST_EVIDENCE_UNSUPPORTED",
    "TXN_OBJECT_INVENTORY_MISMATCH",
    "TXN_RECEIPT_BINDING_MISMATCH",
    "TXN_RECEIPT_CONFLICT",
    "TXN_GENESIS_INVALID",
    "TXN_ALREADY_INITIALIZED",
    "REF_HEAD_MISSING",
    "REF_HEAD_CORRUPT",
    "REF_CAS_STALE",
    "RECOVERY_RECEIPT_INCOMPLETE",
    "RECOVERY_REF_CAS_INCOMPLETE",
    "TXN_IO",
    "TXN_INTERNAL_INVARIANT",
    "TXN_RESOURCE_LIMIT",
)


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def require_markers(
    path: Path, markers: tuple[str, ...], label: str, problems: list[str]
) -> None:
    text = normalized(path)
    for marker in markers:
        if marker not in text:
            problems.append(f"{label}-missing:{marker}")


def fixture_checksum_problems() -> list[str]:
    problems: list[str] = []
    expected: dict[str, str] = {}
    for line in SUMS.read_text(encoding="utf-8").splitlines():
        digest, filename = line.split("  ", maxsplit=1)
        expected[filename] = digest
    if set(expected) != {"accepted.json", "rejected.json"}:
        return ["transaction-fixture-checksum-inventory-drift"]
    for filename, digest in expected.items():
        actual = hashlib.sha256((SUMS.parent / filename).read_bytes()).hexdigest()
        if actual != digest:
            problems.append(f"transaction-fixture-checksum-drift:{filename}")
    return problems


def main() -> int:
    problems: list[str] = []
    paths = (
        SPEC,
        REPOSITORY_SPEC,
        IDENTIFIERS,
        ERRORS,
        ADR,
        THREATS,
        WORK_PACKAGES,
        CRATE_MANIFEST,
        LIBRARY,
        CODEC,
        REPOSITORY,
        VALIDATOR,
        ORACLE,
        ACCEPTED,
        REJECTED,
        SUMS,
        GENERATOR,
        FUZZ_TARGET,
        FUZZ_CHECK,
        CLOSEOUT,
        EVIDENCE,
        MASTER,
    )
    for path in paths:
        if not path.is_file():
            problems.append(f"missing:{path}")
    if problems:
        print(json.dumps({"problems": problems, "result": "FAIL"}, indent=2))
        return 1

    require_markers(
        SPEC,
        (
            '"SLEYTXN1"',
            '"sley2.transaction.v1"',
            '"SLEYRCP1"',
            '"sley2.transaction-receipt.v1"',
            "No `TransactionId` or `ReceiptId` field exists inside",
            "exactly one parent and one aligned parent root",
            "fixed `accepted` head slot",
            "A stale expected head returns `STALE_ROOT`, never last-write-wins",
            "empty selected-test set",
            "does not trust a caller-supplied or imported candidate result",
        ),
        "transaction-spec",
        problems,
    )
    require_markers(
        ADR,
        (
            "No identifier hashes itself",
            "does not depend on `sley-repo`",
            "receipt persistence",
            "fresh `CandidateValidationContext`",
            "A fixed accepted-head slot is a commit visibility primitive",
        ),
        "transaction-adr",
        problems,
    )
    require_markers(
        IDENTIFIERS,
        (
            "TransactionId = H(transaction_domain, canonical_transaction_envelope_preimage)",
            "ReceiptId = H(receipt_domain, canonical_receipt_envelope_preimage)",
            "the outer receipt contains `TransactionId` but excludes `ReceiptId`",
        ),
        "transaction-identifiers",
        problems,
    )
    require_markers(
        REPOSITORY_SPEC,
        (
            "one fixed durable `accepted` head",
            "does not depend on `sley-repo`",
            "S20-500 owns native named branch refs",
        ),
        "transaction-repository-model",
        problems,
    )
    require_markers(
        THREATS,
        ("T38", "T39", "sley-txn", "RECOVERY_RECEIPT_INCOMPLETE"),
        "transaction-threat",
        problems,
    )

    errors = ERRORS.read_text(encoding="utf-8")
    for numeric, symbol in enumerate(ERROR_CODES, start=39_000):
        marker = f"| {numeric} | `{symbol}` |"
        if errors.count(marker) != 1:
            problems.append(f"transaction-error-code-drift:{numeric}:{symbol}")

    manifest = CRATE_MANIFEST.read_text(encoding="utf-8")
    if "sley-repo" in manifest:
        problems.append("transaction-crate-dependency-inversion:sley-repo")
    for marker in (
        'sley-store = { path = "../sley-store" }',
        'sley-policy = { path = "../sley-policy" }',
        'sley-state-root = { path = "../sley-state-root" }',
    ):
        if marker not in manifest:
            problems.append(f"transaction-crate-dependency-missing:{marker}")

    require_markers(
        LIBRARY,
        (
            "TransactionRepository",
            "TrustedGenesisInput",
            "CommitInput",
            "CommitOutput",
            "import_transaction_receipt",
        ),
        "transaction-export",
        problems,
    )
    require_markers(
        CODEC,
        (
            "pub const TRANSACTION_MAGIC",
            "pub const RECEIPT_MAGIC",
            "const TRANSACTION_FIELD_COUNT: u64 = 19;",
            "const RECEIPT_FIELD_COUNT: u64 = 9;",
            "TransactionId::derive(&preimage)",
            "ReceiptId::derive(&preimage)",
            "validate_ordinary_nested",
            "validate_manifest_binding",
            "transaction_error_codes_are_closed_and_contiguous",
        ),
        "transaction-codec",
        problems,
    )
    require_markers(
        REPOSITORY,
        (
            "let _lock = self.acquire_lock()?;",
            "validate_candidate_bytes(&context, input.stored_candidate)",
            "validated_plan()",
            "self.persist_objects(&manifest",
            "self.persist_receipt(&receipt, fault)?;",
            "self.cas_head(Some(actual)",
            "file.lock()?;",
            "fs::hard_link(&stage_path, &final_path)",
            "fs::rename(&stage_path, &head_path)?;",
            "sync_dir(&head_dir)?;",
            "AfterObjectsBeforeReceipt",
            "DuringReceiptWrite",
            "AfterReceiptBeforeHead",
            "BeforeHeadRename",
            "AfterHeadRenameBeforeSync",
            "independent_threads_serialize_and_one_observes_stale_head",
            "interruption_matrix_accepts_only_old_or_complete_new_state",
            "corrupted_head_and_symlinked_owned_directory_fail_closed",
        ),
        "transaction-repository",
        problems,
    )

    validator = VALIDATOR.read_text(encoding="utf-8")
    require_markers(
        VALIDATOR,
        (
            "pub struct ValidatedCandidatePlan",
            "plan: Option<ValidatedCandidatePlan>",
            "plan: Some(plan)",
            "pub const fn validated_plan(&self)",
        ),
        "validated-plan",
        problems,
    )
    plan_start = validator.index("pub struct ValidatedCandidatePlan")
    plan_end = validator.index("}", plan_start)
    if "pub candidate:" in validator[plan_start:plan_end] or "pub proposed_state:" in validator[
        plan_start:plan_end
    ]:
        problems.append("validated-plan-fields-public")

    accepted = json.loads(ACCEPTED.read_text(encoding="utf-8"))
    rejected = json.loads(REJECTED.read_text(encoding="utf-8"))
    expected_claim = (
        "restricted-executable-program-operation-free-test-free-s20-390-conformance"
    )
    expected_contract = "sley2-transaction-receipt-v1"
    for label, corpus in (("accepted", accepted), ("rejected", rejected)):
        if corpus.get("claim") != expected_claim:
            problems.append(f"transaction-fixture-claim-drift:{label}")
        if corpus.get("contract") != expected_contract:
            problems.append(f"transaction-fixture-contract-drift:{label}")
    if [value.get("kind") for value in accepted.get("vectors", [])] != [
        "GENESIS",
        "ORDINARY",
    ]:
        problems.append("transaction-fixture-kind-drift")
    if len(rejected.get("mutations", [])) != 9:
        problems.append("transaction-fixture-rejection-count-drift")
    problems.extend(fixture_checksum_problems())

    require_markers(
        ORACLE,
        (
            "def decode_transaction(data: bytes)",
            "def decode_transaction_receipt(data: bytes)",
            "TRANSACTION_DOMAIN = b\"sley2.transaction.v1\"",
            "RECEIPT_DOMAIN = b\"sley2.transaction-receipt.v1\"",
            "TXN_RESULT_BINDING_MISMATCH",
            "expected_manifest != actual_manifest",
        ),
        "transaction-oracle",
        problems,
    )
    require_markers(
        GENERATOR,
        (
            "emit_transaction_receipt_vectors_for_fixture_refresh",
            '!= ["GENESIS", "ORDINARY"]',
            "receipt_sha256",
            "transaction_sha256",
        ),
        "transaction-generator",
        problems,
    )
    require_markers(
        FUZZ_TARGET,
        (
            "import_transaction(input)",
            "import_transaction_receipt(input)",
            "TransactionId::derive(&first.preimage)",
            "ReceiptId::derive(&first.preimage)",
        ),
        "transaction-fuzz",
        problems,
    )

    closeout = normalized(CLOSEOUT)
    for marker in (
        "restricted S20-390 atomic commit complete",
        "Tier 2 subsystem handoff",
        "Ariadne",
        "Vulcan",
        "S20-500",
        "S20-530",
        "operation-free",
        "empty selected-test set",
    ):
        if marker not in closeout:
            problems.append(f"transaction-closeout-missing:{marker}")

    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    for field, expected in (
        ("contract", "s20-390-atomic-commit-closeout-v1"),
        ("result", "PASS_RESTRICTED_OPERATION_FREE_TEST_FREE"),
        ("validation_tier", "TIER_2_SUBSYSTEM_HANDOFF"),
    ):
        if evidence.get(field) != expected:
            problems.append(f"transaction-evidence-drift:{field}")
    deterministic = evidence.get("deterministic_inputs", {})
    for field, expected in (
        ("accepted_fixture_vectors", 2),
        ("rejected_fixture_vectors", 9),
        ("fault_boundaries", 5),
        ("persistent_fuzz_runs", 512),
    ):
        if deterministic.get(field) != expected:
            problems.append(f"transaction-evidence-drift:{field}")
    commands = evidence.get("commands", {})
    for field in (
        "tier_1_make_quick",
        "tier_2_make_adversarial",
        "tier_2_make_conformance",
        "tier_2_make_core",
    ):
        if commands.get(field) != "PASS":
            problems.append(f"transaction-evidence-drift:{field}")

    packages = normalized(WORK_PACKAGES)
    if "Complete restricted atomic-commit boundary" not in packages:
        problems.append("transaction-work-package-not-closed")

    result = {
        "claim": expected_claim,
        "complete_receipt_codec": True,
        "contract": "s20-390-restricted-atomic-commit-v1",
        "fixed_accepted_head": True,
        "full_crash_recovery_complete": False,
        "named_refs_complete": False,
        "problems": problems,
        "result": "PASS" if not problems else "FAIL",
        "runtime_authority": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
