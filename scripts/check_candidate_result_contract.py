#!/usr/bin/env python3
"""Check the implemented restricted S20-360 candidate-validation contract."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/CANDIDATE_RESULT_V1.md"
PROFILE = ROOT / "docs/spec/VALIDATION_PROFILE_V1.md"
TRANSACTION = ROOT / "docs/spec/TRANSACTION_MODEL_V1.md"
ADR = ROOT / "docs/adr/ADR-0020-candidate-result-and-validation-boundary.md"
ERRORS = ROOT / "docs/spec/ERROR_CODES_V1.md"
VALIDATOR = ROOT / "crates/sley-policy/src/candidate_validation.rs"
PROGRAM = ROOT / "crates/sley-policy/src/candidate_program.rs"
RESULT_CODEC = ROOT / "crates/sley-policy/src/candidate_result.rs"
LIB = ROOT / "crates/sley-policy/src/lib.rs"
ORACLE = ROOT / "oracle/scb1/src/sley2_scb1_oracle/candidate_result.py"
ACCEPTED = ROOT / "conformance/candidate-result/v1/accepted.json"
REJECTED = ROOT / "conformance/candidate-result/v1/rejected.json"
FUZZ_TARGET = ROOT / "fuzz/targets/candidate_result.rs"
CLOSEOUT = ROOT / "docs/audits/S20_360_CANDIDATE_VALIDATION_CLOSEOUT.md"
VALIDATION_EVIDENCE = (
    ROOT / "evidence/validation/s20-360-candidate-validation-closeout-v1.json"
)
MASTER = (
    ROOT.parent
    / "machineresearch/sley/in-progress/2.0/Sley2.0mastergoal.md"
)

PHASES = [
    "canonical frame",
    "schema and limits",
    "stale base and preimages",
    "identity",
    "graph and references",
    "type",
    "CFG",
    "effects",
    "protected capability and policy",
    "contracts",
    "test planning",
    "supported resource analysis",
    "candidate-root construction",
    "final candidate/result digest generation",
]

DECISIONS = [
    "VALID",
    "INVALID_ENCODING",
    "INVALID_SCHEMA",
    "STALE_ROOT",
    "STALE_ENTITY",
    "INVALID_IDENTITY",
    "INVALID_GRAPH",
    "UNRESOLVED_REFERENCE",
    "TYPE_ERROR",
    "CONTROL_FLOW_ERROR",
    "EFFECT_ERROR",
    "CAPABILITY_DENIED",
    "CONTRACT_ERROR",
    "RESOURCE_LIMIT",
    "TEST_PLAN_ERROR",
    "INTERNAL_ERROR",
]


def normalized(path: Path) -> str:
    return " ".join(path.read_text(encoding="utf-8").split())


def main() -> int:
    problems: list[str] = []
    for path in (
        SPEC,
        PROFILE,
        TRANSACTION,
        ADR,
        ERRORS,
        MASTER,
        VALIDATOR,
        PROGRAM,
        RESULT_CODEC,
        LIB,
        ORACLE,
        ACCEPTED,
        REJECTED,
        FUZZ_TARGET,
        CLOSEOUT,
        VALIDATION_EVIDENCE,
    ):
        if not path.is_file():
            problems.append(f"missing:{path}")
    if problems:
        raise SystemExit("\n".join(problems))

    spec = normalized(SPEC)
    for phase in PHASES:
        if phase not in spec:
            problems.append(f"candidate-result-phase-missing:{phase}")
    for decision in DECISIONS:
        if f"`{decision}`" not in spec:
            problems.append(f"candidate-result-decision-missing:{decision}")
    for marker in (
        '"SLEYATT1"',
        '"sley2.candidate-attempt.v1"',
        '"SLEYCRS1"',
        '"sley2.candidate-result.v1"',
        (
            "u32be(phase_tag) || uvar(byte_length(canonical_phase_input_output)) || "
            "canonical_phase_input_output"
        ),
        "candidate_id=None",
        "exactly fourteen ordered `PhaseResult` records",
        "A candidate root is present exactly for `VALID`",
        "The primary diagnostic is exactly list element zero",
        "no caller-supplied phase outcome",
        "S20-390 remains the first package allowed to perform durable commit",
    ):
        if marker not in spec:
            problems.append(f"candidate-result-boundary-missing:{marker}")

    for path, markers in (
        (PROFILE, ("phase_tags", "ordered list `1..14`", "caller-asserted phase success")),
        (TRANSACTION, ("14. candidate result digest", "exact fourteen-phase order")),
        (ADR, ("fourteen phases", "Malformed or noncanonical candidate bytes have no `CandidateId`")),
        (MASTER, ("14. candidate digest and result generation",)),
    ):
        text = normalized(path)
        for marker in markers:
            if marker not in text:
                problems.append(f"phase-authority-drift:{path.name}:{marker}")

    errors = ERRORS.read_text(encoding="utf-8")
    for numeric, decision in enumerate(DECISIONS[1:], start=36_000):
        marker = f"| {numeric} | `CANDIDATE_VALIDATION_{decision}` |"
        if errors.count(marker) != 1:
            problems.append(f"candidate-result-error-drift:{numeric}:{decision}")
    integrity_symbols = (
        "FORMAT_VERSION",
        "PROFILE_INVALID",
        "PHASE_SHAPE",
        "DECISION_PHASE_MISMATCH",
        "DIAGNOSTIC_INVALID",
        "SET_INVALID",
        "CANDIDATE_ID_SHAPE",
        "ROOT_SHAPE",
    )
    for numeric, symbol in enumerate(integrity_symbols, start=36_100):
        marker = f"| {numeric} | `CANDIDATE_RESULT_{symbol}` |"
        if errors.count(marker) != 1:
            problems.append(f"candidate-result-integrity-error-drift:{numeric}:{symbol}")

    validator = VALIDATOR.read_text(encoding="utf-8")
    for marker in (
        "pub fn validate_candidate_bytes(",
        "CandidateValidationContext",
        "apply_candidate_to_snapshot",
        "validate_function_graph",
        "validate_effect_program",
        "validate_contract_test_program",
        "verify_capability_token",
        "validate_ordinary_program_isolation",
        "build_candidate_state_root",
        "encode_phase14_result_core",
        "if !program.operation_analysis_supported()",
        '"CANDIDATE_OPERATION_ANALYSIS_UNSUPPORTED"',
    ):
        if marker not in validator:
            problems.append(f"candidate-validator-missing:{marker}")
    for phase in range(1, 15):
        if f"Phase {phase}" not in validator and phase not in (10, 11):
            problems.append(f"candidate-validator-phase-missing:{phase}")
    if "Phase 10/11" not in validator:
        problems.append("candidate-validator-phase-missing:10/11")

    program = PROGRAM.read_text(encoding="utf-8")
    for marker in (
        "const ALL_ENTITY_KINDS: u32 = (1_u32 << 18) - 1;",
        "pub(crate) fn operation_analysis_supported(&self) -> bool",
        "pub(crate) fn affected_closure(",
        "validate_restricted_type_fingerprint_claims",
        "validate_restricted_function_fingerprint_claims",
    ):
        if marker not in program:
            problems.append(f"candidate-program-missing:{marker}")

    library = LIB.read_text(encoding="utf-8")
    for marker in (
        "CandidateValidationContext",
        "CandidateValidationLimits",
        "CandidateValidationOutput",
        "validate_candidate_bytes",
    ):
        if marker not in library:
            problems.append(f"candidate-validator-export-missing:{marker}")

    accepted = json.loads(ACCEPTED.read_text(encoding="utf-8"))
    rejected = json.loads(REJECTED.read_text(encoding="utf-8"))
    actual_decisions = [vector.get("decision") for vector in accepted.get("vectors", [])]
    if actual_decisions != DECISIONS:
        problems.append("candidate-result-decision-corpus-drift")
    if len(rejected.get("mutations", [])) != 4:
        problems.append("candidate-result-rejected-corpus-drift")

    oracle = ORACLE.read_text(encoding="utf-8")
    for marker in (
        "DECISION_TAG_BY_NAME",
        'result["decision_tag"] != expected_tag',
        'result["failed_phase"] != expected_failed',
        "missing fixture decisions",
    ):
        if marker not in oracle:
            problems.append(f"candidate-result-oracle-missing:{marker}")

    fuzz_target = FUZZ_TARGET.read_text(encoding="utf-8")
    for marker in (
        "import_candidate_result(input)",
        "CandidateResultId::derive(&first.preimage)",
        "record.phase_results.len(), 14",
    ):
        if marker not in fuzz_target:
            problems.append(f"candidate-result-fuzz-missing:{marker}")

    closeout = normalized(CLOSEOUT)
    for marker in (
        "restricted operation-free validation complete",
        "no commit or runtime authority",
        "Ariadne",
        "Vulcan",
        "Tier 2 subsystem handoff",
        "S20-390",
    ):
        if marker not in closeout:
            problems.append(f"candidate-validation-closeout-missing:{marker}")

    validation = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    for field, expected in (
        ("contract", "s20-360-candidate-validation-closeout-v1"),
        ("result", "PASS_RESTRICTED_OPERATION_FREE"),
        ("validation_tier", "TIER_2_SUBSYSTEM_HANDOFF"),
    ):
        if validation.get(field) != expected:
            problems.append(f"candidate-validation-evidence-drift:{field}")
    deterministic = validation.get("deterministic_inputs", {})
    if deterministic.get("validation_phases") != 14:
        problems.append("candidate-validation-evidence-drift:validation_phases")
    if deterministic.get("terminal_decisions") != 16:
        problems.append("candidate-validation-evidence-drift:terminal_decisions")

    result = {
        "candidate_authority": False,
        "candidate_result_codec_implemented": True,
        "candidate_result_implemented": True,
        "candidate_validation_implemented": True,
        "contract": "s20-360-restricted-candidate-validation-v1",
        "decisions": len(DECISIONS),
        "durable_commit": False,
        "operation_success_subset": "operation-free",
        "phase_tags": len(PHASES),
        "problems": problems,
        "result": "PASS" if not problems else "FAIL",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
