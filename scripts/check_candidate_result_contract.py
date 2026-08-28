#!/usr/bin/env python3
"""Check the frozen S20-360 candidate-result contract without claiming code."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/CANDIDATE_RESULT_V1.md"
PROFILE = ROOT / "docs/spec/VALIDATION_PROFILE_V1.md"
TRANSACTION = ROOT / "docs/spec/TRANSACTION_MODEL_V1.md"
ADR = ROOT / "docs/adr/ADR-0020-candidate-result-and-validation-boundary.md"
ERRORS = ROOT / "docs/spec/ERROR_CODES_V1.md"
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
    for path in (SPEC, PROFILE, TRANSACTION, ADR, ERRORS, MASTER):
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
            "u32be(phase_tag) || len(canonical_phase_input_output) || "
            "canonical_phase_input_output"
        ),
        "candidate_id=None",
        "exactly fourteen ordered `PhaseResult` records",
        "A candidate root is present exactly for `VALID`",
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

    result = {
        "candidate_authority": False,
        "candidate_result_implemented": False,
        "contract": "s20-360-candidate-result-contract-freeze-v1",
        "decisions": len(DECISIONS),
        "durable_commit": False,
        "phase_tags": len(PHASES),
        "problems": problems,
        "result": "PASS" if not problems else "FAIL",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
