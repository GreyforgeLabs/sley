"""Frozen-corpus runner for the independent SCB1 oracle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .candidate import check_candidate
from .candidate_result import check_candidate_result
from .codec import decode_accepted_vector, decode_declared_value, encode_accepted_vector
from .errors import ScbError
from .mutation_value import check_mutation_value
from .transaction_receipt import check_transaction_receipt


def check(accepted_path: Path, rejected_path: Path) -> dict[str, object]:
    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    rejected = json.loads(rejected_path.read_text(encoding="utf-8"))
    problems: list[str] = []

    for vector in accepted["vectors"]:
        try:
            actual = encode_accepted_vector(vector).hex()
        except (ScbError, ValueError) as error:
            problems.append(f"{vector['id']}: oracle raised {error}")
            continue
        if actual != vector["expected_hex"]:
            problems.append(
                f"{vector['id']}: expected {vector['expected_hex']}, oracle produced {actual}"
            )
            continue
        try:
            decode_accepted_vector(vector, bytes.fromhex(actual))
        except (ScbError, ValueError) as error:
            problems.append(
                f"{vector['id']}: oracle rejected accepted bytes with {error}"
            )

    for vector in rejected["vectors"]:
        try:
            decode_declared_value(
                vector["declared_type"], bytes.fromhex(vector["input_hex"])
            )
        except ScbError as error:
            if error.code != vector["expected_code"]:
                problems.append(
                    f"{vector['id']}: expected {vector['expected_code']}, oracle returned {error.code}"
                )
        except ValueError as error:
            problems.append(f"{vector['id']}: unsupported oracle path: {error}")
        else:
            problems.append(f"{vector['id']}: rejected vector was accepted")

    return {
        "contract": "s20-130-independent-oracle-v1",
        "result": "FAIL" if problems else "PASS",
        "accepted_vectors": len(accepted["vectors"]),
        "rejected_vectors": len(rejected["vectors"]),
        "byte_agreement": not any("oracle produced" in problem for problem in problems),
        "accepted_decode_agreement": not any(
            "rejected accepted bytes" in problem for problem in problems
        ),
        "code_agreement": not any("oracle returned" in problem for problem in problems),
        "problems": problems,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "check",
            "check-mutation-value",
            "check-mutation-candidate",
            "check-candidate-result",
            "check-transaction-receipt",
        ),
    )
    parser.add_argument("--accepted", required=True, type=Path)
    parser.add_argument("--rejected", required=True, type=Path)
    arguments = parser.parse_args()
    if arguments.command == "check-transaction-receipt":
        result = check_transaction_receipt(arguments.accepted, arguments.rejected)
    elif arguments.command == "check-candidate-result":
        result = check_candidate_result(arguments.accepted, arguments.rejected)
    elif arguments.command == "check-mutation-candidate":
        result = check_candidate(arguments.accepted, arguments.rejected)
    elif arguments.command == "check-mutation-value":
        result = check_mutation_value(arguments.accepted, arguments.rejected)
    else:
        result = check(arguments.accepted, arguments.rejected)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["result"] != "PASS":
        raise SystemExit(1)
