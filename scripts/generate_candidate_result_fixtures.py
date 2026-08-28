#!/usr/bin/env python3
"""Refresh the deterministic S20-360 result fixture from the private codec owner."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "conformance/candidate-result/v1"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when committed fixtures differ from the codec-owned vectors",
    )
    arguments = parser.parse_args()
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "sley-policy",
            "emit_candidate_result_vectors_for_fixture_refresh",
            "--",
            "--ignored",
            "--nocapture",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    vectors = []
    for line in completed.stdout.splitlines():
        if not line.startswith("VECTOR|"):
            continue
        _, decision, failed_phase, result_id, stored = line.split("|", maxsplit=4)
        decision = decision.removeprefix("CANDIDATE_VALIDATION_")
        vectors.append(
            {
                "decision": decision,
                "expected_candidate_result_id_hex": result_id,
                "failed_phase": int(failed_phase),
                "id": decision.lower().replace("_", "-"),
                "phase_count": 14,
                "stored_hex": stored,
            }
        )
    if len(vectors) != 16 or vectors[0]["decision"] != "VALID":
        raise RuntimeError(f"expected 16 ordered result vectors, found {len(vectors)}")
    accepted = {
        "contract": "s20-360-candidate-result-v1",
        "generator": "scripts/generate_candidate_result_fixtures.py",
        "vectors": vectors,
    }
    rejected = {
        "contract": "s20-360-candidate-result-v1",
        "mutations": [
            {
                "expected_code": "SCB_MAGIC_INVALID",
                "id": "magic",
                "operation": "flip-first-byte",
            },
            {
                "expected_code": "SCB_DIGEST_MISMATCH",
                "id": "digest",
                "operation": "flip-last-byte",
            },
            {
                "expected_code": "SCB_TRAILING_BYTES",
                "id": "trailing",
                "operation": "append-zero",
            },
            {
                "expected_code": "SCB_LENGTH_OVERFLOW",
                "id": "truncated",
                "operation": "truncate-half",
            },
        ],
    }
    rendered = {
        FIXTURES / "accepted.json": json.dumps(accepted, indent=2, sort_keys=True) + "\n",
        FIXTURES / "rejected.json": json.dumps(rejected, indent=2, sort_keys=True) + "\n",
    }
    if arguments.check:
        drift = [
            str(path.relative_to(ROOT))
            for path, expected in rendered.items()
            if not path.is_file() or path.read_text(encoding="utf-8") != expected
        ]
        print(
            json.dumps(
                {
                    "drift": drift,
                    "mode": "check",
                    "result": "FAIL" if drift else "PASS",
                    "vectors": len(vectors),
                },
                sort_keys=True,
            )
        )
        return 1 if drift else 0

    FIXTURES.mkdir(parents=True, exist_ok=True)
    for path, payload in rendered.items():
        path.write_text(payload, encoding="utf-8")
    print(
        json.dumps(
            {"mode": "write", "result": "PASS", "vectors": len(vectors)},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
