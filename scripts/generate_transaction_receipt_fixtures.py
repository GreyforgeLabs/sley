#!/usr/bin/env python3
"""Refresh deterministic S20-390 transaction and receipt fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "conformance/transaction-receipt/v1"


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
            "sley-txn",
            "emit_transaction_receipt_vectors_for_fixture_refresh",
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
    vectors: list[dict[str, object]] = []
    emitted_rejections: list[dict[str, object]] = []
    for line in completed.stdout.splitlines():
        if line.startswith("TXN_REJECT|"):
            _, vector_id, expected_code, input_hex, manifest = line.split(
                "|", maxsplit=4
            )
            emitted_rejections.append(
                {
                    "expected_code": expected_code,
                    "expected_object_manifest": parse_manifest(manifest),
                    "id": vector_id,
                    "input_hex": input_hex,
                    "operation": "provided-inventory-mismatch",
                    "target": "receipt",
                }
            )
            continue
        if not line.startswith("TXN_VECTOR|"):
            continue
        (
            _,
            kind,
            transaction_id,
            receipt_id,
            transaction_hex,
            receipt_hex,
            manifest,
        ) = line.split(
            "|", maxsplit=6
        )
        vectors.append(
            {
                "expected_receipt_id_hex": receipt_id,
                "expected_transaction_id_hex": transaction_id,
                "id": kind.lower(),
                "kind": kind,
                "object_manifest": parse_manifest(manifest),
                "receipt_hex": receipt_hex,
                "receipt_sha256": hashlib.sha256(bytes.fromhex(receipt_hex)).hexdigest(),
                "transaction_hex": transaction_hex,
                "transaction_sha256": hashlib.sha256(
                    bytes.fromhex(transaction_hex)
                ).hexdigest(),
            }
        )
    if [vector["kind"] for vector in vectors] != ["GENESIS", "ORDINARY"]:
        raise RuntimeError(
            "expected ordered GENESIS and ORDINARY vectors, found "
            f"{[vector['kind'] for vector in vectors]}"
        )
    if len(emitted_rejections) != 1:
        raise RuntimeError(
            f"expected one emitted inventory rejection, found {len(emitted_rejections)}"
        )

    mutations = []
    expected_codes = {
        "flip-first-byte": "SCB_MAGIC_INVALID",
        "flip-last-byte": "SCB_DIGEST_MISMATCH",
        "append-zero": "SCB_TRAILING_BYTES",
        "truncate-half": "SCB_LENGTH_OVERFLOW",
    }
    for target in ("transaction", "receipt"):
        for operation, expected_code in expected_codes.items():
            mutations.append(
                {
                    "expected_code": expected_code,
                    "id": f"{target}-{operation}",
                    "operation": operation,
                    "seed": "ordinary",
                    "target": target,
                }
            )

    mutations.extend(emitted_rejections)
    accepted = {
        "claim": "restricted-executable-program-operation-free-test-free-s20-390-conformance",
        "contract": "sley2-transaction-receipt-v1",
        "generator": "scripts/generate_transaction_receipt_fixtures.py",
        "vectors": vectors,
    }
    rejected = {
        "claim": "restricted-executable-program-operation-free-test-free-s20-390-conformance",
        "contract": "sley2-transaction-receipt-v1",
        "mutations": mutations,
    }
    rendered = {
        FIXTURES / "accepted.json": json.dumps(accepted, indent=2, sort_keys=True) + "\n",
        FIXTURES / "rejected.json": json.dumps(rejected, indent=2, sort_keys=True) + "\n",
    }
    rendered[FIXTURES / "SHA256SUMS"] = "".join(
        f"{hashlib.sha256(payload.encode()).hexdigest()}  {path.name}\n"
        for path, payload in rendered.items()
    )

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


def parse_manifest(value: str) -> list[dict[str, object]]:
    if not value:
        return []
    return [
        {"object_id_hex": object_id, "stored_length": int(length)}
        for object_id, length in (entry.split(":", maxsplit=1) for entry in value.split(","))
    ]


if __name__ == "__main__":
    raise SystemExit(main())
