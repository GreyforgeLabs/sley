#!/usr/bin/env python3
"""Independently reconstruct the frozen SLEYEP01 bootstrap vector."""

from __future__ import annotations

import json
from pathlib import Path

from blake3 import blake3


ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads(
    (ROOT / "conformance/schema-epoch/v1/bootstrap.json").read_text(encoding="utf-8")
)


def uvar(value: int) -> bytes:
    output = bytearray()
    while True:
        group = value & 0x7F
        value >>= 7
        output.append(group | (0x80 if value else 0))
        if not value:
            return bytes(output)


def sized(value: bytes) -> bytes:
    return uvar(len(value)) + value


def record(fields: tuple[tuple[int, bytes], ...]) -> bytes:
    return uvar(len(fields)) + b"".join(
        uvar(tag) + sized(value) for tag, value in fields
    )


unicode_version = record(
    tuple(
        (tag + 1, uvar(value))
        for tag, value in enumerate(VECTOR["unicode_nfc_version"])
    )
)
limits = record(
    tuple((tag + 1, uvar(value)) for tag, value in enumerate(VECTOR["limits"]))
)
epoch_record = record(
    (
        (1, uvar(VECTOR["epoch_number"])),
        (2, uvar(VECTOR["scb_format_version"])),
        (3, uvar(VECTOR["hash_algorithm_tag"])),
        (4, unicode_version),
        (5, limits),
        (6, b"\x00"),
        (7, b"\x00"),
        (8, b"\x00\x00"),
        (9, b"\x00"),
    )
)
preimage = b"SLEYEP01" + uvar(1) + sized(epoch_record)
epoch_id = blake3(b"sley2.schema-epoch.v1" + preimage).hexdigest()

problems: list[str] = []
if epoch_record.hex() != VECTOR["record_hex"]:
    problems.append("canonical epoch record differs")
if preimage.hex() != VECTOR["preimage_hex"]:
    problems.append("bootstrap preimage differs")
if epoch_id != VECTOR["schema_epoch_id"]:
    problems.append("SchemaEpochId differs")

result = {
    "contract": "s20-140-independent-bootstrap-vector-v1",
    "result": "FAIL" if problems else "PASS",
    "record_bytes": len(epoch_record),
    "preimage_bytes": len(preimage),
    "schema_epoch_id": epoch_id,
    "problems": problems,
}
print(json.dumps(result, indent=2, sort_keys=True))
if problems:
    raise SystemExit(1)
