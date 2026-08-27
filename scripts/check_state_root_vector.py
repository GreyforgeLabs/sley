#!/usr/bin/env python3
"""Independently reconstruct the S20-160 registered StateRoot vector."""

from __future__ import annotations

import json
from pathlib import Path

from blake3 import blake3


ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads(
    (ROOT / "conformance/state-root/v1/accepted.json").read_text(encoding="utf-8")
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


def sequence(values: list[bytes]) -> bytes:
    return uvar(len(values)) + b"".join(sized(value) for value in values)


def mapping(values: list[tuple[bytes, bytes]]) -> bytes:
    return uvar(len(values)) + b"".join(
        sized(key) + sized(value) for key, value in values
    )


field_schema_preimage = (
    b"sley2.state-root.v1.schema:required(1:workspace_id fixed32,"
    b"2:schema_epoch_id fixed32,3:entity_bindings map fixed32 fixed32,"
    b"4:entry_points set fixed32,5:dependency_roots set fixed32,"
    b"6:contract_root fixed32,7:test_root fixed32,8:policy_root fixed32,"
    b"9:interpretation_flags set u32);flags=empty;epoch=1"
)
decoder_limits_preimage = b"sley2.state-root.v1.decoder-limits:scb1-epoch1"
field_schema_hash = blake3(field_schema_preimage).digest()
decoder_limits_hash = blake3(decoder_limits_preimage).digest()

descriptor = record(
    (
        (1, uvar(160)),
        (2, uvar(4)),
        (3, uvar(160)),
        (4, field_schema_hash),
        (5, sequence([uvar(tag) for tag in range(1, 10)])),
        (6, b"\x00"),
        (7, b"\x00"),
        (8, decoder_limits_hash),
    )
)
unicode_version = record(((1, uvar(16)), (2, uvar(0)), (3, uvar(0))))
limits = record(
    tuple(
        (tag + 1, uvar(value))
        for tag, value in enumerate(
            (67_108_864, 16_777_216, 64, 65_535, 1_000_000, 1_000_000, 134_217_728)
        )
    )
)
epoch_record = record(
    (
        (1, uvar(1)),
        (2, uvar(1)),
        (3, uvar(1)),
        (4, unicode_version),
        (5, limits),
        (6, sequence([descriptor])),
        (7, b"\x00"),
        (8, b"\x00\x00"),
        (9, b"\x00"),
    )
)
epoch_preimage = b"SLEYEP01" + uvar(1) + sized(epoch_record)
epoch_id = blake3(b"sley2.schema-epoch.v1" + epoch_preimage).digest()

bindings = mapping(
    [(bytes([2]) * 32, bytes([31]) * 32), (bytes([3]) * 32, bytes([30]) * 32)]
)
payload = record(
    (
        (1, bytes([1]) * 32),
        (2, epoch_id),
        (3, bindings),
        (4, sequence([bytes([2]) * 32])),
        (5, sequence([bytes([40]) * 32, bytes([41]) * 32])),
        (6, bytes([20]) * 32),
        (7, bytes([21]) * 32),
        (8, bytes([22]) * 32),
        (9, b"\x00"),
    )
)
preimage = b"SLEYSCB1" + uvar(1) + uvar(160) + epoch_id + sized(payload)
state_root = blake3(b"sley2.state-root.v1" + preimage).digest()
stored = preimage + state_root

checks = {
    "field_schema_hash": field_schema_hash.hex() == VECTOR["field_schema_hash"],
    "decoder_limits_hash": decoder_limits_hash.hex() == VECTOR["decoder_limits_hash"],
    "epoch_record_bytes": len(epoch_record) == VECTOR["epoch_record_bytes"],
    "schema_epoch_id": epoch_id.hex() == VECTOR["schema_epoch_id"],
    "payload_bytes": len(payload) == VECTOR["payload_bytes"],
    "payload_hex": payload.hex() == VECTOR["payload_hex"],
    "preimage_bytes": len(preimage) == VECTOR["preimage_bytes"],
    "stored_bytes": len(stored) == VECTOR["stored_bytes"],
    "state_root": state_root.hex() == VECTOR["state_root"],
}
problems = [name for name, passed in checks.items() if not passed]
print(
    json.dumps(
        {
            "contract": "s20-160-independent-state-root-vector-v1",
            "problems": problems,
            "result": "PASS" if not problems else "FAIL",
            "schema_epoch_id": epoch_id.hex(),
            "state_root": state_root.hex(),
            "stored_bytes": len(stored),
        },
        indent=2,
        sort_keys=True,
    )
)
if problems:
    raise SystemExit(1)
