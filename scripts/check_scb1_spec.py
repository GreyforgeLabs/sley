#!/usr/bin/env python3
"""Check S20-100's fixed value vectors and rejection taxonomy."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACCEPTED = json.loads((ROOT / "conformance/scb1/v1/accepted.json").read_text())
REJECTED = json.loads((ROOT / "conformance/scb1/v1/rejected.json").read_text())
SPEC = (ROOT / "docs/spec/SCB1.md").read_text()
SUMS = ROOT / "conformance/scb1/v1/SHA256SUMS"


def uvar(value: int) -> bytes:
    if value < 0:
        raise ValueError("uvar input must be nonnegative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def sized(value: bytes) -> bytes:
    return uvar(len(value)) + value


def encode(vector: dict[str, object]) -> bytes:
    kind = vector["kind"]
    value = vector.get("value")
    if kind == "uvar":
        return uvar(int(value))
    if kind == "sint64":
        number = int(value)
        return uvar((number << 1) ^ (number >> 63))
    if kind == "bool":
        return b"\x01" if value is True else b"\x00"
    if kind in {"bytes_utf8_fixture", "text", "normalized_label"}:
        text = str(value)
        if kind == "normalized_label" and unicodedata.normalize("NFC", text) != text:
            raise ValueError("label fixture is not NFC")
        return sized(text.encode("utf-8"))
    if kind == "raw_hex":
        return bytes.fromhex(str(value))
    if kind == "list_uvar":
        items = [uvar(int(item)) for item in value]
        return uvar(len(items)) + b"".join(sized(item) for item in items)
    if kind == "record_bool_uvar":
        fields = [(1, b"\x01"), (3, uvar(int(value["3"])))]
        return uvar(len(fields)) + b"".join(
            uvar(tag) + sized(item) for tag, item in fields
        )
    if kind == "map_uvar_text":
        entries = [
            (uvar(int(key)), sized(str(text).encode("utf-8"))) for key, text in value
        ]
        return uvar(len(entries)) + b"".join(
            sized(key) + sized(item) for key, item in entries
        )
    if kind == "option_uvar":
        return b"\x00\x00" if value is None else b"\x01" + sized(uvar(int(value)))
    if kind == "union_bool":
        return (
            uvar(int(vector["tag"])) + b"\x01" + (b"\x01" if value is True else b"\x00")
        )
    if kind == "standalone_fixture_object":
        digest = str(vector["expected_digest_hex"])
        if digest != vector["expected_object_id"]:
            raise ValueError("fixture ObjectId differs from digest")
        return bytes.fromhex(str(vector["preimage_hex"]) + digest)
    raise ValueError(f"unknown fixture kind {kind}")


problems: list[str] = []
accepted_ids: set[str] = set()
for vector in ACCEPTED["vectors"]:
    vector_id = vector["id"]
    if vector_id in accepted_ids:
        problems.append(f"duplicate accepted ID {vector_id}")
    accepted_ids.add(vector_id)
    actual = encode(vector).hex()
    if actual != vector["expected_hex"]:
        problems.append(
            f"{vector_id}: expected {vector['expected_hex']}, computed {actual}"
        )

required_codes = {
    "SCB_MAGIC_INVALID",
    "SCB_VERSION_UNSUPPORTED",
    "SCB_CONTRACT_UNKNOWN",
    "SCB_EPOCH_MISMATCH",
    "SCB_DIGEST_MISMATCH",
    "SCB_FIELD_MISSING",
    "SCB_FIELD_UNKNOWN",
    "SCB_VARINT_NON_MINIMAL",
    "SCB_INTEGER_OVERFLOW",
    "SCB_BOOL_INVALID",
    "SCB_UTF8_INVALID",
    "SCB_LABEL_NOT_NFC",
    "SCB_FLOAT_NON_CANONICAL",
    "SCB_LENGTH_OVERFLOW",
    "SCB_FIELD_DUPLICATE",
    "SCB_FIELD_ORDER",
    "SCB_UNION_INVALID",
    "SCB_MAP_ORDER",
    "SCB_MAP_DUPLICATE",
    "SCB_TRAILING_BYTES",
    "SCB_EXTENSION_UNKNOWN",
    "SCB_RESOURCE_LIMIT",
}
rejected_ids = [vector["id"] for vector in REJECTED["vectors"]]
if len(rejected_ids) != len(set(rejected_ids)):
    problems.append("duplicate rejected vector ID")
observed_codes = {vector["expected_code"] for vector in REJECTED["vectors"]}
if not required_codes.issubset(observed_codes):
    problems.append(
        f"missing rejection codes: {sorted(required_codes - observed_codes)}"
    )

expected_sums = {
    fields[1]: fields[0]
    for line in SUMS.read_text().splitlines()
    if (fields := line.split())
}
for filename in ("accepted.json", "rejected.json"):
    path = ROOT / "conformance/scb1/v1" / filename
    actual_sum = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected_sums.get(filename) != actual_sum:
        problems.append(f"fixture digest mismatch for {filename}")

normalized_spec = " ".join(SPEC.replace("`", "").split())
required_spec_markers = [
    "digest is outside its own preimage",
    "Unicode Normalization Forms version 16.0.0",
    "67,108,864",
    "SCB_VARINT_NON_MINIMAL",
    "Unknown extension tuples are rejected",
    "Neither implementation may derive expected bytes from the other",
]
for marker in required_spec_markers:
    if marker not in normalized_spec:
        problems.append(f"missing normative marker: {marker}")

if problems:
    print(
        json.dumps(
            {"contract": "s20-100-check-v1", "result": "FAIL", "problems": problems},
            indent=2,
        )
    )
    raise SystemExit(1)

print(
    json.dumps(
        {
            "contract": "s20-100-check-v1",
            "result": "PASS",
            "accepted_vectors": len(ACCEPTED["vectors"]),
            "rejected_vectors": len(REJECTED["vectors"]),
            "rejection_codes": len(observed_codes),
            "codec_implemented": False,
            "oracle_implemented": (ROOT / "oracle/scb1/pyproject.toml").is_file(),
        },
        sort_keys=True,
    )
)
