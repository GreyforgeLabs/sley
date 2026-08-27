#!/usr/bin/env python3
"""Independently reproduce the S20-170 pack ID and digest tree."""

from __future__ import annotations

import json
from pathlib import Path

import blake3


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "conformance/repository-pack/v1/accepted.json"
PACK_DOMAIN = b"sley2.repository-pack.v1"
EPOCH_DOMAIN = b"sley2.schema-epoch.v1"
ROOT_DOMAIN = b"sley2.state-root.v1"
OBJECT_DOMAIN = b"sley2.object.v1"
LEAF_DOMAIN = b"sley2.repository-pack-leaf.v1"
NODE_DOMAIN = b"sley2.repository-pack-node.v1"


class DecodeError(ValueError):
    """Strict vector decode failure."""


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        end = self.offset + count
        if end > len(self.data):
            raise DecodeError("truncated")
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def uvar(self) -> int:
        value = 0
        start = self.offset
        for shift in range(0, 70, 7):
            byte = self.take(1)[0]
            if shift == 63 and byte > 1:
                raise DecodeError("overflow")
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                if self.data[start:self.offset] != encode_uvar(value):
                    raise DecodeError("nonminimal")
                return value
        raise DecodeError("overflow")

    def sized(self) -> bytes:
        return self.take(self.uvar())

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise DecodeError("trailing")


def encode_uvar(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def decode_record(data: bytes) -> dict[int, bytes]:
    reader = Reader(data)
    count = reader.uvar()
    fields: dict[int, bytes] = {}
    previous = 0
    for _ in range(count):
        tag = reader.uvar()
        if tag <= previous:
            raise DecodeError("field-order")
        fields[tag] = reader.sized()
        previous = tag
    reader.finish()
    return fields


def decode_list(data: bytes) -> list[bytes]:
    reader = Reader(data)
    values = [reader.sized() for _ in range(reader.uvar())]
    reader.finish()
    return values


def one_uvar(data: bytes) -> int:
    reader = Reader(data)
    value = reader.uvar()
    reader.finish()
    return value


def digest(domain: bytes, preimage: bytes) -> bytes:
    return blake3.blake3(domain + preimage).digest()


def leaf(section: int, identifier: bytes, stored: bytes) -> bytes:
    preimage = encode_uvar(section) + identifier + encode_uvar(len(stored)) + stored
    return digest(LEAF_DOMAIN, preimage)


def merkle(leaves: list[bytes]) -> bytes:
    level = leaves
    while len(level) > 1:
        next_level: list[bytes] = []
        for index in range(0, len(level), 2):
            if index + 1 == len(level):
                next_level.append(level[index])
            else:
                next_level.append(digest(NODE_DOMAIN, level[index] + level[index + 1]))
        level = next_level
    return level[0]


def main() -> int:
    fixture = json.loads(VECTOR.read_text())
    stored = bytes.fromhex(fixture["stored_hex"])
    reader = Reader(stored)
    if reader.take(8) != b"SLEYSCB1" or reader.uvar() != 1 or reader.uvar() != 170:
        raise DecodeError("envelope")
    pack_epoch = reader.take(32)
    payload = reader.sized()
    trailer = reader.take(32)
    reader.finish()
    preimage = stored[:-32]
    pack_id = digest(PACK_DOMAIN, preimage)
    if trailer != pack_id:
        raise DecodeError("pack-digest")

    fields = decode_record(payload)
    if set(fields) != set(range(1, 10)) or one_uvar(fields[1]) != 1:
        raise DecodeError("payload")
    entries: list[tuple[int, bytes, bytes]] = []
    for section, tag, identity_domain in (
        (1, 2, EPOCH_DOMAIN),
        (2, 3, ROOT_DOMAIN),
        (3, 5, OBJECT_DOMAIN),
    ):
        for encoded in decode_list(fields[tag]):
            entry = decode_record(encoded)
            identifier = entry[1]
            stored_entry = entry[2] if section != 3 else entry[3]
            if len(identifier) != 32:
                raise DecodeError("identifier")
            identity_preimage = stored_entry if section == 1 else stored_entry[:-32]
            if digest(identity_domain, identity_preimage) != identifier:
                raise DecodeError("content-id")
            if section == 3 and one_uvar(entry[2]) != len(stored_entry):
                raise DecodeError("object-length")
            entries.append((section, identifier, stored_entry))

    if pack_epoch not in {identifier for section, identifier, _ in entries if section == 1}:
        raise DecodeError("pack-epoch")
    leaves = [leaf(*entry) for entry in entries]
    tree = decode_record(fields[8])
    stored_leaves = decode_list(tree[3])
    tree_root = merkle(leaves)
    if one_uvar(tree[1]) != 1 or one_uvar(tree[2]) != len(leaves):
        raise DecodeError("tree-header")
    if stored_leaves != leaves or tree[4] != tree_root:
        raise DecodeError("tree")

    checks = {
        "stored_bytes": len(stored),
        "repository_pack_id": pack_id.hex(),
        "digest_tree_root": tree_root.hex(),
        "leaf_count": len(leaves),
    }
    problems = [key for key, value in checks.items() if fixture.get(key) != value]
    print(
        json.dumps(
            {
                "contract": "s20-170-repository-pack-v1",
                "independent_checks": checks,
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
