#!/usr/bin/env python3
"""Check the S20-160 StateRoot contract, fixture, and implementation surface."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/STATE_ROOT_V1.md"
SOURCE = ROOT / "crates/sley-state-root/src/lib.rs"
VECTOR = ROOT / "conformance/state-root/v1/accepted.json"

SPEC_MARKERS = (
    'contract_domain   = "sley2.state-root.v1"',
    "contract_tag      = 160",
    "STATE_ROOT_DUPLICATE_INPUT",
    "The all-zero epoch is not registered",
    "requires a nonzero registered",
)
SOURCE_MARKERS = (
    "pub struct StateRootBuilder",
    "pub fn import_state_root",
    "SchemaEpochRegistry<StateRootEpoch1Decoder>",
    "registry.lookup_contract(epoch_id, CONTRACT_TAG)",
    "registry.decode_contract(epoch_id, CONTRACT_TAG, payload)",
    "StateRoot::derive(&preimage)",
    "FIELD_SCHEMA_HASH",
    "DECODER_LIMITS_HASH",
)


def main() -> int:
    problems: list[str] = []
    for path in (SPEC, SOURCE, VECTOR):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")
    spec = SPEC.read_text() if SPEC.is_file() else ""
    source = SOURCE.read_text() if SOURCE.is_file() else ""
    vector = json.loads(VECTOR.read_text()) if VECTOR.is_file() else {}
    for marker in SPEC_MARKERS:
        if marker not in spec:
            problems.append(f"spec-marker:{marker}")
    for marker in SOURCE_MARKERS:
        if marker not in source:
            problems.append(f"source-marker:{marker}")
    if vector.get("state_root") != (
        "d3914cbffcde449959d6a35eddb16293c3424f4980e64e687a4f47358ad2770a"
    ):
        problems.append("fixture:state_root")
    if VECTOR.is_file() and hashlib.sha256(VECTOR.read_bytes()).hexdigest() != (
        "848044e1f6e51d38368bda3bbcc95a8e04f6ad22928e49fd35f9ef772b3ba832"
    ):
        problems.append("fixture:sha256")
    if "ObjectId::derive(" in source:
        problems.append("source:object-domain-reuse")
    unit_tests = source.count("#[test]")
    if unit_tests < 12:
        problems.append(f"unit-tests:{unit_tests}<12")
    print(
        json.dumps(
            {
                "contract": "s20-160-state-root-v1",
                "implementation": "crates/sley-state-root",
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
                "rust_unit_tests": unit_tests,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
