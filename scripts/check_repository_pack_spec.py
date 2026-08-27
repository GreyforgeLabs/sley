#!/usr/bin/env python3
"""Check the frozen S20-170 repository-pack contract surface."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/REPOSITORY_PACK_V1.md"
SOURCE = ROOT / "crates/sley-repo/src/lib.rs"
VECTOR = ROOT / "conformance/repository-pack/v1/accepted.json"

SPEC_MARKERS = (
    'contract_domain   = "sley2.repository-pack.v1"',
    "contract_tag      = 170",
    "digest_domain_tag = 18",
    "PACK_DIGEST_TREE_MISMATCH",
    "67,108,864",
    "S20-540 later owns",
    "no filesystem paths, Git facts",
)
SOURCE_MARKERS = (
    "pub fn export_conformance_pack",
    "pub fn import_conformance_pack",
    "RepositoryPackId::derive(&preimage)",
    "fn verify_digest_tree",
    "fn validate_dependency_closure",
    "fn preflight_object",
    "COMPRESSION_NONE",
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
    expected = {
        "contract_tag": 170,
        "digest_domain_tag": 18,
        "field_schema_hash": (
            "7231a31c5d9cc159ce9d161ecc434c4b98613f97a00e07fd0728c45128f94e21"
        ),
        "decoder_limits_hash": (
            "38a807922870bae9aca1bbd0afb8d87f2511c876bc087ce1616cbb7c7cc95e00"
        ),
        "stored_bytes": 1421,
        "repository_pack_id": (
            "7a1e139c74191a46cbf03275dcb4ae4e4625765d6d6ee412076628d49d867df8"
        ),
        "digest_tree_root": (
            "1c0ee93f9eaf275808b7f50086ccb2f7aebd8eb61bcf2ad3896f642c34fa13d9"
        ),
    }
    for key, value in expected.items():
        if vector.get(key) != value:
            problems.append(f"fixture:{key}")
    unit_tests = source.count("#[test]")
    if unit_tests < 16:
        problems.append(f"unit-tests:{unit_tests}<16")
    print(
        json.dumps(
            {
                "contract": "s20-170-repository-pack-v1",
                "implementation": "crates/sley-repo",
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
