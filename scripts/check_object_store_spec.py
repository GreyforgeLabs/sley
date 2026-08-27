#!/usr/bin/env python3
"""Check the frozen S20-150 object-store contract and implementation surface."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/OBJECT_STORE_V1.md"
ERRORS = ROOT / "docs/spec/ERROR_CODES_V1.md"
SOURCE = ROOT / "crates/sley-store/src/lib.rs"

SPEC_MARKERS = (
    'BLAKE3-256("sley2.object.v1" || canonical_object_envelope_preimage)',
    "objects/scb1/<hex[0..2]>/<hex[2..4]>/<64-hex-object-id>.scb1",
    "Absent -> Staged -> Verified -> Promoted",
    "STORE_OBJECT_SUBSTITUTION",
    "RECOVERY_STAGED_OBJECT",
    "Recovery is an exclusive startup operation.",
    "T03, T04, and T37",
)
SOURCE_MARKERS = (
    "pub trait CanonicalVerifier",
    "fs::hard_link",
    "create_new(true)",
    "reserve_stage_file",
    "sync_dir(parent)",
    "fs::symlink_metadata",
    'code: "RECOVERY_STAGED_OBJECT"',
    "StoreObjectSubstitution",
)


def main() -> int:
    problems: list[str] = []
    for path in (SPEC, ERRORS, SOURCE):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")

    spec = SPEC.read_text() if SPEC.is_file() else ""
    errors = ERRORS.read_text() if ERRORS.is_file() else ""
    source = SOURCE.read_text() if SOURCE.is_file() else ""

    for marker in SPEC_MARKERS:
        if marker not in spec:
            problems.append(f"spec-marker:{marker}")
    if "`STORE_*`" not in errors:
        problems.append("error-namespace:STORE_*")
    for marker in SOURCE_MARKERS:
        if marker not in source:
            problems.append(f"source-marker:{marker}")

    unit_tests = source.count("#[test]")
    if unit_tests < 21:
        problems.append(f"unit-tests:{unit_tests}<21")

    result = {
        "contract": "s20-150-object-store-v1",
        "implementation": "crates/sley-store",
        "problems": problems,
        "result": "PASS" if not problems else "FAIL",
        "rust_unit_tests": unit_tests,
        "threats": ["T03", "T04", "T37"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
