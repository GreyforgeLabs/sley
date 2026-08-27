#!/usr/bin/env python3
"""Check the frozen S20-200/S20-210 type-system surface."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/TYPE_SYSTEM_V1.md"
MANIFEST = ROOT / "docs/spec/SSMC1_EPOCH1_SCHEMA.txt"
MODEL = ROOT / "crates/sley-ssmc/src/lib.rs"
CHECKER = ROOT / "crates/sley-check/src/lib.rs"

SPEC_MARKERS = (
    "Status: S20-210 normative specification.",
    "`OrderedMap<TypeParameter(_),V>` is rejected",
    "`TYPE_DEFINITION_CYCLE`",
    "`TYPE_FLOAT_NON_CANONICAL`",
    "no CFG, effect, contract, fingerprint, lowering, VM",
)
MODEL_MARKERS = (
    "pub enum TypeExpr",
    "pub const fn tag(&self) -> u32",
    "pub enum ConstData",
    "pub struct TypeDefinition",
    "#![forbid(unsafe_code)]",
)
CHECKER_MARKERS = (
    "pub struct TypeEnvironment",
    "pub fn check_type",
    "pub fn instantiate",
    "pub fn traits",
    "pub fn check_constant",
    "fn reject_definition_cycles",
    "generic_map_key_without_trait_bounds_fails_closed",
    "TYPE_IMPLICIT_COERCION",
    "#![forbid(unsafe_code)]",
)
FORBIDDEN_SOURCE_MARKERS = (
    "use std::fs",
    "std::net",
    "std::process",
    "Command::",
    "SystemTime",
)


def main() -> int:
    problems: list[str] = []
    for path in (SPEC, MANIFEST, MODEL, CHECKER):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")
    spec = SPEC.read_text() if SPEC.is_file() else ""
    manifest = MANIFEST.read_text() if MANIFEST.is_file() else ""
    model = MODEL.read_text() if MODEL.is_file() else ""
    checker = CHECKER.read_text() if CHECKER.is_file() else ""

    for marker in SPEC_MARKERS:
        if marker not in spec:
            problems.append(f"spec-marker:{marker}")
    for marker in MODEL_MARKERS:
        if marker not in model:
            problems.append(f"model-marker:{marker}")
    for marker in CHECKER_MARKERS:
        if marker not in checker:
            problems.append(f"checker-marker:{marker}")
    for marker in FORBIDDEN_SOURCE_MARKERS:
        if marker in model or marker in checker:
            problems.append(f"forbidden-source-marker:{marker}")

    type_tags = [
        int(match.group(1))
        for line in manifest.splitlines()
        if (match := re.fullmatch(r"type (\d+) \S+ .+", line))
    ]
    if type_tags != list(range(1, 21)):
        problems.append(f"type-tags:{type_tags}")
    compact_spec = spec.replace(",", "").replace("_", "")
    for number in range(21_000, 21_021):
        if str(number) not in compact_spec:
            problems.append(f"numeric-error:{number}")
    unit_tests = model.count("#[test]") + checker.count("#[test]")
    if unit_tests < 29:
        problems.append(f"unit-tests:{unit_tests}<29")

    print(
        json.dumps(
            {
                "contract": "s20-210-core-type-system-v1",
                "implementation": ["crates/sley-ssmc", "crates/sley-check"],
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
                "rust_unit_tests": unit_tests,
                "type_tags": len(type_tags),
                "vulcan_review": "PASS_AFTER_GENERIC_MAP_KEY_FIX",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
