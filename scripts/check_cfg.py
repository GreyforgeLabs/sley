#!/usr/bin/env python3
"""Check the frozen S20-220 CFG/value-use validation surface."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/CFG_VALIDATION_V1.md"
MODEL = ROOT / "crates/sley-ssmc/src/lib.rs"
CHECKER = ROOT / "crates/sley-check/src/cfg.rs"
CHECKER_ROOT = ROOT / "crates/sley-check/src/lib.rs"

SPEC_MARKERS = (
    "Status: S20-220 normative specification.",
    "operation operands in block/ordinal order",
    "terminators and switch-key/payload judgment",
    "`CFG_UNREACHABLE_VALUE`",
    "does not reinterpret the 55 opcode semantic signatures",
    "no opcode, effect, contract, fingerprint, VM",
)
MODEL_MARKERS = (
    "pub enum ValueRef",
    "pub enum Opcode",
    "pub enum Terminator",
    "pub struct FunctionGraph",
    "#![forbid(unsafe_code)]",
)
CHECKER_MARKERS = (
    "pub fn validate_function_graph",
    "fn compute_reachability",
    "fn compute_dominators",
    "fn validate_values_and_terminators",
    "operation_use_failures_precede_all_terminator_failures",
    "seeded_unresolved_reference_fuzz_smoke_never_accepts",
)
CHECKER_ROOT_MARKERS = (
    "pub mod cfg;",
    "#![forbid(unsafe_code)]",
)
LIMITS = {
    "MAX_CFG_BLOCKS": "4_096",
    "MAX_CFG_EDGES": "16_384",
    "MAX_CFG_OPERATIONS": "1_000_000",
    "MAX_CFG_VALUES": "1_000_000",
    "MAX_CFG_USES": "262_144",
}
FORBIDDEN_SOURCE_MARKERS = (
    "use std::fs",
    "std::net",
    "std::process",
    "Command::",
    "SystemTime",
)


def enum_body(source: str, name: str) -> str:
    prefix = f"pub enum {name} {{"
    if prefix not in source:
        return ""
    return source.split(prefix, 1)[1].split("\n}", 1)[0]


def main() -> int:
    problems: list[str] = []
    for path in (SPEC, MODEL, CHECKER, CHECKER_ROOT):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")
    spec = SPEC.read_text() if SPEC.is_file() else ""
    model = MODEL.read_text() if MODEL.is_file() else ""
    checker = CHECKER.read_text() if CHECKER.is_file() else ""
    checker_root = CHECKER_ROOT.read_text() if CHECKER_ROOT.is_file() else ""

    for marker in SPEC_MARKERS:
        if marker not in spec:
            problems.append(f"spec-marker:{marker}")
    for marker in MODEL_MARKERS:
        if marker not in model:
            problems.append(f"model-marker:{marker}")
    for marker in CHECKER_MARKERS:
        if marker not in checker:
            problems.append(f"checker-marker:{marker}")
    for marker in CHECKER_ROOT_MARKERS:
        if marker not in checker_root:
            problems.append(f"checker-root-marker:{marker}")
    for marker in FORBIDDEN_SOURCE_MARKERS:
        if marker in model or marker in checker or marker in checker_root:
            problems.append(f"forbidden-source-marker:{marker}")
    for name, value in LIMITS.items():
        declaration = f"pub const {name}: usize = {value};"
        if declaration not in checker:
            problems.append(f"limit:{declaration}")
    if "pub const MAX_DOMINATOR_WORD_OPERATIONS: u64 = 50_000_000;" not in checker:
        problems.append("limit:MAX_DOMINATOR_WORD_OPERATIONS")
    if "for _round in 0..MAX_CFG_BLOCKS" not in checker:
        problems.append("limit:dominance-rounds-not-bound-by-MAX_CFG_BLOCKS")

    opcode_variants = re.findall(
        r"^    ([A-Z][A-Za-z0-9]+),$", enum_body(model, "Opcode"), re.MULTILINE
    )
    terminator_variants = re.findall(
        r"^    ([A-Z][A-Za-z0-9]+)\([^\n]+\),$",
        enum_body(model, "Terminator"),
        re.MULTILINE,
    )
    cfg_codes = [
        int(value.replace("_", ""))
        for value in re.findall(r"Self::[A-Za-z0-9]+ => (22_\d{3}),", checker)
    ]
    if len(opcode_variants) != 55 or len(set(opcode_variants)) != 55:
        problems.append(f"opcodes:{len(opcode_variants)}!=55")
    if len(terminator_variants) != 5 or len(set(terminator_variants)) != 5:
        problems.append(f"terminators:{len(terminator_variants)}!=5")
    if cfg_codes != list(range(22_000, 22_021)):
        problems.append(f"cfg-codes:{cfg_codes}")
    compact_spec = spec.replace(",", "").replace("_", "")
    for number in range(22_000, 22_021):
        if str(number) not in compact_spec:
            problems.append(f"numeric-error:{number}")
    cfg_unit_tests = checker.count("#[test]")
    if cfg_unit_tests < 23:
        problems.append(f"cfg-unit-tests:{cfg_unit_tests}<23")

    print(
        json.dumps(
            {
                "cfg_error_codes": len(cfg_codes),
                "cfg_unit_tests": cfg_unit_tests,
                "contract": "s20-220-cfg-validation-v1",
                "implementation": ["crates/sley-ssmc", "crates/sley-check"],
                "opcodes": len(opcode_variants),
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
                "terminators": len(terminator_variants),
                "vulcan_review": "PASS_AFTER_VALIDATION_PRECEDENCE_FIX",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
