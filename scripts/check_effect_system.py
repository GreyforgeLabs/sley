#!/usr/bin/env python3
"""Check the frozen S20-230 static effect-system surface."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/EFFECT_SYSTEM_V1.md"
MODEL = ROOT / "crates/sley-ssmc/src/lib.rs"
CHECKER_ROOT = ROOT / "crates/sley-check/src/lib.rs"
CHECKER = ROOT / "crates/sley-check/src/effects.rs"

SPEC_MARKERS = (
    "Status: S20-230 normative specification.",
    "exactly one `EffectDef`",
    "least fixed point",
    "recursive call-only SCC cannot self-justify",
    "that earlier exact `GRAPH_INVENTORY_MISMATCH`",
    "does not issue or authenticate capability tokens",
)
MODEL_MARKERS = (
    "pub enum EffectKind",
    "pub struct EffectDefinition",
    "pub struct CapabilityRequirement",
    "pub struct AdapterImport",
    "#![forbid(unsafe_code)]",
)
CHECKER_ROOT_MARKERS = ("pub mod effects;", "#![forbid(unsafe_code)]")
CHECKER_MARKERS = (
    "pub fn validate_effect_program",
    "fn compute_closures",
    "fn compare_const_values",
    "recursive_cycle_cannot_self_justify_unused_effect",
    "noncanonical_function_effect_set_preserves_cfg_inventory_failure",
    "seeded_unresolved_call_smoke_never_accepts_or_panics",
)
USIZE_LIMITS = {
    "MAX_EFFECT_FUNCTIONS": "4_096",
    "MAX_EFFECT_DEFINITIONS": "4_096",
    "MAX_CAPABILITY_REQUIREMENTS": "4_096",
    "MAX_ADAPTER_IMPORTS": "4_096",
    "MAX_EFFECT_CALL_EDGES": "16_384",
    "MAX_EFFECT_CLOSURE_MEMBERSHIPS": "1_000_000",
    "MAX_EFFECT_CLOSURE_ROUNDS": "4_096",
}
U64_LIMITS = {
    "MAX_EFFECT_DOMINATOR_WORK": "50_000_000",
    "MAX_EFFECT_CLOSURE_WORK": "50_000_000",
}
FORBIDDEN_SOURCE_MARKERS = (
    "use std::fs",
    "std::net",
    "std::process",
    "Command::",
    "SystemTime",
)


def main() -> int:
    problems: list[str] = []
    for path in (SPEC, MODEL, CHECKER_ROOT, CHECKER):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")
    spec = SPEC.read_text() if SPEC.is_file() else ""
    model = MODEL.read_text() if MODEL.is_file() else ""
    checker_root = CHECKER_ROOT.read_text() if CHECKER_ROOT.is_file() else ""
    checker = CHECKER.read_text() if CHECKER.is_file() else ""

    for marker in SPEC_MARKERS:
        if marker not in spec:
            problems.append(f"spec-marker:{marker}")
    for marker in MODEL_MARKERS:
        if marker not in model:
            problems.append(f"model-marker:{marker}")
    for marker in CHECKER_ROOT_MARKERS:
        if marker not in checker_root:
            problems.append(f"checker-root-marker:{marker}")
    for marker in CHECKER_MARKERS:
        if marker not in checker:
            problems.append(f"checker-marker:{marker}")
    for marker in FORBIDDEN_SOURCE_MARKERS:
        if marker in model or marker in checker_root or marker in checker:
            problems.append(f"forbidden-source-marker:{marker}")
    for name, value in USIZE_LIMITS.items():
        declaration = f"pub const {name}: usize = {value};"
        if declaration not in checker:
            problems.append(f"limit:{declaration}")
    for name, value in U64_LIMITS.items():
        declaration = f"pub const {name}: u64 = {value};"
        if declaration not in checker:
            problems.append(f"limit:{declaration}")

    effect_codes = [
        int(value.replace("_", ""))
        for value in re.findall(r"Self::[A-Za-z0-9]+ => (23_\d{3}),", checker)
    ]
    if effect_codes != list(range(23_000, 23_014)):
        problems.append(f"effect-codes:{effect_codes}")
    compact_spec = spec.replace(",", "").replace("_", "")
    for number in range(23_000, 23_014):
        if str(number) not in compact_spec:
            problems.append(f"numeric-error:{number}")

    effect_kind_tags = [
        int(value)
        for value in re.findall(
            r"Self::(?:StdoutWrite|StderrWrite|FileRead|FileWrite|ClockRead|RandomRead|EnvironmentRead|AdapterCall) => (\d),",
            model,
        )
    ]
    if effect_kind_tags != list(range(1, 9)):
        problems.append(f"effect-kind-tags:{effect_kind_tags}")
    effect_unit_tests = checker.count("#[test]")
    if effect_unit_tests < 16:
        problems.append(f"effect-unit-tests:{effect_unit_tests}<16")

    print(
        json.dumps(
            {
                "ariadne_review": "PASS_AFTER_CONSTANT_ORDER_AND_ERROR_MAPPING_FIX",
                "contract": "s20-230-effect-system-v1",
                "effect_error_codes": len(effect_codes),
                "effect_kinds": len(effect_kind_tags),
                "effect_unit_tests": effect_unit_tests,
                "implementation": ["crates/sley-ssmc", "crates/sley-check"],
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
                "vulcan_review": "PASS_AFTER_CFG_PRECEDENCE_REGRESSION",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
