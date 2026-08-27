#!/usr/bin/env python3
"""Check the bounded, explicitly incomplete S20-700 schema fuzz slice."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "crates/sley-schema/src/lib.rs").read_text(encoding="utf-8")
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
M1_GATE = (ROOT / "scripts/check_m1_gate.py").read_text(encoding="utf-8")
SUMMARY = json.loads((ROOT / "machineresearch/sley-2.0/machine-summary.json").read_text())

required_source = [
    "fn bounded_schema_bootstrap_import_fuzz_smoke()",
    "const CASES: usize = 512;",
    "const MAX_INPUT_BYTES: usize = 2_048;",
    "fn registry_decode_never_falls_back_across_epoch_or_contract()",
    "SchemaErrorCode::EpochMismatch",
    "SchemaErrorCode::ContractUnknown",
    "ScbErrorCode::BoolInvalid",
]
problems = [f"missing-source-marker:{marker}" for marker in required_source if marker not in SOURCE]
if "cargo test -p sley-schema bounded_schema_bootstrap_import_fuzz_smoke --locked" not in MAKEFILE:
    problems.append("schema-fuzz-smoke-not-wired")
if "512 bounded deterministic schema bootstrap decoder/import inputs" not in M1_GATE:
    problems.append("fuzz-smoke-scope-not-recorded")

status = SUMMARY.get("adversarial", {})
if status.get("status") != "S20_700_BOUNDED_SLICES":
    problems.append("machine-summary-status")
if status.get("full_s20_700_complete") is not False:
    problems.append("machine-summary-overstates-completion")
if status.get("persistent_fuzz_harness") is not False:
    problems.append("machine-summary-overstates-persistence")
if status.get("vulcan_schema_review") != "PASS_NO_OPEN_P0_P1_P2":
    problems.append("machine-summary-vulcan-review")

print(
    json.dumps(
        {
            "adversarial_exact_selection_test": True,
            "bounded_inputs": 512,
            "contract": "s20-700-bounded-schema-fuzz-slice-v1",
            "full_s20_700_complete": False,
            "max_input_bytes": 2_048,
            "persistent_fuzz_harness": False,
            "problems": problems,
            "result": "PASS" if not problems else "FAIL",
            "surface": "SLEYEP01 bootstrap import and exact registry decoder selection",
        },
        indent=2,
        sort_keys=True,
    )
)
raise SystemExit(int(bool(problems)))
