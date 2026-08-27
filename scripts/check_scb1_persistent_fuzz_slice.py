#!/usr/bin/env python3
"""Drift check for the bounded S20-700 SCB1 persistent fuzz slice."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/scb1_decoder.rs"
WRAPPER = ROOT / "scripts/run_scb1_persistent_fuzz.py"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
MAKEFILE = ROOT / "Makefile"

problems: list[str] = []

target = TARGET.read_text()
for marker in [
    "LLVMFuzzerTestOneInput",
    "decode_standalone_fixture(payload, contract)",
    "encode_standalone_fixture(decoded.contract, &decoded.payload)",
    "encoded, payload",
    "assert_eq!(object_id, decoded.object_id",
    "Schema::NestedListFixture",
    "FixtureContract::RequiredBool",
]:
    if marker not in target:
        problems.append(f"target-missing:{marker}")

wrapper = WRAPPER.read_text()
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    "conformance/scb1/v1",
    "SELECTOR_COUNT = 18",
    "\"full_s20_700_complete\": False",
    "\"SCB1_DECODER_ONLY\"",
]:
    if marker not in wrapper:
        problems.append(f"wrapper-missing:{marker}")

makefile = MAKEFILE.read_text()
for marker in [
    "scb1-persistent-fuzz-smoke:",
    "python3 scripts/check_scb1_persistent_fuzz_slice.py",
    "python3 scripts/run_scb1_persistent_fuzz.py",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

summary = json.loads(MACHINE_SUMMARY.read_text())
slice_status = summary.get("s20_700_scb1_persistent_fuzz_slice", {})
if slice_status.get("persistent_fuzz_harness") is not True:
    problems.append("machine-summary-persistent-harness-not-true")
if slice_status.get("full_s20_700_complete") is not False:
    problems.append("machine-summary-full-s20-700-not-false")
if slice_status.get("selector_count") != 18:
    problems.append("machine-summary-selector-count-drift")

for path, marker in [
    (RESULTS, "SCB1 decoder persistent libFuzzer slice"),
    (RESULTS, "not complete S20-700"),
    (GAPS, "remaining persistent targets are still absent"),
]:
    if marker not in path.read_text():
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-scb1-persistent-libfuzzer-slice-v1",
            "result": "PASS",
            "scope": "SCB1_DECODER_ONLY",
            "full_s20_700_complete": False,
        },
        indent=2,
        sort_keys=True,
    )
)
