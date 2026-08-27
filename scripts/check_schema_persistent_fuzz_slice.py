#!/usr/bin/env python3
"""Drift check for the scoped S20-700 schema bootstrap persistent fuzz slice."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/schema_bootstrap_decoder.rs"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
WRAPPER = ROOT / "scripts/run_schema_persistent_fuzz.py"
FIXTURE = ROOT / "conformance/schema-epoch/v1/bootstrap.json"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
AUDIT = ROOT / "docs/audits/S20_700_SCHEMA_FUZZ_SLICE.md"
MAKEFILE = ROOT / "Makefile"

problems: list[str] = []

target = TARGET.read_text()
for marker in [
    "LLVMFuzzerTestOneInput",
    "import_bootstrap_preimage(input)",
    ".canonical_bytes()",
    "bootstrap_preimage(&record_bytes)",
    "schema_epoch_id()",
    "schema bootstrap re-encoded differently",
    "schema epoch identity drifted",
    "MAX_FUZZ_INPUT_BYTES: usize = 2048",
]:
    if marker not in target:
        problems.append(f"target-missing:{marker}")

manifest = FUZZ_MANIFEST.read_text()
for marker in [
    'name = "schema_bootstrap_decoder"',
    'path = "targets/schema_bootstrap_decoder.rs"',
    'sley-schema = { path = "../crates/sley-schema" }',
]:
    if marker not in manifest:
        problems.append(f"fuzz-manifest-missing:{marker}")

wrapper = WRAPPER.read_text()
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    "conformance/schema-epoch/v1/bootstrap.json",
    '"full_s20_700_complete": False',
    '"SCHEMA_BOOTSTRAP_DECODER_ONLY"',
    'MAX_LEN = 2048',
    'EXPECTED_SEED_COUNT = 255',
    "output_tail(error.stdout)",
]:
    if marker not in wrapper:
        problems.append(f"wrapper-missing:{marker}")

fixture = json.loads(FIXTURE.read_text())
if fixture.get("contract") != "sley2-schema-epoch-bootstrap-v1":
    problems.append("fixture-contract-drift")
if not bytes.fromhex(fixture.get("preimage_hex", "")).startswith(b"SLEYEP01"):
    problems.append("fixture-bootstrap-magic-drift")

makefile = MAKEFILE.read_text()
for marker in [
    "schema-persistent-fuzz-smoke:",
    "python3 scripts/check_schema_persistent_fuzz_slice.py",
    "python3 scripts/run_schema_persistent_fuzz.py",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

summary = json.loads(MACHINE_SUMMARY.read_text())
slice_status = summary.get("s20_700_schema_persistent_fuzz_slice", {})
if slice_status.get("persistent_fuzz_harness") is not True:
    problems.append("machine-summary-persistent-harness-not-true")
if slice_status.get("full_s20_700_complete") is not False:
    problems.append("machine-summary-full-s20-700-not-false")
if slice_status.get("max_input_bytes") != 2048:
    problems.append("machine-summary-max-input-bytes-drift")
if slice_status.get("generated_seed_count") != 255:
    problems.append("machine-summary-generated-seed-count-drift")
if slice_status.get("seed_source") != "conformance/schema-epoch/v1/bootstrap.json":
    problems.append("machine-summary-seed-source-drift")
if slice_status.get("vulcan_review") != "DEFERRED_FORGE_OAUTH_401":
    problems.append("machine-summary-vulcan-review-drift")

for path, marker in [
    (RESULTS, "schema bootstrap persistent libFuzzer slice"),
    (RESULTS, "do not complete S20-700"),
    (GAPS, "remaining persistent targets are still absent"),
    (AUDIT, "make schema-persistent-fuzz-smoke"),
]:
    if marker not in path.read_text():
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-schema-bootstrap-persistent-libfuzzer-slice-v1",
            "result": "PASS",
            "scope": "SCHEMA_BOOTSTRAP_DECODER_ONLY",
            "full_s20_700_complete": False,
        },
        indent=2,
        sort_keys=True,
    )
)
