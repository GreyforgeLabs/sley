#!/usr/bin/env python3
"""Drift check for the scoped S20-700 repository-pack persistent fuzz slice."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/repository_pack_importer.rs"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
WRAPPER = ROOT / "scripts/run_pack_persistent_fuzz.py"
FIXTURE = ROOT / "conformance/repository-pack/v1/accepted.json"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
AUDIT = ROOT / "docs/audits/S20_700_PACK_IMPORT_PERSISTENT_SLICE.md"
MAKEFILE = ROOT / "Makefile"

problems: list[str] = []

target = TARGET.read_text(encoding="utf-8")
for marker in [
    "LLVMFuzzerTestOneInput",
    "import_conformance_pack(&store, candidate, &verify_fixture_object)",
    "with_rehashed_pack_trailer(payload)",
    "RepositoryPackId::derive(&candidate[..preimage_len])",
    'store.root().join("objects").exists()',
    "an accepted repository pack must import idempotently",
    "SELECTOR_COUNT: u8 = 2",
    "MAX_FUZZ_INPUT_BYTES: usize = 65_536",
]:
    if marker not in target:
        problems.append(f"target-missing:{marker}")

manifest = FUZZ_MANIFEST.read_text(encoding="utf-8")
for marker in [
    'name = "repository_pack_importer"',
    'path = "targets/repository_pack_importer.rs"',
    'sley-repo = { path = "../crates/sley-repo" }',
    'sley-store = { path = "../crates/sley-store" }',
]:
    if marker not in manifest:
        problems.append(f"fuzz-manifest-missing:{marker}")

wrapper = WRAPPER.read_text(encoding="utf-8")
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    "conformance/repository-pack/v1/accepted.json",
    '"full_s20_700_complete": False',
    '"REPOSITORY_PACK_IMPORTER_ONLY"',
    "MAX_PAYLOAD_LEN = 65_536",
    "SELECTOR_COUNT = 2",
    "output_tail(error.stdout)",
]:
    if marker not in wrapper:
        problems.append(f"wrapper-missing:{marker}")

fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
if fixture.get("contract") != "sley2-repository-pack-accepted-v1":
    problems.append("fixture-contract-drift")
stored = bytes.fromhex(fixture.get("stored_hex", ""))
if len(stored) != fixture.get("stored_bytes") or not stored.startswith(b"SLEYSCB1"):
    problems.append("fixture-stored-bytes-drift")

makefile = MAKEFILE.read_text(encoding="utf-8")
for marker in [
    "pack-persistent-fuzz-smoke:",
    "python3 scripts/check_pack_persistent_fuzz_slice.py",
    "python3 scripts/run_pack_persistent_fuzz.py",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

summary = json.loads(MACHINE_SUMMARY.read_text(encoding="utf-8"))
slice_status = summary.get("s20_700_pack_persistent_fuzz_slice", {})
if slice_status.get("persistent_fuzz_harness") is not True:
    problems.append("machine-summary-persistent-harness-not-true")
if slice_status.get("full_s20_700_complete") is not False:
    problems.append("machine-summary-full-s20-700-not-false")
if slice_status.get("selector_count") != 2:
    problems.append("machine-summary-selector-count-drift")
if slice_status.get("generated_seed_count") != 320:
    problems.append("machine-summary-generated-seed-count-drift")
if slice_status.get("seed_source") != "conformance/repository-pack/v1/accepted.json":
    problems.append("machine-summary-seed-source-drift")
if slice_status.get("vulcan_review") != "DEFERRED_FORGE_OAUTH_401":
    problems.append("machine-summary-vulcan-review-drift")

for path, marker in [
    (RESULTS, "Repository-pack importer persistent libFuzzer slice"),
    (RESULTS, "do not complete S20-700"),
    (GAPS, "importer persistent libFuzzer slices now exist"),
    (AUDIT, "make pack-persistent-fuzz-smoke"),
]:
    if marker not in path.read_text(encoding="utf-8"):
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-pack-import-persistent-libfuzzer-slice-v1",
            "result": "PASS",
            "scope": "REPOSITORY_PACK_IMPORTER_ONLY",
            "full_s20_700_complete": False,
        },
        indent=2,
        sort_keys=True,
    )
)
