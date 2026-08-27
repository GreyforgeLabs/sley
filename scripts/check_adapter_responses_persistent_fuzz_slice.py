#!/usr/bin/env python3
"""Drift check for the scoped S20-700 adapter-response persistent target."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/adapter_responses.rs"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
RUNNER = ROOT / "scripts/run_adapter_responses_persistent_fuzz.py"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
AUDIT = ROOT / "docs/audits/S20_700_ADAPTER_RESPONSES_PERSISTENT_SLICE.md"
MAKEFILE = ROOT / "Makefile"
M1_GATE = ROOT / "scripts/check_m1_gate.py"

problems: list[str] = []

target = TARGET.read_text(encoding="utf-8")
for marker in [
    "LLVMFuzzerTestOneInput",
    "invoke_reference_adapter(",
    "state_id(",
    "adapter response judgment was not deterministic",
    "a rejected adapter response mutated fixture state",
    "generic replay did not preserve the stored adapter response",
    "adapter transcript did not bind StateRoot",
    "KIND_COUNT: u8 = 8",
    "RESPONSE_SCHEMA_COUNT: u8 = 6",
    "MUTATION_COUNT: u8 = 26",
    "MAX_MUTATIONS: usize = 4",
    "MAX_FUZZ_INPUT_BYTES: usize = 4096",
    "MAX_PAYLOAD_BYTES: usize = 32",
    "MAX_COLLECTION_ITEMS: usize = 4",
]:
    if marker not in target:
        problems.append(f"target-missing:{marker}")
for forbidden in [
    "invoke_authorized_reference_adapter",
    "decode_adapter",
    "std::fs",
    "std::env",
    "std::process",
    "std::net",
]:
    if forbidden in target:
        problems.append(f"out-of-scope-adapter-surface:{forbidden}")

manifest = FUZZ_MANIFEST.read_text(encoding="utf-8")
for marker in [
    'name = "adapter_responses"',
    'path = "targets/adapter_responses.rs"',
    'sley-adapter = { path = "../crates/sley-adapter" }',
]:
    if marker not in manifest:
        problems.append(f"fuzz-manifest-missing:{marker}")

runner = RUNNER.read_text(encoding="utf-8")
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    '"RESTRICTED_TYPED_S20_280_ADAPTER_RESPONSES_ONLY"',
    '"full_s20_280_complete": False',
    '"serialized_adapter_decoder_claimed": False',
    '"live_host_access": False',
    '"authorized_adapter_path_covered": False',
    '"source_commit": git_output(["git", "rev-parse", "HEAD"])',
    '"worktree_dirty": bool(git_output(["git", "status", "--porcelain"]))',
    "range(256)",
    "range(KIND_COUNT)",
    "range(RESPONSE_SCHEMA_COUNT)",
    "range(MUTATION_CLASS_COUNT)",
    "output_tail(error.stdout)",
]:
    if marker not in runner:
        problems.append(f"runner-missing:{marker}")

makefile = MAKEFILE.read_text(encoding="utf-8")
for marker in [
    "adapter-responses-persistent-fuzz-smoke:",
    "python3 scripts/check_adapter_responses_persistent_fuzz_slice.py",
    "python3 scripts/run_adapter_responses_persistent_fuzz.py",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

summary_text = MACHINE_SUMMARY.read_text(encoding="utf-8")
summary = json.loads(summary_text)
slice_status = summary.get("s20_700_adapter_responses_persistent_fuzz_slice", {})
expected = {
    "persistent_fuzz_harness": True,
    "full_s20_700_complete": False,
    "full_s20_280_complete": False,
    "serialized_adapter_decoder_claimed": False,
    "live_host_access": False,
    "authorized_adapter_path_covered": False,
    "reference_adapter_kind_count": 8,
    "generic_replay_response_schema_count": 6,
    "mutation_class_count": 26,
    "max_mutations_per_input": 4,
    "max_input_bytes": 4096,
    "max_payload_bytes": 32,
    "max_collection_items": 4,
    "generated_seed_count": 821,
    "atomic_failure_asserted": True,
    "replay_response_fidelity_asserted": True,
    "state_root_transcript_binding_asserted": True,
}
for key, value in expected.items():
    if slice_status.get(key) != value:
        problems.append(f"machine-summary-drift:{key}")
if slice_status.get("vulcan_review") != "DEFERRED_FORGE_OAUTH_401":
    problems.append("machine-summary-vulcan-review-drift")
if '"adapter responses"' in summary_text:
    problems.append("machine-summary-stale-adapter-deferred-surface")

gate = M1_GATE.read_text(encoding="utf-8")
if "future targets for blocked mutation families, merge, and protocol" not in gate:
    problems.append("m1-fuzz-smoke-deferred-surface-drift")

for path, marker in [
    (RESULTS, "Adapter-response persistent libFuzzer slice"),
    (RESULTS, "do not complete S20-700"),
    (GAPS, "persistent targets are still absent"),
    (GAPS, "authorized S20-380 wrapper"),
    (AUDIT, "make adapter-responses-persistent-fuzz-smoke"),
]:
    if marker not in path.read_text(encoding="utf-8"):
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-adapter-responses-persistent-libfuzzer-slice-v1",
            "result": "PASS",
            "scope": "RESTRICTED_TYPED_S20_280_ADAPTER_RESPONSES_ONLY",
            "full_s20_700_complete": False,
        },
        indent=2,
        sort_keys=True,
    )
)
