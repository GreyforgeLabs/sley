#!/usr/bin/env python3
"""Drift check for the scoped S20-700 restricted-VM persistent target."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/vm_canonical_inputs.rs"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
RUNNER = ROOT / "scripts/run_vm_persistent_fuzz.py"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
AUDIT = ROOT / "docs/audits/S20_700_VM_INPUT_PERSISTENT_SLICE.md"
MAKEFILE = ROOT / "Makefile"
M1_GATE = ROOT / "scripts/check_m1_gate.py"

problems: list[str] = []

target = TARGET.read_text(encoding="utf-8")
for marker in [
    "LLVMFuzzerTestOneInput",
    "validated_execution_input_hashes(lowering, &request)",
    "execute_function(lowering, request.clone())",
    "derive_observation_id(",
    "VM canonical-input hash judgment was not deterministic",
    "VM execution judgment was not deterministic",
    "a canonical fixture input under normal limits was rejected",
    "a valid fixed VM fixture under normal limits was rejected",
    "assert_eq!(hashes.len(), request.inputs.len())",
    "FIXTURE_COUNT: u8 = 9",
    "MAX_FUZZ_INPUT_BYTES: usize = 4096",
    "MAX_RAW_INPUTS: usize = 4",
    "MAX_COLLECTION_ITEMS: usize = 4",
    "MAX_PAYLOAD_BYTES: usize = 32",
    "Opcode::BoolNot",
    "Opcode::BoolAnd",
    "Opcode::BoolOr",
]:
    if marker not in target:
        problems.append(f"target-missing:{marker}")
for forbidden in ["decode_bytecode", "execute_bytecode", "RawBytecode"]:
    if forbidden in target:
        problems.append(f"raw-bytecode-surface:{forbidden}")

manifest = FUZZ_MANIFEST.read_text(encoding="utf-8")
for marker in [
    'name = "vm_canonical_inputs"',
    'path = "targets/vm_canonical_inputs.rs"',
    'sley-vm = { path = "../crates/sley-vm" }',
]:
    if marker not in manifest:
        problems.append(f"fuzz-manifest-missing:{marker}")

runner = RUNNER.read_text(encoding="utf-8")
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    '"RESTRICTED_TYPED_S20_270_VM_INPUT_BOUNDARY_ONLY"',
    '"full_s20_270_complete": False',
    '"raw_bytecode_decoder_claimed": False',
    '"raw_bytecode_execution_entrypoint_claimed": False',
    '"source_commit": git_output(["git", "rev-parse", "HEAD"])',
    '"worktree_dirty": bool(git_output(["git", "status", "--porcelain"]))',
    "range(256)",
    "range(FIXTURE_COUNT)",
    "range(6)",
    "output_tail(error.stdout)",
]:
    if marker not in runner:
        problems.append(f"runner-missing:{marker}")

makefile = MAKEFILE.read_text(encoding="utf-8")
for marker in [
    "vm-persistent-fuzz-smoke:",
    "python3 scripts/check_vm_persistent_fuzz_slice.py",
    "python3 scripts/run_vm_persistent_fuzz.py",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

summary_text = MACHINE_SUMMARY.read_text(encoding="utf-8")
summary = json.loads(summary_text)
slice_status = summary.get("s20_700_vm_persistent_fuzz_slice", {})
expected = {
    "persistent_fuzz_harness": True,
    "full_s20_700_complete": False,
    "full_s20_270_complete": False,
    "raw_bytecode_decoder_claimed": False,
    "raw_bytecode_execution_entrypoint_claimed": False,
    "fixture_count": 9,
    "identity_fixture_count": 6,
    "boolean_opcode_fixture_count": 3,
    "max_input_bytes": 4096,
    "max_raw_inputs": 4,
    "max_collection_items": 4,
    "max_payload_bytes": 32,
    "generated_seed_count": 625,
}
for key, value in expected.items():
    if slice_status.get(key) != value:
        problems.append(f"machine-summary-drift:{key}")
if slice_status.get("vulcan_review") != "DEFERRED_FORGE_OAUTH_401":
    problems.append("machine-summary-vulcan-review-drift")
if '"VM canonical inputs"' in summary_text:
    problems.append("machine-summary-stale-vm-deferred-surface")

gate = M1_GATE.read_text(encoding="utf-8")
if "future targets for blocked mutation families, merge, protocol, and adapters" not in gate:
    problems.append("m1-fuzz-smoke-deferred-surface-drift")

for path, marker in [
    (RESULTS, "VM canonical-input persistent libFuzzer slice"),
    (RESULTS, "do not complete S20-700"),
    (GAPS, "persistent targets are still absent"),
    (GAPS, "no raw-bytecode decoder or execution entry point"),
    (AUDIT, "make vm-persistent-fuzz-smoke"),
]:
    if marker not in path.read_text(encoding="utf-8"):
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-vm-canonical-inputs-persistent-libfuzzer-slice-v1",
            "result": "PASS",
            "scope": "RESTRICTED_TYPED_S20_270_VM_INPUT_BOUNDARY_ONLY",
            "full_s20_700_complete": False,
        },
        indent=2,
        sort_keys=True,
    )
)
