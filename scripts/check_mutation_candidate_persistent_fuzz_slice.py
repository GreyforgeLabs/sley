#!/usr/bin/env python3
"""Drift check for the S20-350 mutation-candidate persistent target."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/mutation_candidate.rs"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
RUNNER = ROOT / "scripts/run_mutation_candidate_persistent_fuzz.py"
MAKEFILE = ROOT / "Makefile"
FIXTURES = ROOT / "conformance/mutation-candidate/v1"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"

problems: list[str] = []

target = TARGET.read_text(encoding="utf-8")
for marker in [
    "LLVMFuzzerTestOneInput",
    "MAX_FUZZ_INPUT_BYTES: usize = 1_048_576",
    "SELECTOR_COUNT: u8 = 2",
    "import_candidate(payload)",
    "build_candidate(&imported.record)",
    "assert_eq!(rebuilt, imported",
    "decode_candidate_record(payload)",
    "encode_candidate_record(&record)",
    "assert_eq!(encoded, payload",
]:
    if marker not in target:
        problems.append(f"target-missing:{marker}")

manifest = FUZZ_MANIFEST.read_text(encoding="utf-8")
for marker in [
    'name = "mutation_candidate"',
    'path = "targets/mutation_candidate.rs"',
    'sley-mutate = { path = "../crates/sley-mutate" }',
]:
    if marker not in manifest:
        problems.append(f"fuzz-manifest-missing:{marker}")

runner = RUNNER.read_text(encoding="utf-8")
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    '"PROPOSAL_ONLY_CANDIDATE_RECORD_AND_ENVELOPE"',
    '"candidate_authority": False',
    '"runtime_mutation": False',
    '"source_commit": git_output(["git", "rev-parse", "HEAD"])',
    '"worktree_dirty": bool(git_output(["git", "status", "--porcelain"]))',
    'vector["expected_stored_hex"]',
    'vector["expected_record_hex"]',
    "output_tail(error.stdout)",
]:
    if marker not in runner:
        problems.append(f"runner-missing:{marker}")

makefile = MAKEFILE.read_text(encoding="utf-8")
for marker in [
    "mutation-candidate-persistent-fuzz-smoke:",
    "python3 scripts/check_mutation_candidate_persistent_fuzz_slice.py",
    "python3 scripts/run_mutation_candidate_persistent_fuzz.py",
    "sley2-scb1-oracle check-mutation-candidate",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

accepted = json.loads((FIXTURES / "accepted.json").read_text(encoding="utf-8"))
rejected = json.loads((FIXTURES / "rejected.json").read_text(encoding="utf-8"))
if len(accepted.get("value_vectors", [])) != 44:
    problems.append("accepted-value-vector-count-drift")
if len(accepted.get("candidate_vectors", [])) != 1:
    problems.append("accepted-candidate-vector-count-drift")
if len(rejected.get("value_vectors", [])) != 4:
    problems.append("rejected-value-vector-count-drift")
if len(rejected.get("candidate_vectors", [])) != 14:
    problems.append("rejected-candidate-vector-count-drift")
if accepted.get("source_schema_blake3") != "1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae":
    problems.append("accepted-schema-digest-drift")
declared_sums = {}
for line in (FIXTURES / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, name = line.split(maxsplit=1)
    declared_sums[name] = digest
for name in ("accepted.json", "rejected.json"):
    actual = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
    if declared_sums.get(name) != actual:
        problems.append(f"fixture-checksum-drift:{name}")

summary = json.loads(MACHINE_SUMMARY.read_text(encoding="utf-8"))
profile = summary.get("mutation_value_profile", {})
for key, value in {
    "independent_manifest_fields_pending": 0,
    "independent_conformance_complete": True,
    "persistent_candidate_fuzz_harness": True,
    "persistent_candidate_fuzz_smoke": "PASS",
    "full_s20_350_complete": True,
    "candidate_authority": False,
    "runtime_mutation": False,
}.items():
    if profile.get(key) != value:
        problems.append(f"machine-summary-drift:{key}")

for path, marker in [
    (RESULTS, "Mutation-candidate persistent libFuzzer target"),
    (RESULTS, "make mutation-candidate-persistent-fuzz-smoke"),
    (GAPS, "S20-350 is complete as a proposal-only construction boundary"),
]:
    if marker not in path.read_text(encoding="utf-8"):
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-350-mutation-candidate-persistent-libfuzzer-v1",
            "result": "PASS",
            "scope": "PROPOSAL_ONLY_CANDIDATE_RECORD_AND_ENVELOPE",
            "candidate_authority": False,
            "runtime_mutation": False,
        },
        indent=2,
        sort_keys=True,
    )
)
