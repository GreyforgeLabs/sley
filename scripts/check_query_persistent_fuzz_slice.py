#!/usr/bin/env python3
"""Drift check for the scoped S20-700 restricted-query persistent target."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/restricted_query_request.rs"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
RUNNER = ROOT / "scripts/run_query_persistent_fuzz.py"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
AUDIT = ROOT / "docs/audits/S20_700_QUERY_PERSISTENT_SLICE.md"
MAKEFILE = ROOT / "Makefile"

problems: list[str] = []

target = TARGET.read_text(encoding="utf-8")
for marker in [
    "LLVMFuzzerTestOneInput",
    "build_restricted_query_request(snapshot, query, limits)",
    "execute_restricted_query(alternate, &request)",
    "QueryId::derive(request.preimage())",
    "QueryErrorCode::SnapshotMismatch",
    "restricted-query judgment was not deterministic",
    "QUERY_KIND_COUNT: u8 = 4",
    "MAX_GENERATED_KINDS: usize = 16",
    "MAX_GENERATED_SEEDS: usize = 16",
    "MAX_FUZZ_INPUT_BYTES: usize = 4096",
]:
    if marker not in target:
        problems.append(f"target-missing:{marker}")
for forbidden in ["decode_query", "canonical query decoder"]:
    if forbidden in target:
        problems.append(f"parallel-query-codec:{forbidden}")

manifest = FUZZ_MANIFEST.read_text(encoding="utf-8")
for marker in [
    'name = "restricted_query_request"',
    'path = "targets/restricted_query_request.rs"',
    'sley-query = { path = "../crates/sley-query" }',
]:
    if marker not in manifest:
        problems.append(f"fuzz-manifest-missing:{marker}")

runner = RUNNER.read_text(encoding="utf-8")
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    '"RESTRICTED_TYPED_S20_310_QUERY_REQUESTS_ONLY"',
    '"full_s20_310_complete": False',
    '"canonical_query_decoder_claimed": False',
    '"source_commit": git_output(["git", "rev-parse", "HEAD"])',
    '"worktree_dirty": bool(git_output(["git", "status", "--porcelain"]))',
    "range(256)",
    "output_tail(error.stdout)",
]:
    if marker not in runner:
        problems.append(f"runner-missing:{marker}")

makefile = MAKEFILE.read_text(encoding="utf-8")
for marker in [
    "query-persistent-fuzz-smoke:",
    "python3 scripts/check_query_persistent_fuzz_slice.py",
    "python3 scripts/run_query_persistent_fuzz.py",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

summary = json.loads(MACHINE_SUMMARY.read_text(encoding="utf-8"))
slice_status = summary.get("s20_700_query_persistent_fuzz_slice", {})
expected = {
    "persistent_fuzz_harness": True,
    "full_s20_700_complete": False,
    "full_s20_310_complete": False,
    "canonical_query_decoder_claimed": False,
    "query_kind_count": 4,
    "max_input_bytes": 4096,
    "max_generated_kinds": 16,
    "max_generated_seeds": 16,
    "generated_seed_count": 525,
}
for key, value in expected.items():
    if slice_status.get(key) != value:
        problems.append(f"machine-summary-drift:{key}")
if slice_status.get("vulcan_review") != "DEFERRED_FORGE_OAUTH_401":
    problems.append("machine-summary-vulcan-review-drift")

for path, marker in [
    (RESULTS, "Restricted-query request persistent libFuzzer slice"),
    (RESULTS, "do not complete S20-700"),
    (GAPS, "persistent targets are still absent"),
    (AUDIT, "make query-persistent-fuzz-smoke"),
]:
    if marker not in path.read_text(encoding="utf-8"):
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-restricted-query-request-persistent-libfuzzer-slice-v1",
            "result": "PASS",
            "scope": "RESTRICTED_TYPED_S20_310_QUERY_REQUESTS_ONLY",
            "full_s20_700_complete": False,
        },
        indent=2,
        sort_keys=True,
    )
)
