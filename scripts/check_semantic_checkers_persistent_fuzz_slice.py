#!/usr/bin/env python3
"""Drift check for scoped S20-700 semantic-checker persistent fuzz targets."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TYPE_TARGET = ROOT / "fuzz/targets/type_checker.rs"
GRAPH_TARGET = ROOT / "fuzz/targets/ssmc_graph_cfg_checker.rs"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
RUNNER = ROOT / "scripts/run_semantic_checkers_persistent_fuzz.py"
REGRESSION = ROOT / "fuzz/regressions/S20_700_HARNESS_001.json"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
RESULTS = ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
GAPS = ROOT / "machineresearch/sley-2.0/25-evidence-gaps.md"
NEGATIVE_RESULTS = ROOT / "machineresearch/sley-2.0/24-negative-results.md"
AUDIT = ROOT / "docs/audits/S20_700_SEMANTIC_CHECKERS_PERSISTENT_SLICE.md"
MAKEFILE = ROOT / "Makefile"
GITIGNORE = ROOT / ".gitignore"

problems: list[str] = []

type_target = TYPE_TARGET.read_text(encoding="utf-8")
for marker in [
    "LLVMFuzzerTestOneInput",
    "TypeEnvironment::new(definitions)",
    "environment.check_type(value_type, parameter_count)",
    "environment.traits(value_type)",
    "environment.instantiate_in_scope(",
    "MAX_GENERATED_TYPE_NODES: usize = 512",
    "type-checker judgment was not deterministic",
]:
    if marker not in type_target:
        problems.append(f"type-target-missing:{marker}")

graph_target = GRAPH_TARGET.read_text(encoding="utf-8")
for marker in [
    "LLVMFuzzerTestOneInput",
    "validate_function_graph(",
    "TEMPLATE_COUNT: u8 = 4",
    "MAX_MUTATIONS: usize = 8",
    "MUTATION_COUNT: u8 = 33",
    "graph/CFG judgment was not deterministic",
    "a graph/CFG base template drifted invalid",
]:
    if marker not in graph_target:
        problems.append(f"graph-target-missing:{marker}")

for path, body in [(TYPE_TARGET, type_target), (GRAPH_TARGET, graph_target)]:
    for forbidden in ["sley_mutate", "decode_mutation_value", "canonical graph decoder"]:
        if forbidden in body:
            problems.append(f"private-or-parallel-codec:{path.relative_to(ROOT)}:{forbidden}")

manifest = FUZZ_MANIFEST.read_text(encoding="utf-8")
for marker in [
    'name = "type_checker"',
    'path = "targets/type_checker.rs"',
    'name = "ssmc_graph_cfg_checker"',
    'path = "targets/ssmc_graph_cfg_checker.rs"',
    'sley-check = { path = "../crates/sley-check" }',
    'sley-ssmc = { path = "../crates/sley-ssmc" }',
]:
    if marker not in manifest:
        problems.append(f"fuzz-manifest-missing:{marker}")

runner = RUNNER.read_text(encoding="utf-8")
for marker in [
    "libclang_rt.fuzzer-x86_64.a",
    "nightly-2026-02-27",
    '"canonical_graph_decoder_claimed": False',
    '"private_mutation_codec_used": False',
    '"S20_210_PUBLIC_TYPED_TYPE_CHECKER"',
    '"S20_220_PUBLIC_TYPED_GRAPH_CFG_CHECKER"',
    '"source_commit": git_output(["git", "rev-parse", "HEAD"])',
    '"worktree_dirty": bool(git_output(["git", "status", "--porcelain"]))',
    "S20_700_HARNESS_001.json",
    "range(256)",
    "range(128)",
    "range(33)",
    "range(32)",
    "output_tail(error.stdout)",
]:
    if marker not in runner:
        problems.append(f"runner-missing:{marker}")

regression = json.loads(REGRESSION.read_text(encoding="utf-8"))
if regression.get("finding_id") != "S20-700-HARNESS-001":
    problems.append("regression-finding-id-drift")
if regression.get("input_hex") != "c2":
    problems.append("regression-input-drift")
if regression.get("classification") != "HARNESS_ONLY_FIXED":
    problems.append("regression-classification-drift")
if regression.get("production_checker_defect") is not False:
    problems.append("regression-production-disposition-drift")

makefile = MAKEFILE.read_text(encoding="utf-8")
for marker in [
    "semantic-checkers-persistent-fuzz-smoke:",
    "python3 scripts/check_semantic_checkers_persistent_fuzz_slice.py",
    "python3 scripts/run_semantic_checkers_persistent_fuzz.py",
]:
    if marker not in makefile:
        problems.append(f"makefile-missing:{marker}")

if "/fuzz/target/" not in GITIGNORE.read_text(encoding="utf-8"):
    problems.append("nested-fuzz-target-not-ignored")

summary = json.loads(MACHINE_SUMMARY.read_text(encoding="utf-8"))
slice_status = summary.get("s20_700_semantic_checkers_persistent_fuzz_slice", {})
expected = {
    "persistent_fuzz_harness": True,
    "full_s20_700_complete": False,
    "canonical_graph_decoder_claimed": False,
    "private_mutation_codec_used": False,
    "max_input_bytes": 4096,
    "max_generated_type_nodes": 512,
    "type_checker_seed_count": 385,
    "graph_cfg_seed_count": 396,
    "graph_template_count": 4,
    "graph_mutation_class_count": 33,
    "max_graph_mutations_per_input": 8,
    "closed_harness_findings": 1,
}
for key, value in expected.items():
    if slice_status.get(key) != value:
        problems.append(f"machine-summary-drift:{key}")

for path, marker in [
    (RESULTS, "S20-700-HARNESS-001"),
    (RESULTS, "public typed S20-210 type checker"),
    (RESULTS, "public typed S20-220"),
    (RESULTS, "graph/CFG validator runs twice"),
    (GAPS, "typed graph/CFG persistent target"),
    (NEGATIVE_RESULTS, "S20-700-HARNESS-001"),
    (AUDIT, "make semantic-checkers-persistent-fuzz-smoke"),
]:
    if marker not in path.read_text(encoding="utf-8"):
        problems.append(f"doc-missing:{path.relative_to(ROOT)}:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "contract": "s20-700-semantic-checkers-persistent-libfuzzer-slice-v1",
            "result": "PASS",
            "scope": "PUBLIC_TYPED_S20_210_AND_S20_220_CHECKERS_ONLY",
            "full_s20_700_complete": False,
        },
        indent=2,
        sort_keys=True,
    )
)
