#!/usr/bin/env python3
"""Drift check for the S20-360 candidate-result persistent target."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fuzz/targets/candidate_result.rs"
MANIFEST = ROOT / "fuzz/Cargo.toml"
RUNNER = ROOT / "scripts/run_candidate_result_persistent_fuzz.py"
MAKEFILE = ROOT / "Makefile"
ACCEPTED = ROOT / "conformance/candidate-result/v1/accepted.json"
REJECTED = ROOT / "conformance/candidate-result/v1/rejected.json"
GENERATOR = ROOT / "scripts/generate_candidate_result_fixtures.py"

problems: list[str] = []

for path in (TARGET, MANIFEST, RUNNER, MAKEFILE, ACCEPTED, REJECTED, GENERATOR):
    if not path.is_file():
        problems.append(f"missing:{path.relative_to(ROOT)}")

if not problems:
    target = TARGET.read_text(encoding="utf-8")
    for marker in (
        "LLVMFuzzerTestOneInput",
        "import_candidate_result(input)",
        "CandidateResultId::derive(&first.preimage)",
        "record.phase_results.len(), 14",
        "PhaseOutcome::NotRun",
        "CandidateDecision::InvalidEncoding",
    ):
        if marker not in target:
            problems.append(f"target-missing:{marker}")

    manifest = MANIFEST.read_text(encoding="utf-8")
    for marker in (
        'name = "candidate_result"',
        'path = "targets/candidate_result.rs"',
        'sley-policy = { path = "../crates/sley-policy" }',
    ):
        if marker not in manifest:
            problems.append(f"manifest-missing:{marker}")

    runner = RUNNER.read_text(encoding="utf-8")
    for marker in (
        "libclang_rt.fuzzer-x86_64.a",
        "nightly-2026-02-27",
        '"RESULT_IMPORT_AND_MONOTONIC_SHAPE_NO_AUTHORITY"',
        '"candidate_authority": False',
        '"commit_authority": False',
        '"runtime_mutation": False',
        'stored_vectors = [bytes.fromhex(value["stored_hex"])',
        'if value["decision"] == "VALID"',
    ):
        if marker not in runner:
            problems.append(f"runner-missing:{marker}")

    makefile = MAKEFILE.read_text(encoding="utf-8")
    for marker in (
        "candidate-result-persistent-fuzz-smoke:",
        "python3 scripts/generate_candidate_result_fixtures.py --check",
        "python3 scripts/check_candidate_result_persistent_fuzz_slice.py",
        "python3 scripts/run_candidate_result_persistent_fuzz.py",
    ):
        if marker not in makefile:
            problems.append(f"makefile-missing:{marker}")

    accepted = json.loads(ACCEPTED.read_text(encoding="utf-8"))
    rejected = json.loads(REJECTED.read_text(encoding="utf-8"))
    if len(accepted.get("vectors", [])) != 16:
        problems.append("accepted-vector-count-drift")
    expected_decisions = {
        "VALID",
        "INVALID_ENCODING",
        "INVALID_SCHEMA",
        "STALE_ROOT",
        "STALE_ENTITY",
        "INVALID_IDENTITY",
        "INVALID_GRAPH",
        "UNRESOLVED_REFERENCE",
        "TYPE_ERROR",
        "CONTROL_FLOW_ERROR",
        "EFFECT_ERROR",
        "CAPABILITY_DENIED",
        "CONTRACT_ERROR",
        "RESOURCE_LIMIT",
        "TEST_PLAN_ERROR",
        "INTERNAL_ERROR",
    }
    actual_decisions = {value.get("decision") for value in accepted.get("vectors", [])}
    if actual_decisions != expected_decisions:
        problems.append("accepted-decision-coverage-drift")
    if len(rejected.get("mutations", [])) != 4:
        problems.append("rejected-vector-count-drift")

    generator = GENERATOR.read_text(encoding="utf-8")
    for marker in (
        "emit_candidate_result_vectors_for_fixture_refresh",
        'parser.add_argument(\n        "--check"',
        'if len(vectors) != 16 or vectors[0]["decision"] != "VALID"',
        '"generator": "scripts/generate_candidate_result_fixtures.py"',
    ):
        if marker not in generator:
            problems.append(f"generator-missing:{marker}")

if problems:
    raise SystemExit("\n".join(problems))

print(
    json.dumps(
        {
            "candidate_authority": False,
            "commit_authority": False,
            "contract": "s20-360-candidate-result-persistent-libfuzzer-v1",
            "result": "PASS",
            "runtime_mutation": False,
            "scope": "RESULT_IMPORT_AND_MONOTONIC_SHAPE_NO_AUTHORITY",
        },
        indent=2,
        sort_keys=True,
    )
)
