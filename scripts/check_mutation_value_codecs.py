#!/usr/bin/env python3
"""Check complete proposal-only S20-350 codecs and independent conformance."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/spec/SSMC1_EPOCH1_SCHEMA.txt"
GENERATED = ROOT / "crates/sley-mutate/src/value_generated.rs"
VALUE_SOURCE = ROOT / "crates/sley-mutate/src/value.rs"
DESCRIPTORS = ROOT / "crates/sley-mutate/src/generated.rs"
CODEC_SOURCE = ROOT / "crates/sley-mutate/src/codec.rs"
LIB_SOURCE = ROOT / "crates/sley-mutate/src/lib.rs"
CANDIDATE_SOURCE = ROOT / "crates/sley-mutate/src/candidate.rs"
FIXTURE_TEST_SOURCE = ROOT / "crates/sley-mutate/src/codec/fixture_tests.rs"
ADVERSARIAL_TEST_SOURCE = ROOT / "crates/sley-mutate/src/codec/adversarial_tests.rs"
MAKEFILE_SOURCE = ROOT / "Makefile"
M1_GATE_SOURCE = ROOT / "scripts/check_m1_gate.py"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
ADVERSARIAL_DOSSIER = (
    ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
)
CLOSEOUT_AUDIT = ROOT / "docs/audits/S20_350_CANDIDATE_CLOSEOUT.md"
BOUNDED_VALIDATION_EVIDENCE = (
    ROOT / "evidence/validation/s20-700-mutation-value-bounded-v1.json"
)
CLOSEOUT_VALIDATION_EVIDENCE = (
    ROOT / "evidence/validation/s20-350-candidate-closeout-v1.json"
)
ORACLE_SOURCE = ROOT / "oracle/scb1/src/sley2_scb1_oracle/mutation_value.py"
ORACLE_CANDIDATE_SOURCE = ROOT / "oracle/scb1/src/sley2_scb1_oracle/candidate.py"
ACCEPTED_FIXTURES = ROOT / "conformance/mutation-value/v1/accepted.json"
REJECTED_FIXTURES = ROOT / "conformance/mutation-value/v1/rejected.json"
FIXTURE_SUMS = ROOT / "conformance/mutation-value/v1/SHA256SUMS"
SUPPLEMENT_DIR = ROOT / "conformance/mutation-candidate/v1"
SUPPLEMENT_ACCEPTED = SUPPLEMENT_DIR / "accepted.json"
SUPPLEMENT_REJECTED = SUPPLEMENT_DIR / "rejected.json"
SUPPLEMENT_SUMS = SUPPLEMENT_DIR / "SHA256SUMS"

EXPECTED_ACCEPTED_FIXTURE_SHA256 = (
    "98024278156d66c5d8d94579f9ec09a5691bff876929226822aed78f178330de"
)
EXPECTED_REJECTED_FIXTURE_SHA256 = (
    "509b1b921d54d5e8e53d1a9fed8c7bf66ce0e7253f4b37d9dc2927be601a4291"
)
EXPECTED_SUPPLEMENT_ACCEPTED_SHA256 = (
    "736668bae748a0d7c5aae16c6ed6e745cce66a7b829e009ac93171eec619b360"
)
EXPECTED_SUPPLEMENT_REJECTED_SHA256 = (
    "526f275816b6fbf2b58c08a899909356350da3e12fb6abafc0ea8fed50f65f07"
)
EXPECTED_SCHEMA_BLAKE3 = (
    "1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae"
)
EXPECTED_FIELD_EXCLUSIONS = {
    "Namespace.parent",
    "TypeDef.form",
    "Block.terminator",
    "Constant.value",
    "CapabilityRequirement.allowed_scopes",
    "Contract.resource_limits",
    "TestCase.inputs",
    "TestCase.effect_environment",
    "TestCase.expected",
    "TestCase.observations",
}
BLOCKED_FIELD_TYPES = {
    "ConstValue",
    "EffectEnvironment",
    "ExpectedOutcome",
    "Terminator",
    "TypeDefForm",
    "List<ConstValue>",
    "List<ExpectedObservation>",
    "Option<EntityId>",
    "Option<ResourceLimits>",
}
EXPECTED_CORPUS_EXCLUSIONS = [
    "generic Option<T> value codecs beyond existing internal helpers",
    "ConstValue and recursive constant families",
    (
        "Namespace.parent, TypeDef.form, Block.terminator, Constant.value, "
        "CapabilityRequirement.allowed_scopes, Contract.resource_limits, "
        "TestCase.inputs, TestCase.effect_environment, TestCase.expected, "
        "TestCase.observations"
    ),
    (
        "EntityBodyValue, FieldValue, ProposalValue, preconditions, candidates, "
        "validation, runtime mutation"
    ),
]

ENTITY_RE = re.compile(r"^entity ([0-9]+) ([A-Za-z][A-Za-z0-9]*) ([A-Za-z][A-Za-z0-9]*)$")
RECORD_RE = re.compile(r"^record ([A-Za-z][A-Za-z0-9]*)\((.*)\)$")
DESCRIPTOR_RE = re.compile(
    r"MutationOperationDescriptor \{\s+"
    r"class: MutationClass::([A-Za-z][A-Za-z0-9]*),\s+"
    r"target_kind: ([0-9]+),\s+"
    r"field_tag: (None|Some\(([0-9]+)\)),"
)


def pascal(value: str) -> str:
    return "".join(piece[:1].upper() + piece[1:] for piece in value.split("_"))


def body_fields(raw: str) -> list[tuple[str, str, bool]]:
    fields: list[tuple[str, str, bool]] = []
    depth = 0
    start = 0
    parts: list[str] = []
    for index, char in enumerate(raw):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(raw[start:index])
            start = index + 1
    if raw:
        parts.append(raw[start:])
    for part in parts:
        _tag, name, typed = part.split(":", 2)
        fields.append((name, typed[:-1], typed[-1] == "!"))
    return fields


def snake(value: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", value).lower()


def manifest_records_and_entities() -> tuple[
    dict[str, list[tuple[str, str, bool]]], list[tuple[int, str, str]]
]:
    manifest = MANIFEST.read_text(encoding="utf-8")
    records = {
        match[1]: body_fields(match[2])
        for line in manifest.splitlines()
        if (match := RECORD_RE.fullmatch(line))
    }
    entities = [
        (int(match[1]), match[2], match[3])
        for line in manifest.splitlines()
        if (match := ENTITY_RE.fullmatch(line))
    ]
    return records, entities


def expected_field_fixtures() -> dict[str, str]:
    records, entities = manifest_records_and_entities()
    included: dict[str, str] = {}
    excluded: set[str] = set()
    for _tag, entity_name, body in entities:
        for field_name, value_type, _required_field in records[body]:
            field = f"{entity_name}.{field_name}"
            if field in EXPECTED_FIELD_EXCLUSIONS:
                excluded.add(field)
                continue
            if value_type in BLOCKED_FIELD_TYPES:
                raise SystemExit(f"blocked field type entered fixture inventory: {field}")
            fixture_id = f"field_{snake(entity_name)}_{field_name}"
            if fixture_id in included:
                raise SystemExit(f"partial mutation fixture field ID collision: {fixture_id}")
            included[fixture_id] = value_type
    if excluded != EXPECTED_FIELD_EXCLUSIONS:
        raise SystemExit("partial mutation fixture field exclusion drift")
    if len(included) != 65:
        raise SystemExit("partial mutation fixture field inventory is not 65")
    return included


def check_partial_fixtures() -> None:
    for path in (
        FIXTURE_TEST_SOURCE,
        ADVERSARIAL_TEST_SOURCE,
        MAKEFILE_SOURCE,
        M1_GATE_SOURCE,
        MACHINE_SUMMARY,
        ADVERSARIAL_DOSSIER,
        CLOSEOUT_AUDIT,
        BOUNDED_VALIDATION_EVIDENCE,
        CLOSEOUT_VALIDATION_EVIDENCE,
        ORACLE_SOURCE,
        ACCEPTED_FIXTURES,
        REJECTED_FIXTURES,
        FIXTURE_SUMS,
    ):
        if not path.is_file():
            raise SystemExit(f"partial mutation fixture file missing: {path.relative_to(ROOT)}")

    fixture_hashes = {
        ACCEPTED_FIXTURES.name: hashlib.sha256(ACCEPTED_FIXTURES.read_bytes()).hexdigest(),
        REJECTED_FIXTURES.name: hashlib.sha256(REJECTED_FIXTURES.read_bytes()).hexdigest(),
    }
    expected_hashes = {
        ACCEPTED_FIXTURES.name: EXPECTED_ACCEPTED_FIXTURE_SHA256,
        REJECTED_FIXTURES.name: EXPECTED_REJECTED_FIXTURE_SHA256,
    }
    if fixture_hashes != expected_hashes:
        raise SystemExit("partial mutation fixture digest drift")
    expected_sums = "".join(
        f"{expected_hashes[name]}  {name}\n" for name in ("accepted.json", "rejected.json")
    )
    if FIXTURE_SUMS.read_text(encoding="utf-8") != expected_sums:
        raise SystemExit("partial mutation fixture SHA256SUMS drift")

    accepted = json.loads(ACCEPTED_FIXTURES.read_text(encoding="utf-8"))
    rejected = json.loads(REJECTED_FIXTURES.read_text(encoding="utf-8"))
    for label, fixture in (("accepted", accepted), ("rejected", rejected)):
        if fixture.get("contract") != "sley2-mutation-value-v1-partial":
            raise SystemExit(f"partial mutation {label} fixture contract drift")
        if fixture.get("claim") != "partial":
            raise SystemExit(f"partial mutation {label} fixture overclaims completeness")
        if fixture.get("source_schema_blake3") != EXPECTED_SCHEMA_BLAKE3:
            raise SystemExit(f"partial mutation {label} fixture schema digest drift")
        vector_ids = [vector["id"] for vector in fixture["vectors"]]
        if len(vector_ids) != len(set(vector_ids)):
            raise SystemExit(f"partial mutation {label} fixture ID duplication")

    accepted_vectors = accepted["vectors"]
    rejected_vectors = rejected["vectors"]
    if accepted.get("excluded") != EXPECTED_CORPUS_EXCLUSIONS:
        raise SystemExit("partial mutation fixture exclusion declaration drift")
    if len(accepted_vectors) != 126 or len(rejected_vectors) != 18:
        raise SystemExit("partial mutation fixture vector inventory drift")
    if len([vector for vector in accepted_vectors if vector["id"].startswith("type_expr_")]) != 20:
        raise SystemExit("partial mutation fixture TypeExpr inventory is not 20")
    expected_body_ids = {
        "body_workspace",
        "body_package",
        "body_function",
        "body_parameter",
        "body_operation",
        "body_global_value",
        "body_effect_def",
        "body_adapter_import",
        "body_entry_point",
        "body_policy_binding",
        "body_dependency_binding",
    }
    actual_body_ids = {
        vector["id"] for vector in accepted_vectors if vector["id"].startswith("body_")
    }
    if actual_body_ids != expected_body_ids:
        raise SystemExit("partial mutation fixture body inventory drift")
    actual_field_fixtures = {
        vector["id"]: vector["declared_type"]
        for vector in accepted_vectors
        if vector["id"].startswith("field_")
    }
    if actual_field_fixtures != expected_field_fixtures():
        raise SystemExit("partial mutation fixture field ID/type inventory drift")
    for vector in accepted_vectors:
        if vector["id"].startswith("field_") and (
            vector.get("family") != "field" or vector.get("case") != "manifest-field"
        ):
            raise SystemExit(f"partial mutation fixture field metadata drift: {vector['id']}")
    for vector in accepted_vectors + rejected_vectors:
        declared_type = vector["declared_type"]
        if (
            "Option<" in declared_type
            or "Const" in declared_type
            or declared_type
            in {
                "Terminator",
                "TypeDefForm",
                "EffectEnvironment",
                "ExpectedOutcome",
                "List<ExpectedObservation>",
            }
        ):
            raise SystemExit(f"blocked family entered partial mutation fixtures: {declared_type}")
        encoded = vector.get("expected_hex", vector.get("input_hex"))
        if not isinstance(encoded, str) or encoded != encoded.lower():
            raise SystemExit(f"partial mutation fixture hex drift: {vector['id']}")
        try:
            bytes.fromhex(encoded)
        except ValueError as error:
            raise SystemExit(f"partial mutation fixture hex invalid: {vector['id']}") from error

    fixture_tests = FIXTURE_TEST_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "independent_partial_accepted_fixtures_match_exact_private_codec_bytes",
        "independent_partial_rejected_fixtures_return_exact_private_codes",
        "assert_eq!(corpus.vectors.len(), 126)",
        "assert_eq!(corpus.vectors.len(), 18)",
        "filter(|vector| vector.id.starts_with(\"field_\"))",
        "\"Set<EntityId>\" => assert_fixture(vector, &fixture_entity_id_set(&vector.value))",
        "assert_fixture(vector, &fixture_type_expr(&vector.value))",
        "decode_rejected::<OperationBody>(input)",
    ):
        if marker not in fixture_tests:
            raise SystemExit(f"partial mutation Rust fixture consumer drift: {marker}")
    adversarial_tests = ADVERSARIAL_TEST_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "fn bounded_mutation_value_codec_fuzz_smoke()",
        "fn mutation_value_codec_adversarial()",
        "const ACCEPTED_VECTOR_COUNT: usize = 126",
        "const REJECTED_VECTOR_COUNT: usize = 18",
        "const PREFIX_DERIVED_CASES: usize = 446",
        "const TOTAL_DERIVED_CASES: usize = APPENDED_DERIVED_CASES + PREFIX_DERIVED_CASES",
        "ScbErrorCode::TrailingBytes.as_str()",
        "\"reject_list_resource_limit\"",
        "\"List<UInt32>\"",
        "\"SCB_RESOURCE_LIMIT\"",
        "catch_unwind(AssertUnwindSafe(|| decode_reencode(declared_type, input)))",
        "unsupported mutation-value adversarial type",
    ):
        if marker not in adversarial_tests:
            raise SystemExit(f"partial mutation adversarial/fuzz smoke drift: {marker}")
    if adversarial_tests.count("\n#[test]\nfn ") != 2:
        raise SystemExit("partial mutation adversarial/fuzz smoke test count drift")
    makefile = MAKEFILE_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "cargo test -p sley-mutate bounded_mutation_value_codec_fuzz_smoke --locked",
        "cargo test -p sley-mutate mutation_value_codec_adversarial --locked",
    ):
        if makefile.count(marker) != 1:
            raise SystemExit(f"partial mutation Makefile test command drift: {marker}")
    gate_source = M1_GATE_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "S20-350 partial mutation-value exact 18-vector rejection-code matrix",
        "126 accepted private mutation-value seeds with 698 deterministic trailing/prefix mutations",
        "persistent libFuzzer targets remain separate from this bounded make fuzz-smoke profile",
        "blocked mutation families",
    ):
        if gate_source.count(marker) != 1:
            raise SystemExit(f"partial mutation gate summary drift: {marker}")
    summary = json.loads(MACHINE_SUMMARY.read_text(encoding="utf-8"))
    mutation_profile = summary.get("mutation_value_profile", {})
    expected_mutation_profile = {
        "status": "S20_350_COMPLETE_PROPOSAL_ONLY",
        "private_entity_body_codecs": 18,
        "independent_accepted_vectors": 170,
        "independent_rejected_vectors": 22,
        "independent_candidate_accepted_vectors": 1,
        "independent_candidate_rejected_vectors": 14,
        "manifest_field_fixtures": 75,
        "independent_manifest_fields_pending": 0,
        "bounded_adversarial_seeds": 126,
        "bounded_trailing_mutations": 252,
        "bounded_proper_prefix_mutations": 446,
        "bounded_derived_mutations": 698,
        "exact_rejection_code_vectors": 18,
        "generic_option_canon_resolved": True,
        "const_value_canon_resolved": True,
        "aggregate_codecs": True,
        "candidate_construction": True,
        "candidate_authority": False,
        "native_s20_350_implementation_complete": True,
        "independent_conformance_complete": True,
        "persistent_candidate_fuzz_harness": True,
        "persistent_candidate_fuzz_smoke": "PASS",
        "runtime_mutation": False,
        "full_s20_350_complete": True,
        "closeout_audit": "docs/audits/S20_350_CANDIDATE_CLOSEOUT.md",
        "validation_evidence": "evidence/validation/s20-350-candidate-closeout-v1.json",
    }
    for key, expected in expected_mutation_profile.items():
        if mutation_profile.get(key) != expected:
            raise SystemExit(f"partial mutation machine-summary drift: {key}")
    adversarial_summary = summary.get("adversarial", {})
    expected_adversarial_summary = {
        "mutation_value_accepted_seeds": 126,
        "mutation_value_trailing_cases": 252,
        "mutation_value_proper_prefix_cases": 446,
        "mutation_value_derived_cases": 698,
        "mutation_value_exact_rejection_vectors": 18,
        "mutation_value_panics": 0,
        "persistent_fuzz_harness": False,
        "persistent_target_count": 11,
        "persistent_landed_surface_count": 12,
        "mutation_candidate_persistent_fuzz_smoke": "PASS",
        "candidate_result_persistent_fuzz_smoke": "PASS",
        "transaction_receipt_persistent_fuzz_smoke": "PASS",
        "full_s20_700_complete": False,
    }
    for key, expected in expected_adversarial_summary.items():
        if adversarial_summary.get(key) != expected:
            raise SystemExit(f"partial mutation adversarial summary drift: {key}")
    dossier = ADVERSARIAL_DOSSIER.read_text(encoding="utf-8")
    for marker in (
        "Status: bounded partial S20-700 evidence with eleven scoped persistent libFuzzer",
        "scoped persistent libFuzzer",
        "all 126 accepted fixtures seed 252 trailing-byte and",
        "446 distinct proper-prefix cases, for 698 deterministic derived mutations",
        "Mutation-candidate persistent libFuzzer target",
        "Candidate-result persistent libFuzzer target",
        "Transaction/receipt persistent libFuzzer target",
        "Persistent fuzzing and minimized finding retention",
    ):
        if dossier.count(marker) != 1:
            raise SystemExit(f"partial mutation adversarial dossier drift: {marker}")
    validation = json.loads(BOUNDED_VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
    expected_validation = {
        "contract": "s20-700-mutation-value-bounded-validation-v1",
        "implementation_commit": "f9dcd053fab82b85dcefc73b89397f3c18a7099c",
        "validation_tier": "TIER_2_SUBSYSTEM_HANDOFF",
        "duration_method": "/usr/bin/time -f WALL_SECONDS=%e",
        "result": "PASS_BOUNDED_PARTIAL",
    }
    for key, expected in expected_validation.items():
        if validation.get(key) != expected:
            raise SystemExit(f"partial mutation validation evidence drift: {key}")
    if validation.get("deterministic_inputs", {}).get("derived_mutations") != 698:
        raise SystemExit("partial mutation validation seed inventory drift")
    commands = {entry["command"]: entry["result"] for entry in validation.get("commands", [])}
    for command in (
        "python3 scripts/check_mutation_value_codecs.py",
        "cargo test -p sley-mutate --locked",
        "make fuzz-smoke",
        "make adversarial",
        "make quick",
        "make conformance",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "make check-changed",
    ):
        if not commands.get(command, "").startswith("PASS"):
            raise SystemExit(f"partial mutation validation command drift: {command}")
    skipped = {entry["check"] for entry in validation.get("skipped_checks", [])}
    if skipped != {"make v2", "make release-check", "persistent fuzzing"}:
        raise SystemExit("partial mutation validation skipped-gate drift")
    external_actions = validation.get("external_actions", {})
    if any(external_actions.values()):
        raise SystemExit("partial mutation validation external-action drift")
    oracle_source = ORACLE_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "def check_mutation_value(",
        "def encode_mutation_value(",
        "def decode_declared_mutation_value(",
        "SOURCE_SCHEMA_BLAKE3",
        "_fixture_checksum_problems",
    ):
        if marker not in oracle_source:
            raise SystemExit(f"independent mutation oracle drift: {marker}")
    closeout = CLOSEOUT_AUDIT.read_text(encoding="utf-8")
    for marker in (
        "proposal-only construction complete",
        "26-seed, 512-run smoke passed",
        "35000–35010",
        "does not claim an independent Vulcan pass",
        "S20-360 is the next dependency-complete package",
    ):
        if marker not in closeout:
            raise SystemExit(f"S20-350 closeout audit drift: {marker}")

    closeout_validation = json.loads(
        CLOSEOUT_VALIDATION_EVIDENCE.read_text(encoding="utf-8")
    )
    expected_closeout_validation = {
        "contract": "s20-350-candidate-closeout-validation-v1",
        "implementation_commit": "e9b32f1b2b3d23378b432728619f13cc9af815bc",
        "validation_tier": "TIER_2_SUBSYSTEM_HANDOFF",
        "scope": "PROPOSAL_ONLY_CANDIDATE_CONSTRUCTION",
        "result": "PASS_PROPOSAL_ONLY",
    }
    for key, expected in expected_closeout_validation.items():
        if closeout_validation.get(key) != expected:
            raise SystemExit(f"S20-350 closeout validation drift: {key}")
    deterministic_inputs = closeout_validation.get("deterministic_inputs", {})
    expected_closeout_inputs = {
        "source_schema_blake3": EXPECTED_SCHEMA_BLAKE3,
        "validation_profile_id": (
            "7d8ffff97a3fdafc49b4329d47b0b12f04759c3124274024016483a263265d54"
        ),
        "combined_accepted_value_vectors": 170,
        "combined_rejected_value_vectors": 22,
        "accepted_candidate_vectors": 1,
        "rejected_candidate_vectors": 14,
        "persistent_fuzz_corpus_seeds": 26,
        "persistent_fuzz_runs": 512,
    }
    for key, expected in expected_closeout_inputs.items():
        if deterministic_inputs.get(key) != expected:
            raise SystemExit(f"S20-350 closeout deterministic input drift: {key}")
    closeout_commands = {
        entry["command"]: entry["result"]
        for entry in closeout_validation.get("commands", [])
    }
    expected_closeout_commands = {
        "python3 scripts/check_mutation_value_codecs.py": "PASS",
        "cargo test -p sley-mutate --locked": "PASS_52_TESTS",
        (
            "cargo clippy -p sley-mutate --all-targets --locked -- -D warnings"
        ): "PASS",
        (
            "cargo clippy --manifest-path fuzz/Cargo.toml --bin "
            "mutation_candidate --locked -- -D warnings"
        ): "PASS",
        "make mutation-candidate-persistent-fuzz-smoke": "PASS_512_RUNS_26_SEEDS",
        "make conformance": "PASS",
        (
            "cargo clippy --workspace --all-targets --locked -- -D warnings"
        ): "PASS",
        "make quick": "PASS_WITH_S20_710_DEFERRED",
    }
    if closeout_commands != expected_closeout_commands:
        raise SystemExit("S20-350 closeout validation command drift")
    closeout_skipped = {
        entry["check"] for entry in closeout_validation.get("skipped_checks", [])
    }
    if closeout_skipped != {"make v2", "make release-check"}:
        raise SystemExit("S20-350 closeout skipped-gate drift")
    closeout_scope = closeout_validation.get("scope_limits", {})
    expected_scope = {
        "candidate_construction": True,
        "candidate_authority": False,
        "semantic_validation": False,
        "runtime_mutation": False,
        "full_sley_2_complete": False,
    }
    if closeout_scope != expected_scope:
        raise SystemExit("S20-350 closeout scope drift")
    if any(closeout_validation.get("external_actions", {}).values()):
        raise SystemExit("S20-350 closeout external-action drift")
    reviews = closeout_validation.get("reviews", {})
    if reviews != {
        "codex_focused_security_review": "PASS_NO_REPORT_GRADE_FINDINGS",
        "vulcan_independent_review": "DEFERRED_FORGE_OAUTH_401",
    }:
        raise SystemExit("S20-350 closeout review disposition drift")


def check_complete_s20_350_supplement() -> None:
    for path in (
        ORACLE_CANDIDATE_SOURCE,
        SUPPLEMENT_ACCEPTED,
        SUPPLEMENT_REJECTED,
        SUPPLEMENT_SUMS,
    ):
        if not path.is_file():
            raise SystemExit(f"S20-350 supplement missing: {path.relative_to(ROOT)}")

    expected_hashes = {
        "accepted.json": EXPECTED_SUPPLEMENT_ACCEPTED_SHA256,
        "rejected.json": EXPECTED_SUPPLEMENT_REJECTED_SHA256,
    }
    actual_hashes = {
        name: hashlib.sha256((SUPPLEMENT_DIR / name).read_bytes()).hexdigest()
        for name in expected_hashes
    }
    if actual_hashes != expected_hashes:
        raise SystemExit("S20-350 supplement digest drift")
    expected_sums = "".join(
        f"{expected_hashes[name]}  {name}\n"
        for name in ("accepted.json", "rejected.json")
    )
    if SUPPLEMENT_SUMS.read_text(encoding="utf-8") != expected_sums:
        raise SystemExit("S20-350 supplement SHA256SUMS drift")

    accepted = json.loads(SUPPLEMENT_ACCEPTED.read_text(encoding="utf-8"))
    rejected = json.loads(SUPPLEMENT_REJECTED.read_text(encoding="utf-8"))
    for label, fixture in (("accepted", accepted), ("rejected", rejected)):
        if fixture.get("contract") != "sley2-mutation-candidate-v1":
            raise SystemExit(f"S20-350 {label} supplement contract drift")
        if fixture.get("claim") != "complete-s20-350-conformance":
            raise SystemExit(f"S20-350 {label} supplement completeness drift")
        if fixture.get("source_schema_blake3") != EXPECTED_SCHEMA_BLAKE3:
            raise SystemExit(f"S20-350 {label} supplement schema drift")
        for inventory in ("value_vectors", "candidate_vectors"):
            ids = [vector["id"] for vector in fixture[inventory]]
            if len(ids) != len(set(ids)):
                raise SystemExit(f"S20-350 {label} {inventory} ID duplication")

    if len(accepted["value_vectors"]) != 44:
        raise SystemExit("S20-350 accepted value supplement is not 44")
    if len(accepted["candidate_vectors"]) != 1:
        raise SystemExit("S20-350 accepted candidate supplement is not one")
    if len(rejected["value_vectors"]) != 4:
        raise SystemExit("S20-350 rejected value supplement is not four")
    if len(rejected["candidate_vectors"]) != 14:
        raise SystemExit("S20-350 rejected candidate supplement is not fourteen")
    expected_coverage = {
        "combined_entity_bodies": 18,
        "combined_manifest_fields": 75,
        "combined_with": "conformance/mutation-value/v1/accepted.json",
        "const_data_variants": 16,
        "mutation_classes": 16,
        "supplemental_entity_bodies": 7,
        "supplemental_manifest_fields": 10,
        "terminator_variants": 5,
    }
    if accepted.get("coverage") != expected_coverage:
        raise SystemExit("S20-350 supplement coverage drift")
    expected_fields = {
        "field_namespace_parent": "Option<EntityId>",
        "field_type_def_form": "TypeDefForm",
        "field_block_terminator": "Terminator",
        "field_constant_value": "ConstValue",
        "field_capability_requirement_allowed_scopes": "List<ConstValue>",
        "field_contract_resource_limits": "Option<ResourceLimits>",
        "field_test_case_inputs": "List<ConstValue>",
        "field_test_case_effect_environment": "EffectEnvironment",
        "field_test_case_expected": "ExpectedOutcome",
        "field_test_case_observations": "List<ExpectedObservation>",
    }
    actual_fields = {
        vector["id"]: vector["declared_type"]
        for vector in accepted["value_vectors"]
        if vector["id"].startswith("field_")
    }
    if actual_fields != expected_fields:
        raise SystemExit("S20-350 supplemental field inventory drift")
    expected_bodies = {
        "body_namespace": "NamespaceBody",
        "body_type_def": "TypeDefBody",
        "body_block": "BlockBody",
        "body_constant": "ConstantBody",
        "body_capability_requirement": "CapabilityRequirementBody",
        "body_contract": "ContractBody",
        "body_test_case": "TestCaseBody",
    }
    actual_bodies = {
        vector["id"]: vector["declared_type"]
        for vector in accepted["value_vectors"]
        if vector["id"].startswith("body_")
    }
    if actual_bodies != expected_bodies:
        raise SystemExit("S20-350 supplemental body inventory drift")

    fixture_tests = FIXTURE_TEST_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "independent_s20_350_supplement_closes_values_and_candidate_bytes",
        "independent_s20_350_supplement_rejects_exact_codes",
        "assert_eq!(corpus.value_vectors.len(), 44)",
        "assert_eq!(corpus.candidate_vectors.len(), 1)",
        "assert_eq!(corpus.value_vectors.len(), 4)",
        "assert_eq!(corpus.candidate_vectors.len(), 14)",
        "assert_eq!(import_candidate(&built.stored_bytes).unwrap(), built)",
    ):
        if marker not in fixture_tests:
            raise SystemExit(f"S20-350 Rust supplement consumer drift: {marker}")

    oracle_candidate = ORACLE_CANDIDATE_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "def build_candidate(",
        "def import_candidate(",
        "def encode_candidate_record_unchecked(",
        "def check_candidate(",
        "def validation_profile_id(",
        "MUTATION_CANDIDATE_OPERATION_ORDINAL",
    ):
        if marker not in oracle_candidate:
            raise SystemExit(f"independent candidate oracle drift: {marker}")


def main() -> int:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_mutation_value_codecs.py"), "--check"],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_oracle_independence.py")],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            "uv",
            "run",
            "--project",
            "oracle/scb1",
            "--frozen",
            "python",
            "oracle/scb1/generate_s20_350_fixtures.py",
            "--check",
        ],
        cwd=ROOT,
        check=True,
    )
    check_partial_fixtures()
    check_complete_s20_350_supplement()

    manifest = MANIFEST.read_text(encoding="utf-8")
    generated = GENERATED.read_text(encoding="utf-8")
    value_source = VALUE_SOURCE.read_text(encoding="utf-8")
    descriptors = DESCRIPTORS.read_text(encoding="utf-8")
    codec_source = CODEC_SOURCE.read_text(encoding="utf-8")
    lib_source = LIB_SOURCE.read_text(encoding="utf-8")
    records = {
        match[1]: body_fields(match[2])
        for line in manifest.splitlines()
        if (match := RECORD_RE.fullmatch(line))
    }
    entities = [
        (int(match[1]), match[2], match[3])
        for line in manifest.splitlines()
        if (match := ENTITY_RE.fullmatch(line))
    ]
    if len(entities) != 18:
        raise SystemExit("mutation value host model entity inventory is not 18")
    if sum(len(records[body]) for _, _, body in entities) != 75:
        raise SystemExit("mutation value host model field inventory is not 75")

    for tag, name, body in entities:
        required = [
            f"pub struct {body} {{",
            f"{name}({body}),",
            f"Self::{name} => {tag},",
            f"Self::{name}(..) => EntityBodyValueKind::{name},",
        ]
        for field_tag, (field_name, _value_type, required_field) in enumerate(
            records[body], start=1
        ):
            variant = f"{name}{pascal(field_name)}"
            required.extend(
                [
                    f"\n    {variant}(",
                    f"Self::{variant} => ({tag}, {field_tag}),",
                    f"Self::{variant}(..) => FieldValueKind::{variant},",
                ]
            )
            if not required_field:
                body_start = generated.index(f"pub struct {body} {{")
                body_end = generated.index("\n}\n", body_start)
                body_source = generated[body_start:body_end]
                if f"pub {field_name}: Option<" not in body_source:
                    raise SystemExit(
                        f"optional manifest field lost in host body: {name}.{field_name}"
                    )
                if f"\n    {variant}(Option<" not in generated:
                    raise SystemExit(
                        f"optional manifest field lost in field value: {name}.{field_name}"
                    )
        for marker in required:
            if generated.count(marker) != 1:
                raise SystemExit(f"mutation value host model marker drift: {marker}")

    entity_by_tag = {tag: (name, body) for tag, name, body in entities}
    descriptor_rows = DESCRIPTOR_RE.findall(descriptors)
    if len(descriptor_rows) != 179:
        raise SystemExit("immutable descriptor inventory is not exactly 179")
    if generated.count("\n    TypedValueBinding {") != 179:
        raise SystemExit("typed value binding inventory is not exactly 179")
    for class_name, target_raw, field_option, field_raw in descriptor_rows:
        target = int(target_raw)
        entity_name, body = entity_by_tag[target]
        if class_name in {"DeleteEntityBinding", "RemoveEntryPoint"}:
            expected_kind = "ProposalValueKind::Unit"
        elif field_option == "None":
            expected_kind = (
                "ProposalValueKind::EntityBody("
                f"EntityBodyValueKind::{entity_name})"
            )
        else:
            field_tag = int(field_raw)
            field_name = records[body][field_tag - 1][0]
            variant = f"{entity_name}{pascal(field_name)}"
            expected_kind = f"ProposalValueKind::Field(FieldValueKind::{variant})"
        marker = "\n".join(
            [
                "    TypedValueBinding {",
                f"        class: MutationClass::{class_name},",
                f"        target_kind: {target},",
                f"        field_tag: {field_option},",
                f"        value_kind: {expected_kind},",
                "    },",
            ]
        )
        if generated.count(marker) != 1:
            raise SystemExit(
                "typed value binding does not match immutable descriptor: "
                f"{class_name}/{target}/{field_option}"
            )

    forbidden = [
        "ManifestValue",
        "GeneratedFieldCodec",
        "GeneratedValueBinding",
        "value_type: &'static str",
        "fn encode_type(",
        "fn decode_type(",
        "pub fn encode_proposal_value(",
        "pub fn decode_proposal_value(",
    ]
    combined = generated + value_source
    for marker in forbidden:
        if marker in combined:
            raise SystemExit(f"forbidden dynamic or premature codec surface: {marker}")

    if lib_source.count("\nmod codec;\n") != 1 or "pub mod codec" in lib_source:
        raise SystemExit("mutation value codec foundation must remain crate-private")
    if codec_source.count("\nmod fixture_tests;\n") != 1:
        raise SystemExit("private mutation fixture consumer module drift")
    if codec_source.count("\nmod adversarial_tests;\n") != 1:
        raise SystemExit("private mutation adversarial test module drift")
    codec_markers = [
        "trait MutationValueCodec",
        "MAX_NESTING_DEPTH",
        "MAX_TOTAL_ALLOCATION",
        "fn check_container_depth(",
        "impl MutationValueCodec for EntityIdSet",
        "impl MutationValueCodec for IntegerWidth",
        "impl MutationValueCodec for BuiltinFailureKind",
        "impl MutationValueCodec for NamedType",
        "impl MutationValueCodec for MapType",
        "impl MutationValueCodec for ResultType",
        "impl MutationValueCodec for FunctionType",
        "impl MutationValueCodec for TypeExpr",
        "fn encode_entity_id_set_vec(",
        "fn decode_entity_id_set_vec(",
        "impl MutationValueCodec for MemberId",
        "impl MutationValueCodec for OperationResultRef",
        "impl MutationValueCodec for ValueRef",
        "impl MutationValueCodec for FunctionRefValue",
        "impl MutationValueCodec for VariantImmediate",
        "impl MutationValueCodec for Immediate",
        "impl MutationValueCodec for TargetEdge",
        "impl SimpleEnumCodec for BuiltinCase",
        "impl MutationValueCodec for CaseKey",
        "impl MutationValueCodec for SwitchArgument",
        "impl MutationValueCodec for SwitchEdge",
        "impl MutationValueCodec for SwitchCase",
        "impl SimpleEnumCodec for TrapCode",
        "impl MutationValueCodec for ReturnTerminator",
        "impl MutationValueCodec for BranchTerminator",
        "impl MutationValueCodec for CondBranchTerminator",
        "impl MutationValueCodec for VariantSwitchTerminator",
        "impl MutationValueCodec for TrapTerminator",
        "impl MutationValueCodec for Terminator",
        "impl MutationValueCodec for TypeParameterDef",
        "impl MutationValueCodec for RecordField",
        "impl MutationValueCodec for VariantCase",
        "impl MutationValueCodec for TypeDefForm",
        "impl MutationValueCodec for BuiltinFailureValue",
        "impl MutationValueCodec for FieldConst",
        "impl MutationValueCodec for RecordConst",
        "impl MutationValueCodec for VariantConst",
        "impl MutationValueCodec for MapEntryConst",
        "impl MutationValueCodec for ResultConst",
        "impl MutationValueCodec for ConstData",
        "impl MutationValueCodec for ConstValue",
        "impl MutationValueCodec for ContractSource",
        "impl MutationValueCodec for ContractBinding",
        "impl MutationValueCodec for ReplayBinding",
        "impl MutationValueCodec for AdapterConfig",
        "impl MutationValueCodec for EffectEnvironment",
        "impl MutationValueCodec for ExpectedOutcome",
        "impl MutationValueCodec for ExpectedObservation",
        "impl MutationValueCodec for ResourceLimits",
        "impl MutationValueCodec for OperationBody",
        "impl MutationValueCodec for EntityBodyValue",
        "impl MutationValueCodec for CandidateExpiry",
        "impl MutationValueCodec for PreconditionPayload",
        "impl MutationValueCodec for BoundPrecondition",
        "impl MutationValueCodec for ValidationProfileRecord",
        "impl MutationValueCodec for MutationOperation",
        "impl MutationValueCodec for CandidateRecord",
        "pub(crate) fn encode_candidate_record",
        "pub(crate) fn decode_candidate_record",
        "pub(crate) fn build_candidate",
        "pub(crate) fn import_candidate",
        "pub(crate) fn full_validation_profile_id",
        "cfg_variant_switch_preserves_noncanonical_duplicate_case_list_order",
        "independent_manifest_helpers_round_trip_exact_records_and_unions",
        "independent_manifest_helpers_reject_payload_and_record_failures",
        "operation_body_round_trips_the_exact_six_field_record",
        "operation_body_rejects_record_shape_and_nested_trailing_failures",
        "None => encode_union(0, &[])",
        "Some(value) => encode_union(1, &encode_at_depth(value, depth + 1)?)",
        "ScbErrorCode::MapDuplicate",
        "ScbErrorCode::MapOrder",
    ]
    for marker in codec_markers:
        if marker not in codec_source:
            raise SystemExit(f"private mutation codec foundation drift: {marker}")
    required_macro_body_codecs = [
        "WorkspaceBody",
        "PackageBody",
        "NamespaceBody",
        "TypeDefBody",
        "FunctionBody",
        "ParameterBody",
        "BlockBody",
        "ConstantBody",
        "GlobalValueBody",
        "EffectDefBody",
        "CapabilityRequirementBody",
        "TestCaseBody",
        "AdapterImportBody",
        "EntryPointBody",
        "PolicyBindingBody",
        "DependencyBindingBody",
    ]
    for body in required_macro_body_codecs:
        marker = rf"impl_required_record_codec!\(\s*{body},"
        if len(re.findall(marker, codec_source)) != 1:
            raise SystemExit(f"complete private body codec drift: {body}")
    for body in ("OperationBody", "ContractBody"):
        if codec_source.count(f"impl MutationValueCodec for {body}") != 1:
            raise SystemExit(f"complete private body codec drift: {body}")
    for marker in [
        "workspace_and_package_bodies_use_exact_manifest_fields",
        "function_parameter_and_global_bodies_use_exact_manifest_fields",
        "effect_and_adapter_bodies_use_exact_manifest_fields",
        "entry_policy_and_dependency_bodies_use_exact_manifest_fields",
        "dependency_closed_body_records_reject_nested_trailing_bytes",
    ]:
        if marker not in codec_source:
            raise SystemExit(f"dependency-closed private body fixture drift: {marker}")
    type_expr_decode_arms = [
        (1, "Unit"),
        (2, "Bool"),
        (3, "SInt"),
        (4, "UInt"),
        (5, "F32"),
        (6, "F64"),
        (7, "Bytes"),
        (8, "Text"),
        (9, "Tuple"),
        (10, "Named"),
        (11, "Vector"),
        (12, "OrderedMap"),
        (13, "Option"),
        (14, "Result"),
        (15, "FunctionRef"),
        (16, "AdapterHandle"),
        (17, "CapabilityToken"),
        (18, "LocalCell"),
        (19, "TypeParameter"),
        (20, "BuiltinFailure"),
    ]
    type_expr_start = codec_source.index("impl MutationValueCodec for TypeExpr")
    type_expr_end = codec_source.index("\n#[cfg(test)]", type_expr_start)
    type_expr_codec = codec_source[type_expr_start:type_expr_end]
    for tag, variant in type_expr_decode_arms:
        arm_match = re.search(
            rf"\n\s*{tag}(?:\s+if\s+payload\.is_empty\(\))?\s*=>",
            type_expr_codec,
        )
        if arm_match is None:
            raise SystemExit(
                f"private TypeExpr decode arm drift: tag {tag} / {variant}"
            )
        next_arm = re.search(
            r"\n\s*(?:[0-9]+|_)(?:\s+if\s+payload\.is_empty\(\))?\s*=>",
            type_expr_codec[arm_match.end() :],
        )
        arm_end = (
            arm_match.end() + next_arm.start()
            if next_arm is not None
            else len(type_expr_codec)
        )
        if f"Self::{variant}" not in type_expr_codec[arm_match.start() : arm_end]:
            raise SystemExit(
                f"private TypeExpr decode arm drift: tag {tag} / {variant}"
            )
    for marker in (
        "pub fn encode_proposal",
        "pub fn decode_proposal",
        "impl MutationValueCodec for FieldValue",
        "impl MutationValueCodec for ProposalValue",
    ):
        if marker in codec_source:
            raise SystemExit(f"premature public codec/candidate surface: {marker}")
    candidate_source = CANDIDATE_SOURCE.read_text(encoding="utf-8")
    for marker in (
        "pub struct CandidateRecord",
        "pub enum MutationPayload",
        "pub struct BoundPrecondition",
        "pub fn encode_candidate_record",
        "pub fn decode_candidate_record",
        "pub fn build_candidate",
        "pub fn import_candidate",
        "pub fn full_validation_profile_id",
        'Self::TargetEntityMismatch => "MUTATION_CANDIDATE_TARGET_ENTITY"',
        "pub const fn numeric_code(&self) -> Option<u32>",
        "candidate_error_registry_is_exact_and_scb_stays_separate",
    ):
        if candidate_source.count(marker) != 1:
            raise SystemExit(f"candidate construction surface drift: {marker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
