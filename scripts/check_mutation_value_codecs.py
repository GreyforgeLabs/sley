#!/usr/bin/env python3
"""Check closed S20-350 host, binding, and private staged codec slices."""

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
FIXTURE_TEST_SOURCE = ROOT / "crates/sley-mutate/src/codec/fixture_tests.rs"
ADVERSARIAL_TEST_SOURCE = ROOT / "crates/sley-mutate/src/codec/adversarial_tests.rs"
MAKEFILE_SOURCE = ROOT / "Makefile"
M1_GATE_SOURCE = ROOT / "scripts/check_m1_gate.py"
MACHINE_SUMMARY = ROOT / "machineresearch/sley-2.0/machine-summary.json"
ADVERSARIAL_DOSSIER = (
    ROOT / "machineresearch/sley-2.0/14-property-fuzz-and-adversarial-results.md"
)
VALIDATION_EVIDENCE = (
    ROOT / "evidence/validation/s20-700-mutation-value-bounded-v1.json"
)
ORACLE_SOURCE = ROOT / "oracle/scb1/src/sley2_scb1_oracle/mutation_value.py"
ACCEPTED_FIXTURES = ROOT / "conformance/mutation-value/v1/accepted.json"
REJECTED_FIXTURES = ROOT / "conformance/mutation-value/v1/rejected.json"
FIXTURE_SUMS = ROOT / "conformance/mutation-value/v1/SHA256SUMS"

EXPECTED_ACCEPTED_FIXTURE_SHA256 = (
    "57b1e3845dad4264c379e0f293131b4fc1076abc28fb786f15ff9e6977beca3e"
)
EXPECTED_REJECTED_FIXTURE_SHA256 = (
    "44a2752f830a057aad3a636c266d64ab9738f5800ed6fbf6404f91c6c1eee756"
)
EXPECTED_SCHEMA_BLAKE3 = (
    "044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73"
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
        VALIDATION_EVIDENCE,
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
        "status": "S20_350_PARTIAL_PRIVATE_VALUE_CODEC_AND_CONFORMANCE",
        "private_entity_body_codecs": 11,
        "independent_accepted_vectors": 126,
        "independent_rejected_vectors": 18,
        "manifest_field_fixtures": 65,
        "blocked_manifest_fields": 10,
        "bounded_adversarial_seeds": 126,
        "bounded_trailing_mutations": 252,
        "bounded_proper_prefix_mutations": 446,
        "bounded_derived_mutations": 698,
        "exact_rejection_code_vectors": 18,
        "generic_option_canon_resolved": False,
        "const_value_canon_resolved": False,
        "aggregate_codecs": False,
        "candidate_construction": False,
        "runtime_mutation": False,
        "full_s20_350_complete": False,
        "validation_evidence": "evidence/validation/s20-700-mutation-value-bounded-v1.json",
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
        "full_s20_700_complete": False,
    }
    for key, expected in expected_adversarial_summary.items():
        if adversarial_summary.get(key) != expected:
            raise SystemExit(f"partial mutation adversarial summary drift: {key}")
    dossier = ADVERSARIAL_DOSSIER.read_text(encoding="utf-8")
    for marker in (
        "Status: bounded partial S20-700 evidence with",
        "scoped persistent libFuzzer",
        "all 126 accepted fixtures seed 252 trailing-byte and",
        "446 distinct proper-prefix cases, for 698 deterministic derived mutations",
        "Persistent fuzzing and minimized finding retention",
    ):
        if dossier.count(marker) != 1:
            raise SystemExit(f"partial mutation adversarial dossier drift: {marker}")
    validation = json.loads(VALIDATION_EVIDENCE.read_text(encoding="utf-8"))
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
    check_partial_fixtures()

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
        if field_option == "None":
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
        "impl MutationValueCodec for TypeParameterDef",
        "impl MutationValueCodec for RecordField",
        "impl MutationValueCodec for BuiltinFailureValue",
        "impl MutationValueCodec for ContractSource",
        "impl MutationValueCodec for ContractBinding",
        "impl MutationValueCodec for ResourceLimits",
        "impl MutationValueCodec for OperationBody",
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
    required_body_codecs = [
        "WorkspaceBody",
        "PackageBody",
        "FunctionBody",
        "ParameterBody",
        "GlobalValueBody",
        "EffectDefBody",
        "AdapterImportBody",
        "EntryPointBody",
        "PolicyBindingBody",
        "DependencyBindingBody",
    ]
    for body in required_body_codecs:
        marker = rf"impl_required_record_codec!\(\s*{body},"
        if len(re.findall(marker, codec_source)) != 1:
            raise SystemExit(f"dependency-closed private body codec drift: {body}")
    for body in [
        "NamespaceBody",
        "TypeDefBody",
        "BlockBody",
        "ConstantBody",
        "CapabilityRequirementBody",
        "ContractBody",
        "TestCaseBody",
    ]:
        marker = rf"(?:impl MutationValueCodec for {body}|impl_required_record_codec!\(\s*{body},)"
        if re.search(marker, codec_source) is not None:
            raise SystemExit(f"premature blocked private body codec: {body}")
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
    for marker in [
        "pub fn encode_proposal",
        "pub fn decode_proposal",
        "pub fn encode_candidate",
        "pub fn decode_candidate",
        "impl MutationValueCodec for TrapTerminator",
        "impl MutationValueCodec for Terminator",
        "impl MutationValueCodec for EntityBodyValue",
        "impl MutationValueCodec for FieldValue",
        "impl MutationValueCodec for ProposalValue",
    ]:
        if marker in codec_source:
            raise SystemExit(f"premature public codec/candidate surface: {marker}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
