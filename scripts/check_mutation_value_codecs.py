#!/usr/bin/env python3
"""Check closed S20-350 host, binding, and private staged codec slices."""

from __future__ import annotations

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


def main() -> int:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/generate_mutation_value_codecs.py"), "--check"],
        cwd=ROOT,
        check=True,
    )

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
