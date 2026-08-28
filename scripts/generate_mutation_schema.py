#!/usr/bin/env python3
"""Generate immutable S20-340 Rust descriptors from the frozen SSMC1 manifest."""

from __future__ import annotations

import argparse
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/spec/SSMC1_EPOCH1_SCHEMA.txt"
OUTPUT = ROOT / "crates/sley-mutate/src/generated.rs"
EXPECTED_SHA256 = "8dbf14458d69482692464e00745f8f11a17007fa1e140ec040e92c7fd43f9c50"
EXPECTED_BLAKE3 = "1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae"

ENTITY_RE = re.compile(r"^entity ([0-9]+) ([A-Za-z][A-Za-z0-9]*) ([A-Za-z][A-Za-z0-9]*)$")
RECORD_RE = re.compile(r"^record ([A-Za-z][A-Za-z0-9]*)\((.*)\)$")
ENUM_RE = re.compile(r"^enum ([A-Za-z][A-Za-z0-9]*)\(")

SCALAR_PRIMITIVES = {
    "Bool",
    "Bytes",
    "F32",
    "F64",
    "FixedBytes32",
    "SInt",
    "Text",
    "UInt16",
    "UInt32",
    "UInt64",
}


@dataclass(frozen=True)
class Field:
    tag: int
    name: str
    value_type: str
    required: bool

    def scalar(self, enum_names: set[str]) -> bool:
        return self.value_type in SCALAR_PRIMITIVES or self.value_type in enum_names

    def direct_reference(self) -> bool:
        return self.value_type in {"EntityId", "Option<EntityId>"}

    def ordered_children(self) -> bool:
        return self.value_type == "List<EntityId>"

    def mutation_shape(self, enum_names: set[str]) -> str:
        if self.scalar(enum_names):
            return "Scalar"
        if self.direct_reference():
            return "DirectEntityReference"
        if self.ordered_children():
            return "OrderedEntityChildren"
        return "TypedOnly"


@dataclass(frozen=True)
class Entity:
    tag: int
    name: str
    body_name: str
    fields: tuple[Field, ...]


@dataclass(frozen=True)
class Operation:
    class_name: str
    target_kind: int
    field_tag: int | None
    value_type: str
    preimage: str


def split_top_level(value: str) -> list[str]:
    if not value:
        return []
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(value):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
            if depth < 0:
                raise ValueError(f"unbalanced generic close in {value!r}")
        elif char == "," and depth == 0:
            parts.append(value[start:index])
            start = index + 1
    if depth != 0:
        raise ValueError(f"unbalanced generic expression in {value!r}")
    parts.append(value[start:])
    return parts


def parse_field(raw: str) -> Field:
    pieces = raw.split(":", 2)
    if len(pieces) != 3:
        raise ValueError(f"invalid record field {raw!r}")
    tag_raw, name, typed = pieces
    if not typed or typed[-1] not in "!?":
        raise ValueError(f"field requiredness is not explicit in {raw!r}")
    return Field(
        tag=int(tag_raw),
        name=name,
        value_type=typed[:-1],
        required=typed[-1] == "!",
    )


def parse_manifest(raw: bytes) -> tuple[list[Entity], set[str]]:
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(
            "canonical manifest changed: update its frozen review and both digest pins before codegen"
        )
    text = raw.decode("utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "schema sley2.ssmc1.v1":
        raise ValueError("unexpected schema identity")

    entity_rows: list[tuple[int, str, str]] = []
    record_rows: dict[str, tuple[Field, ...]] = {}
    enum_names: set[str] = set()
    for line in lines:
        if match := ENTITY_RE.fullmatch(line):
            entity_rows.append((int(match[1]), match[2], match[3]))
        if match := RECORD_RE.fullmatch(line):
            fields = tuple(parse_field(raw_field) for raw_field in split_top_level(match[2]))
            if [field.tag for field in fields] != list(range(1, len(fields) + 1)):
                raise ValueError(f"record {match[1]} field tags are not closed and ascending")
            if match[1] in record_rows:
                raise ValueError(f"duplicate record {match[1]}")
            record_rows[match[1]] = fields
        if match := ENUM_RE.match(line):
            enum_names.add(match[1])

    if [row[0] for row in entity_rows] != list(range(1, 19)):
        raise ValueError("entity tags must be exactly 1 through 18")
    if len({row[1] for row in entity_rows}) != 18:
        raise ValueError("entity names must be unique")

    entities = [
        Entity(tag, name, body_name, record_rows[body_name])
        for tag, name, body_name in entity_rows
    ]
    expected_specials = {
        13: "Contract",
        14: "TestCase",
        16: "EntryPoint",
        18: "DependencyBinding",
    }
    for tag, name in expected_specials.items():
        if entities[tag - 1].name != name:
            raise ValueError(f"special mutation target {tag} is not {name}")
    return entities, enum_names


def build_operations(entities: list[Entity], enum_names: set[str]) -> list[Operation]:
    operations: list[Operation] = []

    for class_name, preimage in [
        ("CreateEntity", "ExpectedIdentityAbsent"),
        ("ReplaceEntityVersion", "ExactEntityVersion"),
        ("DeleteEntityBinding", "ExactEntityVersion"),
    ]:
        operations.extend(
            Operation(class_name, entity.tag, None, entity.body_name, preimage)
            for entity in entities
        )

    field_classes = [
        ("SetScalarField", lambda field: field.scalar(enum_names), "ExactEntityVersion"),
        ("ReplaceTypedField", lambda _field: True, "ExactEntityVersion"),
        ("RetargetReference", Field.direct_reference, "ExactEntityVersion"),
        ("InsertOrderedChild", Field.ordered_children, "ExactContainerVersion"),
        ("RemoveOrderedChild", Field.ordered_children, "ExactContainerVersion"),
        ("MoveOrderedChild", Field.ordered_children, "ExactContainerVersion"),
    ]
    for class_name, eligible, preimage in field_classes:
        for entity in entities:
            for field in entity.fields:
                if eligible(field):
                    operations.append(
                        Operation(class_name, entity.tag, field.tag, field.value_type, preimage)
                    )

    special_classes = [
        ("AddEntryPoint", 16),
        ("RemoveEntryPoint", 16),
        ("AddTest", 14),
        ("ReplaceTest", 14),
        ("AddContract", 13),
        ("ReplaceContract", 13),
        ("UpdateDependencyBinding", 18),
    ]
    for class_name, kind_tag in special_classes:
        entity = entities[kind_tag - 1]
        operations.append(
            Operation(class_name, kind_tag, None, entity.body_name, "ExactEntityVersion")
        )
    return operations


def rust_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def bool_literal(value: bool) -> str:
    return "true" if value else "false"


def render(entities: list[Entity], enum_names: set[str]) -> str:
    digest_bytes = ", ".join(f"0x{EXPECTED_BLAKE3[index:index + 2]}" for index in range(0, 64, 2))
    lines = [
        "// @generated by scripts/generate_mutation_schema.py; DO NOT EDIT.",
        f"// source: docs/spec/SSMC1_EPOCH1_SCHEMA.txt; blake3-256: {EXPECTED_BLAKE3}",
        "",
        "/// BLAKE3-256 of the exact canonical source schema manifest.",
        f"pub const SOURCE_SCHEMA_BLAKE3: [u8; 32] = [{digest_bytes}];",
        "",
    ]

    for entity in entities:
        lines.append(f"const FIELDS_{entity.tag}: &[FieldSchemaDescriptor] = &[")
        for field in entity.fields:
            lines.extend(
                [
                    "    FieldSchemaDescriptor {",
                    f"        tag: {field.tag},",
                    f"        name: {rust_string(field.name)},",
                    f"        value_type: {rust_string(field.value_type)},",
                    f"        required: {bool_literal(field.required)},",
                    f"        mutation_shape: FieldMutationShape::{field.mutation_shape(enum_names)},",
                    "    },",
                ]
            )
        lines.extend(["];"])

    lines.extend(["", "/// All eighteen frozen SSMC1 entity-body schemas.", "pub const ENTITY_SCHEMAS: &[EntitySchemaDescriptor] = &["])
    for entity in entities:
        lines.extend(
            [
                "    EntitySchemaDescriptor {",
                f"        kind_tag: {entity.tag},",
                f"        kind_name: {rust_string(entity.name)},",
                f"        body_name: {rust_string(entity.body_name)},",
                f"        fields: FIELDS_{entity.tag},",
                "    },",
            ]
        )
    lines.extend(["];", "", "/// All concrete, schema-generated S20-340 operation affordances.", "pub const MUTATION_OPERATIONS: &[MutationOperationDescriptor] = &["])
    for operation in build_operations(entities, enum_names):
        field_tag = "None" if operation.field_tag is None else f"Some({operation.field_tag})"
        lines.extend(
            [
                "    MutationOperationDescriptor {",
                f"        class: MutationClass::{operation.class_name},",
                f"        target_kind: {operation.target_kind},",
                f"        field_tag: {field_tag},",
                f"        value_type: {rust_string(operation.value_type)},",
                f"        preimage: PreimageRequirement::{operation.preimage},",
                "    },",
            ]
        )
    lines.extend(["];", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed output differs")
    args = parser.parse_args()

    entities, enum_names = parse_manifest(MANIFEST.read_bytes())
    generated = render(entities, enum_names)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != generated:
            raise SystemExit("generated mutation schema drift: run scripts/generate_mutation_schema.py")
        return 0
    OUTPUT.write_text(generated, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
