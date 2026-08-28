#!/usr/bin/env python3
"""Generate the closed S20-350a mutation proposal host-value model."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/spec/SSMC1_EPOCH1_SCHEMA.txt"
OUTPUT = ROOT / "crates/sley-mutate/src/value_generated.rs"
SCHEMA_GENERATOR = ROOT / "scripts/generate_mutation_schema.py"
EXPECTED_SHA256 = "8dbf14458d69482692464e00745f8f11a17007fa1e140ec040e92c7fd43f9c50"
EXPECTED_BLAKE3 = "1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae"

ENTITY_RE = re.compile(r"^entity ([0-9]+) ([A-Za-z][A-Za-z0-9]*) ([A-Za-z][A-Za-z0-9]*)$")
RECORD_RE = re.compile(r"^record ([A-Za-z][A-Za-z0-9]*)\((.*)\)$")


@dataclass(frozen=True)
class Field:
    tag: int
    name: str
    value_type: str
    required: bool


@dataclass(frozen=True)
class Entity:
    tag: int
    name: str
    body_name: str
    fields: tuple[Field, ...]


def load_schema_generator():
    spec = importlib.util.spec_from_file_location("sley2_mutation_schema_codegen", SCHEMA_GENERATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load mutation schema generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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
    tag_raw, name, typed = raw.split(":", 2)
    if not typed or typed[-1] not in "!?":
        raise ValueError(f"field requiredness is not explicit in {raw!r}")
    return Field(int(tag_raw), name, typed[:-1], typed[-1] == "!")


def parse_manifest(raw: bytes) -> list[Entity]:
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise ValueError("canonical manifest changed: update frozen review and digest pins")
    records: dict[str, tuple[Field, ...]] = {}
    entity_rows: list[tuple[int, str, str]] = []
    for line in raw.decode("utf-8").splitlines():
        if match := RECORD_RE.fullmatch(line):
            fields = tuple(parse_field(part) for part in split_top_level(match[2]))
            if [field.tag for field in fields] != list(range(1, len(fields) + 1)):
                raise ValueError(f"record {match[1]} field tags are not closed and ascending")
            records[match[1]] = fields
        if match := ENTITY_RE.fullmatch(line):
            entity_rows.append((int(match[1]), match[2], match[3]))
    if [row[0] for row in entity_rows] != list(range(1, 19)):
        raise ValueError("entity tags must be exactly 1 through 18")
    entities = [Entity(tag, name, body, records[body]) for tag, name, body in entity_rows]
    if sum(len(entity.fields) for entity in entities) != 75:
        raise ValueError("entity-body field inventory must remain exactly 75")
    return entities


def generic_arg(value: str, head: str) -> str | None:
    prefix = f"{head}<"
    if value.startswith(prefix) and value.endswith(">"):
        return value[len(prefix) : -1]
    return None


def rust_type(value: str) -> str:
    if inner := generic_arg(value, "List"):
        return f"Vec<{rust_type(inner)}>"
    if inner := generic_arg(value, "Set"):
        if inner != "EntityId":
            raise ValueError(f"no closed canonical set host type for {value}")
        return "EntityIdSet"
    if inner := generic_arg(value, "Option"):
        return f"Option<{rust_type(inner)}>"
    primitives = {
        "Bool": "bool",
        "Bytes": "Vec<u8>",
        "F32": "u32",
        "F64": "u64",
        "FixedBytes32": "[u8; 32]",
        "SInt": "i64",
        "Text": "String",
        "UInt16": "u16",
        "UInt32": "u32",
        "UInt64": "u64",
        "EntityId": "EntityId",
        "StateRoot": "StateRoot",
        "EntryExposure": "EntryExposure",
    }
    if value in primitives:
        return primitives[value]
    return f"sley_ssmc::{value}"


def rust_field_type(field: Field) -> str:
    value_type = rust_type(field.value_type)
    return value_type if field.required else f"Option<{value_type}>"


def pascal(value: str) -> str:
    return "".join(piece[:1].upper() + piece[1:] for piece in value.split("_"))


def render(entities: list[Entity], operations) -> str:
    digest_bytes = ", ".join(
        f"0x{EXPECTED_BLAKE3[index:index + 2]}" for index in range(0, 64, 2)
    )
    lines = [
        "// @generated by scripts/generate_mutation_value_codecs.py; DO NOT EDIT.",
        f"// source: docs/spec/SSMC1_EPOCH1_SCHEMA.txt; blake3-256: {EXPECTED_BLAKE3}",
        "",
        "/// BLAKE3-256 of the exact canonical schema manifest used for host values.",
        f"pub const VALUE_HOST_SOURCE_SCHEMA_BLAKE3: [u8; 32] = [{digest_bytes}];",
        "/// Closed entity-body host-value count.",
        f"pub const ENTITY_BODY_VALUE_COUNT: usize = {len(entities)};",
        "/// Closed entity-body field-value count.",
        f"pub const FIELD_VALUE_COUNT: usize = {sum(len(entity.fields) for entity in entities)};",
        "/// Exact immutable descriptor-to-typed-value binding count.",
        f"pub const TYPED_VALUE_BINDING_COUNT: usize = {len(operations)};",
        "",
    ]
    for entity in entities:
        lines.extend([
            f"/// Closed proposal-only body for entity kind {entity.tag} (`{entity.name}`).",
            "#[derive(Clone, Debug, Eq, PartialEq)]",
            f"pub struct {entity.body_name} {{",
        ])
        for field in entity.fields:
            lines.extend([
                f"    /// Exact manifest field {field.tag} (`{field.name}`).",
                f"    pub {field.name}: {rust_field_type(field)},",
            ])
        lines.extend(["}", ""])

    lines.extend([
        "/// Closed discriminant for one complete SSMC1 entity-body value.",
        "#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]",
        "pub enum EntityBodyValueKind {",
    ])
    for entity in entities:
        lines.extend([
            f"    /// Entity kind {entity.tag} (`{entity.name}`).",
            f"    {entity.name},",
        ])
    lines.extend([
        "}",
        "",
        "impl EntityBodyValueKind {",
        "    /// Returns the exact closed SSMC1 entity-kind tag.",
        "    #[must_use]",
        "    pub const fn kind_tag(self) -> u16 {",
        "        match self {",
    ])
    for entity in entities:
        lines.append(f"            Self::{entity.name} => {entity.tag},")
    lines.extend(["        }", "    }", "}", ""])

    lines.extend([
        "/// Closed typed value for one complete SSMC1 entity body.",
        "#[derive(Clone, Debug, Eq, PartialEq)]",
        "pub enum EntityBodyValue {",
    ])
    for entity in entities:
        lines.extend([
            f"    /// Entity kind {entity.tag} (`{entity.name}`).",
            f"    {entity.name}({entity.body_name}),",
        ])
    lines.extend([
        "}",
        "",
        "impl EntityBodyValue {",
        "    /// Returns the exact closed body-value discriminant.",
        "    #[must_use]",
        "    pub const fn value_kind(&self) -> EntityBodyValueKind {",
        "        match self {",
    ])
    for entity in entities:
        lines.append(
            f"            Self::{entity.name}(..) => EntityBodyValueKind::{entity.name},"
        )
    lines.extend([
        "        }",
        "    }",
        "",
        "    /// Returns the exact closed SSMC1 entity-kind tag.",
        "    #[must_use]",
        "    pub const fn kind_tag(&self) -> u16 {",
        "        self.value_kind().kind_tag()",
        "    }",
        "}",
        "",
    ])

    lines.extend([
        "/// Closed discriminant for one exact SSMC1 entity-body field value.",
        "#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]",
        "pub enum FieldValueKind {",
    ])
    for entity in entities:
        for field in entity.fields:
            variant = f"{entity.name}{pascal(field.name)}"
            lines.extend([
                f"    /// Kind {entity.tag}, field {field.tag} (`{entity.name}.{field.name}`).",
                f"    {variant},",
            ])
    lines.extend([
        "}",
        "",
        "impl FieldValueKind {",
        "    /// Returns the exact `(entity_kind, field_tag)` selected by this discriminant.",
        "    #[must_use]",
        "    pub const fn field_key(self) -> (u16, u16) {",
        "        match self {",
    ])
    for entity in entities:
        for field in entity.fields:
            variant = f"{entity.name}{pascal(field.name)}"
            lines.append(f"            Self::{variant} => ({entity.tag}, {field.tag}),")
    lines.extend(["        }", "    }", "}", ""])

    lines.extend([
        "/// Closed typed value for one exact SSMC1 entity-body field.",
        "#[derive(Clone, Debug, Eq, PartialEq)]",
        "pub enum FieldValue {",
    ])
    for entity in entities:
        for field in entity.fields:
            variant = f"{entity.name}{pascal(field.name)}"
            lines.extend([
                f"    /// Kind {entity.tag}, field {field.tag} (`{entity.name}.{field.name}`).",
                f"    {variant}({rust_field_type(field)}),",
            ])
    lines.extend([
        "}",
        "",
        "impl FieldValue {",
        "    /// Returns the exact closed field-value discriminant.",
        "    #[must_use]",
        "    pub const fn value_kind(&self) -> FieldValueKind {",
        "        match self {",
    ])
    for entity in entities:
        for field in entity.fields:
            variant = f"{entity.name}{pascal(field.name)}"
            lines.append(f"            Self::{variant}(..) => FieldValueKind::{variant},")
    lines.extend([
        "        }",
        "    }",
        "",
        "    /// Returns the exact `(entity_kind, field_tag)` selected by this value.",
        "    #[must_use]",
        "    pub const fn field_key(&self) -> (u16, u16) {",
        "        self.value_kind().field_key()",
        "    }",
        "}",
        "",
    ])

    lines.extend([
        "/// Closed descriptor-selectable proposal-value discriminant.",
        "#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]",
        "pub enum ProposalValueKind {",
        "    /// Unit operation payload with no body bytes.",
        "    Unit,",
        "    /// One complete entity-body kind.",
        "    EntityBody(EntityBodyValueKind),",
        "    /// One exact body-field kind.",
        "    Field(FieldValueKind),",
        "}",
        "",
        "/// Closed proposal value before any candidate record exists.",
        "#[derive(Clone, Debug, Eq, PartialEq)]",
        "pub enum ProposalValue {",
        "    /// Unit operation payload with no body bytes.",
        "    Unit,",
        "    /// One complete entity body.",
        "    EntityBody(EntityBodyValue),",
        "    /// One exact entity-body field.",
        "    Field(FieldValue),",
        "}",
        "",
        "impl ProposalValue {",
        "    /// Returns the exact closed discriminant used for descriptor admission.",
        "    #[must_use]",
        "    pub const fn value_kind(&self) -> ProposalValueKind {",
        "        match self {",
        "            Self::Unit => ProposalValueKind::Unit,",
        "            Self::EntityBody(value) => ProposalValueKind::EntityBody(value.value_kind()),",
        "            Self::Field(value) => ProposalValueKind::Field(value.value_kind()),",
        "        }",
        "    }",
        "}",
        "",
        "/// One exact immutable mutation descriptor to closed value-kind binding.",
        "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
        "pub struct TypedValueBinding {",
        "    /// Closed mutation class.",
        "    pub class: MutationClass,",
        "    /// Exact target entity kind.",
        "    pub target_kind: u16,",
        "    /// Exact field tag, or `None` for a complete body or Unit operation.",
        "    pub field_tag: Option<u16>,",
        "    /// Exact closed proposal-value kind.",
        "    pub value_kind: ProposalValueKind,",
        "}",
        "",
        "/// Complete immutable descriptor-to-value-kind binding table.",
        "pub const TYPED_VALUE_BINDINGS: &[TypedValueBinding] = &[",
    ])
    entity_by_tag = {entity.tag: entity for entity in entities}
    for operation in operations:
        entity = entity_by_tag[operation.target_kind]
        if operation.value_type == "Unit":
            field_tag = "None"
            value_kind = "ProposalValueKind::Unit"
        elif operation.field_tag is None:
            field_tag = "None"
            value_kind = (
                "ProposalValueKind::EntityBody("
                f"EntityBodyValueKind::{entity.name})"
            )
        else:
            field_tag = f"Some({operation.field_tag})"
            field = entity.fields[operation.field_tag - 1]
            variant = f"{entity.name}{pascal(field.name)}"
            value_kind = f"ProposalValueKind::Field(FieldValueKind::{variant})"
        lines.extend([
            "    TypedValueBinding {",
            f"        class: MutationClass::{operation.class_name},",
            f"        target_kind: {operation.target_kind},",
            f"        field_tag: {field_tag},",
            f"        value_kind: {value_kind},",
            "    },",
        ])
    lines.extend(["];", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed output differs")
    args = parser.parse_args()
    raw = MANIFEST.read_bytes()
    entities = parse_manifest(raw)
    schema_generator = load_schema_generator()
    schema_entities, enum_names = schema_generator.parse_manifest(raw)
    operations = schema_generator.build_operations(schema_entities, enum_names)
    if len(operations) != 179:
        raise ValueError("descriptor binding inventory must remain exactly 179")
    generated = render(entities, operations)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != generated:
            raise SystemExit(
                "generated mutation value host model drift: run scripts/generate_mutation_value_codecs.py"
            )
        return 0
    OUTPUT.write_text(generated, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
