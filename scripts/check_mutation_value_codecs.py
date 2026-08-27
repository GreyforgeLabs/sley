#!/usr/bin/env python3
"""Check closed S20-350 proposal host values and typed descriptor bindings."""

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
