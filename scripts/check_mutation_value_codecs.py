#!/usr/bin/env python3
"""Check the closed S20-350a mutation proposal host-value model."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/spec/SSMC1_EPOCH1_SCHEMA.txt"
GENERATED = ROOT / "crates/sley-mutate/src/value_generated.rs"
VALUE_SOURCE = ROOT / "crates/sley-mutate/src/value.rs"

ENTITY_RE = re.compile(r"^entity ([0-9]+) ([A-Za-z][A-Za-z0-9]*) ([A-Za-z][A-Za-z0-9]*)$")
RECORD_RE = re.compile(r"^record ([A-Za-z][A-Za-z0-9]*)\((.*)\)$")


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
            f"Self::{name}(..) => {tag},",
        ]
        for field_tag, (field_name, _value_type, required_field) in enumerate(
            records[body], start=1
        ):
            variant = f"{name}{pascal(field_name)}"
            required.extend(
                [
                    f"\n    {variant}(",
                    f"Self::{variant}(..) => ({tag}, {field_tag}),",
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
