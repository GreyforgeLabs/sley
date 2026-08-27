#!/usr/bin/env python3
"""Fail if the independent SCB1 oracle acquires a Rust implementation dependency."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "oracle/scb1"
forbidden = (
    "subprocess",
    "cargo",
    "sley-id",
    "sley_id",
    "sley-mutate",
    "sley_mutate",
    "crates/sley-mutate",
    "value_generated.rs",
    "target/",
)
problems: list[str] = []
for path in sorted((ORACLE / "src").rglob("*.py")):
    text = path.read_text(encoding="utf-8")
    for marker in forbidden:
        if marker in text:
            problems.append(
                f"{path.relative_to(ROOT)} contains forbidden marker {marker!r}"
            )

result = {
    "contract": "s20-130-oracle-independence-v1",
    "result": "FAIL" if problems else "PASS",
    "python_sources": len(list((ORACLE / "src").rglob("*.py"))),
    "forbidden_markers": list(forbidden),
    "problems": problems,
}
print(json.dumps(result, indent=2, sort_keys=True))
if problems:
    raise SystemExit(1)
