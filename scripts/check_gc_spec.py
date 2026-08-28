#!/usr/bin/env python3
"""Check the frozen S20-180 GC/retention contract surface."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs/spec/GARBAGE_COLLECTION_V1.md"
SOURCE = ROOT / "crates/sley-repo/src/gc.rs"
THREATS = ROOT / "docs/THREAT_REGISTER.md"

SPEC_MARKERS = (
    "`ref`",
    "`tag`",
    "`lease`",
    "`transaction`",
    "`pack_manifest`",
    "`protected_root`",
    "`session_pin`",
    "There is no expiry timestamp or age comparison in this API.",
    "GC_REACHABILITY_VIOLATION",
    "`locks/maintenance.lock` ownership",
    "S20-390 transaction operations and S20-500",
    "interleaving with GC deletion",
    "inventory objects: `262,144`",
)
SOURCE_MARKERS = (
    "pub trait GcObjectVerifier",
    "pub fn gc_dry_run",
    "pub fn gc_collect",
    "pub fn acquire_exclusive_gc",
    "fn plan_gc",
    "fn inventory",
    "fn traverse_roots",
    "fn traverse_objects",
    "GcDecision::PartialDeleteFailure",
    "DeleteFault::AfterDeleteBeforeSync",
)
FORBIDDEN_SOURCE_MARKERS = (
    "SystemTime",
    ".modified()",
    ".created()",
    "UNIX_EPOCH",
)


def main() -> int:
    problems: list[str] = []
    for path in (SPEC, SOURCE, THREATS):
        if not path.is_file():
            problems.append(f"missing:{path.relative_to(ROOT)}")
    spec = SPEC.read_text() if SPEC.is_file() else ""
    source = SOURCE.read_text() if SOURCE.is_file() else ""
    threats = THREATS.read_text() if THREATS.is_file() else ""
    for marker in SPEC_MARKERS:
        if marker not in spec:
            problems.append(f"spec-marker:{marker}")
    for marker in SOURCE_MARKERS:
        if marker not in source:
            problems.append(f"source-marker:{marker}")
    for marker in FORBIDDEN_SOURCE_MARKERS:
        if marker in source:
            problems.append(f"forbidden-source-marker:{marker}")
    if "| T40 | GC deletes reachable object |" not in threats:
        problems.append("threat:T40")
    unit_tests = source.count("#[test]")
    if unit_tests < 19:
        problems.append(f"unit-tests:{unit_tests}<19")
    print(
        json.dumps(
            {
                "anchor_kinds": 7,
                "contract": "s20-180-gc-retention-v1",
                "implementation": "crates/sley-repo/src/gc.rs",
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
                "rust_unit_tests": unit_tests,
                "threat": "T40",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
