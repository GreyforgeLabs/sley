#!/usr/bin/env python3
"""Emit honest scoped M1 profile completion after Make has run the checks."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = json.loads((ROOT / "machineresearch/sley-2.0/machine-summary.json").read_text())
GATE = sys.argv[1] if len(sys.argv) > 1 else "unknown"

SCOPES = {
    "core": {
        "executed_scope": [
            "SCB1 and identifier tests",
            "schema epoch tests",
            "immutable object-store tests",
            "StateRoot tests",
            "repository pack and GC tests",
        ],
        "deferred_unimplemented": [
            "SSMC graph/type/effect kernel",
            "transaction/policy/protocol/VM cores",
        ],
    },
    "adversarial": {
        "executed_scope": [
            "T03/T04 object corruption and substitution",
            "T37 object-write interruption/recovery",
            "T40 GC graph/pin/lease reachability and delete/sync faults",
            "T41 malicious pack and inventory closure",
            "T42 unsupported compression fail-closed",
            "T50 host/Git identity exclusion",
            "T51 transport tamper detection at the pack boundary",
        ],
        "deferred_unimplemented": [
            "candidate, policy, capability, query, merge, protocol, and VM attacks",
        ],
    },
    "fuzz-smoke": {
        "executed_scope": [
            "256 deterministic SCB1 decoder noise inputs",
            "512 bounded deterministic schema bootstrap decoder/import inputs",
            "128 deterministic invalid object-store inputs",
            "128 rehashed repository-pack byte mutations",
            "GC malformed graph/inventory/reference regression matrix",
        ],
        "deferred_unimplemented": [
            "persistent harnesses beyond the bounded S20-700 schema smoke slice",
            "future graph, type, CFG, query, mutation, merge, protocol, VM, and adapter targets",
        ],
    },
}


def main() -> int:
    problems: list[str] = []
    scope = SCOPES.get(GATE)
    if scope is None:
        problems.append("unknown-gate")
        scope = {"executed_scope": [], "deferred_unimplemented": []}
    for section, expected in (
        ("scb1", "S20_100_SPEC_S20_120_CODEC_S20_130_ORACLE_COMPLETE"),
        ("schema_epoch", "S20_140_COMPLETE"),
        ("object_store", "S20_150_COMPLETE"),
        ("state_root", "S20_160_COMPLETE"),
        ("repository_pack", "S20_170_COMPLETE"),
        ("garbage_collection", "S20_180_COMPLETE"),
    ):
        if SUMMARY.get(section, {}).get("status") != expected:
            problems.append(f"summary:{section}")
    print(
        json.dumps(
            {
                "deferred_unimplemented": scope["deferred_unimplemented"],
                "executed_scope": scope["executed_scope"],
                "gate": GATE,
                "phase": "M1",
                "problems": problems,
                "result": "PASS" if not problems else "FAIL",
                "scope": "IMPLEMENTED_M1_SURFACES_ONLY",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return int(bool(problems))


if __name__ == "__main__":
    raise SystemExit(main())
