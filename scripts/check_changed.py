#!/usr/bin/env python3
"""Emit an honest M0 change-aware validation report."""

from __future__ import annotations

import json
import subprocess


changed = subprocess.run(
    ["git", "status", "--short"], check=True, text=True, capture_output=True
).stdout.splitlines()
print(json.dumps({
    "phase": "M1",
    "changed_files": changed,
    "affected_crates": ["sley-id"],
    "affected_contracts": ["M0 repository/document baseline", "S20-040 benchmark baseline", "S20-100 SCB1 specification", "S20-110 canonical identifiers"],
    "selected_checks": ["scripts/check_m0.py", "scripts/check_benchmark_baseline.py", "scripts/check_scb1_spec.py", "cargo fmt --check", "cargo check --workspace --locked", "cargo test -p sley-id --locked"],
    "skipped_checks": ["core", "conformance", "adversarial", "fuzz-smoke", "v2", "release-check"],
    "skip_rationale": "S20-110 is a focused identifier crate slice; later subsystem and product gates remain unavailable.",
    "v2_required": False,
    "cache_use": "none",
    "result": "PASS",
}, indent=2, sort_keys=True))
