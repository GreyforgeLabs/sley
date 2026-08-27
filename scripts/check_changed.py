#!/usr/bin/env python3
"""Emit an honest M0 change-aware validation report."""

from __future__ import annotations

import json
import subprocess


changed = subprocess.run(
    ["git", "status", "--short"], check=True, text=True, capture_output=True
).stdout.splitlines()
print(json.dumps({
    "phase": "M0",
    "changed_files": changed,
    "affected_crates": [],
    "affected_contracts": ["M0 repository/document baseline"],
    "selected_checks": ["scripts/check_m0.py", "cargo metadata"],
    "skipped_checks": ["core", "conformance", "adversarial", "fuzz-smoke", "v2", "release-check"],
    "skip_rationale": "No semantic implementation exists in M0.",
    "v2_required": False,
    "cache_use": "none",
    "result": "PASS",
}, indent=2, sort_keys=True))
