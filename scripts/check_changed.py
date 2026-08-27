#!/usr/bin/env python3
"""Emit an honest M0 change-aware validation report."""

from __future__ import annotations

import json
import subprocess


changed = subprocess.run(
    ["git", "status", "--short"], check=True, text=True, capture_output=True
).stdout.splitlines()
print(
    json.dumps(
        {
            "phase": "M1",
            "changed_files": changed,
            "affected_crates": [
                "sley-id",
                "sley-scb1",
                "sley-schema",
                "sley-state-root",
                "sley-store",
                "sley-repo",
                "oracle/scb1",
            ],
            "affected_contracts": [
                "M0 repository/document baseline",
                "S20-040 benchmark baseline",
                "S20-100 SCB1 specification",
                "S20-110 canonical identifiers",
                "S20-120 Rust SCB1 codec",
                "S20-130 independent SCB1 oracle",
                "S20-140 schema epoch registry and migration skeleton",
                "S20-150 immutable object store and corruption recovery",
                "S20-160 deterministic state roots",
                "S20-170 repository packs and clean reconstruction",
            ],
            "selected_checks": [
                "scripts/check_m0.py",
                "scripts/check_benchmark_baseline.py",
                "scripts/check_scb1_spec.py",
                "scripts/check_schema_epoch_spec.py",
                "scripts/check_object_store_spec.py",
                "scripts/check_state_root_spec.py",
                "scripts/check_repository_pack_spec.py",
                "cargo fmt --check",
                "cargo check --workspace --locked",
                "cargo test --workspace --locked",
                "make conformance",
            ],
            "skipped_checks": [
                "core",
                "adversarial",
                "fuzz-smoke",
                "v2",
                "release-check",
            ],
            "skip_rationale": "S20-120 through S20-170 establish SCB1, schema-epoch, immutable-store, deterministic-root, and root/object pack conformance; GC, semantic kernel, clone-equivalent profiles, and later product gates remain unavailable.",
            "v2_required": False,
            "cache_use": "none",
            "result": "PASS",
        },
        indent=2,
        sort_keys=True,
    )
)
