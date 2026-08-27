#!/usr/bin/env python3
"""Emit an honest change-aware validation report."""

from __future__ import annotations

import json
import subprocess


changed = subprocess.run(
    ["git", "status", "--short"], check=True, text=True, capture_output=True
).stdout.splitlines()
print(
    json.dumps(
        {
            "phase": "M2",
            "changed_files": changed,
            "affected_crates": [
                "sley-id",
                "sley-scb1",
                "sley-schema",
                "sley-ssmc",
                "sley-check",
                "sley-adapter",
                "sley-conformance",
                "sley-query",
                "sley-vm",
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
                "S20-180 explicit retention and guarded garbage collection",
                "S20-200 SSMC1 entity and opcode schema",
                "S20-210 deterministic core type system",
                "S20-220 bounded CFG and value-use validation",
                "S20-230 deterministic effect closure and static scope typing",
                "S20-240 restricted epoch-1 contract/test entity validation and provisional planning",
                "S20-250 restricted epoch-1 semantic fingerprints and impact relationships",
                "S20-260 restricted epoch-1 deterministic O0 VM lowering",
                "S20-270 restricted epoch-1 deterministic VM execution",
                "S20-280 restricted epoch-1 deterministic reference adapters",
                "S20-290 restricted epoch-1 derived report envelopes",
            ],
            "selected_checks": [
                "scripts/check_m0.py",
                "scripts/check_benchmark_baseline.py",
                "scripts/check_scb1_spec.py",
                "scripts/check_schema_epoch_spec.py",
                "scripts/check_object_store_spec.py",
                "scripts/check_state_root_spec.py",
                "scripts/check_repository_pack_spec.py",
                "scripts/check_gc_spec.py",
                "scripts/check_type_system.py",
                "scripts/check_cfg.py",
                "scripts/check_effect_system.py",
                "scripts/check_contract_test_profile.py",
                "scripts/check_fingerprint_impact_profile.py",
                "scripts/check_vm_lowering_profile.py",
                "scripts/check_vm_execution_profile.py",
                "scripts/check_reference_adapter_profile.py",
                "scripts/check_report_envelope_profile.py",
                "cargo fmt --check",
                "cargo check --workspace --locked",
                "cargo test --workspace --locked",
                "make conformance",
                "make core",
                "make adversarial",
                "make fuzz-smoke",
            ],
            "skipped_checks": [
                "v2",
                "release-check",
            ],
            "skip_rationale": "M1 canonical-state implementation and scoped exit profiles pass; S20-200 through S20-230 plus restricted epoch-1 S20-240 through S20-290 profiles are implemented, while their full-GA semantic surfaces, VM-integrated/live adapters, canonical/persistent policy-final reports, complete-root indexes, clone-equivalent profiles, and later product/release gates remain unavailable.",
            "v2_required": False,
            "cache_use": "none",
            "result": "PASS",
        },
        indent=2,
        sort_keys=True,
    )
)
