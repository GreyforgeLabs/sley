#!/usr/bin/env python3
"""Validate the committed constitutional skeleton without claiming GA readiness."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md", "ARCHITECTURE.md", "SECURITY.md", "CONTRIBUTING.md",
    "rust-toolchain.toml", "Cargo.toml", "Cargo.lock", "docs/WORK_PACKAGES.md",
    "docs/ANTI_GOALS.md", "docs/spec/SSMC1.md", "docs/spec/SCB1.md",
    "docs/THREAT_REGISTER.md",
    "docs/spec/SMP1.md", "docs/spec/TYPE_SYSTEM_V1.md",
    "docs/spec/TRANSACTION_MODEL_V1.md", "docs/spec/EXECUTION_MODEL_V1.md",
    "docs/spec/REPOSITORY_MODEL_V1.md", "docs/spec/ERROR_CODES_V1.md",
    "machineresearch/sley-2.0/machine-summary.json",
]
missing = [name for name in REQUIRED if not (ROOT / name).is_file()]
summary = json.loads((ROOT / "machineresearch/sley-2.0/machine-summary.json").read_text())
if summary.get("publication_authorized") is not False:
    missing.append("machine-summary publication_authorized=false")

for forbidden in ROOT.rglob("*.sley"):
    missing.append(f"forbidden Sley source: {forbidden.relative_to(ROOT)}")

threats = (ROOT / "docs/THREAT_REGISTER.md").read_text()
for number in range(1, 56):
    threat_id = f"T{number:02d}"
    if f"| {threat_id} |" not in threats:
        missing.append(f"missing threat mapping {threat_id}")

if missing:
    print(json.dumps({"result": "FAIL", "problems": missing}, indent=2))
    raise SystemExit(1)

print(json.dumps({
    "result": "PASS",
    "baseline": "M0",
    "required_files": len(REQUIRED),
    "semantic_crates": len(list((ROOT / "crates").glob("*/Cargo.toml"))),
    "sley_source_files": 0,
    "publication_authorized": False,
}, sort_keys=True))
