#!/usr/bin/env python3
"""Check the frozen S20-140 bootstrap, registry, and migration contract."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = (ROOT / "docs/spec/SCHEMA_EPOCH_V1.md").read_text(encoding="utf-8")
IDENTIFIERS = (ROOT / "docs/spec/IDENTIFIERS_V1.md").read_text(encoding="utf-8")
normalized = " ".join(SPEC.replace("`", "").split())
required = [
    '53 4c 45 59 45 50 30 31 ("SLEYEP01")',
    'BLAKE3-256("sley2.schema-epoch.v1" || epoch_id_preimage)',
    "There is no digest trailer and no schema-epoch field",
    "Epoch 1 requires 16.0.0",
    "67,108,864",
    "134,217,728",
    "After construction it has no insertion, removal, replacement",
    "There is no retry under another decoder",
    "SCHEMA_ROOT_OVERWRITE_FORBIDDEN",
    "does not define production SSMC contracts",
]
problems = [
    f"missing normative marker: {marker}"
    for marker in required
    if marker not in normalized
]
if "SLEYEP01 || uvar(1) || len(epoch_record) || epoch_record" not in IDENTIFIERS:
    problems.append("identifier specification does not bind the SLEYEP01 preimage")

result = {
    "contract": "s20-140-schema-epoch-spec-v1",
    "result": "FAIL" if problems else "PASS",
    "bootstrap_magic": "SLEYEP01",
    "bootstrap_version": 1,
    "stable_errors": SPEC.count("- `SCHEMA_"),
    "implementation_complete": False,
    "problems": problems,
}
print(json.dumps(result, indent=2, sort_keys=True))
if problems:
    raise SystemExit(1)
