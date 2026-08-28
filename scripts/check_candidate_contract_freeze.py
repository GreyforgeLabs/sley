#!/usr/bin/env python3
"""Check the specification-only S20-345 candidate contract freeze."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    "candidate": "docs/spec/CANDIDATE_RECORD_V1.md",
    "values": "docs/spec/MUTATION_VALUE_CODEC_V1.md",
    "preconditions": "docs/spec/PRECONDITION_PAYLOAD_V1.md",
    "capability_summary": "docs/spec/CAPABILITY_SUMMARY_V1.md",
    "validation_profile": "docs/spec/VALIDATION_PROFILE_V1.md",
    "expiry": "docs/spec/EXPIRY_V1.md",
    "adr": "docs/adr/ADR-0017-candidate-contract-freeze.md",
}
MARKERS = {
    "candidate": ['"SLEYCAN1"', '"sley2.candidate.v1"', "All thirteen fields", "proposal to transform one exact state", "tags 1 through 16"],
    "values": ["all eighteen `EntityBody`", "all seventy-five entity-body fields", "179 descriptors", "may not use opaque bytes"],
    "preconditions": ["ExpectedIdentityAbsent", "ExactEntityVersion", "ExactContainerVersion", "not proof of absence"],
    "capability_summary": ['"SLEYCAS1"', '"sley2.capability-summary.v1"', "contains no host secret", "necessary but never sufficient"],
    "validation_profile": ['"SLEYVAP1"', '"sley2.validation-profile.v1"', "ordered list `1..14`", "not evidence that its phases ran"],
    "expiry": ["Unix time in milliseconds", "now_unix_millis < not_after", "never reads a clock"],
    "adr": ["Candidate data is always a proposal", "S20-350 depends on S20-345", "adds no executable mutation"],
}

problems: list[str] = []
documents: dict[str, str] = {}
for name, relative in FILES.items():
    path = ROOT / relative
    if not path.is_file():
        problems.append(f"missing:{relative}")
        continue
    raw = path.read_text(encoding="utf-8")
    documents[name] = raw
    document = " ".join(raw.split())
    for marker in MARKERS[name]:
        if marker not in document:
            problems.append(f"{name}:missing-marker:{marker}")


def table_rows(document: str, header: str) -> list[list[str]]:
    if header not in document:
        return []
    lines = document.split(header, 1)[1].splitlines()[1:]
    rows: list[list[str]] = []
    for line in lines:
        if not line.startswith("|"):
            if rows:
                break
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and re.fullmatch(r"\d+", cells[0]):
            rows.append(cells)
    return rows


candidate_rows = table_rows(documents.get("candidate", ""), "| Tag | Field | Type | Rule |")
expected_candidate_fields = [
    "format_version", "workspace_id", "base_transaction_id", "base_root",
    "schema_epoch_id", "policy_root_id", "principal_id",
    "capability_summary_digest", "operations", "preconditions",
    "validation_profile_id", "candidate_nonce", "expiry",
]
if [int(row[0]) for row in candidate_rows] != list(range(1, 14)):
    problems.append("candidate:field-tags-not-exact-1-through-13")
if [row[1] for row in candidate_rows] != expected_candidate_fields:
    problems.append("candidate:field-order-or-names")
if any(row[1] in {"candidate_id", "candidate_digest"} for row in candidate_rows):
    problems.append("candidate:self-digest-field-cycle")

profile_rows = table_rows(
    documents.get("validation_profile", ""), "| Tag | Field | Exact value |"
)
expected_profile = [
    (1, "format_version", "`1`"),
    (2, "phase_tags", "ordered list `1..14`"),
    (3, "max_operations", "`65,535`"),
    (4, "max_preconditions", "`65,535`"),
    (5, "max_candidate_bytes", "`67,108,864`"),
    (6, "max_decoded_value_bytes", "`67,108,864`"),
    (7, "max_graph_work", "`10,000,000`"),
    (8, "max_selected_tests", "`65,535`"),
]
if [(int(row[0]), row[1], row[2]) for row in profile_rows] != expected_profile:
    problems.append("validation-profile:table-not-exact")

identifier_source = (ROOT / "crates/sley-id/src/lib.rs").read_text(encoding="utf-8")
identifier_spec = (ROOT / "docs/spec/IDENTIFIERS_V1.md").read_text(encoding="utf-8")
for marker in [
    "CapabilitySummaryDigest", "ValidationProfileId",
    'b"sley2.capability-summary.v1"', 'b"sley2.validation-profile.v1"',
    "bad9f879f53483061bd181da955a62cb6c758bbd0381ee93630781a074f5fd19",
    "974290a6758c97f547093e707ba18055c3ab73a6a504c3c0514b2a7d4dc7bf11",
    "const ALL: [Self; 28]",
]:
    if marker not in identifier_source:
        problems.append(f"identifier-registry:missing:{marker}")
for marker in ["`sley2.capability-summary.v1`", "`sley2.validation-profile.v1`"]:
    if marker not in identifier_spec:
        problems.append(f"identifier-spec:missing:{marker}")

summary = json.loads((ROOT / "machineresearch/sley-2.0/machine-summary.json").read_text())
freeze = summary.get("candidate_contract_freeze", {})
if freeze.get("status") != "S20_345_CONTRACT_AND_IDENTITY_FREEZE_COMPLETE":
    problems.append("machine-summary:freeze-status")
for reviewer in ("nabu_review", "vulcan_review"):
    if freeze.get(reviewer) != "PASS_NO_OPEN_P0_P1_P2":
        problems.append(f"machine-summary:{reviewer}")
if freeze.get("s20_350_unblocked") is not True:
    problems.append("machine-summary:s20-350-unblocked")

print(json.dumps({
    "candidate_construction": False,
    "candidate_fields": 13,
    "contract": "s20-345-candidate-contract-freeze-v1",
    "entity_kinds_bound_to_typed_codecs": 18,
    "executable_mutation": False,
    "files": len(FILES),
    "problems": problems,
    "result": "PASS" if not problems else "FAIL",
    "s20_350_unblocked": True,
    "nabu_review": "PASS_NO_OPEN_P0_P1_P2",
    "vulcan_review": "PASS_NO_OPEN_P0_P1_P2",
}, indent=2, sort_keys=True))
raise SystemExit(int(bool(problems)))
