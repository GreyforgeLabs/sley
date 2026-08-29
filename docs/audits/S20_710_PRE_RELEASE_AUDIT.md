# S20-710 Pre-Release Supply-Chain Audit

Status: **BLOCKED — operator-approved root license text required**

This is a bounded, offline pre-release audit. It is not the S20-710 acceptance
record, a legal opinion, a standards SBOM, release provenance, or permission to
publish. The audit is frozen through Git commit
`9e958289086d715acedcb0899f84a1c855665ca9`; this is the sanitized-history
equivalent of the original pre-release anchor. A later release audit must use a
new anchor and cover all subsequent history.

## Local results

- Cargo is locked and inspected offline: 14 workspace crates and 22 registry
  crates, with registry sources, lock checksums, and dependency relationships.
- The SCB1 Python oracle is locked: an offline `uv lock --check` proves the
  lock is fresh for the project metadata, and the inventory covers one local
  package and two PyPI packages with registry sources and artifact hashes.
- All 15 local packages declare `LicenseRef-Proprietary`. No root `LICENSE`,
  `COPYING`, or `NOTICE` file exists, so their license disposition is blocked.
- Cargo registry license expressions come from offline Cargo metadata. The two
  Python dependency expressions are curated local pre-release dispositions,
  not lockfile declarations. Neither category is a legal compatibility
  opinion.
- The bounded high-confidence scan found no matching secret pattern in the
  candidate file set or reachable Git blobs through the audit anchor. It does
  not scan ignored local files, reflogs, remotes, provider stores, or external
  secret managers, and it does not perform entropy or credential validation.
- Common secret-bearing files are ignored at the repository boundary.

Machine-readable evidence:

- `evidence/security/T52/pre-release-inventory.json`
- `evidence/security/T54/secret-scan.json`

`python3 scripts/check_supply_chain_audit.py` validates deterministic
regeneration, locked sources and hashes, package/relationship coverage, the
absence of emitted secret values and host paths, and the exact remaining
blocker. Its successful outcome is deliberately `DEFERRED`, not `PASS`.

## Required operator decision

Provide or approve the exact root proprietary license text, including the
copyright holder, year/range, grant or restriction terms, and any required
notice language. The implementation must not invent these legal facts.

After that decision, Argus must re-run license and secret review, generate the
release-standard SBOM/provenance artifacts, re-anchor history at the release
candidate, and disposition every finding before S20-710 can pass.
