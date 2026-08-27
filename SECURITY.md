# Security and Threat Model

Status: M0 threat register. Implementation evidence is not yet available.

## Security invariants

The kernel fails closed. Unknown, incomparable, ambiguous, missing, stale, or
over-limit facts never imply validity or permission. Opaque binary encoding is
not a security boundary. Prompt text, labels, documentation, adapter text, and
model output cannot grant authority.

Policy, schema epoch, validator, kernel version, and mandatory oracle changes
are isolated from the candidate they judge. There is no ambient filesystem,
network, clock, randomness, environment, process, secret, deployment, or spend
authority. Arbitrary shell execution is outside Sley 2.0 GA.

## Severity and evidence

- P0: integrity or authority failure that can commit invalid state or escape a
  capability boundary.
- P1: exploitable denial, cross-workspace leak, durable corruption, or release
  substitution.
- P2: material hardening or architecture debt; GA blocks while open.
- P3/P4: non-blocking improvement or observation.

Every P0/P1 row must gain a mitigation, stable error code, deterministic,
property, or fuzz test, evidence path, and independent disposition before GA.

## Threat register

The one-to-one owner/code/test/evidence map is `docs/THREAT_REGISTER.md`. The
grouped view below is only a navigation summary.

| IDs | Threat family | Initial severity | Required control and later evidence |
|---|---|---:|---|
| T01-T06 | malformed/noncanonical SCB1, hash substitution, downgrade, epoch confusion | P0 | strict decoder, domain hashes, epoch pinning, Rust/oracle rejection corpus |
| T07-T12 | identity reuse, dangling/cyclic/pathological graph, checker nontermination | P0 | identity ledger, bounded traversal, graph/type/CFG property and fuzz suites |
| T13-T16 | query explosion, hidden truncation, stale handles, mutation flooding | P1 | exact limits, omission markers, root-bound handles, resource tests |
| T17-T21 | stale commit and self-modified policy/epoch/tests | P0 | exact preimages, protected roots, phase-ordered candidate tests |
| T22-T26 | capability forgery/replay/scope confusion and adapter impersonation/injection | P0 | authenticated root-bound tokens, typed adapter identity, adversarial fixtures |
| T27-T32 | path/symlink escape, environment/output/cancellation/fuel bypass | P0 | confined adapters, no ambient state, hard budgets, process isolation tests |
| T33-T36 | VM divergence, floating drift, cache poisoning, derived-as-canonical | P0 | frozen FP profile, exact cache keys, VM conformance and fault seeding |
| T37-T40 | crash boundaries and GC deleting reachable objects | P0 | write ordering, fsync/CAS, crash matrix, reachability property tests |
| T41-T44 | malicious/decompression pack and lossy/silent merge | P0 | bounded pack decode, digest tree, explicit conflict objects, merge properties |
| T45-T47 | downgrade, request confusion, cross-workspace leakage | P0 | explicit negotiation, typed IDs, session/workspace binding tests |
| T48-T51 | prompt/debug/Git/ZJX facts mistaken for semantics | P0 | semantic authority boundary and negative conformance fixtures |
| T52-T55 | dependency/artifact substitution, secrets, benchmark contamination | P1 | lockfile, SBOM, provenance, secret scan, frozen corpus and failure retention |

The detailed one-to-one mapping and expected codes will be completed by
S20-030 and then maintained in the evidence dossier. This grouped register
tracks all 55 required threats without claiming mitigations are implemented.

## Reporting

Do not open a public issue for a suspected vulnerability. Record it locally and
route it to the operator and independent reviewer. Public disclosure or release
communication requires separate authorization.
