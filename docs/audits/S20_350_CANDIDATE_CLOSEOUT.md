# S20-350 Candidate Closeout

Status: **PASS — proposal-only construction complete; no validation or mutation authority**

## Scope

This closeout covers the native mutation-value codecs, bound preconditions,
validation-profile identity, candidate record, `SLEYCAN1` envelope, independent
fixture oracle, and production candidate fuzz target. It does not cover S20-360
semantic validation, trusted host facts/time, policy or capability judgment,
mutation application, persistence, repository refs, transactions, receipts, or
CAS.

The frozen schema BLAKE3-256 is
`1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae`.
The full-v1 validation profile ID is
`7d8ffff97a3fdafc49b4329d47b0b12f04759c3124274024016483a263265d54`.

## Evidence

- Native coverage: 18 entity-body variants, 75 descriptor-selected field
  values, 179 immutable operation descriptors, 16 mutation classes, three
  precondition forms, and one exact 13-field record.
- Independent values: the retained 126 accepted/18 rejected corpus plus 44
  accepted/4 rejected supplemental vectors. Combined coverage is 18 bodies,
  75 fields, all 16 `ConstData` variants, and all five terminators.
- Independent candidates: one accepted all-class record/envelope and 14 exact
  rejection-code vectors covering framing, digest, record shape, ordinals,
  precondition binding/count, creation identity, validation profile, and
  expiry.
- Persistent fuzz: `mutation_candidate` uses separate selectors for stored
  candidate import/rebuild and raw record decode/re-encode. The initial
  26-seed, 512-run smoke passed and retained no crash artifact.

## Focused semantic/security review

The review traced every public API to the crate-private strict codec and found:

- construction validates format, expiry shape, exact profile ID, nonempty and
  bounded operation/precondition lists, contiguous ordinals, descriptor keys,
  payload shape, deterministic creation IDs, and same-ordinal preconditions;
- candidate identity covers the exact envelope preimage, and import checks the
  digest before accepting the decoded record;
- unknown tags, fields, ordering, duplicates, trailing bytes, integer widths,
  recursive depth, allocation, collection, and standalone size limits fail
  closed through exact `SCB_*` codes;
- candidate-specific structural errors retain the frozen 35000–35010 registry,
  while SCB failures remain in the separate `SCB_*` namespace;
- `sley-mutate` forbids unsafe code and exposes no filesystem, network, process,
  provider, repository-write, apply, execute, commit, receipt, CAS, session, or
  ambient-clock path.

Two conformance disagreements were resolved during review. `ContractBody`'s
optional record field is encoded by field presence, while the corresponding
field-mutation value is an explicit `Option<ResourceLimits>` union. Invalid
expiry proposal data now reaches the candidate-specific error boundary rather
than being prematurely collapsed into `SCB_UNION_INVALID`.

No open report-grade finding remains in this scoped local review. Forge
specialist review could not run because the configured OAuth session returned
401; this document does not claim an independent Vulcan pass.

## Boundary result

S20-350 is complete only as immutable proposal construction. Candidate bytes,
their digest, a decoded record, or a passing construction test are never a
`VALID` result and grant no authority. S20-360 is the next dependency-complete package;
S20-390 remains the first package allowed to durably commit a later
validated result.

Focused commands:

```text
python3 scripts/check_mutation_value_codecs.py
make conformance
cargo test -p sley-mutate --locked
cargo clippy -p sley-mutate --all-targets --locked -- -D warnings
make mutation-candidate-persistent-fuzz-smoke
```
