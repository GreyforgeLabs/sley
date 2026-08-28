# S20-500 Native Refs and Branches Closeout

Status: **S20-500 native refs and branches complete; the Sley 2 goal remains incomplete**

Date: 2026-08-28

Validation tier: **Tier 2 subsystem handoff**

## Closed claim

This package closes the local S20-500 native named-branch boundary over fully
verified durable S20-390 revisions. The implementation provides:

- a transaction-owned read-only `VerifiedRevision` API that is independent of
  accepted-head authority and does not create missing receipt fan-out paths;
- strict lowercase ASCII branch names mapped to digest-keyed confined paths;
- an immutable eight-field branch-origin record and a mutable nine-field
  visible ref, each with a separate domain and exact digest verification;
- exact origin and current facts derived from durable verified receipts;
- idempotent create with exact conflict precedence and three closed success
  statuses: `CREATED`, `ADVANCED`, and exact-retry `PRESENT`;
- direct-parent fast-forward compare-and-swap advancement with distinct stale,
  parent-shape, non-fast-forward, workspace, and target errors;
- deterministic head-first bounded ancestry with convergent-parent handling,
  active-cycle rejection, and a 65,536-node ceiling;
- a 4,096 visible-branch ceiling and an independent 65,536 immutable-origin
  ceiling enforced before fresh persistence;
- owned-stage cleanup and orphan-origin reporting without guessing, promotion,
  deletion, force movement, or last-write-wins behavior;
- shared maintenance ownership for transactions and refs, exclusive maintenance
  ownership for GC, and the frozen lock order `maintenance -> refs -> accepted`;
- retry durability for maintenance and accepted lock files, record install and
  replacement, layout directories, and digest fan-out directories.

The dependency remains one-way: `sley-repo -> sley-txn`. `VerifiedRevision`
proves durable revision closure but never establishes acceptance or branch
visibility.

## Durability and concurrency

Branch creation installs and syncs the immutable origin before installing and
syncing the visible ref. Advancement writes and verifies a same-directory
temporary ref, atomically renames it, syncs the directory, and rereads the
result. Exact existing records are reverified and resynced before an
idempotent retry may return success.

Every repository-owned layout or digest fan-out component is validated and its
parent is synced before use, whether the component was just created or was
observed through `AlreadyExists`. An injected regression interrupts both the
initial create and the exact-existing retry for `branches/v1` and for a digest
fan-out component. Both attempts return `REF_IO` with no visible origin or ref;
only the subsequent resyncing retry may return `CREATED`.

Transaction and ref operations hold `locks/maintenance.lock` shared through
their visibility boundary. GC holds the same file exclusively while deleting.
The adversarial race proves transaction and ref mutation block until exclusive
GC ownership is released. Code that bypasses repository locking or performs
privileged concurrent path replacement remains outside the trusted local
repository threat model.

## Independent review

The managed Merlin implementation handoff was attempted, but its second pass
was unavailable because Forge/OpenClaw OAuth refresh returned 401. Codex kept
orchestration, locally audited and hardened the partial implementation, and did
not treat the failed handoff as review evidence.

Nabu verified the one-way dependency, accepted-head separation, lock order,
capacity placement, and cross-lane frontier. Nabu confirmed that full S20-250
still blocks S20-510 and that S20-530 is the next authority-safe package.

Ariadne verified codec and name canons, create precedence, origin capacity,
non-creating receipt lookup, retry durability, exact limits, and evidence
counts. The final diff-only review confirmed that initial and `AlreadyExists`
directory faults cannot return branch success before parent resync.

Vulcan verified corruption, race, symlink, lock, GC, resource-limit, and retry
surfaces. Vulcan found the final P2 directory-parent durability gap: an existing
component could bypass parent resync after an interrupted first creation. The
unconditional parent sync and injected end-to-end regression closed that
finding. Vulcan's final verdict reported no open P0-P4 finding.

Nabu, Ariadne, and Vulcan each returned final PASS on the same source snapshot,
with no open P0-P4 or new report-grade finding.

## Validation record

Focused validation passed:

```text
cargo test -p sley-repo
cargo test -p sley-txn
cargo clippy -p sley-txn -p sley-repo --all-targets -- -D warnings
python3 scripts/check_ref_branch_contract.py
python3 scripts/check_gc_spec.py
python3 scripts/check_s20_700_frontier.py
python3 scripts/check_local_completion_frontier.py
```

The final source contains 28 focused native-ref tests, 5 verified-revision
tests, 64 total `sley-repo` tests, and 19 active `sley-txn` tests plus one
explicitly ignored fixture generator. Formatting, strict clippy, JSON parsing,
supply-chain evidence drift checks, and `git diff --check` passed.

Tier 1 `make quick` passed. Tier 2 `make core`, `make conformance`, and
`make adversarial` passed. The full `make v1` gate was skipped because S20-500
is a subsystem handoff, not a release boundary. `make v2` and
`make release-check` remain intentionally fail closed because the full goal and
release are not implemented.

## Explicitly open

This closeout does not complete:

- full S20-250 entity bodies or complete-root impact semantics;
- S20-510 semantic comparison or S20-520 merge and conflict semantics;
- S20-530 full crash injection, recursive recovery, or cross-component fault
  matrix;
- S20-540 clone-equivalent pack exchange;
- named-branch candidate commit, deletion, rename, force movement, tags, or
  symbolic refs;
- protocol, bridge, CLI, runtime deployment, real benchmark trials, release
  evidence, packaging, publication, or GA.

S20-530 is the next dependency-complete local package. The local-write gate
remained in force: no push, runtime deployment, provider call, publication,
spend, trading action, or external system mutation occurred.
