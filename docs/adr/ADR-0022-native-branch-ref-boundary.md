# ADR-0022: Native branch and named-ref boundary

Status: accepted for S20-500 implementation

Date: 2026-08-28

## Context

S20-390 owns canonical transactions, complete receipts, and one fixed durable
`accepted` head. That head is deliberately not caller-named. S20-500 must add
native branch metadata and named-ref compare-and-swap without making
`sley-txn` depend on `sley-repo`, turning a ref into commit authority, or
allowing host path rules to define repository identity.

A branch name is repository metadata. It is not a `StateRoot`, `TransactionId`,
or `ReceiptId` input. A named ref may expose only a transaction whose receipt,
root, policy, and object closure already verify through the S20-390 owner.
Imported receipt bytes, an imported ref record, or a caller-supplied root claim
cannot create that authority.

Ref creation and advancement also need a crash-safe identity boundary. Using a
raw branch name as a host path would admit traversal, case-fold, reserved-name,
and filesystem-alias ambiguity. Reusing a mutable ref record as the branch
origin record would erase the exact ancestry facts inherited at creation.

## Decision

`sley-repo` owns S20-500. It may depend on `sley-txn`; `sley-txn` remains
independent of `sley-repo`. S20-500 implementation adds a transaction-owned,
read-only verified revision lookup by arbitrary `TransactionId` and a
`VerifiedRevision` return type. That lookup verifies the receipt,
transaction relationship, root, policy, tombstones, manifest lengths, and
complete bound-object closure. It grants no ref update or commit authority.

S20-500 defines two strict repository-metadata records:

- an immutable branch-origin record binding the canonical branch name to its
  verified origin transaction, root, workspace, epoch, policy, and dependency
  roots;
- a mutable branch-ref record binding the same name and origin-record digest to
  one current verified transaction and its current root facts.

Both records use SCB1 field rules and domain-separated BLAKE3 trailers. Their
digests are repository metadata digests, not new canonical program identifiers.
Neither record is included in `StateRoot`, `TransactionId`, or `ReceiptId`.

Branch names are already canonical or invalid. The exact grammar is lowercase
ASCII path components with frozen byte, component, and depth limits. No
lowercasing, Unicode normalization, path cleaning, or alias resolution occurs.
The name is mapped to a host path only through a domain-separated digest. Raw
name bytes never become a filesystem component.

The layout is separate from the fixed accepted head:

```text
branches/v1/<aa>/<bb>/<name-key>.branch.scb1
refs/v1/<aa>/<bb>/<name-key>.ref.scb1
locks/refs.lock
```

One repository-wide refs lock serializes branch creation, resolution,
enumeration, advancement, and restricted ref recovery. S20-500 also closes the
normative S20-180 ownership dependency through the transaction-owned
`locks/maintenance.lock`. Transaction/ref operations hold it shared and GC
holds it exclusively. The lock order is:

1. GC witness or future repository-wide recovery ownership;
2. `locks/maintenance.lock`;
3. `locks/refs.lock`;
4. the S20-390 transaction/fixed-head lock when verified revision loading needs
   it.

The fixed accepted-head path never acquires the refs lock, so the current order
has no inverse. Replacing the global refs lock with finer-grained locks requires
a later ADR and an unchanged observable CAS contract.

The local repository root is trusted against actors that bypass these locks.
Static symlinks and non-regular components fail closed, while concurrent
privileged path replacement is outside S20-500. Descriptor-relative host
hardening may be added later without changing canonical records or API-level
concurrency semantics.

Branch creation derives every origin fact from one verified transaction. It
validates each layout and digest fan-out directory and syncs its parent on both
new creation and exact-existing retry before using that component. It then
durably installs the immutable origin record before the visible ref. A crash may
leave an exact orphan origin record, but no visible branch. An exact retry may
complete that record. `CREATED`, `ADVANCED`, and exact-retry `PRESENT` are the
only mutation success states. Same-name origin disagreement is
`BRANCH_ORIGIN_MISMATCH`; a valid branch already advanced during a create retry
is `REF_ALREADY_EXISTS`; corrupt or cross-bound records retain their exact
codec or binding code.

Branch advancement requires the exact current `TransactionId`, a fully verified
new transaction, and a direct parent edge from the new transaction to the
expected current transaction. Missing direct ancestry is
`BRANCH_NOT_FAST_FORWARD`; duplicate-parent shape preserves
`TXN_PARENT_SHAPE`; workspace disagreement is `BRANCH_ORIGIN_MISMATCH`. It
writes and verifies a same-directory temporary ref, syncs it, atomically
renames it over the old ref, syncs the directory, and then rereads the ref. The
only accepted outcomes are the old complete ref or the new complete ref. There
is no last-write-wins path.

S20-500 exposes deterministic head-first ancestry traversal over verified
transaction parent IDs. It uses active and completed visit sets so convergence
is not mistaken for a cycle, enforces a hard node ceiling, and fails on missing
or corrupt ancestry. Branch names, timestamps, filesystem order, and Git facts
never establish ancestry.

This first contract does not expose branch deletion, force movement, symbolic
refs, tags, rename, transaction construction, arbitrary detached receipts,
comparison, merge, conflict objects, or pack exchange. Full cross-component
crash injection remains S20-530, and clone-equivalent ref/transaction exchange
remains S20-540.

## Consequences

- Named refs cannot bypass fresh S20-390 validation because they can expose
  only already durable, fully verified revisions.
- Branch origin facts remain immutable even as the head advances.
- Host filename behavior cannot alias two canonical branch names.
- A branch advances one verified transaction edge at a time. Multi-parent merge
  transactions can use the same rule later when their transaction kind exists.
- An orphan exact origin record is recoverable metadata, not a visible ref and
  not an accepted semantic state.
- Deletion and force movement remain fail closed until ABA, retention, policy,
  and recovery semantics are separately frozen.
- GC may consume verified live branch heads as explicit retention anchors, but
  S20-500 does not own deletion or infer retention from branch-record age.

## Review evidence

Nabu recommended the one-way dependency, repository-metadata boundary, strict
name grammar, separate origin/ref records, verified-target CAS, explicit lock
order, fail-closed ancestry, and separation from S20-530 and S20-540.

Ariadne required the new arbitrary-revision API to be identified as S20-500
transaction-owner work and required exact direct-parent, duplicate-parent, and
workspace error precedence. The patched contract closed both findings, and
Ariadne issued `PASS` with no new P0-P4.

Vulcan required a closed mutation-success enum and exact create/retry conflict
mapping. The patched `BranchUpdateStatus` and Section 8.5 precedence table
closed all three Vulcan findings. Vulcan issued `PASS` with no new P0-P4.
