# Native Refs and Branches v1

Status: S20-500 implemented locally against the frozen contract. Tier 2 and
independent implementation review are pending.

## 1. Scope and authority

This contract defines repository-local named branch refs over complete
S20-390 transaction receipts. It does not create a second transaction engine.

`sley-repo` owns:

- branch-name validation and host-path derivation;
- immutable branch-origin records;
- mutable branch-ref records;
- named-ref locking and compare-and-swap;
- branch enumeration and resolution;
- bounded transaction ancestry traversal;
- cleanup of S20-500-owned temporary files.

`sley-txn` continues to own transaction and receipt codecs, receipt storage,
complete revision verification, candidate commit, and the fixed `accepted`
head. The dependency direction is `sley-repo -> sley-txn` only.

A branch ref is repository visibility and retention metadata. It is never
candidate validation evidence, transaction authority, runtime authority, or a
canonical program fact.

## 2. Canonical branch-name grammar

A branch name is an exact nonempty byte string. Valid names satisfy all of the
following:

- total length is 1 through 255 bytes;
- there are 1 through 8 slash-separated components;
- each component is 1 through 63 bytes;
- every byte is lowercase ASCII `a` through `z`, digit `0` through `9`, `.`,
  `_`, or `-`;
- the first and last byte of every component is lowercase ASCII alphanumeric;
- no component ends in `.lock`;
- no component is one of `accepted`, `branch`, `branches`, `head`, `heads`,
  `lock`, `locks`, `object`, `objects`, `ref`, `refs`, `tag`, `tags`,
  `transaction`, or `transactions`.

An uppercase byte, non-ASCII byte, backslash, colon, NUL, control byte, empty
component, repeated slash, leading slash, trailing slash, `.` or `..` component,
leading or trailing dot/space, or over-limit form is invalid. The validator
does not lowercase, normalize, clean, decode escapes, or otherwise rewrite
input.

Reserved components return `REF_NAME_RESERVED`. Every other grammar failure
returns `REF_NAME_INVALID`.

## 3. Name-to-path key

Raw branch-name bytes never become host path components.

```text
name_key_preimage = "SLEYBNM1" || uvar(1) ||
                    encode_bytes(canonical_branch_name)
name_key = BLAKE3-256("sley2.branch-name-path.v1" ||
                      name_key_preimage)
```

The lowercase hex form of `name_key` selects the two fan-out directories and
filename. Decoding a stored record recomputes the key from the embedded name
and requires it to match the path. A valid record under the wrong key returns
`REF_NAME_COLLISION`.

The path key is not a branch identity and is not serialized into either record.

## 4. Immutable branch-origin record

```text
branch_preimage = "SLEYBR01" || uvar(1) ||
                  len(branch_record) || branch_record
branch_record_digest = BLAKE3-256("sley2.branch-record.v1" ||
                                  branch_preimage)
stored_branch_record = branch_preimage || branch_record_digest[32]
```

The record has exactly eight required fields in increasing tag order:

| Tag | Field | Type and rule |
|---:|---|---|
| 1 | format_version | `UInt32`, exactly `1` |
| 2 | branch_name | `Bytes`, exact valid canonical name |
| 3 | workspace_id | `WorkspaceId[32]` |
| 4 | origin_transaction_id | `TransactionId[32]` |
| 5 | origin_state_root | `StateRoot[32]` |
| 6 | schema_epoch_id | `SchemaEpochId[32]` |
| 7 | policy_root_id | `PolicyRootId[32]` |
| 8 | dependency_roots | strictly raw-byte-sorted unique `StateRoot[32]` list |

Every field other than `branch_name` is derived from the fully verified origin
receipt and root. The caller supplies only the branch name and origin
`TransactionId`.

`branch_record_digest` is an integrity digest over immutable repository
metadata. It is not a `StateRoot` input and is not added to the `sley-id` domain
registry.

## 5. Mutable branch-ref record

```text
ref_preimage = "SLEYRF01" || uvar(1) || len(ref_record) || ref_record
ref_record_digest = BLAKE3-256("sley2.branch-ref.v1" || ref_preimage)
stored_ref_record = ref_preimage || ref_record_digest[32]
```

The record has exactly nine required fields in increasing tag order:

| Tag | Field | Type and rule |
|---:|---|---|
| 1 | format_version | `UInt32`, exactly `1` |
| 2 | branch_name | `Bytes`, exact valid canonical name |
| 3 | branch_record_digest | exact digest of the immutable origin record |
| 4 | workspace_id | current verified `WorkspaceId[32]` |
| 5 | head_transaction_id | current verified `TransactionId[32]` |
| 6 | head_state_root | current verified `StateRoot[32]` |
| 7 | schema_epoch_id | current verified `SchemaEpochId[32]` |
| 8 | policy_root_id | current verified `PolicyRootId[32]` |
| 9 | dependency_roots | current strictly sorted unique `StateRoot[32]` list |

The name and branch-record digest never change. All current fields are derived
from the fully verified head receipt and root. A stored claim that differs from
durable transaction evidence returns `REF_TARGET_MISMATCH`.

## 6. Filesystem layout and confinement

For a lowercase 64-character `name_key` hex string:

```text
branches/v1/<hex[0:2]>/<hex[2:4]>/<hex>.branch.scb1
refs/v1/<hex[0:2]>/<hex[2:4]>/<hex>.ref.scb1
locks/refs.lock
```

All repository-owned root and fan-out components must be real directories.
Branch records, ref records, lock files, and temporary files must be regular
files. Symlinks and other file kinds fail as `REF_IO`. Creation uses exclusive
files or no-overwrite hard links; existing bytes are strictly decoded and must
be exact before reuse.

Temporary filenames use owned prefixes and exclusive creation. Recovery may
remove only files whose full names match those prefixes and suffixes inside the
owned fan-out depth.

The repository root and its owned directories are trusted local storage. The
concurrent threat model covers cooperating Sley callers that use the frozen
locks. A privileged or external actor that renames or replaces repository
directory entries while an operation holds those locks is outside S20-500.
Static symlinks and non-regular entries are still rejected before use. A later
host-hardening package may add descriptor-relative no-follow operations without
changing the repository record or error contract.

## 7. New verified revision lookup

The public lookup does not exist at contract-freeze time. S20-500
implementation must add a read-only `sley-txn` lookup by arbitrary
`TransactionId` and export its `VerifiedRevision` return type. This is
transaction-owner work inside the S20-500 slice, not a pre-existing API and not
named-ref logic inside `sley-txn`.

Successful lookup proves:

- exact receipt path and receipt digest;
- nested transaction identity and parent binding;
- accepted state-root and policy-root codecs;
- object-manifest identities and stored lengths;
- complete live object closure and entity/object bindings;
- sorted non-reusable tombstones;
- current direct-parent relationship supported by S20-390.

The result is a `VerifiedRevision`, not an accepted-head claim. Fixed-head
acceptance still requires the separate durable `accepted` pointer.

Every upstream transaction, SCB1, state-root, policy, or store failure is
preserved. S20-500 does not collapse it into a generic target-not-found result.

## 8. Branch operations

Mutation operations return one closed `BranchUpdateStatus` enum:

| Tag | Symbol | Meaning |
|---:|---|---|
| 1 | `CREATED` | origin and visible ref were durably created by this call |
| 2 | `ADVANCED` | the visible ref was durably advanced by this call |
| 3 | `PRESENT` | the exact requested visible state was already durable and fully verified |

`PRESENT` is success only for an exact idempotent retry. It is never a fallback
for a stale, corrupt, conflicting, or merely existing branch.

### 8.1 Create

`create_branch(name, origin_transaction_id)`:

1. validates the exact name;
2. acquires shared repository-maintenance ownership and then
   `locks/refs.lock` exclusively;
3. classifies and strictly imports any existing origin/ref topology before
   loading an unrelated proposed target;
4. verifies the selected origin revision from durable S20-390 evidence;
5. derives and persists the immutable branch-origin record when absent;
6. derives and persists the visible ref record pointing at the origin;
7. syncs each reused or newly installed file and containing directory before
   returning.

If an exact origin record exists without a ref after interruption, an exact
retry may finish creation. If the exact visible branch already exists at the
same origin, the operation returns an idempotent `PRESENT` status. Any different
origin or metadata for the same name fails according to the exact mapping in
Section 8.5.

The ref file is the visibility boundary. An orphan origin record is not a live
branch and does not by itself retain a semantic root.

### 8.2 Resolve

`resolve_branch(name)` acquires the refs lock, verifies name-to-path binding,
strictly imports both records, verifies their immutable binding, loads the
current revision through `sley-txn`, and compares every current ref fact with
that durable revision. It returns no partial or unverified branch.

### 8.3 List

`list_branches(limit)` holds the refs lock for one deterministic snapshot,
enumerates only the exact two-level ref fan-out, rejects unknown files or
malformed paths, fully resolves every visible branch, sorts by raw branch-name
bytes, and returns all results or one hard failure. It never silently omits a
branch. The requested limit may be stricter than the frozen maximum.

### 8.4 Advance

`advance_branch(name, expected_head, new_head)`:

1. acquires the refs lock;
2. resolves and verifies the current branch;
3. requires `expected_head` to equal the exact current `TransactionId`;
4. loads and fully verifies `new_head`;
5. requires the new transaction to name `expected_head` exactly once as a
   direct parent and to preserve workspace identity;
6. derives a new ref record while preserving name and origin-record digest;
7. writes, syncs, and verifies a same-directory temporary record;
8. atomically renames it over the old ref and syncs the ref directory;
9. rereads and verifies the new visible ref before returning.

If a retry finds the exact requested `new_head` already visible with all facts
valid, it returns idempotent `PRESENT` before applying the expected-head check.
Any other current-head mismatch returns `REF_NAMED_CAS_STALE`.

After strict transaction import and revision verification, workspace mismatch
with the immutable branch origin returns `BRANCH_ORIGIN_MISMATCH` before the
branch layer evaluates a missing direct-parent edge. This ordering makes the
workspace result reachable for a valid foreign genesis revision. Otherwise,
zero occurrences of `expected_head` in the new transaction parent list returns
`BRANCH_NOT_FAST_FORWARD`. A duplicate parent ID is an invalid transaction and
preserves the earlier S20-390 `TXN_PARENT_SHAPE` failure; branch logic does not
reinterpret it. Arbitrary
rewinds, sideways moves, skipped parent edges, and last-write-wins updates are
not supported.

### 8.5 Exact conflict precedence

Branch create and advance apply these outcomes after name-to-path validation:

| Condition | Exact result |
|---|---|
| newly persisted origin and ref | `CREATED` |
| exact origin and exact origin-pointing ref already durable | `PRESENT` |
| exact origin exists but no ref exists | complete creation, then `CREATED` |
| ref exists but the origin record is absent | `RECOVERY_NAMED_REF_INCOMPLETE` |
| same name has a valid origin record for a different origin transaction or workspace | `BRANCH_ORIGIN_MISMATCH` |
| existing origin has bad version, digest, or field shape | exact `BRANCH_RECORD_FORMAT_VERSION`, `BRANCH_RECORD_DIGEST_MISMATCH`, or `BRANCH_RECORD_FIELD_SHAPE` |
| ref name or origin digest disagrees with the exact origin record | `REF_BRANCH_BINDING_MISMATCH` |
| valid same-name branch already advanced beyond its origin during create | `REF_ALREADY_EXISTS` |
| ref current root, workspace, epoch, policy, or dependencies disagree with its verified head transaction | `REF_TARGET_MISMATCH` |
| valid record appears under another name key | `REF_NAME_COLLISION` |
| exact requested new head already visible | `PRESENT` |
| current head differs from expected and is not the requested new head | `REF_NAMED_CAS_STALE` |
| verified new head lacks the expected direct-parent edge | `BRANCH_NOT_FAST_FORWARD` |
| duplicate transaction parent | preserve upstream `TXN_PARENT_SHAPE` |
| verified new head workspace differs from immutable branch origin | `BRANCH_ORIGIN_MISMATCH` |
| newly persisted ref advance | `ADVANCED` |

Codec integrity failures precede semantic cross-record comparisons. Name-to-key
collision precedes origin/ref binding. Current-head CAS comparison precedes
loading an unrelated proposed target, except the exact already-visible retry
case. No condition maps to both success and an error.

## 9. Locking and durability

Every transaction and S20-500 ref operation holds shared
`locks/maintenance.lock` ownership. GC holds the same file exclusively. Every
S20-500 operation then uses one exclusive repository-wide refs lock. The frozen
lock order is:

```text
GC witness or future recovery owner
  -> maintenance.lock (exclusive for GC, shared for transactions/refs)
  -> refs.lock
  -> S20-390 accepted.lock
```

The fixed accepted-head commit path acquires shared maintenance ownership and
then `accepted.lock`; it never acquires `refs.lock`. Arbitrary revision lookup
under an already-held maintenance guard acquires only `accepted.lock` and uses
non-creating receipt paths.

Every repository-owned directory component is validated, then its parent
directory is synced before that component may be used. This parent sync occurs
for both a newly created component and an exact existing component observed by
a retry or concurrent first-use operation. No branch success may rely on an
unsynced layout or digest fan-out entry.

Creation durability is origin record before ref. Advancement durability is
temporary ref file before atomic rename before ref-directory sync. A failure
may leave an owned temporary or an orphan immutable origin record. It may not
make malformed or unverified ref bytes visible as a successful branch.

`recover_refs` removes only S20-500-owned temporary files, syncs changed
directories, and verifies every visible ref. It reports orphan origin records
without promoting, deleting, or guessing them. Full cross-component recovery
and the complete fault matrix remain S20-530.

## 10. Ancestry

`branch_ancestry(name, max_nodes)` starts from the verified branch head and
walks ordered `parent_transaction_ids` from verified transaction records.
Traversal order is deterministic head-first depth-first order. A transaction
is emitted on first visit; a completed convergent node is not emitted again.
An edge to an active node returns `BRANCH_ANCESTRY_CYCLE`.

The caller ceiling must be 1 through 65,536 and cannot loosen the frozen
maximum. Exceeding the ceiling returns `BRANCH_RESOURCE_LIMIT` with no partial
success. Missing or corrupt ancestry preserves the exact upstream error.

Branch names, ref update order, timestamps, filesystem enumeration order, Git
commits, and reflogs never establish ancestry.

## 11. Fixed accepted-head interaction

The fixed `heads/accepted` slot remains solely owned by S20-390. S20-500:

- may create a named branch at its verified transaction;
- may advance a branch to another already durable verified transaction;
- cannot name, replace, alias, or delete the fixed accepted head;
- cannot create a transaction, receipt, candidate result, root, or policy;
- cannot turn an imported record into commit authority;
- cannot make named-ref visibility imply fixed-head acceptance.

## 12. GC, recovery, and pack boundaries

Verified visible branch heads may be projected into the explicit S20-180
retention-snapshot input. Collection owns exclusive repository-maintenance
access, so a successful transaction or ref mutation cannot interleave object
promotion/verification and GC deletion. The caller still owns a complete
retention snapshot acquired under that boundary or an enclosing recovery
owner. S20-500 does not run GC, infer retention from record age, or treat orphan
origin records as live anchors.

S20-530 owns interruption injection across transaction and ref locks and any
repair policy beyond owned temporary cleanup. S20-540 owns transaction/ref pack
sections and clone-equivalent exchange. S20-170 packs continue to reject refs
and transactions.

## 13. Frozen limits

| Limit | Value |
|---|---:|
| branch-name bytes | 255 |
| branch-name components | 8 |
| bytes per component | 63 |
| visible branches per repository | 4,096 |
| immutable branch-origin records per repository | 65,536 |
| ancestry nodes per request | 65,536 |
| stored branch/ref record bytes | 67,108,864 |
| temporary-name reservation attempts | 1,024 |

The standalone-byte ceiling intentionally matches the epoch-1 SCB1 ceiling.
Implementations should reject impossible branch/ref shapes before allocating
that amount.

## 14. Frozen S20-500 error range

Numeric codes 50000 through 50020 are exact:

| Numeric | Symbolic |
|---:|---|
| 50000 | `REF_FORMAT_VERSION` |
| 50001 | `REF_NAME_INVALID` |
| 50002 | `REF_NAME_RESERVED` |
| 50003 | `REF_DIGEST_MISMATCH` |
| 50004 | `REF_FIELD_SHAPE` |
| 50005 | `REF_BRANCH_BINDING_MISMATCH` |
| 50006 | `REF_NOT_FOUND` |
| 50007 | `REF_ALREADY_EXISTS` |
| 50008 | `REF_NAME_COLLISION` |
| 50009 | `REF_TARGET_MISMATCH` |
| 50010 | `REF_NAMED_CAS_STALE` |
| 50011 | `BRANCH_RECORD_FORMAT_VERSION` |
| 50012 | `BRANCH_RECORD_DIGEST_MISMATCH` |
| 50013 | `BRANCH_RECORD_FIELD_SHAPE` |
| 50014 | `BRANCH_ORIGIN_MISMATCH` |
| 50015 | `BRANCH_NOT_FAST_FORWARD` |
| 50016 | `BRANCH_ANCESTRY_CYCLE` |
| 50017 | `BRANCH_RESOURCE_LIMIT` |
| 50018 | `RECOVERY_NAMED_REF_INCOMPLETE` |
| 50019 | `REF_IO` |
| 50020 | `REF_INTERNAL_INVARIANT` |

Strict lower-layer failures retain their exact owning code and numeric value.
Unknown or future ref kinds, symbolic refs, deletion, force movement, and
rename are unavailable APIs rather than generic successes.

## 15. Required evidence

Implementation acceptance requires at least:

- exact branch/ref codec round trips and field-perturbation tests;
- the complete name grammar acceptance/rejection matrix;
- name-key path and cross-path substitution tests;
- root, fan-out, record, and lock symlink rejection;
- cooperating transaction/ref versus exclusive-GC serialization;
- exact create retry and origin-conflict tests;
- injected layout and digest fan-out creation failures before parent sync,
  including an exact retry that cannot report branch success before resync;
- injected origin-link, ref-link, and ref-rename pre-sync retry tests;
- concurrent create and advance races with one CAS winner;
- stale expected-head and non-fast-forward rejection with distinct exact codes;
- all three `BranchUpdateStatus` tags and the complete Section 8.5 precedence
  table;
- corrupt ref, missing receipt, corrupt root, policy, object, and manifest
  target failures;
- branch-origin and current-target mismatch tests;
- deterministic ancestry, convergence, cycle-seed, and hard-limit tests;
- owned-stage recovery and orphan-origin reporting;
- a structural dependency check proving no `sley-txn -> sley-repo` edge;
- Tier 1 plus repository-focused Tier 2 validation;
- Nabu, Ariadne, and Vulcan review with every report-grade finding closed.

## 16. Explicit exclusions

This contract does not claim:

- branch deletion, rename, force movement, tags, or symbolic refs;
- policy-authorized ref administration;
- candidate commit directly against a named branch;
- detached transaction creation or imported transaction authority;
- root comparison, merge, or conflict objects;
- full recursive transaction recovery;
- ref/transaction pack exchange or clone equivalence;
- SMP1, JSON bridge, CLI, runtime, benchmark, packaging, release, or GA.
