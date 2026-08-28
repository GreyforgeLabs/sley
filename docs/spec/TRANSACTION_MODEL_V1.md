# Transaction Model v1

Status: restricted S20-390 implementation complete; S20-500 named refs and
S20-530 full recovery remain separate.

## Authority boundary

`sley-txn` is the only crate allowed to turn a freshly validated candidate
into durable accepted state. Candidate bytes, imported result bytes, object
bytes, a root digest, a receipt, or a caller-provided head value grants no
commit authority by itself.

The current conformance profile accepts only executable programs containing no
semantic operation entities, the restricted subset already proven by S20-360.
This does not mean candidate mutation operations are absent: typed mutation
operations may construct or change entities inside that semantic boundary. The
profile also requires an empty selected-test set until executable test-report
verification is connected to this kernel layer. Unsupported semantic operation
analysis or test evidence fails closed and cannot advance the accepted head.

## Candidate binding

A candidate binds workspace, exact base transaction and state root, schema
epoch, protected policy root, principal, session capability-summary digest,
ordered typed operations, exact preconditions, validation profile, nonce,
expiry, and candidate digest.

Entity creation IDs derive deterministically from candidate nonce, workspace
domain, entity kind, and creation ordinal and are collision-checked against the
identity ledger, including tombstoned identities.

## Validation order

1. canonical frame decode;
2. schema and limits;
3. base-root and preimage freshness;
4. identity;
5. graph structure and reference resolution;
6. type;
7. CFG;
8. effects;
9. protected policy and capability;
10. contracts;
11. test plan;
12. supported resource analysis;
13. candidate root;
14. candidate result digest.

Failure is monotonic: a later phase cannot erase an earlier failure. Validation
does not advance any ref.

The later S20-345/S20-360 freeze in `VALIDATION_PROFILE_V1.md` and
`CANDIDATE_RESULT_V1.md` owns this exact fourteen-phase order. It supersedes
the earlier combined type/CFG shorthand without changing their separate
terminal states.

## Commit

Commit locks and resolves the live accepted head, verifies its complete
receipt, transaction core, state root, policy root, tombstone ledger, and bound
objects, then constructs a fresh S20-360 trusted context from those durable
facts. It does not trust a caller-supplied or imported candidate result.

Only a fresh `VALID` output may produce a validator-owned commit plan. The plan
contains the exact imported candidate, proposed immutable entity state, and
registry-authorized candidate root. `sley-txn` independently derives the exact
base-to-candidate binding diff and rejects any omitted, extra, or inconsistent
binding.

The durability order is:

1. hold exclusive accepted-head ownership;
2. recheck the exact parent transaction, root, policy, epoch, principal,
   capability summary, candidate digest, expiry, and every preimage;
3. verify and promote missing immutable objects through `sley-store`;
4. write and verify the complete receipt under the new `TransactionId`;
5. fsync the receipt and containing directories, including reverification and
   resync of exact existing bytes on retry;
6. compare-and-swap the fixed accepted head from the expected parent to the new
   `TransactionId`;
7. fsync the head directory;
8. return the new `StateRoot`, `TransactionId`, `ReceiptId`, and commit-time
   `CandidateResultId`.

Success is impossible before Step 7 completes. A failure after object or
receipt promotion may leave unreachable immutable data but never advances
accepted state.

Program transactions cannot modify the policy, epoch, validator/kernel, or
mandatory oracle that judges them. Those changes use separately authorized
transactions and cannot be bundled with ordinary program state.

## Transaction identity

The canonical parent-bound transaction core is:

```text
transaction_preimage = "SLEYTXN1" || uvar(1) ||
                       len(transaction_record) || transaction_record
TransactionId = BLAKE3-256("sley2.transaction.v1" ||
                           transaction_preimage)
stored_transaction = transaction_preimage || TransactionId[32]
```

The digest trailer is outside its own preimage. No `TransactionId` or
`ReceiptId` field exists inside `transaction_record`.

The closed record has these required fields:

| Tag | Field | Type |
|---:|---|---|
| 1 | format_version | `UInt32`, exactly `1` |
| 2 | transaction_kind | `UInt32`: trusted genesis `1`, ordinary candidate `2` |
| 3 | workspace_id | `WorkspaceId` |
| 4 | parent_transaction_ids | ordered `List<TransactionId>` |
| 5 | parent_roots | ordered `List<StateRoot>` aligned with tag 4 |
| 6 | schema_epoch_id | `SchemaEpochId` |
| 7 | policy_root_id | `PolicyRootId` |
| 8 | principal_id | `Option<PrincipalId>` |
| 9 | candidate_id | `Option<CandidateId>` |
| 10 | candidate_result_id | `Option<CandidateResultId>` |
| 11 | validation_context_digest | `Option<ValidationContextDigest>` |
| 12 | validation_profile_id | `Option<ValidationProfileId>` |
| 13 | committed_root | `StateRoot` |
| 14 | changed_entity_bindings | canonical raw-`EntityId` ordered list |
| 15 | capability_summary_digest | `Option<CapabilitySummaryDigest>` |
| 16 | selected_tests | `CanonicalSet<EntityId>` |
| 17 | test_result_refs | `CanonicalSet<TestReportId>` |
| 18 | tombstoned_entities | `CanonicalSet<EntityId>` |
| 19 | commit_metadata | fixed three-field record |

An ordinary transaction has exactly one parent and one aligned parent root.
Tags 8 through 12 and 15 are `Some`, and they must equal the commit-time
candidate and result. A trusted genesis has no parents and uses `None` for
those fields. Its changed bindings are the exhaustive empty-state-to-genesis
root inventory.

One changed-binding record is:

| Tag | Field | Type |
|---:|---|---|
| 1 | entity_id | `EntityId` |
| 2 | preimage | `Option<ObjectId>` |
| 3 | postimage | `Option<ObjectId>` |
| 4 | mutation_ordinals | ordered `List<UInt32>` |

The list is the exact diff between parent and committed binding maps. At least
one of preimage or postimage is present and equal pairs are forbidden. An
ordinary record has at least one mutation ordinal per binding, in exact
candidate order. A genesis record has empty ordinal lists.

Commit metadata contains only deterministic profile tags:

| Tag | Field | Value |
|---:|---|---:|
| 1 | commit_profile | `1` |
| 2 | semantic_profile | `1` for executable-program-operation-free |
| 3 | durability_profile | `1` for receipt-before-head CAS |

No timestamp, ref name, host fact, filesystem path, label, source, Git fact,
session handle, or model output enters transaction identity.

## Complete persisted receipt

The complete receipt uses a second non-cyclic envelope:

```text
receipt_preimage = "SLEYRCP1" || uvar(1) ||
                   len(receipt_record) || receipt_record
ReceiptId = BLAKE3-256("sley2.transaction-receipt.v1" || receipt_preimage)
stored_receipt = receipt_preimage || ReceiptId[32]
```

The receipt record contains:

| Tag | Field | Type |
|---:|---|---|
| 1 | format_version | `UInt32`, exactly `1` |
| 2 | transaction_id | `TransactionId` |
| 3 | stored_transaction | exact `Bytes` including its trailer |
| 4 | stored_candidate | `Option<Bytes>` |
| 5 | stored_candidate_result | `Option<Bytes>` |
| 6 | stored_state_root | exact `Bytes` including its trailer |
| 7 | stored_policy_root | exact `Bytes` including its trailer |
| 8 | object_manifest | raw-`ObjectId` ordered records of ID and stored length |
| 9 | durability_profile | `UInt32`, exactly `1` |

Strict receipt import verifies every nested envelope and every binding that is
self-contained in the receipt. The transaction ID must equal the exact stored
transaction trailer. Candidate, result, root, policy, profile, context,
selected tests, and the manifest object-ID set must agree with the transaction
core. Genesis requires absent candidate and result bytes. Ordinary
transactions require both. Accepted-head closure verification additionally
loads the direct parent and durable objects, recomputes changed bindings and
tombstones, and compares every authenticated manifest length with the exact
stored object byte length.

Object-manifest entries contain `(ObjectId, stored_length)` and are the exact
postimage-object set needed by changed bindings. Existing-versus-promoted host
write status is deliberately excluded so retry and clone produce identical
receipt bytes.

## Fixed accepted-head visibility primitive

S20-390 owns one fixed `accepted` head slot mapping to a `TransactionId`. This
is not a named branch or native ref API. S20-500 later owns those semantics and
may reuse the transaction codec and compare-and-swap mechanism without
creating a `sley-txn -> sley-repo` dependency.

The fixed head is updated under an OS-released exclusive lock by writing and
syncing a same-directory temporary file, atomically renaming it over the old
head, and syncing the directory. The head value is checksummed and resolves
only when its receipt, transaction, root, policy, and objects verify. Receipt
paths are keyed by `TransactionId`; `ReceiptId` is the receipt trailer, not the
lookup key.

The exact fixed-head bytes are:

```text
head_prefix = "SLEYHD01" || uvar(1) || TransactionId[32]
head_checksum = BLAKE3-256("sley2.accepted-head.v1" || head_prefix)
stored_head = head_prefix || head_checksum[32]
```

The v1 value is exactly 73 bytes. Alternate versions, lengths, trailing bytes,
or checksums fail as `REF_HEAD_CORRUPT`.

A stale expected head returns `STALE_ROOT`, never last-write-wins. The lock is
held from live-state resolution through durable head update, so another commit
must observe either the old complete head or the new complete head.

## Recovery and trusted genesis

Recovery removes owned staging remnants, then verifies the current accepted
receipt/root/object closure and its direct parent binding. It never repairs an
invalid accepted head by guessing. A head that does not resolve fails closed.
Repeated recovery is idempotent. Recursive ancestry recovery, named-ref
reconciliation, and the full interruption matrix remain S20-500/S20-530 work.

Interruption before head rename leaves the old accepted transaction.
Interruption after head rename may expose the new head only because its objects
and receipt were already durable. Unreachable objects and receipts are later
GC inputs.

`initialize_trusted_genesis` is an explicit root-of-trust boundary. It requires
an absent head and exact registry-authorized state, policy, object inventory,
and tombstone set. It uses the same object, receipt, and head durability order.
It is not callable through ordinary candidate commit and does not authorize a
policy transition.

## Stable failures

Exact earlier `SCB_*`, `SCHEMA_*`, `STORE_*`, `STATE_ROOT_*`, `POLICY_*`, and
candidate-result failures are preserved. S20-390 freezes its own numeric codes
in `ERROR_CODES_V1.md`. Unknown, unsupported, ambiguous, internal, or
incompletely recovered states never become accepted.
