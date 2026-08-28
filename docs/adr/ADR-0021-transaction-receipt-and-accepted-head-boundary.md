# ADR-0021: Transaction receipt and accepted-head boundary

Status: accepted and implemented for restricted S20-390

Date: 2026-08-28

## Context

The master goal calls `TransactionId` the content address of a parent-bound
transaction receipt. S20-110 separately froze `TransactionId` and `ReceiptId`
domains and says the complete persisted receipt contains its `TransactionId`.
Section 17.6 also lists both transaction identity and receipt digest. Putting
both identifiers inside one preimage would create a self-hash cycle.

The package graph has a second ambiguity. S20-390 must make a commit visible by
durable compare-and-swap, while S20-500 owns native refs and depends on
S20-390. Making S20-390 call an S20-500 ref implementation would reverse that
dependency.

Finally, S20-360 returns pure validation evidence. Imported result bytes are
not authority, and the current valid profile is restricted to executable
programs containing no semantic operation entities. Candidate mutation
operations are distinct and remain supported. S20-390 must not broaden that
claim while adding persistence.

## Decision

`sley-transaction-v1` is the canonical parent-bound transaction receipt core.
Its trailer is `TransactionId`. The core excludes both `TransactionId` and
`ReceiptId` from its payload:

```text
transaction_preimage = "SLEYTXN1" || uvar(1) ||
                       len(transaction_record) || transaction_record
TransactionId = BLAKE3-256("sley2.transaction.v1" ||
                           transaction_preimage)
stored_transaction = transaction_preimage || TransactionId[32]
```

`sley-transaction-receipt-v1` is the complete persisted commit evidence. It
contains the exact stored transaction and its derived `TransactionId`, but it
excludes `ReceiptId` from its payload:

```text
receipt_preimage = "SLEYRCP1" || uvar(1) ||
                   len(receipt_record) || receipt_record
ReceiptId = BLAKE3-256("sley2.transaction-receipt.v1" || receipt_preimage)
stored_receipt = receipt_preimage || ReceiptId[32]
```

This is non-cyclic. The transaction core owns revision identity and ancestry.
The outer receipt owns exact candidate, commit-time validation result, state
root, policy, and immutable-object evidence needed to verify that revision.
The receipt is stored under its `TransactionId`; its trailer independently
authenticates the complete evidence. Accepted-head loading compares each
authenticated manifest length with the durable object bytes; the outer codec
cannot infer that external filesystem fact by itself.

S20-390 creates `sley-txn`. The crate owns commit orchestration, both canonical
records, receipt persistence, a single fixed durable accepted-head slot, and
its compare-and-swap lock. It does not depend on `sley-repo`. S20-500 later
owns named refs, branches, ancestry queries, comparison, merge, and ref
exchange on top of S20-390 transaction types. A fixed accepted-head slot is a
commit visibility primitive, not the native branch model.

The transaction engine acquires exclusive accepted-head ownership before it
reads live state. It resolves and verifies the current receipt, transaction,
state root, policy root, tombstone set, and every bound object from durable
bytes. It constructs a fresh `CandidateValidationContext` from those facts and
runs the complete S20-360 pipeline under the lock. A validator-owned valid plan
may expose proposed immutable objects and the accepted candidate root to
`sley-txn`; imported result bytes alone never create that plan.

Commit order is exact:

1. lock and resolve the accepted head;
2. recheck the expected parent and load verified accepted state;
3. run fresh validation and derive the exact changed-binding proof;
4. stage, verify, promote, and sync missing immutable objects, or reverify and
   resync exact existing objects during retry;
5. build, write, verify, and sync the complete receipt, or reverify and resync
   the exact existing receipt during retry;
6. sync its containing directories;
7. compare-and-swap the fixed accepted head to the new `TransactionId`;
8. sync the head directory and only then return success.

The receipt contains no ref name or success assertion. Acceptance is defined
only by a durable head that resolves to a valid complete receipt. A receipt
left unreachable before compare-and-swap is valid GC input, not accepted
state.

The first implementation may expose a clearly named trusted genesis
initialization boundary. It must verify the full supplied root, policy, object
inventory, and empty prior head, and it must use the same object, receipt, and
head durability order. It is not an ordinary program transaction and confers
no policy-transition authority.

## Consequences

- No identifier hashes itself, directly or indirectly through the other
  transaction identifier.
- `StateRoot` remains ancestry-independent while `TransactionId` changes with
  parents and commit evidence.
- Receipt lookup from a ref is deterministic because receipt paths are keyed
  by `TransactionId`; `ReceiptId` still verifies the complete stored bytes.
- An identical transaction and evidence yields identical receipt bytes even if
  some objects were already present. Host-specific write statuses are logs,
  not canonical receipt fields.
- A crash may leave unreachable objects or a receipt. It may expose only the
  old complete accepted head or the new complete accepted head.
- Normal transactions preserve policy root, schema epoch, contract root, test
  root, and protected entity bindings. Policy and schema transitions remain
  outside this package.
- The current implementation claim remains restricted until complete
  operation analysis and executable selected-test evidence are integrated.

## Review evidence

Nabu recommended the non-cyclic crate boundary and S20-390-owned visibility
CAS. Ariadne independently required fresh live-state recheck, exact
changed-binding proof, fail-closed result handling, and interruption tests.
Codex resolved their preimage alternatives against the already-frozen S20-110
identifier contract and remains implementation owner.
