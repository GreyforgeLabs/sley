# S20-500 Native Ref and Branch Contract Freeze

Status: **PASS - contract frozen; implementation not yet present**

Date: 2026-08-28

Validation tier: **Tier 1 contract checkpoint plus independent architecture and
adversarial review**

## Frozen boundary

This checkpoint freezes the smallest S20-500 contract that can be implemented
without reversing the S20-390 dependency or inventing unowned authority.

The contract fixes:

- `sley-repo -> sley-txn` as the only new dependency direction;
- one new transaction-owned, read-only arbitrary-`TransactionId`
  `VerifiedRevision` API;
- a lowercase ASCII branch-name grammar with exact byte, component, depth, and
  reserved-name limits;
- a domain-separated name-to-path key so raw branch names never become host
  path components;
- an eight-field immutable branch-origin record and nine-field mutable ref
  record;
- three exact mutation success statuses: `CREATED`, `ADVANCED`, and exact-retry
  `PRESENT`;
- one repository-wide refs lock and the future recovery-to-refs-to-transaction
  lock order;
- origin-before-ref create durability and temporary-file-before-rename advance
  durability;
- direct-parent fast-forward only, with distinct stale, ancestry, duplicate-
  parent, and workspace failures;
- head-first bounded ancestry over verified transaction parent IDs;
- twenty-one exact S20-500 error codes;
- fail-closed separation from delete, force movement, rename, symbolic refs,
  tags, named-branch candidate commit, merge, full recovery, and pack exchange.

Ref records are repository visibility and retention metadata. They do not enter
`StateRoot`, `TransactionId`, or `ReceiptId`, and imported records never grant
candidate, commit, policy, runtime, or fixed-head authority.

## Review record

Nabu found S20-500 dependency-ready but required a written name, record,
layout, CAS, lock, ancestry, error, and recovery contract before implementation.
The resulting draft adopted that boundary.

Ariadne initially found two items:

- the arbitrary-revision API was required but not explicitly identified as new
  S20-500 transaction-owner work;
- direct-parent, duplicate-parent, and workspace failure precedence was
  incomplete.

Both were patched. Ariadne closed the findings and issued `PASS` with no new
P0-P4.

Vulcan initially found three items:

- `PRESENT` lacked a frozen success vocabulary;
- non-fast-forward and stale CAS were not explicitly distinct;
- create/retry conflict conditions could map to several codes.

The closed `BranchUpdateStatus` enum and Section 8.5 precedence table resolved
all three. Vulcan issued `PASS` with no new P0-P4.

## Validation record

The structural owner is:

```text
python3 scripts/check_ref_branch_contract.py
```

It verifies the exact record domains and field counts, limits, success tags,
error range, review state, one-way dependency, honest absent implementation,
work-package status, and machine-summary agreement. `make quick` is the Tier 1
checkpoint recorded in
`evidence/validation/s20-500-ref-branch-contract-freeze-v1.json`.

The complete `make v1`, future `make v2`, and release gate are not contract-
draft debugging tools and were not run.

## Explicitly open

This checkpoint contains no S20-500 implementation. It does not complete M4,
branch-local candidate commit, comparison, merge/conflict objects, S20-530
cross-component recovery, S20-540 clone-equivalent exchange, SMP1, benchmarks,
packaging, release review, or GA.

The local-write gate remained in force. No push, deploy, provider call,
publication, spend, trading action, or external runtime mutation occurred.
