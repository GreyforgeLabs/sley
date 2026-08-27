# Transaction Model v1

Status: M0 normative draft.

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
6. type and CFG;
7. effects;
8. protected policy and capability;
9. contracts;
10. test plan;
11. supported resource analysis;
12. candidate root;
13. candidate result digest.

Failure is monotonic: a later phase cannot erase an earlier failure. Validation
does not advance any ref.

## Commit

Commit rechecks base transaction/root/policy and candidate digest, verifies and
durably installs immutable objects, writes and syncs a parent-bound receipt,
then compare-and-swaps the target ref. Only `VALID` may commit. The response is
success only after the ref is durable.

Program transactions cannot modify the policy, epoch, validator/kernel, or
mandatory oracle that judges them. Those changes use separately authorized
transactions and cannot be bundled with ordinary program state.
