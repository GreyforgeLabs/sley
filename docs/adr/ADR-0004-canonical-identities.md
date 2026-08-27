# ADR-0004: Canonical identities and domain separation

Status: Accepted for M0

## Decision

Logical identity (`EntityId`), immutable content (`ObjectId`), semantic state
(`StateRoot`), parent-bound ancestry (`TransactionId`), workspace, schema epoch,
policy, candidate, capsule, execution, test, receipt, and pack digests use
separate fixed ASCII domain separators and BLAKE3-256 unless an epoch explicitly
migrates the algorithm.

`EntityId` derives from candidate nonce, workspace domain, kind, and creation
ordinal and is never reused, including after deletion. `StateRoot` excludes
repository ancestry; `TransactionId` includes it.

## Consequences

Every preimage receives an exact encoded contract and cross-implementation
fixture before implementation is considered complete.
