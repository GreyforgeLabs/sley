# Canonical Identifiers and Hash Domains v1

Status: S20-110 implementation contract

## Invariants

All canonical identifiers are exactly 32 bytes. BLAKE3-256 is the epoch-1 hash
algorithm. Domain strings are exact non-NUL-terminated ASCII bytes prepended
directly to the defined preimage. Domains are closed constants; kernel callers
cannot supply arbitrary domain text.

No identifier derives from a label, source path, ref name, branch, timestamp,
filesystem layout, object-store location, Git metadata, cache, debug text, or
model output. Text parsing and display are derived tooling concerns and are not
part of the `sley-id` kernel API.

## Frozen domains

| Purpose | Exact bytes |
|---|---|
| workspace | `sley2.workspace.v1` |
| logical entity | `sley2.entity.v1` |
| immutable semantic object | `sley2.object.v1` |
| semantic state root | `sley2.state-root.v1` |
| parent-bound transaction | `sley2.transaction.v1` |
| complete transaction receipt | `sley2.transaction-receipt.v1` |
| schema epoch | `sley2.schema-epoch.v1` |
| protected policy root | `sley2.policy-root.v1` |
| capability token digest | `sley2.capability-token.v1` |
| candidate | `sley2.candidate.v1` |
| candidate result | `sley2.candidate-result.v1` |
| typed query | `sley2.query.v1` |
| context capsule | `sley2.context-capsule.v1` |
| semantic fingerprint | `sley2.semantic-fingerprint.v1` |
| canonical value hash | `sley2.value-hash.v1` |
| VM bytecode cache key | `sley2.vm-bytecode-cache-key.v1` |
| reference adapter identity | `sley2.reference-adapter-id.v1` |
| adapter fixture state | `sley2.adapter-state.v1` |
| adapter invocation transcript | `sley2.adapter-transcript.v1` |
| derived semantic index snapshot | `sley2.index-snapshot.v1` |
| restricted complete-query capsule | `sley2.restricted-query-capsule.v1` |
| deterministic observation | `sley2.observation.v1` |
| execution report | `sley2.execution-report.v1` |
| test report | `sley2.test-report.v1` |
| repository pack | `sley2.repository-pack.v1` |
| protocol handshake | `sley2.protocol-handshake.v1` |

A domain cannot be renamed, aliased, or reused for another preimage. Adding a
domain requires an ADR, fixtures, and registry drift validation.

## Workspace identity

Workspace creation receives a 32-byte `GenesisNonce` from the creating host.
Given the same nonce, derivation is deterministic:

```text
WorkspaceId = BLAKE3-256("sley2.workspace.v1" || genesis_nonce[32])
```

Nonce generation policy is outside the hash contract. A host must collision-
check a proposed workspace ID before acceptance.

## Entity identity

Entity creation binds exact workspace, candidate nonce, entity kind, and
creation ordinal:

```text
entity_preimage = WorkspaceId[32] || CandidateNonce[32] ||
                  entity_kind_u32_be || creation_ordinal_u64_be
EntityId = BLAKE3-256("sley2.entity.v1" || entity_preimage)
```

`CandidateNonce` is exactly 32 bytes. `entity_kind` is the epoch-frozen object-
kind tag. `creation_ordinal` is the zero-based position among create-entity
operations in the candidate after canonical operation ordering. Fixed-width
big-endian integers are deliberate here: identifier derivation does not depend
on or duplicate the SCB1 varint implementation.

The transaction layer collision-checks the result against both live and
tombstoned identities. Deletion never permits reuse.

## Content-addressed identifiers

Each type hashes the exact preimage defined by its owning contract:

```text
ObjectId      = H(object_domain, canonical_object_envelope_preimage)
StateRoot     = H(state_root_domain, canonical_state_root_envelope_preimage)
TransactionId = H(transaction_domain, canonical_transaction_envelope_preimage)
ReceiptId     = H(receipt_domain, canonical_receipt_envelope_preimage)
SchemaEpochId = H(schema_epoch_domain, canonical_epoch_envelope_preimage)
PolicyRootId  = H(policy_domain, canonical_policy_envelope_preimage)
```

where `H(domain, preimage) = BLAKE3-256(domain || preimage)`. The SCB1 digest
trailer is outside its own preimage. For semantic objects, the trailer equals
`ObjectId`. Other contract digests equal their corresponding typed identifier.

`StateRoot` excludes ancestry. `TransactionId` includes exact ordered parent
transaction IDs and therefore binds ancestry. `ReceiptId` independently
authenticates the complete persisted receipt evidence, including its
`TransactionId`, validation/test references, capability-use summary, and commit
metadata. The owning contracts supply exact preimages and canonical parent
ordering for merges.

`canonical_epoch_envelope_preimage` is the fixed, non-SCB standalone
`SLEYEP01 || uvar(1) || len(epoch_record) || epoch_record` bootstrap preimage
defined by `SCHEMA_EPOCH_V1.md`. It contains no `SchemaEpochId` and therefore
does not create a self-hash cycle. Calling it an envelope does not give it an
SCB1 digest trailer or registry-selected schema.

## Rust API boundary

`sley-id` exposes opaque newtypes for every identifier and fixed nonce, byte-
array construction/access, type-specific derivation functions, and no generic
public `hash(domain_string, bytes)` escape hatch. All types are value types with
byte equality and ordering. Debug output, if implemented, is explicitly
derived, non-round-trippable, and non-canonical.

The crate uses `#![forbid(unsafe_code)]`, has no filesystem/network/environment
access, and depends only on the pinned BLAKE3 implementation plus the standard
library. It neither encodes SCB1 nor knows repository, policy, or VM semantics.

## Acceptance

- fixed vectors cover every frozen domain plus WorkspaceId and EntityId;
- changing any domain, preimage byte, kind, ordinal, workspace, or nonce changes
  the digest in the vector suite;
- repeated derivation is byte-identical;
- all identifier types remain 32 bytes;
- no generic arbitrary-domain public API exists;
- no source/text/Git/host facts influence derivation;
- focused unit and property tests pass with the pinned toolchain.
