# ADR-0011: Restricted derived index snapshot domain

Status: accepted for the S20-300 restricted epoch-1 profile

## Decision

Register `sley2.index-snapshot.v1` with opaque `IndexSnapshotId`. The ID hashes
the exact restricted cache-record preimage and is used only for corruption,
version, and byte-equality checks.

An `IndexSnapshotId` never proves that its inventory or edges were extracted
from a `StateRoot`. Cache admission must first rebuild from the explicit closed
modeled entity request and compare the candidate record byte-for-byte with the
fresh result. A claimed root is context only.

## Rationale

A typed domain prevents confusion with `StateRoot`, `ObjectId`,
`SemanticFingerprint`, `QueryId`, or a raw host checksum. A digest alone still
cannot authenticate semantic provenance: an attacker can create
self-consistent false cache bytes. Exact rebuild comparison is therefore the
restricted authority boundary.

## Consequences

- decoded candidate bytes are not exposed as a queryable trusted index;
- missing, corrupt, stale, incompatible, or unequal cache bytes are discarded;
- every admitted hit is already equal to a fresh authoritative modeled-request
  rebuild, so this conformance profile intentionally provides no speedup;
- complete-root extraction and useful safe cache reuse remain S20-300-full
  work after all SSMC entity bodies are modeled.
