# Immutable Object Store v1

Status: S20-150 normative contract; implementation pending.

This contract defines persistence for already validated SCB1 standalone
objects. It is newly designed for Sley 2.0. It does not import a Sley 1.x
storage pattern and gives the store no schema, policy, transaction, ref, pack,
garbage-collection, or derived-cache authority.

## Stored object record

The bytes of an object file are exactly one SCB1 standalone object:

```text
object_record = canonical_object_envelope_preimage || object_digest
object_digest = BLAKE3-256("sley2.object.v1" || canonical_object_envelope_preimage)
ObjectId      = object_digest
```

The final 32 bytes are the digest trailer. No store header, wrapper, sidecar,
compression profile, filename, timestamp, permission, path, or debug text
participates in object identity.

The semantic layer MUST validate the object in memory with the exact decoder
selected by its schema epoch before requesting persistence. The store MUST run
that supplied canonical verifier before staging and again over the bytes read
back from the staging file. It MUST also independently recompute the digest
from every byte preceding the trailer. A verifier result is not a substitute
for the store's digest and declared-ID checks.

The complete record MUST be at most the SCB1 epoch limit of 67,108,864 bytes
and MUST contain a 32-byte digest trailer. Store limits may become stricter in
a later epoch but MUST never be looser than the selected SCB1 epoch.

## Object path

The relative path is derived only from lowercase hexadecimal raw `ObjectId`
bytes:

```text
objects/scb1/<hex[0..2]>/<hex[2..4]>/<64-hex-object-id>.scb1
```

The path is a lookup index, not identity. Callers cannot supply a relative or
absolute object path. The store root is configured out of band and never
participates in a canonical digest.

## Write, verify, and promote

One object follows this state machine:

```text
Absent -> Staged -> Verified -> Promoted
                             \-> Present (same-object idempotence)
```

The required algorithm is:

1. validate the caller-supplied record in memory;
2. recompute its `ObjectId` and compare it with both trailer and declared ID;
3. derive and create the final fan-out directory;
4. create a new staging file in that final directory with exclusive creation;
5. write all bytes, flush, and sync the staging file;
6. read the staging file through the bounded path and repeat canonical,
   trailer, and declared-ID verification;
7. promote with an atomic no-overwrite operation on the same filesystem;
8. sync the containing directory, remove any remaining staging link, and sync
   the directory again;
9. return success only after the promoted file verifies at its final path.

Promotion MUST NOT use an operation that can silently replace an existing
object. If the final path already contains a valid record for the same
`ObjectId`, the write is idempotent: discard the stage and return `Present`.
If that path contains corrupt bytes or a different valid object, do not
overwrite, repair, quarantine, or normalize it in place.

## Read and error precedence

A read derives the path from the requested `ObjectId`, performs a bounded
read, runs the supplied canonical verifier, recomputes the record digest, and
requires the verified ID to equal the requested/path ID.

Failure precedence is deterministic:

1. host access failure: `STORE_IO` or `STORE_OBJECT_NOT_FOUND`;
2. record over the SCB1 limit: `SCB_RESOURCE_LIMIT`;
3. record shorter than the digest trailer, or a recomputed digest that differs
   from the trailer: `SCB_DIGEST_MISMATCH`;
4. canonical SCB1 verification failure: preserve its exact `SCB_*` code;
5. valid record ID differs from the declared or path-derived ID:
   `STORE_OBJECT_SUBSTITUTION`.

`STORE_OBJECT_SUBSTITUTION` never collapses into not-found, success, or a
generic unknown result. No failure may promote bytes or advance accepted
state.

## Crash and recovery boundary

A crash before promotion may leave only a staging file. A crash after
promotion may leave an unreachable valid immutable object and a staging hard
link. Neither case advances accepted state because S20-150 owns no ref or
transaction operation.

Recovery enumerates only files matching the store-owned staging convention in
canonical object fan-out directories. It may remove those files after bounded
inspection, and it emits one `RECOVERY_STAGED_OBJECT` event per remnant. It
MUST NOT infer acceptance or reachability from timestamps and MUST NOT remove
final `.scb1` object paths. Full reachability and garbage collection belong to
S20-180.

## Required evidence

S20-150 is complete only when tests cover:

- write/read round trip and exact path derivation;
- same-object idempotence without replacement;
- one-byte payload and trailer corruption with exact failure codes;
- a different valid object placed at a target path;
- declared-ID substitution before staging;
- exclusive staging creation and atomic no-overwrite promotion;
- injected interruption before promotion;
- injected interruption after promotion but before staging cleanup;
- recovery reporting/removal of staging remnants while preserving final files;
- exact maximum-size boundaries without unbounded allocation;
- randomized invalid records that never create a promoted object;
- assertion-effectiveness fault seeds for threats T03, T04, and T37.

Independent Vulcan review is required because all three threats are P0.
