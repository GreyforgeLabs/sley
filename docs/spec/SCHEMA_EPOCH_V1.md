# Schema Epoch Registry and Migration Contract v1

Status: S20-140 normative specification

## 1. Scope

This contract defines immutable schema-epoch identity, exact registry lookup,
decoder preservation, and the evidence-only migration boundary. It does not
define production SSMC contracts, construct state roots, persist objects, move
refs, or commit migration transactions; those belong to S20-160, S20-200, and
S20-390.

An implementation must not select a latest epoch, fall back to a nearby epoch,
reinterpret a tag, register schemas from environment or repository input, or
let candidate content choose its decoder or equivalence verifier.

## 2. Bootstrap identity preimage

`SchemaEpochId` cannot be derived from an ordinary SCB1 standalone envelope:
that envelope contains the epoch ID and would create a self-hash cycle. Epoch
identity therefore uses this fixed bootstrap preimage:

```text
bootstrap_magic       8 raw bytes = 53 4c 45 59 45 50 30 31 ("SLEYEP01")
bootstrap_version     canonical uvar = 1
epoch_record_length   canonical uvar
epoch_record          canonical SchemaEpochRecordV1 bytes

epoch_id_preimage = bootstrap_magic || bootstrap_version ||
                    epoch_record_length || epoch_record
SchemaEpochId = BLAKE3-256("sley2.schema-epoch.v1" || epoch_id_preimage)
```

There is no digest trailer and no schema-epoch field in this bootstrap
preimage. The record is encoded by the fixed meta-schema below, not by a
registry-selected schema. Changing any byte changes identity. Implementations
must reject non-minimal lengths and trailing data when importing a bootstrap
preimage.

## 3. Canonical epoch record

`SchemaEpochRecordV1` is one canonical SCB1 Record with all fields required:

| Tag | Field | Type |
|---:|---|---|
| 1 | epoch_number | `UInt<32>` |
| 2 | scb_format_version | `UInt<32>` |
| 3 | hash_algorithm_tag | `UInt<32>` |
| 4 | unicode_nfc_version | `UnicodeVersion` |
| 5 | limits | `EpochLimits` |
| 6 | contracts | `CanonicalSet<ContractDescriptor>` |
| 7 | extensions | `CanonicalSet<ExtensionDescriptor>` |
| 8 | predecessor | `Option<SchemaEpochId>` |
| 9 | migration_contracts | `CanonicalSet<MigrationContractDescriptor>` |

Closed tags for v1 are `scb_format_version = 1` and
`hash_algorithm_tag = 1` for BLAKE3-256. `UnicodeVersion` is a Record with
required UInt32 fields `1 major`, `2 minor`, and `3 patch`. Epoch 1 requires
`16.0.0`.

Epoch numbers begin at 1. Epoch 1 has no predecessor; every later epoch has one
exact predecessor. Every migration descriptor in a record must name that same
predecessor.

`EpochLimits` is a Record with these required UInt64 fields, whose epoch-1
values exactly match SCB1:

| Tag | Limit | Value |
|---:|---|---:|
| 1 | standalone stored bytes | 67,108,864 |
| 2 | byte/text/label/extension payload | 16,777,216 |
| 3 | nesting depth | 64 |
| 4 | fields per record | 65,535 |
| 5 | elements per list/set/map | 1,000,000 |
| 6 | decoded standalone values per request | 1,000,000 |
| 7 | decoder allocation per standalone value | 134,217,728 |

All canonical sets use the SCB1 list encoding ordered strictly by each
element's complete canonical bytes. Empty sets are encoded as count zero.

## 4. Descriptors

`ContractDescriptor` is a Record with required fields:

| Tag | Field | Type |
|---:|---|---|
| 1 | contract_tag | `UInt<32>` |
| 2 | digest_domain_tag | `UInt<32>` |
| 3 | kind_tag | `UInt<32>` |
| 4 | field_schema_hash | `FixedBytes<32>` |
| 5 | required_fields | `CanonicalSet<UInt<32>>` |
| 6 | optional_fields | `CanonicalSet<UInt<32>>` |
| 7 | variant_tags | `CanonicalSet<UInt<32>>` |
| 8 | decoder_limits_hash | `FixedBytes<32>` |

Contract tags, domain tags, and kind tags are unique within one epoch.
Required and optional field sets are disjoint. The descriptor commits to a
separately frozen exact field schema; it does not make SCB1 self-describing.

`ExtensionDescriptor` has required fields `1 namespace_id FixedBytes<16>`,
`2 type_tag UInt<32>`, `3 version UInt<32>`, and
`4 payload_schema_hash FixedBytes<32>`. Its tuple is unique within an epoch.

`MigrationContractDescriptor` has required fields
`1 predecessor_epoch FixedBytes<32>`, `2 contract_id FixedBytes<32>`,
`3 verifier_id FixedBytes<32>`, and `4 scope_hash FixedBytes<32>`. A migration
is unsupported unless the target epoch contains an exact descriptor match.

Production descriptor rows are added only by their owning semantic work
packages. S20-140 freezes the representation and lookup rules, not premature
SSMC contract contents.

## 5. Immutable registry and decoder selection

A registry is constructed from a statically supplied, strictly ID-sorted set
of `(SchemaEpochId, SchemaEpochRecordV1, preserved decoder)` entries. It rejects
duplicate IDs, a record whose recomputed ID differs from its key, or a decoder
whose declared epoch differs. After construction it has no insertion, removal,
replacement, configuration, environment, network, or repository mutation API.

Lookup takes one exact 32-byte `SchemaEpochId`. Absence returns
`SCHEMA_EPOCH_MISMATCH`. A request that requires an equal-or-newer epoch and
selects a lower epoch returns `SCHEMA_DOWNGRADE`. Contract lookup is exact
within the selected epoch and absence returns `SCHEMA_CONTRACT_UNKNOWN`.

Every supported old epoch keeps its exact decoder implementation addressable by
ID. Its interface accepts an exact contract tag and canonical input bytes and
returns the original `SCB_*` result. Import and migration must decode with that
preserved decoder. There is no retry under another decoder after any failure.

## 6. Migration skeleton

Until S20-160 supplies canonical state construction, S20-140 migrations are
plans and validation evidence only:

```text
MigrationPlan {
  old_epoch: SchemaEpochId,
  new_epoch: SchemaEpochId,
  contract_id: FixedBytes<32>,
  verifier_id: FixedBytes<32>,
  scope_hash: FixedBytes<32>
}

MigrationTransactionDraft {
  old_root: StateRoot,
  new_root: StateRoot,
  old_epoch: SchemaEpochId,
  new_epoch: SchemaEpochId,
  plan_id: FixedBytes<32>,
  equivalence_evidence_digest: FixedBytes<32>
}
```

The registry must contain both epochs, the new epoch must differ from and name
the old epoch as predecessor, its epoch number must be greater, and the exact
migration descriptor must exist. The draft's `plan_id` must equal an externally
approved plan identifier rather than candidate-supplied authority.
Old and new root values must differ. A target root slot must be empty; any
attempt to replace, reuse, or overwrite the old root returns
`SCHEMA_ROOT_OVERWRITE_FORBIDDEN`. Durable insertion and ref movement remain
out of scope and cannot be reported as completed by this skeleton.

An equivalence verifier receives an approved plan, exact old/new epoch entries,
and already-decoded canonical state views. It returns an evidence digest or
`SCHEMA_EQUIVALENCE_FAILED`. It cannot select decoders, mutate state, mutate the
registry, authorize policy changes, or derive authority from candidate input.
Its exact `verifier_id` must match the migration descriptor, and the reproduced
evidence digest must equal the draft before validation succeeds.

## 7. Stable failures

- `SCHEMA_EPOCH_MISMATCH`
- `SCHEMA_DOWNGRADE`
- `SCHEMA_CONTRACT_UNKNOWN`
- `SCHEMA_MIGRATION_UNSUPPORTED`
- `SCHEMA_EQUIVALENCE_FAILED`
- `SCHEMA_SELF_MODIFICATION`
- `SCHEMA_ROOT_OVERWRITE_FORBIDDEN`
- `SCHEMA_RECORD_INVALID`

SCB1 byte failures retain their `SCB_*` codes and are never collapsed into a
schema success or generic unknown state.

## 8. S20-140 acceptance

- bootstrap preimage and fixed meta-schema have deterministic vectors;
- record changes alter `SchemaEpochId`;
- registry creation rejects unsorted, duplicate, mismatched, or mutable inputs;
- exact lookup never falls back and downgrade probes fail closed;
- preserved old and new decoders remain separately selected by ID;
- migration plan validation rejects missing descriptors, same epochs, same
  roots, verifier mismatch, and occupied target slots;
- no S20-140 test claims durable state migration or root construction.
