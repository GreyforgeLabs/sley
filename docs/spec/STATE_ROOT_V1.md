# Deterministic State Root v1

Status: S20-160 normative contract; implementation pending.

## Scope and authority

A `StateRoot` identifies semantic program state under one exact schema epoch.
It does not identify a transaction, repository path, branch, ref, or history.
This contract is newly designed for Sley 2.0 and imports no Sley 1.x storage or
revision pattern.

The byte codec and digest function alone do not authorize accepted state. An
authorized constructor or importer MUST receive an exact immutable
`SchemaRegistry` entry, require that its `SchemaEpochId` equals the envelope
and payload epoch, require a `ContractDescriptor` for contract tag 160, and run
that entry's preserved decoder for tag 160. Candidate content cannot select or
construct the registry, descriptor, decoder, or interpretation-flag policy.

The descriptor's `field_schema_hash` commits to the complete field schema and
allowed interpretation-flag tags. The preserved decoder enforces that
allowlist. This uses the existing S20-140 descriptor shape; it does not add or
reinterpret descriptor fields. Epoch 1 accepts only an empty interpretation
flag set until a descriptor-bound decoder explicitly declares tags.

S20-160 proves root construction and strict import. Object existence,
cross-object semantic validity, ref movement, transaction ancestry, and commit
authority remain later validation/transaction obligations.

## Standalone envelope and identity

The StateRoot standalone contract uses:

```text
format_version    = 1
contract_tag      = 160
contract_domain   = "sley2.state-root.v1"
digest_domain_tag = 4
kind_tag          = 160
```

Its envelope is the SCB1 standalone envelope from `SCB1.md`:

```text
envelope_preimage = "SLEYSCB1" || uvar(1) || uvar(160) ||
                    SchemaEpochId[32] || len(payload) || payload
StateRoot = BLAKE3-256("sley2.state-root.v1" || envelope_preimage)
stored_bytes = envelope_preimage || StateRoot[32]
```

The trailer is outside its own preimage. It is exactly the derived
`StateRoot`, and no bytes follow it.

## Payload record

The payload is a closed SCB1 Record with all fields required:

| Tag | Field | Type |
|---:|---|---|
| 1 | workspace_id | `FixedBytes<32>` / `WorkspaceId` |
| 2 | schema_epoch_id | `FixedBytes<32>` / `SchemaEpochId` |
| 3 | entity_bindings | `Map<FixedBytes<32>, FixedBytes<32>>` / `EntityId -> ObjectId` |
| 4 | entry_points | `CanonicalSet<FixedBytes<32>>` / `EntityId` |
| 5 | dependency_roots | `CanonicalSet<FixedBytes<32>>` / `StateRoot` |
| 6 | contract_root | `FixedBytes<32>` / `ObjectId` |
| 7 | test_root | `FixedBytes<32>` / `ObjectId` |
| 8 | policy_root | `FixedBytes<32>` / `PolicyRootId` |
| 9 | interpretation_flags | `CanonicalSet<UInt<32>>` |

The payload epoch MUST equal the envelope epoch and the selected registry
entry. Every entry point MUST have an entity binding. Different entities MAY
bind the same object; duplicate entity keys are always invalid.

Entity bindings are ordered by complete canonical map-key bytes. Because every
key is `FixedBytes<32>`, that is raw unsigned lexicographic `EntityId` order.
Entry points, dependency roots, and flags use SCB1 canonical-set ordering by
complete encoded element bytes. Duplicate keys or set elements are rejected,
even if repeated values match.

Construction from semantic collections sorts unordered inputs into canonical
order but rejects duplicate or conflicting inputs and unknown flags. Strict
decoding never normalizes: noncanonical order, duplicates, unknown or missing
fields, nonminimal integers, epoch mismatch, digest mismatch, and trailing
bytes fail closed.

All selected-epoch SCB1 limits apply. State-root code may impose a stricter
local/session bound but never a looser one. Construction and import document
linear time and memory in the encoded bindings and sets, plus sorting cost
`O(n log n)` for unordered construction.

## Identity exclusions

There is no constructor field or decoder path for:

- ref names or heads, branch names, or tags;
- transaction parents, ancestry, IDs, receipts, or commit metadata;
- actors, principals, sessions, or capability-use evidence;
- timestamps, filesystem or object-store paths, permissions, or host identity;
- Git commits, trees, refs, configuration, or remotes;
- pack compression/profile data, leases, pins, locks, or recovery metadata;
- caches, indexes, query results, benchmark facts, or debug dumps;
- environment data, model output, labels, comments, source, or formatting.

Two records with identical nine fields under the same authorized epoch derive
the same root regardless of construction order or repository ancestry.

## Stable failures

- registry or descriptor absence preserves `SCHEMA_EPOCH_MISMATCH` or
  `SCHEMA_CONTRACT_UNKNOWN`;
- byte/canonical/digest/limit failures preserve exact `SCB_*` codes;
- unordered builder duplicates return `STATE_ROOT_DUPLICATE_INPUT`;
- an entry point without a binding returns `STATE_ROOT_ENTRY_UNBOUND`;
- an unknown interpretation tag returns `STATE_ROOT_FLAG_UNKNOWN`;
- any attempt to supply excluded identity facts returns
  `STATE_ROOT_EXCLUDED_FACT` where such a higher-level typed request exists.

Unknown, missing, ambiguous, or internal results never become a root.

## Synthetic byte vector

The following all-zero-epoch vector proves only encoding and domain-separated
hashing. The all-zero epoch is not registered and this vector MUST be rejected
by the authorized constructor/import boundary.

Payload bytes: 183.

```text
090120000000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000000030100040100050100062000000000000000000000000000000000000000000000000000000000000000000720000000000000000000000000000000000000000000000000000000000000000008200000000000000000000000000000000000000000000000000000000000000000090100
```

Envelope preimage bytes: 228.

```text
534c45595343423101a0010000000000000000000000000000000000000000000000000000000000000000b701090120000000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000000030100040100050100062000000000000000000000000000000000000000000000000000000000000000000720000000000000000000000000000000000000000000000000000000000000000008200000000000000000000000000000000000000000000000000000000000000000090100
```

Synthetic `StateRoot`:

```text
8c8bf5f5aba59d6816e1ae3d7ffd4b79ee0434b7c5d72782c929e4e97db50fc2
```

An independent implementation reproduced all three lengths/bytes and the
digest. Accepted-state conformance additionally requires a nonzero registered
epoch fixture containing the exact tag-160 descriptor and matching decoder;
the implementation package must freeze that fixture before completion.

## S20-160 acceptance

- synthetic bytes and digest match the fixed vector, but authorization rejects
  its unregistered zero epoch;
- a registered conformance epoch with exact tag-160 descriptor and decoder
  round-trips one fixed accepted vector;
- unordered semantic inputs construct byte-identical roots;
- changing any of the nine fields changes the root;
- duplicate/conflicting bindings or set elements fail before root exposure;
- unknown flags and unbound entry points fail closed;
- strict import rejects noncanonical map/set order, duplicates, unknown/missing
  fields, epoch mismatch, digest mismatch, trailing bytes, and limit breaches;
- API and dependency review confirm that excluded ancestry, repository, host,
  source, Git, cache, and model facts cannot enter the preimage;
- S20-170 later proves pack reconstruction of exact standalone root bytes;
- S20-390 later proves ancestry changes transaction/receipt identity without
  changing an otherwise identical semantic `StateRoot`.
