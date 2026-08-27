# Restricted Index Snapshot Profile v1

Status: S20-300 restricted epoch-1 normative specification.

This profile freezes a deterministic, disposable cache record for the exact
S20-250 restricted `ImpactIndex`. It consumes an explicit, closed,
raw-`EntityId`-sorted request containing only modeled SSMC kinds 4 through 15.
It does not extract a complete `StateRoot`, model kinds 1 through 3 or 16
through 18, validate canonical objects, or authorize S20-310 root-backed
queries.

The central security rule is:

> A snapshot digest authenticates bytes, never semantic provenance.

Cache admission always rebuilds from the explicit modeled entity request
first and then requires exact byte equality. No digest, claimed root, decoded
edge, or cache hit can substitute for S20-250 extraction.

## 1. Domain and authority

ADR-0011 registers:

```text
sley2.index-snapshot.v1 -> IndexSnapshotId
```

```text
IndexSnapshotId =
  BLAKE3-256("sley2.index-snapshot.v1" || snapshot_preimage)
```

`IndexSnapshotId` is derived/disposable evidence. It is not `StateRoot`,
`ObjectId`, `EntityId`, `SemanticFingerprint`, `QueryId`, a policy decision,
or proof that the record came from canonical repository state.

## 2. Completeness and context

```text
IndexCompleteness = RestrictedModeledKinds4To15Only(1)

SnapshotContext {
  schema_epoch: SchemaEpochId,
  claimed_root_context: Option<StateRoot>
}
```

The completeness arm is mandatory. Unknown or broader arms fail. The schema
epoch is exact context for the S20-250 profile. The optional root is named a
claim because this restricted constructor has no root/object extractor and
does not verify that the supplied modeled bodies are the bindings of that
root. `None` is the honest default for a free-standing modeled request.

Changing either context field changes the bytes/ID, but matching context does
not establish provenance.

## 3. Snapshot contents

The fresh builder first calls `ImpactIndex::build`. S20-250 failures remain
exact. It then projects:

```text
IndexInventoryEntry { entity: EntityId, kind: ModeledEntityKind }

IndexSnapshot {
  snapshot_id: IndexSnapshotId,
  context: SnapshotContext,
  completeness: RestrictedModeledKinds4To15Only,
  inventory: list(IndexInventoryEntry),
  direct_edges: list(ImpactEdge),
  reverse_groups: list(ReverseGroup)
}

ReverseGroup {
  dependency: EntityId,
  dependents: list((dependent: EntityId, kind: ImpactKind))
}
```

Inventory is strict raw-ID order and covers every supplied modeled entity.
Direct edges retain S20-250 canonical `(dependent, dependency, kind)` order.
Reverse groups contain only referenced dependencies, use strict raw dependency
order, and each dependent/kind list is exact canonical order. Reverse groups
must be the exact inversion of direct edges; redundant disagreement is
`INDEX_SNAPSHOT_FORMAT_INVALID`.

No caller-provided fingerprint, ranking, label, path, cache timestamp, query
result, or partial closure is accepted. The TypeDef/Function fingerprint
catalog is omitted from restricted v1 rather than accepting unverified claims.

## 4. Canonical record

All integers are fixed-width big endian. Lists use
`u64be(count)||items`; options use `u32be(1)` for none and
`u32be(2)||item` for some.

```text
snapshot_preimage =
  "SLEYIDX1" || u32be(format_version=1) || u32be(profile_version=1) ||
  SchemaEpochId[32] || ssmc1_field_schema_hash[32] ||
  u32be(limits_profile=1) || option(StateRoot[32], claimed_root_context) ||
  u32be(completeness=1) ||
  list(inventory_entry) || list(direct_edge) || list(reverse_group)

inventory_entry = EntityId[32] || u32be(modeled_kind)
direct_edge = dependent[32] || dependency[32] || u32be(impact_kind)
reverse_group = dependency[32] || list(dependent[32] || u32be(impact_kind))

snapshot_record = snapshot_preimage || IndexSnapshotId[32]
```

The trailer is outside its own preimage. There is no host serializer,
platform integer, map iteration order, pointer, debug string, or extension
bag. Every append/allocation is checked so the complete record cannot exceed
67,108,864 bytes.

## 5. Build, inspect, and admission APIs

`build_index_snapshot(context, entities)` returns a fresh snapshot and exact
record bytes only after S20-250 succeeds.

A private bounded decoder may inspect candidate bytes for format, version,
context, completeness, canonical ordering, endpoint inventory, reverse
inversion, trailer digest, and trailing data. No public `from_digest`,
`from_state_root`, `trust_snapshot_for_root`, or queryable decoded-candidate API
exists in restricted v1.

```text
admit_index_snapshot(context, entities, candidate: Option<bytes>) =
  Hit(fresh_snapshot) |
  Rebuilt { reason, fresh_snapshot }
```

Admission order is exact:

1. rebuild the fresh snapshot from the explicit modeled request;
2. if no candidate exists, return `Rebuilt(Missing)`;
3. bounded-decode and self-check the candidate using exact expected context;
4. on candidate format/version/context/completeness/digest/resource failure,
   discard it and return the corresponding `Rebuilt` reason;
5. compare the complete candidate record byte-for-byte to the fresh record;
6. unequal valid bytes return `Rebuilt(ContentMismatch)`;
7. exact equality returns `Hit` containing the already-fresh snapshot.

Candidate failure never returns partial edges and never changes S20-250
failure semantics. Because every hit requires a fresh rebuild, this profile is
conformance/security evidence, not a performance cache.

## 6. Discard reasons and stable failures

```text
CacheDiscardReason =
  Missing | FormatInvalid | VersionUnsupported | ContextMismatch |
  DigestMismatch | CompletenessUnsupported | ResourceLimit |
  ContentMismatch
```

Candidate discard reasons are outcomes, not canonical errors. Fresh rebuild
failures preserve exact `IMPACT_*` codes. Direct snapshot construction or
record encoding uses:

| Numeric | Symbolic code |
|---:|---|
| 30000 | `INDEX_SNAPSHOT_PROFILE_UNSUPPORTED` |
| 30001 | `INDEX_SNAPSHOT_FORMAT_INVALID` |
| 30002 | `INDEX_SNAPSHOT_VERSION_UNSUPPORTED` |
| 30003 | `INDEX_SNAPSHOT_CONTEXT_MISMATCH` |
| 30004 | `INDEX_SNAPSHOT_DIGEST_MISMATCH` |
| 30005 | `INDEX_SNAPSHOT_COMPLETENESS_UNSUPPORTED` |
| 30006 | `INDEX_SNAPSHOT_RESOURCE_LIMIT` |
| 30007 | `INDEX_SNAPSHOT_INTERNAL_INVARIANT` |

No candidate-cache failure changes canonical program meaning or becomes a
partial successful index.

## 7. Limits

The stricter of S20-250 and this profile applies:

| Limit | Maximum |
|---|---:|
| modeled inventory entries | 65,535 |
| direct edges | 400,000 |
| reverse groups | 65,535 |
| reverse dependent/kind entries | 400,000 |
| complete snapshot record | 67,108,864 bytes |
| charged encode/decode/comparison work | 100,000,000 |

Counts, size multiplication, cursor movement, work, and allocation arithmetic
are checked before append/allocation. Decode count claims must fit both the
profile limit and remaining bytes before capacity is reserved.

## 8. Acceptance and explicit gaps

- fixed vectors freeze an empty and nonempty record/ID;
- at least 128 equal modeled-request rebuilds produce byte-identical inventory,
  edges, reverse groups, record, and ID;
- entity input allocation/order outside the frozen raw-ID list does not affect
  a previously canonical request;
- every format/version/context/completeness/order/endpoint/reverse/digest/
  trailer/count perturbation is discarded or fails deterministically;
- internally valid but unequal candidate bytes are `ContentMismatch` and never
  admitted;
- deleting/missing a cache yields the same fresh snapshot as no cache;
- no ambient filesystem, environment, clock, process, network, or cache path
  is read;
- strict lint and independent review have no open P0/P1/P2.

Full S20-300 and root-backed S20-310 remain blocked until all 18 SSMC1 bodies
are modeled, strict root/object extraction exists, complete-root indexes are
proven reproducible, and a useful cache can be admitted without trusting
derived bytes as semantic authority. This restricted profile does not satisfy
the M3 blocker or claim cache performance.
