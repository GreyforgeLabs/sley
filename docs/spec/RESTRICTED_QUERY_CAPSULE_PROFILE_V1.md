# Restricted Complete-Query Capsule Profile v1

Status: S20-320 restricted epoch-1 normative specification.

This profile freezes a deterministic evidence envelope over one successful,
complete `RestrictedQueryResponse`. It is not the master
`sley-context-capsule-v1` and does not contain or imply session, workspace,
verified-root, type/effect/contract/test, diagnostic, mutation, omission,
continuation, or protocol authority.

The authority rule is:

> A restricted capsule can reorganize facts already present in one complete
> response; it cannot add, omit, resume, import, or authorize facts.

## 1. Identity and source

ADR-0013 registers:

```text
sley2.restricted-query-capsule.v1 -> RestrictedQueryCapsuleId
```

```text
RestrictedQueryCapsuleId =
  BLAKE3-256("sley2.restricted-query-capsule.v1" || capsule_preimage)
```

The only public constructor accepts `&RestrictedQueryResponse`, whose public
construction already requires a successful exact S20-310 query. Query errors,
partial bytes, candidate snapshot bytes, raw `SLEYQRS1` records, digests,
claimed roots, and caller-provided dictionaries cannot construct a capsule.

The capsule ID authenticates its exact preimage only. It is not
`ContextCapsuleId`, `QueryId`, `StateRoot`, `ObjectId`, a session, policy
decision, continuation capability, or root-provenance proof.

## 2. Fixed completeness state

```text
RestrictedCapsuleCompleteness = CompleteRestrictedResult(1)
Truncation = False(1)
Continuation = None(1)
```

There are no other public arms. A restricted query that cannot return its
complete result fails with S20-310 `QUERY_RESOURCE_LIMIT` or
`QUERY_REQUIRED_FACT_OMITTED` before capsule construction, so no partial query
payload can be reclassified as complete.

## 3. Entity dictionary

The entity dictionary is a strict raw-`EntityId`-sorted unique list derived
only from the typed response result:

- `ModeledEntityKind(entry)`: the entry entity;
- `DirectEdges(edges)`: every dependent and dependency endpoint;
- `ReverseImpactClosure(entities)`: the exact returned entity list.

No label, type, path, source position, local handle, ranking, summary, or
caller-supplied identity enters the dictionary. It contains at most 65,535
entries because the source snapshot inventory has that ceiling.

## 4. Relationship table

For `DirectEdges`, each exact edge becomes:

```text
RestrictedCapsuleRelationship {
  dependent_index: u32,
  dependency_index: u32,
  kind: ImpactKind
}
```

Indexes are zero-based positions in the entity dictionary. Relationship order
is the source edge order, which is canonical `(dependent, dependency, kind)`
order. Both indexed identities must resolve back to the exact edge endpoints.

Other result kinds have an empty relationship table. The table contains at
most 400,000 entries. It never invents transitive edges or relationships absent
from the response.

## 5. Canonical record

All integers are fixed-width big endian. Lists and byte strings use
`u64be(count_or_length)||items_or_bytes`. Options use their frozen tags.

```text
capsule_preimage =
  "SLEYRQC1" || u32be(format_version=1) ||
  u32be(profile_version=1) || QueryId[32] || IndexSnapshotId[32] ||
  SchemaEpochId[32] || option(StateRoot[32], claimed_root_context) ||
  u32be(index_completeness=1) || u32be(limits_profile=1) ||
  query_limits || u32be(query_kind) ||
  u64be(returned_entities) || u64be(returned_edges) ||
  u32be(reached_depth) || u64be(query_charged_work) ||
  u64be(response_bytes) ||
  u32be(capsule_completeness=1) || u32be(truncation_false=1) ||
  u32be(continuation_none=1) ||
  bytes(exact_SLEYQRS1_response_record) ||
  list(EntityId[32], entity_dictionary) ||
  list(u32be(dependent_index) || u32be(dependency_index) ||
       u32be(impact_kind), relationships)

capsule_record = capsule_preimage || RestrictedQueryCapsuleId[32]
```

`query_limits` has the exact S20-310 layout. Every repeated response metadata
field must equal the trusted response getters, `response_bytes` must equal the
copied record length, and the copied record must begin `SLEYQRS1`. The ID
trailer is outside its own preimage.

There is no public record decoder, importer, hydrator, continuation expander,
or constructor from caller-provided components. A record is derived evidence
for conformance and later design, not canonical program state.

## 6. Limits and work

| Limit | Maximum |
|---|---:|
| source response bytes accepted by this capsule profile | 33,554,432 |
| entity dictionary entries | 65,535 |
| relationships | 400,000 |
| complete capsule record | 67,108,864 bytes |
| charged derivation/encoding work | 100,000,000 |

Work charges one unit per inspected result item, dictionary insertion/lookup,
relationship projection, copied source-response byte, and emitted capsule byte.
Counts, index conversion, multiplication, total size, capacity, and work are
checked before allocation or append. Resource failure returns no capsule.

The current four query kinds fit the capsule-source ceiling by construction:
the largest payload is 400,000 direct edges at 68 bytes each plus the fixed
response header and list count, which is below 33,554,432 bytes. A future
restricted-query profile expansion must revise this capsule profile rather
than silently accepting a larger response. The capsule's 67,108,864-byte
ceiling then has checked room for that copied response, the 65,535-entry entity
dictionary, the 400,000-entry relationship table, metadata, and ID trailer.

## 7. Errors and precedence

| Numeric | Symbolic code |
|---:|---|
| 32000 | `RESTRICTED_CAPSULE_PROFILE_UNSUPPORTED` |
| 32001 | `RESTRICTED_CAPSULE_SOURCE_INVALID` |
| 32002 | `RESTRICTED_CAPSULE_DICTIONARY_INVALID` |
| 32003 | `RESTRICTED_CAPSULE_RELATIONSHIP_INVALID` |
| 32004 | `RESTRICTED_CAPSULE_RESOURCE_LIMIT` |
| 32005 | `RESTRICTED_CAPSULE_OMISSION_UNSUPPORTED` |
| 32006 | `RESTRICTED_CAPSULE_CONTINUATION_UNSUPPORTED` |
| 32007 | `RESTRICTED_CAPSULE_INTERNAL_INVARIANT` |

S20-310 failures occur before capsule construction and remain exact `IMPACT_*`,
`INDEX_SNAPSHOT_*`, or `QUERY_*` failures. For an accepted typed response,
capsule construction checks:

1. exact trusted response record magic/length and metadata consistency
   (`RESTRICTED_CAPSULE_SOURCE_INVALID`);
2. profile count/byte/work preflight (`RESTRICTED_CAPSULE_RESOURCE_LIMIT`);
3. dictionary canonicality/completeness
   (`RESTRICTED_CAPSULE_DICTIONARY_INVALID`);
4. relationship index/order/endpoint agreement
   (`RESTRICTED_CAPSULE_RELATIONSHIP_INVALID`);
5. fixed complete/nontruncated/no-continuation state;
6. checked encoding and ID derivation.

The omission and continuation codes are reserved for private invariant checks;
no public caller can request those states. Unknown or incomplete source facts
never become an empty successful capsule.

## 8. Acceptance and explicit gaps

- fixed record/ID vectors cover all three result variants and all four
  restricted query kinds;
- at least 128 equal response derivations produce byte-identical dictionaries,
  relationships, records, and IDs;
- entity allocation/order outside the response cannot change the capsule;
- direct-edge endpoint/index inversion round-trips exactly;
- cycles and fanout do not add relationships beyond the response;
- source length/magic, dictionary, index, count, size, and work perturbations
  fail without a capsule;
- query limit/failure paths cannot invoke the capsule constructor;
- no filesystem, environment, clock, process, network, cache path, session,
  workspace, label, free text, or host serializer is read;
- strict lint and independent review have no open P0/P1/P2.

Full S20-320 remains blocked by a full root-backed S20-310 engine, verified
workspace/root/session bindings, type/effect/contract/test facts, diagnostics,
mutation affordances, lawful omission/truncation/continuation semantics,
master `ContextCapsuleId`, and SMP1 integration. This restricted profile does
not unblock S20-330, S20-400, S20-620, M3, M5, or GA.
