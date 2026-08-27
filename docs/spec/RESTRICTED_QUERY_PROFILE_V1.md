# Restricted Modeled-Snapshot Query Profile v1

Status: S20-310 restricted epoch-1 normative specification.

This profile freezes a small typed, bounded query surface over the exact
freshly derived `IndexSnapshot` from the S20-300 restricted profile. It does
not implement the master goal's full root-backed query engine, its nineteen
required classes, SMP1 transport, truncation/continuation, or S20-320 context
capsules.

The authority rule is:

> A restricted query may inspect only an opaque snapshot already rebuilt from
> the explicit modeled request; no digest or candidate bytes can supply facts.

## 1. Authority and scope

Accepted input authority is an `IndexSnapshot` returned by
`build_index_snapshot`, or the fresh snapshot carried by either arm of
`admit_index_snapshot`. Snapshot fields remain private and candidate inspection
remains private. `IndexSnapshotId`, a cache hit, response bytes, and
`claimed_root_context` do not prove canonical-root provenance.

The profile supports only modeled SSMC1 kinds 4 through 15 and the S20-250
impact relationships already present in the snapshot. It accepts no root,
object, entity body, label, path, fingerprint claim, timestamp, ranking,
diagnostic, policy, test plan, mutation, or free-form query text.

## 2. Query classes and tags

```text
RestrictedQuery =
  GetModeledEntityKind { entity }                         (1) |
  ListDirectDependencies { entity, kinds }                (2) |
  ListDirectDependents { entity, kinds }                  (3) |
  ReverseImpactClosure { seeds }                          (4)
```

`GetModeledEntityKind` returns the exact inventory entry. It is not the master
goal's `GetEntity`: no semantic body or version is returned.

`ListDirectDependencies` returns every direct edge whose `dependent` equals
`entity` and whose relationship kind is in `kinds`.

`ListDirectDependents` returns every direct edge whose `dependency` equals
`entity` and whose relationship kind is in `kinds`.

`ReverseImpactClosure` returns the reverse-reachable entity set, including all
seeds at depth zero, across every relationship kind. Seeds are expanded at
most once. The result is strict raw-`EntityId` order, independent of traversal
order.

Relationship filters are nonempty lists whose tags must first resolve to the
closed `ImpactKind` domain 1 through 12 and must then be strictly increasing
with no duplicates. An unknown tag is `QUERY_UNSUPPORTED` even when its raw
number would also violate ordering. Seed lists are nonempty, strict raw-
`EntityId` order with no duplicates. Every named entity and seed must occur in
the snapshot inventory. Edge results retain canonical `ImpactEdge` order.

## 3. Applied limits

```text
QueryLimits {
  max_returned_entities: u64,
  max_returned_edges: u64,
  max_depth: u32,
  max_response_bytes: u64,
  max_work: u64
}
```

All values except `max_depth` must be at least one. Applied limits are caller-
selected inputs and part of `QueryId`. They may not exceed:

| Limit | Maximum |
|---|---:|
| request preimage | 4,194,304 bytes |
| filter kinds | 12 |
| seeds | 65,535 |
| returned entities | 65,535 |
| returned edges | 400,000 |
| reverse depth | 65,535 |
| response record | 67,108,864 bytes |
| charged traversal plus response encoding work | 100,000,000 |

Traversal charges one unit per inventory lookup, expanded entity, and examined
reverse/direct edge. Response encoding charges one unit per emitted byte.
Arithmetic, capacity, and append bounds are checked before allocation or
append.

If a request exceeds a profile ceiling or charged work exceeds `max_work`, the
query returns `QUERY_RESOURCE_LIMIT`. If the exact complete result would exceed
an applied entity, edge, depth, or response-byte limit, it returns
`QUERY_REQUIRED_FACT_OMITTED`. Neither failure returns a partial result.

## 4. Query identity

All integers are fixed-width big endian. Lists use `u64be(count)||items` and
options use `u32be(1)` for none or `u32be(2)||item` for some.

```text
query_preimage =
  "SLEYQRY1" || u32be(format_version=1) ||
  u32be(profile_version=1) || IndexSnapshotId[32] ||
  SchemaEpochId[32] || option(StateRoot[32], claimed_root_context) ||
  u32be(completeness=1) || u32be(limits_profile=1) ||
  query_limits || query_body

query_limits =
  u64be(max_returned_entities) || u64be(max_returned_edges) ||
  u32be(max_depth) || u64be(max_response_bytes) || u64be(max_work)

query_body =
  u32be(kind_tag) ||
  entity[32]                                           // kind 1
  entity[32] || list(u32be(impact_kind))               // kinds 2,3
  list(EntityId[32])                                   // kind 4

QueryId = BLAKE3-256("sley2.query.v1" || query_preimage)
```

The snapshot ID, exact schema/root-claim context, completeness arm, request,
and all applied limits are therefore bound. The ID authenticates the request
preimage only; it is not a result digest, state root, policy decision, or proof
of root provenance.

## 5. Response

```text
RestrictedQueryResponse {
  query_id,
  snapshot_id,
  context,
  completeness,
  applied_limits,
  query_kind,
  returned_entities,
  returned_edges,
  reached_depth,
  charged_work,
  response_bytes,
  result
}

RestrictedQueryResult =
  ModeledEntityKind(IndexInventoryEntry) |
  DirectEdges(list(ImpactEdge)) |
  ReverseImpactClosure(list(EntityId))
```

The response record is exact:

```text
response_record =
  "SLEYQRS1" || u32be(format_version=1) ||
  u32be(profile_version=1) || QueryId[32] || IndexSnapshotId[32] ||
  SchemaEpochId[32] || option(StateRoot[32], claimed_root_context) ||
  u32be(completeness=1) || u32be(limits_profile=1) || query_limits ||
  u32be(query_kind) || u64be(returned_entities) ||
  u64be(returned_edges) || u32be(reached_depth) ||
  u64be(charged_work) || u64be(response_bytes) ||
  u32be(result_tag) || result_payload

result_payload =
  inventory_entry                                      // result tag 1
  list(direct_edge)                                    // result tags 2,3
  list(EntityId[32])                                   // result tag 4

inventory_entry = EntityId[32] || u32be(modeled_kind)
direct_edge = dependent[32] || dependency[32] || u32be(impact_kind)
```

`result_tag` must equal `query_kind`. Modeled-kind tags are the exact SSMC1
tags 4 through 15. Impact-kind tags are the exact S20-250 tags 1 through 12.
The list, option, and integer encodings are those frozen in section 4. The
fixed response header through `result_tag` is 204 bytes when the root claim is
absent and 236 bytes when present. Payload lengths are exactly 36 bytes for
tag 1, `8 + 68*n` bytes for tags 2/3, and `8 + 32*n` bytes for tag 4.

`response_bytes` is the complete `response_record` length. The encoder
computes that length with checked arithmetic before allocation. It then sets
`charged_work = traversal_work + response_bytes`, checks the applied and
profile work ceilings, and encodes both already-known fixed-width values; no
self-referential sizing or patch-dependent semantics exist.

The record has no digest trailer and no import/decoder API. S20-320 owns
capsule identity, omissions, dictionaries, and continuation.

Counts describe payload entries: entity-kind and closure results count returned
entities; direct-edge results count returned edges. `reached_depth` is zero for
non-closure queries and the maximum shortest reverse distance for a closure.
`charged_work` includes traversal and complete response-record bytes.

## 6. Errors and precedence

| Numeric | Symbolic code |
|---:|---|
| 31000 | `QUERY_PROFILE_UNSUPPORTED` |
| 31001 | `QUERY_REQUEST_NOT_CANONICAL` |
| 31002 | `QUERY_UNSUPPORTED` |
| 31003 | `QUERY_SNAPSHOT_MISMATCH` |
| 31004 | `QUERY_UNRESOLVED_ENTITY` |
| 31005 | `QUERY_RESOURCE_LIMIT` |
| 31006 | `QUERY_REQUIRED_FACT_OMITTED` |
| 31007 | `QUERY_INTERNAL_INVARIANT` |

The end-to-end helper rebuilds the snapshot before examining the query. Exact
`IMPACT_*` failures remain `Impact`; snapshot projection/encoding failures
remain `INDEX_SNAPSHOT_*`. Query processing then orders failures as:

1. invalid limit profile/ceiling (`QUERY_RESOURCE_LIMIT`);
2. unsupported format/profile (`QUERY_PROFILE_UNSUPPORTED`), then unsupported
   query or filter tag (`QUERY_UNSUPPORTED`);
3. noncanonical supported filters/seeds or request-ID drift
   (`QUERY_REQUEST_NOT_CANONICAL`);
4. request/snapshot binding mismatch (`QUERY_SNAPSHOT_MISMATCH`);
5. absent entity or seed (`QUERY_UNRESOLVED_ENTITY`);
6. traversal/work ceiling (`QUERY_RESOURCE_LIMIT`);
7. exact result cannot fit applied entity/edge/depth/byte limit
   (`QUERY_REQUIRED_FACT_OMITTED`);
8. impossible trusted-construction invariant (`QUERY_INTERNAL_INVARIANT`).

Unknown, missing, incomplete, over-limit, or ambiguous results never become
empty successful results unless the exact query answer is genuinely empty.

## 7. Acceptance and explicit gaps

- fixed request-ID and response-record vectors cover all four query kinds;
- at least 128 equal queries produce byte-identical IDs, payloads, counts,
  depth, work, and response records;
- filters, seeds, snapshot/context bindings, result ordering, and error
  precedence have exact negative fixtures;
- fanout, cycles, depth, entity, edge, byte, and work ceilings return no partial
  payload (`T13`);
- limits that would hide a required fact fail explicitly (`T14`);
- candidate bytes and claimed roots cannot enter query execution (`T35/T36`);
- no filesystem, environment, clock, process, network, cache path, free-form
  text, or host serializer is read;
- strict lint and independent review have no open P0/P1/P2.

Full S20-310 and the M3 blocker remain open until full S20-300 provides strict
root/object extraction and complete indexes, all nineteen master-goal query
classes have exact bounded semantics, and SMP1/S20-320 define lawful
truncation, continuation, capsules, and omissions. This restricted profile
does not unblock S20-320, S20-400, or GA.
