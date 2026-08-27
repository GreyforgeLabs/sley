# ADR-0012: Restricted modeled-snapshot query authority

Status: accepted for the S20-310 restricted epoch-1 profile

## Decision

Implement only `RestrictedModeledSnapshotQueryV1` in the current epoch. It may
query an opaque `IndexSnapshot` produced by the public fresh-builder or
rebuild-first admission APIs. It may not decode, hydrate, or query candidate
cache bytes.

The profile has four closed query kinds: modeled entity-kind lookup, direct
dependencies, direct dependents, and reverse impact closure. Every result is
complete within the restricted snapshot or the query fails. There is no
truncation, continuation, pagination, omission marker, label lookup, free-form
search, root/object lookup, capsule, diagnostic, or mutation-affordance API.

## Rationale

Full S20-310 depends on a full S20-300 root-backed index and nineteen master-
goal query classes. Those prerequisites do not exist. A smaller typed surface
can still freeze exact ordering, request identity, context binding, and query-
explosion controls without converting a claimed root or snapshot digest into
semantic provenance.

Hard failure is required when a caller limit would omit a required fact. A
partial result without S20-320 omission/continuation semantics would be
indistinguishable from a complete answer.

## Consequences

- `QueryId` binds the exact snapshot ID/context/completeness, typed request,
  canonical filters/seeds, and applied limits;
- a query response is derived in-memory evidence and has no import decoder;
- `claimed_root_context` remains an unverified context claim;
- query candidate bytes, snapshot IDs, and response bytes grant no root,
  policy, mutation, execution, or persistence authority;
- the nineteen root-backed query classes, continuation, context capsules, and
  full S20-310/M3 completion remain blocked.
