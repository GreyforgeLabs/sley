# Sley 2 Architecture

Status: M1 normative baseline

## Target state

Sley 2 owns one semantic authority: a narrow Rust kernel that validates and
executes immutable SSMC1 objects encoded in SCB1. Higher layers may transport,
query, cache, display, or benchmark those facts but may not redefine them.

```text
agent -> generated adapter -> SMP1 -> query/mutation -> checker/policy
                                                   -> transaction engine
                                                   -> object store/repository
                                                   -> deterministic VM/adapters
```

## Dependency law

The intended dependency direction is:

```text
canon + id + schema -> ssmc -> check
check -> query + mutate + policy -> txn -> repo + vm -> protocol
protocol -> json-bridge + cli + conformance + bench
vm -> adapter (typed boundary only)
```

Transport, CLI, adapters, benchmarks, optional ZJX compression, Git, Siglum,
and every model provider remain outside the semantic kernel. No dependency may
point from a kernel crate to `sley-cli`, `sley-json-bridge`, `sley-bench`, or a
Greyforge product adapter.

## Planned crates

| Crate | Sole authority |
|---|---|
| `sley-canon` | SCB1 bytes and strict canonical decode |
| `sley-id` | domain-separated identifiers and digests |
| `sley-schema` | schema epochs and generated field contracts |
| `sley-ssmc` | entity, type, opcode, and semantic-fingerprint model |
| `sley-check` | graph, reference, type, CFG, effect, and contract validity |
| `sley-store` | immutable object persistence and corruption checks |
| `sley-query` | derived indexes, bounded queries, and capsules |
| `sley-mutate` | typed candidates, operations, and preconditions |
| `sley-policy` | protected policy roots and capability validation |
| `sley-txn` | validation orchestration, atomic commit, and receipts |
| `sley-repo` | refs, ancestry, comparisons, merge, conflicts, packs, GC |
| `sley-vm` | deterministic SSMC1 execution oracle |
| `sley-adapter` | bounded out-of-process host adapter contracts |
| `sley-protocol` | SMP1 framing and versioned request/response contracts |
| `sley-json-bridge` | generated non-canonical JSON mapping |
| `sley-cli` | thin machine wrapper; no semantic rules |
| `sley-conformance` | cross-implementation and corpus harness |
| `sley-bench` | succession and resource measurement |

Crates are created only when their first approved work package starts. Empty
crate proliferation is avoided; boundary ownership is already frozen here.

## Canonical and derived state

Canonical state is limited to facts required for program identity and kernel
judgment. Reverse indexes, caches, bytecode, short handles, rankings, reports
not explicitly bound into program state, JSON, and debug notation are derived.
Derived state must be reproducible or disposable and cannot grant authority.

## Version identities

- `EntityId` is stable logical identity.
- `ObjectId` addresses immutable canonical bytes.
- `StateRoot` addresses ancestry-independent semantic state.
- `TransactionId` addresses a parent-bound receipt and therefore repository
  ancestry.
- `SchemaEpochId` addresses the rules needed to decode and judge a state.

The policy root is protected and separately versioned. A candidate binds the
exact policy root used for judgment but may not modify it in the same
transaction.

## Durability

Commit order is validate, stage immutable objects, verify, promote, write and
sync receipt, sync directories, compare-and-swap the ref, then report success.
A crash may create unreachable objects; it may never expose partial accepted
state.

## Evolution

Epoch migrations decode with the old epoch, build a new state, record both
roots in a migration transaction, and preserve the old root. Silent fallback,
normalization, or schema downgrade is forbidden.
