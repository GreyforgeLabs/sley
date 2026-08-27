# Mutation Schema v1

Status: S20-340 normative schema-generation specification.

This package freezes immutable mutation-operation descriptors generated from
the exact SSMC1 epoch-1 schema manifest. It describes what later candidate
construction may express. It cannot construct or execute a mutation, establish
authority, validate a candidate, change canonical state, or commit a
transaction.

## 1. Canonical input and generation

The sole structural input is:

```text
docs/spec/SSMC1_EPOCH1_SCHEMA.txt
BLAKE3-256 = 044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73
```

`scripts/generate_mutation_schema.py` accepts only those exact reviewed bytes.
It parses the eighteen `entity` declarations and their named body `record`
declarations. Entity and field tags must be closed, unique, and ascending.
Generation has no filesystem discovery, environment input, time, Git, network,
provider, workspace, root, session, policy, or capability dependency.

The generated Rust file identifies its generator and source digest. It is
committed, and `--check` regenerates it in memory and requires exact byte
equality. The independent Rust digest test recomputes BLAKE3 over the source
manifest, so the Python generator does not need a second BLAKE3 implementation.

## 2. Closed primitive classes

The generated schema contains exactly these sixteen classes and tags:

| Tag | Class |
|---:|---|
| 1 | create entity |
| 2 | replace entity version |
| 3 | delete entity binding |
| 4 | set scalar field |
| 5 | replace typed field |
| 6 | retarget reference |
| 7 | insert ordered child |
| 8 | remove ordered child |
| 9 | move ordered child |
| 10 | add entry point |
| 11 | remove entry point |
| 12 | add test |
| 13 | replace test |
| 14 | add contract |
| 15 | replace contract |
| 16 | update dependency binding |

Entity creation, version replacement, and binding deletion are generated for
all eighteen entity kinds. The special classes target only the canonical
`EntryPoint` (16), `TestCase` (14), `Contract` (13), or
`DependencyBinding` (18) entity kind named by the class.

## 3. Field eligibility

Every entity-body field receives one `replace typed field` descriptor with its
exact manifest type expression and requiredness.

Additional field operations use closed syntactic rules:

- `set scalar field`: the exact field type is a frozen enum or one of `Bool`,
  `Bytes`, `F32`, `F64`, `FixedBytes32`, `SInt`, `Text`, `UInt16`, `UInt32`,
  or `UInt64`;
- `retarget reference`: the exact type is `EntityId` or `Option<EntityId>`;
- ordered-child insert, remove, and move: the exact type is
  `List<EntityId>`.

No recursive type inference, runtime Rust model, labels, heuristics, or
caller-supplied classification can add an affordance. Complex and collection
types outside those rules remain replaceable only as complete typed fields.

These are schema affordances, not permission or validity judgments. Later
kernel validation remains authoritative.

## 4. Preimage shapes

Creation requires `ExpectedIdentityAbsent`; this is an absence proof for the
deterministically derived logical identity, including the future tombstone
check. Every other generated operation requires an exact immutable preimage:

- entity and ordinary field operations require `ExactEntityVersion`;
- ordered-child operations require `ExactContainerVersion`.

The descriptor only names the requirement. It contains no `EntityId`,
`ObjectId`, root, value, nonce, principal, expiry, or caller claim. S20-350 must
define and construct actual bound preconditions; S20-360 must judge them.

## 5. Generated artifact boundary

Public output is limited to:

- the exact source-schema digest;
- eighteen immutable entity descriptors;
- exact field tag/name/type/requiredness descriptors;
- the closed sixteen-class enum;
- concrete class/kind/field eligibility descriptors;
- preimage-requirement metadata and read-only lookup iterators.

There is deliberately no operation-value type, decoder/importer, candidate
builder, mutation applier, repository dependency, state-root derivation,
session handle, policy/capability path, transaction, receipt, or CAS surface.

## 6. Acceptance and remaining gates

Acceptance requires exact source-digest reproduction, deterministic generated
bytes, all eighteen entity kinds, all sixteen classes, one complete typed-field
replacement per body field, unique `(class, kind, field)` keys, exact syntactic
eligibility, preimage metadata, and a clean committed-output drift check.

S20-340 supplies schema input to S20-350 only. S20-350, S20-360, S20-370,
S20-380, S20-390, S20-400, M3, M4, M5, release, and GA remain blocked.
