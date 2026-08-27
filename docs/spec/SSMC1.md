# Sley Semantic Machine Code v1 (SSMC1)

Status: S20-200 normative specification.

## 1. Scope

SSMC1 is the only canonical Sley 2 program representation. It is a typed,
immutable semantic graph encoded as SCB1 objects. It is not source text, an
AST, debug data, CPU code, Wasm, arbitrary bytes, or a serialization of host
objects. Normal creation, query, mutation, validation, and execution paths
never require or emit Sley source.

S20-200 freezes the epoch-1 entity object contract, entity-kind tags,
structural type-expression tags, operation tags, terminator tags, and local
signatures. S20-210 through S20-270 own type, CFG, effect, contract,
fingerprint, lowering, and execution judgments. They must consume this schema
without silently extending or reinterpreting it.

All fields and tags are closed. Unknown, missing, duplicated, mismatched, or
ambiguous data fails closed. Labels are optional normalized metadata: they may
change an immutable `ObjectId`, but never derive or replace an `EntityId`,
select a schema, or enter a semantic fingerprint.

## 2. Standalone entity object

Every SSMC1 entity version is exactly one SCB1 standalone object:

```text
format_version    = 1
contract_tag      = 200
contract_domain   = "sley2.object.v1"
digest_domain_tag = 3
kind_tag          = 200
```

```text
envelope_preimage = "SLEYSCB1" || uvar(1) || uvar(200) ||
                    SchemaEpochId[32] || len(payload) || payload
ObjectId = BLAKE3-256("sley2.object.v1" || envelope_preimage)
stored_bytes = envelope_preimage || ObjectId[32]
```

The payload is one closed Record:

| Tag | Field | Type | Presence |
|---:|---|---|---|
| 1 | entity_id | `FixedBytes<32>` / `EntityId` | required |
| 2 | body | `EntityBody` closed Union | required |
| 3 | label | `NormalizedLabel` | optional |
| 4 | semantic_fingerprint | `FixedBytes<32>` | optional/reserved for S20-250 |

The `EntityBody` tag is the entity kind and must equal the kind used to
derive `entity_id`. There is no caller-supplied dependency list: references
are extracted from the body by the exact selected-epoch schema, preventing a
second inconsistent graph.

Semantic references use `EntityId`, never paths, labels, object addresses, or
host pointers. A `StateRoot` resolves each entity to an exact immutable
`ObjectId`. Ordinary entity bodies do not pin another entity version.

## 3. Frozen schema input and descriptor

`SSMC1_EPOCH1_SCHEMA.txt` is the exact ASCII, LF-terminated manifest for all
fields, unions, enum tags, opcodes, and terminators. Its notation is closed:

- `record N(...)` lists ascending `tag:name:type` fields; `!` means required and `?`
  optional;
- `union N(...)` and `enum N(...)` list ascending closed tags;
- `entity`, `type`, `term`, and `op` rows freeze numeric tags;
- `List` preserves order and `Set` uses SCB1 canonical-set order;
- signature metavariables (`T`, `K`, `V`, `E`, `N`) unify exactly and
  authorize no coercion, inference, subtyping, or host behavior.

The production epoch containing SSMC1 must include exactly this descriptor:

| Descriptor field | Epoch-1 value |
|---|---|
| contract_tag | `200` |
| digest_domain_tag | `3` |
| kind_tag | `200` |
| required_fields | `{1,2}` |
| optional_fields | `{3,4}` |
| variant_tags | `{1..18}` |
| field_schema_hash | `044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73` |
| decoder_limits_hash | `389791b170bc9d8575f7e6f338e4f9e9f2b75f35d7a2e52c7cb106cb2cd6136a` |

The field-schema hash is raw BLAKE3-256 of the complete manifest bytes. The
decoder-limits hash is raw BLAKE3-256 of this exact ASCII preimage:

```text
sley2.ssmc1.v1.decoder-limits:scb1-epoch1;label_bytes=1024;type_depth=64;type_args=1024;tuple_items=65535;fields_or_cases=65535;function_params=65535;block_params=65535;blocks_per_function=1000000;operations_per_block=1000000;operands_per_operation=65535;results_per_operation=65535;switch_cases=65535;constant_depth=64;constant_elements=1000000;constant_payload_bytes=16777216
```

These are inputs to the eventual complete production epoch. They do not
mutate the S20-140 conformance epoch or claim later descriptors already exist.

## 4. Entity kinds

| Tag | Kind | Role |
|---:|---|---|
| 1 | `Workspace` | packages, root namespace, workspace semantic roots |
| 2 | `Package` | membership, exports, dependencies |
| 3 | `Namespace` | hierarchical semantic membership |
| 4 | `TypeDef` | record or tagged-variant definition |
| 5 | `Function` | signature, effects, contracts, block graph |
| 6 | `Parameter` | stable function or block parameter |
| 7 | `Block` | ordered operations and one terminator |
| 8 | `Operation` | typed operation and declared results |
| 9 | `Constant` | persistable typed constant |
| 10 | `GlobalValue` | immutable explicitly referenced global |
| 11 | `EffectDef` | request, response, failure, and scope types |
| 12 | `CapabilityRequirement` | static effect/scope requirement |
| 13 | `Contract` | typed predicate binding |
| 14 | `TestCase` | input, replay, expectation, observations, ceilings |
| 15 | `AdapterImport` | stable typed adapter ABI declaration |
| 16 | `EntryPoint` | explicit callable function exposure |
| 17 | `PolicyBinding` | entity-to-requirement binding |
| 18 | `DependencyBinding` | external root/package namespace binding |

The manifest freezes every payload field. Sets are canonical unless semantic
order matters. Function parameters, block parameters, blocks, operations,
type fields/cases, call arguments, and test inputs are ordered lists.

`Parameter`, `Block`, and `Operation` are distinct entities. An operation
result is addressed by `(operation EntityId, result index)`; parameters use
their `EntityId`. Owner and ordinal facts must agree with the owner's list.
Source order, line numbers, and host allocation order never enter identity.

## 5. Structural types

Epoch 1 includes `Unit`, `Bool`, explicit-width signed/unsigned integers,
`F32`, `F64`, `Bytes`, exact-scalar-sequence `Text`, fixed tuples,
named record/variant instantiations, vectors, ordered maps, `Option`,
`Result`, function references, opaque adapter handles, capability tokens,
local cells, type parameters, and five closed built-in failure kinds.

Integer width is one of 8, 16, 32, 64, or 128. `Text` preserves its exact
Unicode scalar sequence; it is never normalized. Only `NormalizedLabel`
metadata uses epoch-pinned NFC. Structural depth is at most 64. Definition
recursion is possible only through a named reference and is rejected until
S20-210 freezes a termination-safe rule.

`LocalCell<T>`, adapter handles, and capability tokens cannot occur in
`Constant`, test input/expectation, object metadata, or other persistable
values. Function references contain stable function identity and explicit
type arguments, never an address.

Record fields and variant cases use a 32-byte `MemberId`: a creator-supplied
nonce that is unique within its `TypeDef` and remains stable across versions.
It is not globally addressed, is not an `EntityId` or `ObjectId`, and cannot
be derived from a label or ordinal. Duplicate or reused member IDs are invalid.

S20-210 owns kind checking, type equality, generic instantiation,
equality/order/hash traits, and constant/type agreement. It may reject more
combinations but cannot renumber or reinterpret structural tags.

Constant tuples/vectors preserve element order; record fields exactly follow
the defining field order; and ordered-map entries are strictly sorted by the
complete canonical key-value bytes with no duplicate key. A constant's outer
type must match its closed data variant exactly.

## 6. Control flow

Functions use explicit CFGs with block parameters. Every block has ordered
operations and exactly one terminator:

| Tag | Name | Local signature |
|---:|---|---|
| 1 | `return` | one value equal to the function result type |
| 2 | `branch` | target plus arguments matching block parameters |
| 3 | `cond_branch` | `Bool`, then two target/argument edges |
| 4 | `variant_switch` | closed variant/Option/Result and exhaustive edges |
| 5 | `trap` | closed `TrapCode` and optional value reference |

Loops are backedges. A switch key is either a named case's stable `MemberId` or
a closed built-in case (`None`, `Some`, `Ok`, `Err`). Rows are strictly ordered
by canonical case-key bytes, have no default, and exactly cover the selected
variant. A switch-edge argument is an ordinary `ValueRef` or the selected case
payload; payload use is invalid for a payload-free case. This is the only
implicit edge value and it is explicit in the edge schema. A trap is an
explicit unrecoverable result and cannot be caught or converted to `Result`.
Trap codes are `1 Unreachable`, `2 ResourceExhausted`,
`3 AdapterContractViolation`, and `4 InternalInvariant`.
Its optional `ValueRef` payload must have a persistable static type; the trap
does not embed a second object or permit a handle, token, or local cell to
escape.

S20-220 owns owner/ordinal consistency, reachability, edge typing, dominance,
use-before-definition, result bounds, switch exhaustiveness, and cycles.
Structural decoding alone never claims CFG validity.

## 7. Opcodes

The manifest is authoritative for tags, operand/result shapes, immediates, and
explicit failure values:

| Range | Family | Operations |
|---:|---|---|
| 1 | constant | `constant_ref` |
| 16–21 | aggregate | tuple/record/variant construction and projection |
| 32–40 | collection | vector/map construction, access, persistent update |
| 64–71 | checked integer | arithmetic and shifts |
| 80–85 | deterministic float | arithmetic and explicit FMA |
| 96–104 | compare/boolean | equality, order predicates, boolean logic |
| 112 | call | typed direct call |
| 128–131 | sum constructors | `Option` and `Result` |
| 144–145 | contract/test | assertion and observation |
| 160–162 | effect/authority | request, adapter invoke, capability narrow |
| 176–178 | local mutation | cell create, read, write |
| 192–194 | identity/global | value hash, global read, function reference |

Numeric operands have identical widths/kinds. There is no widening, narrowing,
truthiness, coercion, or host overload. Checked integer operations return
`Result`; overflow, division by zero, signed-minimum division by negative
one, and invalid shifts are values, not hidden exceptions. Collection absence
or invalid update is `Option` or `Result` as frozen in the manifest.

Float operations use IEEE-754 round-to-nearest ties-to-even, preserve
subnormals, and canonicalize NaN results. FMA occurs only through opcode 85.
Host fast-math and unversioned transcendentals are forbidden.

Effect, adapter, and capability operations return typed `Result` values.
Static effect validity is separate from runtime capability. Epoch 1 has only
stdout/stderr capture, confined file read/write, deterministic clock/random,
explicit environment lookup, and typed replayable adapter call. There is no
network, process, secret, deployment, spend, shell, or ambient effect.
`effect_request` operands are the declared resource scope and request value;
`adapter_invoke` operands are the declared adapter scope and request value;
`capability_narrow` operands are a capability token and requested narrower
scope. Their immediate entity must be an `EffectDef`, `AdapterImport`, or
`CapabilityRequirement`, respectively.

`value_hash` is limited to canonically hashable types and returns exactly 32
bytes in `Bytes`. Its S20-250 rule is not `ObjectId`, `EntityId`, host
hashing, or object layout. The opcode is not executable before S20-250 freezes
that rule.

## 8. Semantic boundaries

- `TypeDef` has stable field/case IDs, declaration order, invariants, and
  visibility. Labels/layout are excluded from its fingerprint.
- `Function` declares ordered parameters, one result type (including
  explicit `Result`), exact effects, entry block, ordered blocks, contracts,
  and a semantic fingerprint. There are no hidden exceptions.
- `GlobalValue` is immutable and initialized by `Constant`; it is never
  ambient or shared mutable memory.
- `EffectDef` binds request, response, failure, and scope types.
  `AdapterImport` binds stable identity and ABI; runtime handles are opaque.
- `Contract` binds a target and typed predicate function, never prose.
  `TestCase` binds canonical values, replay, expected value/failure,
  observations, and deterministic resource ceilings.
- `PolicyBinding` grants no capability. Candidate content cannot mint
  authority.
- `DependencyBinding` names an exact external `StateRoot`, never a path,
  Git ref, branch, network location, or mutable latest version.

S20-230 owns effect closure/scope. S20-240 owns contract/test judgment.
S20-250 owns fingerprints/impact. Field 4 must be absent until S20-250 provides
the exact verifier; GA-valid `TypeDef` and `Function` entities require it.

## 9. Limits

All S20-140 SCB1 epoch-1 limits apply, plus the closed limits committed in
Section 3. A stricter request/repository policy may reject a valid object but
cannot make an invalid object valid or change identity.

Decode/local checks are linear in fields/elements. Construction may sort
unordered semantic sets/maps in `O(n log n)`; strict decode rejects
noncanonical order. Cross-entity validation has a later bounded work budget
and cannot be reported complete by S20-200.

## 10. Stable failures

| Numeric | Symbolic code | Condition |
|---:|---|---|
| 20000 | `SSMC_ENTITY_KIND_UNKNOWN` | unknown body tag |
| 20001 | `SSMC_BODY_KIND_MISMATCH` | body differs from creation kind |
| 20002 | `SSMC_FIELD_UNKNOWN` | unknown record field |
| 20003 | `SSMC_FIELD_MISSING` | required field absent |
| 20004 | `SSMC_FIELD_DUPLICATE` | field/key duplicated |
| 20005 | `SSMC_REFERENCE_MALFORMED` | malformed typed reference |
| 20006 | `SSMC_TYPE_TAG_UNKNOWN` | unknown type tag |
| 20007 | `SSMC_OPCODE_UNKNOWN` | unknown opcode |
| 20008 | `SSMC_IMMEDIATE_MISMATCH` | immediate wrong/absent/illegal |
| 20009 | `SSMC_OPERAND_ARITY` | invalid operand count |
| 20010 | `SSMC_RESULT_ARITY` | invalid result count |
| 20011 | `SSMC_TERMINATOR_UNKNOWN` | unknown terminator |
| 20012 | `SSMC_NONPERSISTABLE_VALUE` | handle/token/cell persisted |
| 20013 | `SSMC_SOURCE_ARTIFACT_FORBIDDEN` | source/path/location supplied |
| 20014 | `SSMC_RESOURCE_LIMIT` | SSMC-specific limit exceeded |
| 20015 | `SSMC_RESERVED_FIELD_PRESENT` | reserved field lacks verifier |

SCB/schema failures preserve exact `SCB_*`/`SCHEMA_*` codes. Later phases
use finite `GRAPH_*`, `TYPE_*`, `CFG_*`, `EFFECT_*`, `CAP_*`,
`CONTRACT_*`, `TEST_*`, and `VM_*` codes. Unknown, internal, unsupported,
or unvalidated outcomes never become valid state.

## 11. Exclusions

Epoch 1 has no classes, inheritance, implicit dispatch, reflection, eval,
macros, textual preprocessing, unrestricted metaprogramming, hidden exceptions,
ambient globals, null, raw pointers, pointer arithmetic, shared mutable global
memory, untyped foreign calls, dynamic imports, architecture code, source
files, source locations, comments, formatting, paths, Git facts, host object
identity, or debug data in semantic identity.

There is no parser/formatter contract and no source artifact may enter the GA
dependency graph.

## 12. Acceptance

- manifest and decoder-limit hashes reproduce the descriptor;
- one object-domain descriptor contains exactly 18 body variants;
- all entity/type/opcode/terminator enums are closed, unique, and ascending;
- every opcode has exact local operand/result/immediate and failure behavior;
- no source, host, path, ambient authority, hidden exception, coercion, or
  undefined-behavior path exists;
- independent review checks every master-goal Section 7 MUST;
- no S20-200 result claims type, CFG, effect, contract, VM, or runtime
  completion.
