# Semantic Fingerprint and Impact Profile v1

Status: S20-250 restricted epoch-1 normative specification.

This contract freezes the smallest complete, deterministic fingerprint and
impact judgment that can be implemented over the current SSMC1 Rust model. A
Function fingerprint consumes successful S20-210, S20-220, and S20-230
judgments. A TypeDef fingerprint consumes successful S20-210 judgment. The
impact builder consumes structurally decoded, closed modeled entities and
performs only its own inventory/reference checks. No S20-250 API depends on
S20-240, and no S20-250 result converts an earlier failure into success.

This is not full S20-250 GA. The frozen SSMC1 schema defines 18 entity bodies,
but the current model does not yet expose `Workspace`, `Package`, `Namespace`,
`EntryPoint`, `PolicyBinding`, or `DependencyBinding` bodies. The restricted
profile therefore computes required fingerprints only for `TypeDef` and
`Function`, computes `value_hash` for valid canonically hashable constants,
and derives impact edges only for the twelve modeled entity kinds 4 through
15. Field 4 must be absent on every unsupported kind. A later package must add
the six missing bodies and extend this profile before S20-300, S20-510, or GA
may claim a complete-root impact index.

Fingerprints and impact indexes are derived evidence. They never replace an
`EntityId`, `ObjectId`, `StateRoot`, schema judgment, or repository authority.

## 1. Semantic equivalence

Two supported entities are equivalent for this profile exactly when their
canonical projections below are byte-identical. The projection excludes:

- the entity's own `EntityId`;
- labels, source locations, debug data, and presentation order not frozen as
  semantic order;
- `ObjectId`, object envelope layout, repository path/ref/ancestry, cache
  placement, host allocation, timestamps, and Git facts;
- the identities and storage order of Function-owned Parameter, Block, and
  Operation entities after they have been replaced by canonical local slots.

Stable `MemberId` values and references to external semantic entities remain
semantic. They are encoded as their exact 32-byte identities. This is a local
semantic fingerprint, not a recursively expanded Merkle root. A referenced
entity's later change is represented by a direct impact edge and reverse
impact closure rather than by silently changing the referring entity's local
fingerprint.

The special case of a Function referring to itself encodes the distinguished
`self` reference rather than its own `EntityId`. Direct and mutual recursive
call graphs are therefore supported without hash fixed points. References to
other functions retain those functions' exact stable identities.

## 2. Canonical fingerprint preimage

```text
SemanticFingerprint =
  BLAKE3-256("sley2.semantic-fingerprint.v1" || fingerprint_preimage)

fingerprint_preimage =
  "SLEYSFP1" ||
  u32be(profile_version=1) ||
  schema_epoch_id[32] ||
  ssmc1_field_schema_hash[32] ||
  u32be(entity_kind) ||
  bytes(canonical_projection)
```

`bytes(x)` is `u64be(len(x)) || x`. The exact field-schema hash is
`1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae`.
All arithmetic is checked. No host serializer, hash map order, debug format,
pointer value, or platform integer representation enters the preimage.

The projection encoder uses these primitives:

| Value | Encoding |
|---|---|
| enum/union tag | `u32be(tag)` |
| `u16`, `u32`, `u64`, `u128` | fixed-width big endian |
| `i128` | exact two's-complement 16-byte big endian |
| Boolean | one byte `00` or `01` |
| fixed 32 bytes / identity | exact 32 bytes |
| byte or UTF-8 text sequence | `u64be(length) || bytes` |
| list | `u64be(count) || item...` |
| option | `u32be(1)` for none; `u32be(2) || value` for some |

The exhaustive recursive encoding grammar is Appendix A. Lists retain semantic
order. Sets must already be in strict raw-ID order and encode as lists.
Canonical floating values encode their validated raw big-endian bits. The
implementation's fixed vectors are part of this contract; changing any encoder
rule requires a new profile version.

## 3. TypeDef projection

The TypeDef projection encodes, in order:

1. ordered type-parameter ordinals;
2. form tag, then ordered record fields or variant cases;
3. raw-ID-sorted invariant Contract identities;
4. visibility tag.

Each record field includes its stable `MemberId`, exact `TypeExpr`, and
visibility. Each variant case includes its stable `MemberId` and optional
payload type. Field/case declaration order is semantic and therefore retained.
The TypeDef's own identity and label are absent.

The encoder represents the frozen invariant-identity field exactly. Whether an
invariant is permitted by a selected contract profile is S20-240's independent
judgment and does not alter the S20-250 bytes.

## 4. Function projection and local slots

One Function fingerprint request contains its `FunctionGraph` plus its exact
complete Parameter, Block, and Operation inventories. The inventory must match
the successful S20-220 graph judgment.

Canonical slots are assigned without sorting:

- function parameters: their position in `Function.parameters`;
- blocks: their position in `Function.blocks`;
- block parameters: their position in each `Block.parameters` list;
- operations: their position in each `Block.operations` list;
- operation results: operation slot plus declared result index.

The projection encodes:

1. ordered function type parameters;
2. ordered function parameter types by function-parameter slot;
3. exact result type;
4. raw-ID-sorted declared effects;
5. entry-block slot;
6. every block in Function block-list order;
7. raw-ID-sorted attached contracts;
8. visibility.

Each block encodes reachability, ordered block-parameter types, ordered
operations, and its terminator. Each operation encodes opcode tag, operands,
result types, and immediate; owner and ordinal are implied by its slot. Every
local `ValueRef` and branch/switch target is rewritten to its canonical slot.
An unresolved, cross-function, duplicated, missing, or inconsistently ordered
local entity fails rather than falling back to raw identity.

An external entity reference is encoded as `u32be(1) || EntityId`. A reference
to the enclosing function is encoded as `u32be(2)`. A `FunctionRefValue`
always encodes that reference discriminator and then its complete ordered
`type_arguments` list; the discriminator never replaces or consumes generic
arguments. Local references use their own closed tags and canonical slots. CFG
block order is frozen semantic order; physical object layout and input-slice
order are not.

## 5. Fingerprint claim verification

For a GA-required TypeDef or Function field-4 claim:

- absence is `FINGERPRINT_CLAIM_MISSING`;
- a nonmatching 32-byte value is `FINGERPRINT_MISMATCH`;
- a matching computed value succeeds.

The restricted profile rejects a present field-4 claim on every other entity
kind with `FINGERPRINT_ENTITY_UNSUPPORTED`. It never copies, repairs, or trusts
a caller-provided digest. The returned digest is always recomputed.

## 6. `value_hash`

The frozen `value_hash` opcode computes:

```text
value_hash_preimage =
  "SLEYVHS1" ||
  u32be(profile_version=1) ||
  schema_epoch_id[32] ||
  ssmc1_field_schema_hash[32] ||
  bytes(canonical TypeExpr) ||
  bytes(canonical ConstData)

value_hash = BLAKE3-256("sley2.value-hash.v1" || value_hash_preimage)
```

The result is exactly 32 raw bytes in the SSMC `Bytes` value. The new
`sley2.value-hash.v1` domain is registered by ADR-0007 and the identifier-domain
fixtures. It is not an alias or reuse of the semantic-fingerprint domain.

Only a constant that passes S20-210 and whose exact type has
`canonical_hash=true` is accepted. Non-hashable, nonpersistable, malformed,
unresolved, noncanonical, or resource-exhausted values fail closed. The hash is
not an ObjectId, EntityId, host hash, object envelope digest, or serialization
of an in-memory Rust value.

## 7. Direct impact edges

An edge is `(dependent, dependency, kind)`: changing the dependency may affect
the dependent. Edges are a canonical set sorted first by dependent raw ID,
then dependency raw ID, then numeric kind. Duplicate edges are removed.

The restricted profile freezes these edge kinds:

| Tag | Kind | Source examples |
|---:|---|---|
| 1 | `Ownership` | Function to Parameter/Block; Block to Parameter/Operation |
| 2 | `TypeReference` | named type, adapter handle, capability token |
| 3 | `ValueReference` | Constant/global and CFG value references |
| 4 | `ControlFlow` | entry block and terminator targets |
| 5 | `Call` | direct call and function-reference construction |
| 6 | `Effect` | declarations, effect request, adapter effect |
| 7 | `Capability` | requirement and capability narrowing |
| 8 | `Contract` | attachments, predicates, bindings, assertions |
| 9 | `Initializer` | GlobalValue to Constant |
| 10 | `TestTarget` | TestCase to Function |
| 11 | `Adapter` | replay/configuration/invocation to AdapterImport |
| 12 | `DefinitionMember` | record/variant values or immediates to TypeDef |

Extraction follows the exhaustive matrices in Sections 7.1 through 7.3. An
identity may have more than one typed relationship. Self-edges are retained
when explicitly present. Every edge endpoint must resolve to exactly one
entity of the specified kind in the same closed request. `Any modeled` means
one of kinds 4 through 15 and performs existence but not a narrower kind check.
There is no lookup in a root, cache, repository, label table, filesystem, or
latest-version source.

### 7.1 Top-level body fields

Every row emits `dependent = enclosing entity` and the referenced field value
as `dependency`. Fields absent from the table contain no EntityId.

| Body and field | Edge kind | Required dependency kind |
|---|---|---|
| TypeDef `form.*.value_type` / `payload_type` | recursive TypeExpr rules | per Section 7.2 |
| TypeDef `invariants[]` | Contract | Contract |
| Function `parameters[]` | Ownership | Parameter |
| Function `result_type` | recursive TypeExpr rules | per Section 7.2 |
| Function `effects[]` | Effect | EffectDef |
| Function `entry_block`, `blocks[]` | ControlFlow, Ownership respectively | Block |
| Function `contracts[]` | Contract | Contract |
| Parameter `owner` | Ownership | Function when role=Function; Block when role=Block |
| Parameter `value_type` | recursive TypeExpr rules | per Section 7.2 |
| Block `function` | Ownership | Function |
| Block `parameters[]`, `operations[]` | Ownership | Parameter, Operation |
| Block terminator values/targets | recursive local-reference rules | per Section 7.3 |
| Operation `block` | Ownership | Block |
| Operation operands | ValueReference | Parameter or Operation per ValueRef tag |
| Operation result types | recursive TypeExpr rules | per Section 7.2 |
| Operation immediate | opcode/immediate rules | per Section 7.3 |
| Constant `value` | recursive ConstValue rules | per Section 7.2 |
| GlobalValue `value_type` | recursive TypeExpr rules | per Section 7.2 |
| GlobalValue `initializer` | Initializer | Constant |
| EffectDef four type fields | recursive TypeExpr rules | per Section 7.2 |
| CapabilityRequirement `effect` | Effect | EffectDef |
| CapabilityRequirement `allowed_scopes[]` | recursive ConstValue rules | per Section 7.2 |
| CapabilityRequirement `constraint_contracts[]` | Contract | Contract |
| Contract `target` | Contract | Any modeled |
| Contract `predicate` | Contract | Function |
| Contract binding Parameter/Global source | ValueReference | Parameter / GlobalValue |
| TestCase `target` | TestTarget | Function |
| TestCase inputs/expected/observations | recursive ConstValue rules | per Section 7.2 |
| TestCase replay/config `adapter_import` | Adapter | AdapterImport |
| TestCase replay request/response and config value | recursive ConstValue rules | per Section 7.2 |
| AdapterImport three type fields | recursive TypeExpr rules | per Section 7.2 |
| AdapterImport `effects[]` | Effect | EffectDef |

### 7.2 Nested type and constant fields

| Nested field | Edge kind | Required dependency kind |
|---|---|---|
| `TypeExpr::Named.definition` | TypeReference | TypeDef |
| `TypeExpr::AdapterHandle` | Adapter | AdapterImport |
| `TypeExpr::CapabilityToken` | Capability | CapabilityRequirement |
| `FunctionType.effects[]` | Effect | EffectDef |
| all child TypeExpr values | recurse | — |
| `RecordConst.definition`, `VariantConst.definition` | DefinitionMember | TypeDef |
| `FunctionRefValue.function` | Call | Function |
| `ConstValue.value_type` and all nested ConstValue values | recurse | — |

`MemberId`, adapter ID, observation ID, and fixed payload bytes are not
EntityIds and never create edges.

### 7.3 Local references and operation immediates

| Field/form | Edge kind | Required dependency kind |
|---|---|---|
| `ValueRef::Parameter` | ValueReference | Parameter |
| `ValueRef::OperationResult.operation` | ValueReference | Operation |
| branch/switch target | ControlFlow | Block |
| `Immediate::Entity` for `constant_ref` | ValueReference | Constant |
| `Immediate::Entity` for `record_new` | DefinitionMember | TypeDef |
| `Immediate::Entity` for `contract_assert` | Contract | Contract |
| `Immediate::Entity` for `effect_request` | Effect | EffectDef |
| `Immediate::Entity` for `adapter_invoke` | Adapter | AdapterImport |
| `Immediate::Entity` for `capability_narrow` | Capability | CapabilityRequirement |
| `Immediate::Entity` for `global_get` | ValueReference | GlobalValue |
| `Immediate::Variant.definition` | DefinitionMember | TypeDef |
| `Immediate::Function.function` | Call | Function |
| `Immediate::Function.type_arguments[]` | recursive TypeExpr rules | per Section 7.2 |

Every other opcode/immediate pairing is invalid input to this profile. Index,
Field, Observation, and None immediates contain no EntityId. Switch case member
IDs and built-in tags contain no EntityId; switch arguments recurse through the
local-reference rules.

The six currently unmodeled SSMC1 kinds make a complete-root index impossible.
A request containing or requiring one fails with
`IMPACT_ENTITY_UNSUPPORTED`; omission is never reported as completeness.

## 8. Reverse and transitive impact

The reverse index is the exact inversion of the direct edge set, grouped by
dependency and preserving canonical edge order. It is derived and disposable.

Given a raw-ID-sorted unique seed set, transitive impact is bounded graph
reachability over reverse direct edges. The output contains the seeds and all
reachable dependents exactly once in raw-ID order. Traversal uses a FIFO queue
whose newly discovered neighbors are visited in raw-ID/kind order. Cycles
terminate through the visited set. Exhaustion returns no partial successful
closure.

Rebuilding from the same closed request must produce byte-identical direct
edges, reverse edges, and closures regardless of caller slice allocation or
hash-map state. S20-300 may cache this index but cannot make it authoritative.

## 9. Limits

| Limit | Maximum |
|---|---:|
| modeled entities per request | 65,535 |
| Function-owned graph entities | 2,000,000 |
| operations | 1,000,000 |
| direct impact edges | 4,000,000 |
| TypeExpr / ConstValue depth | 64 |
| encoded fingerprint or value preimage | 67,108,864 bytes |
| transitive-impact seeds | 65,535 |
| transitive-impact visited entities | 65,535 |
| charged encoding/extraction/traversal work | 100,000,000 |

All counts and arithmetic are checked before allocation or append. Limit or
integer overflow is a typed failure and never a truncated success.

Encoding charges one work unit per output preimage byte plus one per
Function-inventory entity visited. Impact construction charges one per
top-level entity, nested `TypeExpr`, nested `ConstValue`, local reference,
terminator, target edge, immediate, test-environment node, and attempted edge.
Transitive impact charges one per seed, dequeued identity, and reverse edge
visited. Checked accumulated work above 100,000,000 fails without a partial
successful digest, index, or closure.

## 10. Stable failures

| Numeric | Symbolic code |
|---:|---|
| 25000 | `FINGERPRINT_ENTITY_UNSUPPORTED` |
| 25001 | `FINGERPRINT_INVENTORY_INVALID` |
| 25002 | `FINGERPRINT_LOCAL_REFERENCE_INVALID` |
| 25003 | `FINGERPRINT_CLAIM_MISSING` |
| 25004 | `FINGERPRINT_MISMATCH` |
| 25005 | `FINGERPRINT_RESOURCE_LIMIT` |
| 25006 | `VALUE_HASH_TYPE_UNSUPPORTED` |
| 25007 | `VALUE_HASH_VALUE_INVALID` |
| 25008 | `IMPACT_ENTITY_UNSUPPORTED` |
| 25009 | `IMPACT_SET_NOT_CANONICAL` |
| 25010 | `IMPACT_UNRESOLVED_ENTITY` |
| 25011 | `IMPACT_WRONG_ENTITY_KIND` |
| 25012 | `IMPACT_RESOURCE_LIMIT` |

Earlier `TYPE_*`, `CFG_*`, and `EFFECT_*` failures are preserved by the owning
validation pipeline. An optional later S20-240 judgment is independent and
does not alter fingerprints or edges. The standalone fingerprint and impact
APIs return only the S20-250 failures they own.

## 11. Acceptance

- exact vectors freeze TypeDef, Function, and `value_hash` preimages/digests;
- changing a label, own EntityId, child EntityIds, inventory slice order, or
  physical layout does not change the corresponding supported fingerprint;
- changing a semantic field, stable external reference, member ID, declaration
  order, opcode, type, constant, control-flow edge, effect, or contract does;
- direct edges equal schema-extracted relationships with no missing or surplus
  pair/kind;
- reverse edges are the exact inverse and bounded cyclic reachability
  terminates deterministically;
- unresolved/wrong-kind endpoints and all unsupported entity kinds fail closed;
- repeated builds and at least 128 shuffled-input seeds are byte-identical;
- full-GA completion remains false until all 18 entity bodies and complete-root
  extraction are implemented and independently reviewed.

## Appendix A: exhaustive projection grammar

`tag(x)` means `u32be` of the frozen SSMC1 tag. `list(f,xs)` means
`u64be(count) || f(x)...`. `opt(f,None)=u32be(1)` and
`opt(f,Some(x))=u32be(2)||f(x)`. `ref(id)` is the enclosing-Function-aware
external/self encoding from Section 4. Member IDs and other fixed-32 values are
raw 32 bytes.

```text
type(Unit|Bool|F32|F64|Bytes|Text) = tag
type(SInt|UInt) = tag || u16be(width)
type(Tuple) = tag || list(type, elements)
type(Named) = tag || ref(definition) || list(type, arguments)
type(Vector|Option|LocalCell) = tag || type(element)
type(OrderedMap) = tag || type(key) || type(value)
type(Result) = tag || type(ok) || type(error)
type(FunctionRef) = tag || list(type, parameters) || type(result) || list(ref, effects)
type(AdapterHandle|CapabilityToken) = tag || ref(entity)
type(TypeParameter) = tag || u32be(ordinal)
type(BuiltinFailure) = tag || u16be(kind_tag)

function_ref = ref(function) || list(type, type_arguments)
const_value = type(value_type) || const_data
const_data(Unit) = tag
const_data(Bool) = tag || bool
const_data(SInt) = tag || i128be(value)
const_data(UInt) = tag || u128be(value)
const_data(F32Bits) = tag || u32be(bits)
const_data(F64Bits) = tag || u64be(bits)
const_data(Bytes) = tag || bytes(value)
const_data(Text) = tag || bytes(utf8(value))
const_data(Sequence) = tag || list(const_value, values)
const_data(Record) = tag || ref(definition) ||
                     list(member_id || const_value, fields)
const_data(Variant) = tag || ref(definition) || member_id ||
                      opt(const_value, payload)
const_data(Map) = tag || list(const_value(key) || const_value(value), entries)
const_data(Option) = tag || opt(const_value, value)
const_data(Result) = tag || tag(ok_or_err) || const_value(value)
const_data(FunctionRef) = tag || function_ref
const_data(BuiltinFailure) = tag || u16be(kind_tag) || u16be(code)

value_ref(Parameter) = tag || u32be(owner_class) || u32be(block_slot_or_zero) ||
                       u32be(parameter_slot)
value_ref(OperationResult) = tag || u32be(block_slot) ||
                             u32be(operation_slot) || u32be(result_index)
switch_argument(Value) = tag || value_ref
switch_argument(CasePayload) = tag
target_edge = u32be(target_block_slot) || list(value_ref, arguments)
switch_edge = u32be(target_block_slot) || list(switch_argument, arguments)
case_key(Member) = tag || member_id
case_key(Builtin) = tag || tag(builtin_case)

immediate(None) = tag
immediate(Entity) = tag || ref(entity)
immediate(Index) = tag || u32be(index)
immediate(Field) = tag || member_id
immediate(Variant) = tag || ref(definition) || member_id
immediate(Observation) = tag || fixed32
immediate(Function) = tag || function_ref

terminator(Return) = tag || value_ref(value)
terminator(Branch) = tag || target_edge
terminator(CondBranch) = tag || value_ref(condition) ||
                         target_edge(if_true) || target_edge(if_false)
terminator(VariantSwitch) = tag || value_ref(value) ||
                            list(case_key || switch_edge, cases)
terminator(Trap) = tag || tag(trap_code) || opt(value_ref, payload)
```

For `value_ref(Parameter)`, `owner_class=1` denotes a Function parameter and
requires `block_slot_or_zero=0`; `owner_class=2` denotes a Block parameter and
uses its actual block slot. No raw local entity identity is encoded.

TypeDef nested types use `ref(id)=u32be(1)||id` because no enclosing Function
exists. Function external/self discrimination applies recursively throughout
its complete projection, including nested types, constants, and immediates.
