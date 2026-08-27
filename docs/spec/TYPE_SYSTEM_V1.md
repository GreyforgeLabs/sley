# Sley Core Type System v1

Status: S20-210 normative specification.

## 1. Scope

S20-210 implements deterministic judgment over the 20 structural `TypeExpr`
tags and constant forms frozen by S20-200. It owns type well-formedness,
explicit invariant generic substitution, epoch-1 definition-cycle rejection,
equality/order/hash/persistability traits, canonical floating constants, and
constant/type agreement.

It does not own SCB decoding, CFG edges/dominance/uses, operation signatures,
effect closure, contracts/tests, semantic fingerprints, VM lowering/execution,
policy, repository state, or protocol behavior. A successful S20-210 judgment
is not a complete candidate or executable-program judgment.

There is no implicit widening, narrowing, coercion, inference, subtyping,
variance, null, hidden exception, untyped foreign call, or host-type fallback.
Unknown, missing, cyclic, ambiguous, or resource-exhausted input fails closed.

## 2. Frozen structural types

The `TypeExpr` tags are exactly those in `SSMC1_EPOCH1_SCHEMA.txt`:

| Tag | Type | Payload |
|---:|---|---|
| 1 | `Unit` | none |
| 2 | `Bool` | none |
| 3 | `SInt` | width |
| 4 | `UInt` | width |
| 5 | `F32` | none |
| 6 | `F64` | none |
| 7 | `Bytes` | none |
| 8 | `Text` | none |
| 9 | `Tuple` | ordered element types |
| 10 | `Named` | definition `EntityId`, ordered type arguments |
| 11 | `Vector` | element type |
| 12 | `OrderedMap` | key and value types |
| 13 | `Option` | element type |
| 14 | `Result` | success and error types |
| 15 | `FunctionRef` | ordered parameters, result, canonical effect set |
| 16 | `AdapterHandle` | adapter-import `EntityId` |
| 17 | `CapabilityToken` | capability-requirement `EntityId` |
| 18 | `LocalCell` | element type |
| 19 | `TypeParameter` | zero-based declaration ordinal |
| 20 | `BuiltinFailure` | one closed failure kind |

Integer widths are exactly 8, 16, 32, 64, and 128. A function effect set is
strictly increasing by raw `EntityId` bytes with no duplicate. Tuple size is
at most 65,535, type-argument count at most 1,024, structural depth at most 64,
and every list/set additionally obeys its SCB1 epoch limit.

A `TypeParameter(i)` is valid only while checking a declaration with
`i < declared_parameter_count`. Type parameters are invariant and
substitution is positional, explicit, complete, and capture-free. There is no
partial application or inferred argument.

## 3. Definitions and recursion

An epoch-1 type definition is a record or tagged variant with:

- one stable `EntityId`;
- declaration parameters whose ordinals are exactly `0..n` in order;
- ordered fields/cases with definition-local stable `MemberId` values;
- no duplicate member ID;
- well-formed member types under the declaration parameter count;
- a strictly ordered, duplicate-free invariant-contract set.

A named instantiation must resolve one exact definition and provide exactly its
declared number of type arguments. The arguments are checked in the caller's
parameter scope before invariant substitution.

Epoch 1 rejects every cycle in the named-definition dependency graph,
including direct self-reference and cycles passing through tuple, collection,
sum, function-reference, handle, token, or local-cell payloads. Recursive
types require a future schema epoch and termination proof; no host recursion or
depth heuristic turns a cycle into success.

## 4. Type traits

The checker returns four independent facts:

| Type family | Equality | Total order | Canonical hash | Persistable |
|---|---:|---:|---:|---:|
| Unit, Bool, integers, Bytes, Text, built-in failures | yes | yes | yes | yes |
| F32, F64 | yes | no | yes | yes |
| Tuple | iff every element | iff every element | iff every element | iff every element |
| Named record/variant | iff every instantiated member | iff every instantiated member | iff every instantiated member | iff every instantiated member |
| Vector | iff element | no | iff element | iff element |
| OrderedMap | iff key and value | no | iff key and value | iff key and value |
| Option | iff element | iff element | iff element | iff element |
| Result | iff both | iff both | iff both | iff both |
| FunctionRef | yes | no | yes | yes |
| AdapterHandle, CapabilityToken | identity only | no | no | no |
| LocalCell | no | no | no | no |
| unresolved TypeParameter | invalid | invalid | invalid | invalid |

Float equality uses IEEE comparison: NaN is unequal to every value. Canonical
hashing uses canonicalized bits. Trait calculation is structural and must
resolve/substitute named definitions; it never uses labels, layout, addresses,
host traits, caches, or source facts.

An `OrderedMap<K,V>` type is well formed only if `K` has total order,
equality, canonical hashing, and persistability. This prevents float, vector,
map, function-reference, handle, token, or cell keys unless a future epoch
defines a new closed rule.

Epoch 1 has no trait-bound syntax, so a free `TypeParameter` cannot prove
those key traits. `OrderedMap<TypeParameter(_),V>` is rejected in a generic
declaration rather than conditionally accepted for some later instantiations.

## 5. Constants

Every constant carries one exact `TypeExpr` and one closed data variant. The
checker first validates the type with zero free parameters and requires it to
be persistable, then requires exact data agreement:

- signed and unsigned values fit their declared width;
- F32/F64 bits obey SCB1: the sole canonical quiet NaN is accepted, negative
  zero and every other NaN are rejected, and infinities/subnormals are allowed;
- Bytes/Text payloads are at most 16,777,216 bytes; Rust/SCB text validation
  supplies well-formed UTF-8 and no normalization occurs;
- tuple and vector lengths/types agree exactly;
- a record names the instantiated definition and contains fields in declared
  order with exact member IDs and values;
- a variant names the definition and one exact case, with payload
  presence/type equal to that case;
- an ordered-map key/value pair agrees exactly, the key type is orderable, and
  no two canonical semantic keys are equal;
- Option and Result select exactly one closed arm;
- a function-reference value has a stable target `EntityId`, no more than
  1,024 explicit well-formed type arguments, and no address/label/layout fact;
- a built-in failure code is valid for its declared failure kind;
- handles, capability tokens, local cells, and free parameters have no
  persistable constant form.

Exact SCB map byte ordering is enforced by the selected SCB encoder/decoder,
not reimplemented by the type checker. S20-210 rejects duplicate or
non-orderable semantic keys and never silently sorts or normalizes a decoded
constant.

## 6. Determinism and limits

Definition lookup uses exact `EntityId`; duplicate definitions are rejected.
All validation order is declaration/list order except cycle traversal, whose
roots and adjacency are raw-ID sorted. Repeated judgment over identical input
returns the same result and stable code.

Closed limits:

| Limit | Maximum |
|---|---:|
| structural type depth | 64 |
| type arguments per named/function reference | 1,024 |
| tuple elements | 65,535 |
| definition fields/cases | 65,535 |
| definitions per environment | 1,000,000 |
| constant nesting depth | 64 |
| constant collection elements | 1,000,000 |
| Bytes/Text payload | 16,777,216 bytes |

The checker performs bounded linear traversal, plus deterministic
`O(n log n)` definition/set construction and duplicate-map-key checks.
Request policy may impose stricter bounds but never looser validity.

## 7. Stable failures

| Numeric | Symbolic code |
|---:|---|
| 21000 | `TYPE_DEPTH_LIMIT` |
| 21001 | `TYPE_WIDTH_INVALID` |
| 21002 | `TYPE_PARAMETER_OUT_OF_SCOPE` |
| 21003 | `TYPE_ARGUMENT_LIMIT` |
| 21004 | `TYPE_ARGUMENT_ARITY` |
| 21005 | `TYPE_DEFINITION_UNKNOWN` |
| 21006 | `TYPE_DEFINITION_DUPLICATE` |
| 21007 | `TYPE_DEFINITION_CYCLE` |
| 21008 | `TYPE_MEMBER_DUPLICATE` |
| 21009 | `TYPE_MEMBER_UNKNOWN` |
| 21010 | `TYPE_SET_ORDER` |
| 21011 | `TYPE_NOT_ORDERABLE` |
| 21012 | `TYPE_NOT_HASHABLE` |
| 21013 | `TYPE_NOT_PERSISTABLE` |
| 21014 | `TYPE_CONST_SHAPE` |
| 21015 | `TYPE_CONST_RANGE` |
| 21016 | `TYPE_FLOAT_NON_CANONICAL` |
| 21017 | `TYPE_CONST_DUPLICATE_KEY` |
| 21018 | `TYPE_RESOURCE_LIMIT` |
| 21019 | `TYPE_IMPLICIT_COERCION` |
| 21020 | `TYPE_BUILTIN_FAILURE_INVALID` |

Structural SCB/SSMC failures preserve their earlier exact codes. Unknown,
ambiguous, internal, or limit-exhausted state never becomes a valid type or
constant.

## 8. S20-210 acceptance

- all 20 type tags match the frozen S20-200 manifest;
- positive and negative corpora cover every type family and stable code;
- invalid widths, free parameters, wrong arity, duplicate members, definition
  cycles, generic/unprovable or non-orderable map keys, noncanonical floats, range overflow,
  implicit-coercion probes, nonpersistable constants, and duplicate map keys
  fail deterministically;
- explicit substitution is invariant and input-immutable;
- trait results are independent of definition insertion order;
- focused unit/property tests and strict lint pass;
- no CFG, effect, contract, fingerprint, lowering, VM, source, repository,
  runtime, or protocol completion is claimed.
