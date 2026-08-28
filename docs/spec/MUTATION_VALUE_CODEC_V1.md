# Mutation Value Codec v1

Status: S20-350 complete as a proposal-only construction boundary; semantic
validation, authority, apply, and commit remain later packages.

## Exact schema source

The sole value-schema source is the exact byte file
`docs/spec/SSMC1_EPOCH1_SCHEMA.txt`, whose BLAKE3-256 is
`1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae`.
The codec generator must fail unless those bytes match.

ADR-0019 resolves the provisional tag conflict in favor of SCB1: generic
`Option<T>` uses `0=None` and `1=Some<T>`. Ordinary manifest unions retain
their nonzero tags.

The generator must produce closed typed codecs for all eighteen `EntityBody`
variants, all seventy-five entity-body fields, and every recursively referenced
manifest record/union/enum/generic. It may reuse the exact SSMC1 structural
types and SCB1 primitives; it may not use opaque bytes, JSON, type-name strings,
dynamic reflection, host serialization, labels, or the restricted twelve-body
runtime model.

## Descriptor-selected values

An entity body is encoded as the exact manifest `EntityBody` union variant
whose tag equals `target_kind`. A field value is encoded directly as the exact
manifest type expression selected by the immutable S20-340 descriptor. It has
no self-declared type tag beyond tags already required by that manifest type.

Generated host types must be equivalent to a closed per-field sum such as
`Workspace_packages(Set<EntityId>)`, not a generic `(type_name, bytes)` pair.
Required/optional presence belongs to the owning entity record; an optional
field replacement encodes the manifest `Option<T>` value, not field absence.

The landed S20-350a slice generates the eighteen body structs,
`EntityBodyValue`, and a seventy-five-variant `FieldValue` directly from the
digest-pinned manifest. It includes a canonical unique raw-ID-ordered
`EntityIdSet`; it deliberately exposes no encoder, decoder, runtime type-name
selector, precondition, or candidate builder. S20-350b adds a generated closed
discriminant for every body and field plus one exact type-selection-only binding
for each of S20-340's 179 immutable descriptors. Admission compares only those
closed discriminants; it does not encode or validate value contents. Binary
codecs and later candidate surfaces remain separate gates rather than implied
behavior of the host representation.

S20-350c exposes the already-frozen strict SCB primitive decoder through a
schema-neutral bounded cursor. It adds no SSMC, descriptor, mutation, or
candidate selection. Recursive mutation value codecs remain private future
work until every manifest type family closes.

S20-350d adds a crate-private staged mutation codec for primitive leaves,
identities, direct body enums, lists, options, and canonical entity-ID sets.
Decode owns a cumulative allocation budget, distinguishes the structural depth
boundary from the allowed leaf boundary, rejects inner trailing bytes, and
rejects unordered or duplicate set encodings. The module is intentionally not
publicly descriptor-selectable while recursive manifest families remain open.

S20-350e closes the complete twenty-variant `TypeExpr` union and its
`IntegerWidth`, `NamedType`, ordered-map, result, `FunctionType`, and
`BuiltinFailureKind` dependencies inside that private module. It preserves raw
integer widths without semantic normalization, enforces exact `UInt16` failure
tags, and treats function effects as a canonical entity-ID set. Recursive
depth and cumulative allocation limits remain shared with the leaf foundation.
`ConstValue`, CFG, contract/test, body/field, precondition, and candidate
families remain later gates.

The current native closeout implements those later structural gates: both
terminator layers, the complete recursive `ConstValue` family, type-definition
and contract/test aggregates, all eighteen entity bodies, direct encoding for
all seventy-five descriptor-selected fields, three bound-precondition forms,
the exact full-v1 validation profile, and the thirteen-field candidate record
and `SLEYCAN1` envelope. Candidate construction is proposal-only. It performs
no graph/type/effect/policy/capability/contract/test judgment, reads no clock,
and exposes no apply, commit, repository, filesystem, process, network, or
provider path.

The implementation-independent corpus retains the earlier partial 126-accepted
and 18-rejected set and adds 44 accepted plus 4 rejected value vectors and one
accepted plus 14 rejected candidate vectors. The combined corpus covers all 18
bodies, all 75 fields, 16 constant-data variants, five terminators, all 16
mutation classes, all three precondition shapes, the 13-field record, the
`SLEYCAN1` envelope, and digest failures. The exact full-v1 validation profile
identity is
`7d8ffff97a3fdafc49b4329d47b0b12f04759c3124274024016483a263265d54`.

## Canonical rules

- Record fields and union/enum tags use exact manifest tags.
- `List` preserves order; `Set` and ordered maps use complete canonical element
  byte order and reject duplicates or alternate order.
- Integers use SCB1 minimal unsigned/signed forms and exact widths.
- `F32`/`F64`, `Text`, `ConstValue`, `TypeExpr`, and nested values obey SSMC1
  canonical and persistability rules without normalization.
- `EntityId`, `StateRoot`, and fixed digests are exact 32-byte typed values.
- Unknown kinds/tags/fields, trailing bytes, excess depth/elements/bytes, and a
  descriptor/value mismatch fail closed before candidate construction.
- Decode followed by encode must reproduce identical bytes; construction may
  canonicalize unordered host input only before the candidate exists.

## Completeness gate

Generation emits a manifest-derived inventory proving 18 entity bodies, 75
fields, and one exact codec binding for each of S20-340's 179 descriptors.
Drift checking regenerates committed artifacts byte-for-byte. The independent
Python oracle, Rust corpus consumer, exact rejection matrix, production
record/envelope libFuzzer target, and focused semantic/security review satisfy
the S20-350 completeness gate. S20-360 may consume this proposal boundary but
must not treat construction or hashing as semantic validity or authority.

These codecs represent proposal values only. They perform no graph, type,
effect, policy, capability, contract, test, root, or commit judgment.
