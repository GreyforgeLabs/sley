# Mutation Value Codec v1

Status: S20-345 normative contract freeze; S20-350a closed host model and
S20-350b typed descriptor bindings implemented; S20-350c low-level SCB cursor
foundation and S20-350d private leaf/collection codec implemented; complete
binary codecs deferred.

## Exact schema source

The sole value-schema source is the exact byte file
`docs/spec/SSMC1_EPOCH1_SCHEMA.txt`, whose BLAKE3-256 is
`044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73`.
The codec generator must fail unless those bytes match.

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

Generation must emit a manifest-derived inventory proving 18 entity bodies,
75 fields, and one exact codec binding for each of S20-340's 179 descriptors.
Drift checking must regenerate committed artifacts byte-for-byte. S20-350 may
not land a candidate builder until cross-language or structurally independent
fixtures cover every entity kind and every field type family.

These codecs represent proposal values only. They perform no graph, type,
effect, policy, capability, contract, test, root, or commit judgment.
