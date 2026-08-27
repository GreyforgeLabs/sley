# Sley Canonical Binary v1 (SCB1)

Status: M0 normative draft; wire tags are not frozen.

## Scope

SCB1 is the only canonical byte encoding for Sley 2 objects, roots,
transactions, declared canonical protocol payloads, and packs. Decoding is
strict: malformed or non-minimal input is rejected and never normalized into
accepted state.

## Envelope

Every standalone value begins with the eight bytes `53 4c 45 59 53 43 42 31`
(`SLEYSCB1`), followed by a shortest-form unsigned format version, object-kind
tag, schema-epoch identifier, payload length, and payload. A schema object
assigns all kind and field tags. Tags cannot be reinterpreted within an epoch.

Structured payloads are ordered field records. Required fields occur exactly
once in ascending numeric-tag order. Optional fields are omitted when absent;
there is no null sentinel. Unknown mandatory fields, duplicate fields, wrong
order, and trailing bytes are errors. Extensions occupy one explicitly tagged
final section and use epoch-declared vendor/type identifiers.

## Primitive encoding

- Unsigned integers use shortest-form base-128 varints.
- Signed integers use ZigZag followed by a shortest-form unsigned varint.
- Fixed-width digests and identifiers are raw bytes at their declared width.
- Byte strings are length-prefixed; lengths and allocation are policy-bounded.
- Booleans are one byte, `00` or `01` only.
- F32/F64 use big-endian IEEE-754 bits. NaNs use one epoch-defined quiet NaN;
  every other NaN payload is rejected in canonical input. Negative zero is
  rejected for types whose semantics do not distinguish it.
- Runtime `Text` is valid UTF-8 preserved exactly. Only fields typed
  `NormalizedLabel` require NFC under the Unicode version pinned by the epoch.
- Lists preserve declared order.
- Maps encode each key independently, sort entries lexicographically by the
  complete canonical key bytes, and reject equal adjacent key encodings.
- Tagged unions encode one tag and exactly one matching payload.

## Limits

The decoder accepts an explicit limits profile covering input bytes, nesting,
field count, collection entries, decoded objects, referenced objects, and total
allocation. Limit exhaustion returns a typed resource error without partial
canonical output.

## Hashing

Object identity is:

`BLAKE3-256("sley2.object.v1" || canonical_object_bytes)`.

Every other digest receives a distinct ASCII domain separator defined in the
identifier ADR. The digest field, when a contract carries one, is verified
against bytes that exclude that digest field; the schema must state this
preimage exactly.

## Strict rejection corpus

Conformance must reject non-minimal integers, invalid UTF-8, non-NFC labels,
silently normalized runtime text, unsorted or duplicate maps, duplicate or
misordered fields, alternate NaNs, forbidden negative zero, unknown tags,
overflow, excessive nesting, trailing bytes, digest mismatch, and epoch
mismatch. The Rust codec and independent oracle must agree on every fixture.

## Evolution

An epoch freezes tags, field order, required/optional status, opcodes, encoding-
relevant type rules, hash algorithms, Unicode normalization version, extension
policy, and validity-affecting limits. Migration preserves the old decoder and
root and emits a transaction binding old and new roots plus equivalence
evidence. Silent downgrade is forbidden.
