# Sley Canonical Binary v1 (SCB1)

Status: S20-100 normative encoding specification

## 1. Scope and notation

SCB1 is the only canonical byte encoding for Sley 2 objects, roots,
transactions, declared canonical protocol payloads, and packs. Decoding is
strict: malformed or non-minimal input is rejected and is never normalized
into accepted state.

The implementation's low-level `ScbValueCursor` exposes these same strict
primitive reads to schema-aware callers. The cursor itself never selects a
contract, schema epoch, or semantic type, and successful complete-value callers
must explicitly reject unread trailing bytes.

This document uses `||` for byte concatenation, `uvar(x)` for the unsigned
varint of `x`, `len(x)` for `uvar(byte_length(x))`, and `BLAKE3-256` for the
32-byte BLAKE3 digest. Numeric tags are unsigned 32-bit values encoded as
uvarints. All byte comparisons are unsigned lexicographic comparisons.

## 2. Standalone envelope

A stored standalone SCB1 contract is exactly:

```text
magic              8 bytes = 53 4c 45 59 53 43 42 31 ("SLEYSCB1")
format_version      uvar = 1
contract_tag        uvar in 1..=0xffff_ffff
schema_epoch_id     32 raw bytes
payload_length      uvar
payload             payload_length bytes, a canonical Record value
digest              32 raw bytes
```

No bytes follow `digest`. The envelope is not a generic self-describing data
format: `contract_tag` and `schema_epoch_id` select one exact schema needed to
decode `payload`.

`digest` is outside its own preimage. Define:

```text
envelope_preimage = magic || format_version || contract_tag ||
                    schema_epoch_id || payload_length || payload
digest = BLAKE3-256(contract_domain || envelope_preimage)
stored_bytes = envelope_preimage || digest
```

`contract_domain` is the exact non-NUL-terminated ASCII byte string assigned by
the contract registry. Semantic entity objects use `sley2.object.v1`, so their
digest is their `ObjectId`. Roots, transactions, candidates, receipts, packs,
and reports use distinct domains frozen by S20-110. A decoder verifies the
trailer before exposing a successful standalone value.

Nested values never contain the standalone magic, epoch, or digest trailer
unless their declared type is `EmbeddedContractBytes`, in which case they are
an opaque byte string until separately decoded with explicit limits.

## 3. Unsigned and signed integers

Unsigned integers use base-128 little-endian groups. Bits 0–6 carry payload;
bit 7 means another byte follows. The final byte has bit 7 clear. The encoding
must use the fewest bytes possible: a multi-byte encoding whose final payload
group is zero is rejected. The decoder checks target-width overflow before
shifting or allocating.

Examples:

| Value | Hex |
|---:|---|
| 0 | `00` |
| 1 | `01` |
| 127 | `7f` |
| 128 | `80 01` |
| 300 | `ac 02` |

Signed integer `n` at width `w` uses ZigZag:

```text
zigzag(n) = (unsigned(n) << 1) XOR unsigned(n >> (w - 1))
```

followed by the canonical unsigned encoding. The declared width is part of the
schema/type, not the bytes. Examples: `0 -> 00`, `-1 -> 01`, `1 -> 02`,
`-2 -> 03`.

## 4. Canonical value encodings

Every value is schema-directed and encoded exactly as follows.

| Type | Encoding |
|---|---|
| `UInt<W>` | canonical uvarint within width W |
| `SInt<W>` | canonical ZigZag uvarint within width W |
| `Bool` | exactly `00` or `01` |
| `FixedBytes<N>` | exactly N raw bytes |
| `Bytes` | `len(bytes) || bytes` |
| `Text` | `len(utf8) || utf8` |
| `NormalizedLabel` | `len(utf8_nfc) || utf8_nfc` |
| `F32` | four big-endian IEEE-754 bytes |
| `F64` | eight big-endian IEEE-754 bytes |
| `List<T>` | `uvar(count) || element*` |
| `Map<K,V>` | `uvar(count) || entry*` |
| `Record<S>` | `uvar(field_count) || field*` |
| `Union<S>` | `uvar(variant_tag) || len(value) || value` |

Each list element is `len(encoded_value) || encoded_value`. Each map entry is
`len(encoded_key) || encoded_key || len(encoded_value) || encoded_value`.
Each record field is `uvar(field_tag) || len(encoded_value) || encoded_value`.
The length must equal the declared value’s complete encoding; inner trailing
bytes are rejected.

`Option<T>` is a union with tag 0 and zero-length payload for `None`, or tag 1
and one canonical T payload for `Some`. Every other tag is invalid. Other unions
use only epoch-declared nonzero tags and exactly one payload.

## 5. Records, lists, and maps

Record fields appear once in strictly increasing numeric-tag order. Required
fields must be present. Optional fields are omitted when absent; they have no
null or default byte encoding. Unknown, duplicate, out-of-order, and forbidden
fields are rejected.

Lists preserve semantic order. A field marked `CanonicalSet<T>` uses the list
encoding but requires elements to be in strictly increasing order by their
complete canonical encoded bytes and rejects duplicates.

Maps require entries in strictly increasing order by the complete canonical
key encoding, excluding the element length prefix. Equal adjacent key bytes are
duplicates and are rejected. Key types must have an epoch-declared total
canonical order. Runtime insertion order never affects map bytes or iteration.

## 6. Text and normalization

All text must be well-formed shortest-form UTF-8: reject invalid continuation,
overlong encodings, surrogate scalar values, and values above U+10FFFF.

Runtime `Text` and every unmarked text field preserve the exact Unicode scalar
sequence. They are never normalized, case-folded, locale-transformed, or
trimmed. Two canonically equivalent but byte-distinct sequences remain distinct
runtime text values.

Only `NormalizedLabel` requires Unicode NFC. Schema epoch 1 pins Unicode
Normalization Forms version 16.0.0. Input that is valid UTF-8 but not already
NFC is rejected rather than rewritten. Labels do not participate in logical
entity identity unless a later contract explicitly says otherwise.

## 7. Floating point

F32 and F64 use big-endian IEEE-754 bits. SCB1 canonical NaNs are:

- F32: `7f c0 00 00`
- F64: `7f f8 00 00 00 00 00 00`

All other NaN signs, signaling encodings, and payloads are rejected. SSMC1 v1
does not distinguish negative zero, so F32 `80 00 00 00` and F64
`80 00 00 00 00 00 00 00` are rejected; zero is encoded with all bits clear.
Infinities and finite subnormals retain their IEEE bit encodings.

The VM must canonicalize NaN and zero results before a value can become
canonical SCB1. The decoder never performs that canonicalization on input.

## 8. Extensions

Epoch 1 does not accept unknown record fields. Extensible contracts may declare
one optional final field named `extensions` with the epoch-assigned highest
field tag. Its value is a `CanonicalSet<Extension>` where:

```text
Extension = Record {
  1: namespace_id FixedBytes<16>,
  2: type_tag UInt<32>,
  3: version UInt<32>,
  4: payload Bytes
}
```

Ordering is by the complete Extension record encoding. An epoch registry must
allowlist the `(namespace_id, type_tag, version)` tuple and define payload
validation before acceptance. Unknown extension tuples are rejected. This
preserves deterministic extension bytes without making arbitrary opaque data a
semantic escape hatch.

## 9. Validity-affecting limits

Schema epoch 1 hard maxima are:

| Limit | Maximum |
|---|---:|
| standalone stored bytes | 67,108,864 |
| one `Bytes`, `Text`, label, or extension payload | 16,777,216 |
| nesting depth | 64 |
| fields in one record | 65,535 |
| elements in one list/set/map | 1,000,000 |
| decoded standalone values per request | 1,000,000 |
| total decoder allocation per standalone value | 134,217,728 |

Protocol/session policy may negotiate stricter values but never looser values
for epoch 1. Every length/count is checked against its local limit, remaining
input, and total allocation budget before allocation. Limit failure exposes no
partially successful canonical value.

## 10. Stable decode failures

The owning error registry must distinguish at least:

- `SCB_MAGIC_INVALID`, `SCB_VERSION_UNSUPPORTED`, `SCB_CONTRACT_UNKNOWN`;
- `SCB_EPOCH_MISMATCH`, `SCB_DIGEST_MISMATCH`, `SCB_TRAILING_BYTES`;
- `SCB_VARINT_NON_MINIMAL`, `SCB_INTEGER_OVERFLOW`, `SCB_LENGTH_OVERFLOW`;
- `SCB_BOOL_INVALID`, `SCB_UTF8_INVALID`, `SCB_LABEL_NOT_NFC`;
- `SCB_FLOAT_NON_CANONICAL`, `SCB_FIELD_MISSING`, `SCB_FIELD_UNKNOWN`;
- `SCB_FIELD_DUPLICATE`, `SCB_FIELD_ORDER`, `SCB_UNION_INVALID`;
- `SCB_MAP_ORDER`, `SCB_MAP_DUPLICATE`, `SCB_EXTENSION_UNKNOWN`;
- `SCB_RESOURCE_LIMIT`.

The first structural failure in byte order is returned. Digest mismatch is
checked after envelope bounds but before semantic payload exposure. A later
phase cannot convert a decode failure into success.

## 11. Schema epochs and migration

An epoch freezes contract/field/variant tags, required/optional status, value
types, canonical order, opcode tables, digest domains and algorithms, Unicode
normalization version, extension registry, floating profile, and all validity-
affecting limits.

Migration preserves the old decoder, decodes under the exact old epoch,
constructs a fresh canonical state under the new epoch, records old and new
roots and declared equivalence evidence in a migration transaction, and never
overwrites the old root. Silent fallback, tag reinterpretation, and input
normalization are forbidden.

## 12. Conformance obligation

S20-100 fixtures under `conformance/scb1/v1/` freeze primitive and structural
examples plus rejection classes. S20-120’s Rust codec and S20-130’s independent
oracle must produce byte-identical accepted vectors and the same stable failure
codes for rejected vectors. Neither implementation may derive expected bytes
from the other.

The envelope fixtures use a synthetic test registry that is never a production
epoch: epoch ID is 31 zero bytes followed by `01`; contract tag 1 is
`FixtureEmptyObject` with an empty Record payload; contract tag 2 is
`FixtureRequiredBool` with required Bool field tag 1. Both use digest domain
`sley2.object.v1`. The accepted envelope vector was calculated with Rust crate
`blake3` 1.8.2 and records the complete preimage, digest/ObjectId, and stored
bytes so later implementations can compute independently.
