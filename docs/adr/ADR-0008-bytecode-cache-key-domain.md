# ADR-0008: Dedicated VM bytecode cache-key domain

Status: accepted for the S20-260 restricted epoch-1 profile

## Decision

Register exact domain `sley2.vm-bytecode-cache-key.v1` and opaque
`BytecodeCacheKey`. Its preimage is frozen by
`docs/spec/VM_LOWERING_PROFILE_V1.md` and binds the root, entry function,
schema, VM/lowerer versions, lowering profile, and explicit empty restricted
generic/adapter/ABI fields.

The domain is not an alias for ObjectId, StateRoot, semantic fingerprint,
value hash, or execution report. A cache key authenticates no canonical state
and never bypasses validation.

## Consequences

- `sley-id` gains one closed domain, typed value, and fixed vector;
- cache artifacts remain derived and disposable;
- expanding generics, adapters, flags, or optimization requires a new profile
  contract and cannot silently reuse the restricted preimage.
