# ADR-0007: Dedicated value-hash domain

Status: accepted for the S20-250 restricted epoch-1 profile

## Context

SSMC1 freezes opcode 192, `value_hash`, but delegates its exact hash rule to
S20-250. `sley2.semantic-fingerprint.v1` is already assigned to entity semantic
fingerprints. The identifier contract forbids reusing a domain for a different
preimage purpose, even when an inner discriminator would make collisions
impractical.

## Decision

Register the exact ASCII domain `sley2.value-hash.v1` for the SSMC1 epoch-1
canonical value hash. It is distinct from ObjectId, EntityId, semantic
fingerprint, and every host hashing facility.

```text
ValueHash = BLAKE3-256("sley2.value-hash.v1" || canonical_value_preimage)
```

The preimage and accepted value traits are frozen by
`docs/spec/FINGERPRINT_IMPACT_PROFILE_V1.md`. `sley-id` exposes a dedicated
opaque `ValueHash` type and type-specific derivation API. It does not expose a
generic caller-supplied domain API.

## Consequences

- the frozen domain registry and fixed-vector suite gain one entry;
- `value_hash` cannot be substituted for a semantic fingerprint or object ID;
- changing the domain or preimage requires a new versioned contract and ADR;
- no existing identifier domain is renamed, aliased, or reinterpreted.

## Acceptance

- the domain registry contains the exact bytes once;
- a fixed vector freezes the new domain;
- the same canonical value produces the same bytes repeatedly;
- a semantic fingerprint preimage and value-hash preimage do not share a
  domain or typed Rust result.
