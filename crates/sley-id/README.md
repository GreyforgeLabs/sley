# sley-id

`sley-id` implements Sley 2 canonical identifier derivation for S20-110.

The crate exposes opaque 32-byte value types for identifiers and nonces. It
keeps the frozen domain registry internal and exposes only type-specific
derivation functions, so callers cannot provide arbitrary domain strings.
ADR-0007 adds a dedicated `ValueHash` domain; it is not an alias for semantic
fingerprints or immutable-object identities.

This crate has no filesystem, network, environment, SCB1 encoding, repository,
policy, or VM authority.
