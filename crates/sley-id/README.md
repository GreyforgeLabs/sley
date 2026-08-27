# sley-id

`sley-id` implements Sley 2 canonical identifier derivation for S20-110.

The crate exposes opaque 32-byte value types for identifiers and nonces. It
keeps the frozen domain registry internal and exposes only type-specific
derivation functions, so callers cannot provide arbitrary domain strings.
ADR-0007 adds a dedicated `ValueHash` domain; it is not an alias for semantic
fingerprints or immutable-object identities.
ADR-0008 adds a distinct derived `BytecodeCacheKey` domain that carries no
canonical-state authority.
ADR-0009 adds separate `ReferenceAdapterId`, `AdapterStateId`, and
`AdapterTranscriptId` domains for restricted adapter selection and derived
fixture/transcript evidence; none grants policy or capability authority.
ADR-0011 adds `IndexSnapshotId` for restricted derived cache-record integrity;
it does not authenticate root provenance or grant query authority.
ADR-0013 adds `RestrictedQueryCapsuleId` for complete restricted-query evidence;
it is deliberately distinct from the reserved master `ContextCapsuleId`.
S20-370 adds `PrincipalId` as opaque host-supplied 32-byte identity data. It has
no derivation domain and grants no authority by itself; only an accepted policy
record may associate it with policy data.
ADR-0017 adds `CapabilitySummaryDigest` and `ValidationProfileId` as
proposal-binding domains. Neither authenticates capabilities nor proves that
validation ran; trusted S20-360 judgment remains required.

This crate has no filesystem, network, environment, SCB1 encoding, repository,
policy, or VM authority.
