# ADR-0009: Reference adapter evidence domains

Status: accepted for the S20-280 restricted epoch-1 profile

## Decision

Register exact domains `sley2.reference-adapter-id.v1`,
`sley2.adapter-state.v1`, and `sley2.adapter-transcript.v1` with opaque
`ReferenceAdapterId`, `AdapterStateId`, and `AdapterTranscriptId` types.

## Rationale

An external adapter identity, a complete request-owned fixture-state digest,
and one invocation transcript have different authority and preimages. Reusing
`EntityId`, `ObjectId`, `ValueHash`, `ObservationId`, or a cache/report domain
would permit type confusion. None of these values authenticates policy,
capability, canonical program state, or a live host resource.

## Consequences

- all three preimages are frozen by `REFERENCE_ADAPTER_PROFILE_V1.md`;
- future live adapters keep the identity type but require a new profile and
  protected capability/policy integration;
- state/transcript values are derived evidence and may be discarded;
- changing fixture state or any transcript binding changes the corresponding
  digest.
