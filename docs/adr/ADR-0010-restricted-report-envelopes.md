# ADR-0010: Restricted derived report envelopes

Status: accepted for S20-290 restricted epoch-1 design review

## Decision

Implement S20-290's currently provable subset in a new `sley-conformance`
crate as derived in-memory execution and test report envelopes. Reuse the
existing `ExecutionReportId` and `TestReportId` digest domains with frozen
restricted-profile preimages, but do not model these envelopes as canonical
SSMC entities, stored objects, or persistent report references.

`sley-vm` remains the sole authority for observation derivation. The
conformance crate verifies an observed envelope through that authority and
aggregates S20-240 plan evidence without duplicating VM semantics.

## Rationale

The frozen epoch-1 Rust model has report identifier domains but no
`ExecutionReport` or `TestReport` entity bodies. S20-240 selection is also
explicitly policy-incomplete, and its byte/wall-time/call-depth resource
ceilings do not yet have equivalent S20-270 evidence units. Creating canonical
or persistent report entities now would invent schema and authority. Blocking
all report work would unnecessarily postpone deterministic conformance
envelopes that can already bind exact observations and expectation matches.

## Consequences

- report IDs identify restricted derived envelopes, not canonical objects;
- measured or host metadata is excluded and not accepted by the deterministic
  constructors;
- test entries report restricted expectation comparison, never final pass;
- policy/resource finality remains incomplete and cannot authorize commit;
- canonical report bodies, persistence, protected selection, and complete
  resource/effect/capability/replay evidence require later packages/epochs.
