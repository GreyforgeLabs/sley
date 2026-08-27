# ADR-0017: Freeze Candidate Proposal Contracts Before Construction

Status: accepted for S20-345 specification review.

## Decision

Insert S20-345 between immutable mutation descriptors and candidate
construction. Freeze the candidate record, manifest-derived typed value codec,
bound preconditions, capability-summary projection, validation-profile
identity, and expiry representation before adding any builder or decoder.

Candidate data is always a proposal. Principal IDs, capability-summary
digests, roots, policy IDs, profile IDs, and expiry values are comparisons for
later trusted judgment; none grants authority merely by being canonical or
hashed.

## Consequences

- S20-350 depends on S20-345 and remains blocked until all six contracts pass
  architecture, semantic, and adversarial review.
- All eighteen entity bodies and seventy-five fields must use generated typed
  codecs from the exact SSMC1 manifest; opaque bytes and type-name dispatch are
  forbidden.
- S20-345 adds no executable mutation, candidate-root construction, session,
  policy transition, capability consumption, commit, receipt, CAS, filesystem,
  provider, network, process, deployment, or release surface.
- S20-345 extends the closed identifier registry with
  `CapabilitySummaryDigest`/`sley2.capability-summary.v1` and
  `ValidationProfileId`/`sley2.validation-profile.v1`, including fixed domain
  vectors. Candidate implementation therefore cannot invent or mutate them.
