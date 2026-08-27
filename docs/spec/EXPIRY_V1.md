# Candidate Expiry v1

Status: S20-345 canonical time-bound contract; no ambient clock authority.

`CandidateExpiry` is one SCB1 Record:

| Tag | Field | Type |
|---:|---|---|
| 1 | clock | `UInt16` |
| 2 | not_after | `UInt64` |

Epoch 1 permits only clock tag `1`, Unix time in milliseconds. `not_after` must
be nonzero. The candidate is temporally eligible exactly when an explicit
trusted host input satisfies `now_unix_millis < not_after`; equality is
expired. Encoding, hashing, decoding, or constructing the record never reads a
clock and never proves freshness.

The expiry participates in `CandidateId`. S20-350 accepts it as proposal data;
S20-360 compares it with explicit host time and policy/session ceilings before
deeper validation. Expiry cannot be extended by retry, normalization, missing
time, clock rollback, candidate content, a model claim, or a session handle.
An unsupported clock tag, zero deadline, missing trusted time, overflow, or
expired deadline fails closed and cannot advance state.
