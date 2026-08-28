# ADR-0019: Re-anchor the unreleased epoch-1 Option contract

Status: accepted for local implementation

Date: 2026-08-27

## Context

SCB1 assigns its generic `Option<T>` a special canonical encoding: tag `0`
with an empty payload is `None`, and tag `1` with one canonical payload is
`Some<T>`. The provisional SSMC1 epoch-1 manifest instead declared the ordinary
union tags `1` and `2`. The Rust mutation codec and independent SCB1 behavior
already implement the SCB1 rule.

No Sley 2 production schema epoch, accepted program root, release artifact, or
compatibility promise exists. The manifest is still an input to the eventual
production epoch, so preserving the contradiction as an epoch-1 compatibility
fact would create an incoherent first release.

## Decision

Correct the unreleased SSMC1 epoch-1 manifest in place:

- `0` with a zero-length payload means `None`;
- `1` with one canonical `T` payload means `Some<T>`;
- every other tag and every nonempty `None` payload is invalid;
- ordinary unions retain their nonzero epoch-declared tags;
- `BuiltinCase` remains a distinct non-generic enum and is unchanged.

The manifest bytes and every derived schema hash, generated descriptor,
fixture, vector, cache key, and evidence record must be re-anchored together.
Old provisional evidence is not compatibility authority and must not remain as
current passing evidence.

## Consequences

- S20-350 may implement `TrapTerminator`, `Terminator`, `ConstValue`, the
  remaining body and field codecs, preconditions, and the candidate record
  without choosing between conflicting tag systems.
- Strict fixtures must cover both valid tags, malformed `None` payloads,
  unknown tags, and nested trailing bytes.
- The re-anchor changes derived identifiers that include the SSMC1 field-schema
  hash. It does not migrate or overwrite an accepted `StateRoot`, because none
  exists.
- A future change after a production epoch or accepted root exists must use the
  schema migration contract instead of editing that epoch in place.

## Review evidence

- Ariadne: high-confidence decision to correct the unreleased epoch in place
  and retain SCB1 as the canonical Option authority.
- Nabu: confirmed the conflict is real contract work, not a project-level
  authority blocker.
- Vulcan: initial P2 for stale machine-summary query/capsule vectors; PASS after
  those vectors and the later adapter/report identities were re-anchored and
  workspace tests passed.
