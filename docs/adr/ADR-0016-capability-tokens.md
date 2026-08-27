# ADR-0016: Capability tokens for local runtime enforcement

Status: accepted for the S20-380 narrow local profile

## Decision

S20-380 defines capability tokens in `sley-policy` and the authorized reference
adapter wrapper in `sley-adapter`.

The token body is canonical SCB1 data bound to exact issuer/key IDs, principal,
workspace, state root, effect definition and kind, resource-scope `ValueHash`,
reference adapter ID, bounded resource budget, issue/expiry times, nonce, and
accepted policy root. The token digest and keyed MAC use distinct preimages.
The host supplies the secret and current time explicitly; neither is serialized
or read ambiently.

`sley-policy` owns issuance, verification, and the deterministic replay/budget
ledger. `sley-adapter` depends on `sley-policy` and owns only the wrapper that
derives a conservative charge from every caller-supplied adapter resource
limit, verifies and charges that full limit envelope, then calls the existing
clone-before-commit fixture. There is no reverse dependency.

## Consequences

- Programs cannot mint tokens.
- Accepted policy roots remain the grant source and are rechecked on every use.
- Reused per-use nonces fail as `CAP_REPLAY`.
- Adapter action, output, random, virtual-file, state-preimage, and transcript
  ceilings cannot exceed the token's corresponding conservative resource
  reservation.
- Failed authorized adapter attempts consume replay/budget but do not mutate
  fixture state.
- The old fixture call remains available for conformance tests only and is not
  authority.
- Live hosts, VM adapter opcodes, candidates, commits, sessions, providers,
  policy transitions, runtime deployment, and GA remain outside this profile.
