# Capability Token v1

Status: S20-380 narrow local-only normative profile.

This profile adds authenticated, exact-scope capability tokens for local
reference-adapter enforcement. It does not grant live host, VM adapter opcode,
candidate, commit, session, policy-transition, provider, runtime deployment, or
GA authority.

## 1. Authority boundary

Only the host can issue or verify tokens because the keyed BLAKE3 secret and
current time are explicit host inputs. They are never serialized and are never
read from ambient process state. Programs, labels, prompts, metadata, adapter
responses, debug text, and repository objects cannot mint or validate tokens.

The S20-370 accepted policy root remains the source of grants. S20-380 binds a
token to one exact policy root and rechecks that root during verification.

## 2. Canonical token body

The unauthenticated body is one SCB1 record with fields 1 through 15:

| Tag | Field | Type |
|---:|---|---|
| 1 | version | `UInt32`, exactly `1` |
| 2 | issuer_id | opaque `FixedBytes32` |
| 3 | key_id | opaque `FixedBytes32` |
| 4 | principal_id | `PrincipalId` |
| 5 | workspace_id | `WorkspaceId` |
| 6 | state_root | exact `StateRoot` |
| 7 | effect_id | exact effect-definition `EntityId` |
| 8 | effect_kind_tag | frozen SSMC1 `EffectKind` tag |
| 9 | scope_hash | canonical resource-scope `ValueHash` |
| 10 | adapter_id | `ReferenceAdapterId` |
| 11 | budget | six-field resource budget record |
| 12 | issued_unix_millis | `UInt64` |
| 13 | expiry_unix_millis | `UInt64`, exclusive |
| 14 | token_nonce | opaque `FixedBytes32` |
| 15 | policy_root | `PolicyRootId` |

The budget record matches `PolicyResourceCeilings`: fuel, memory bytes, output
bytes, effect count, mutation count, and adapter calls. At least one dimension
must be nonzero and every dimension must be within the principal grant.

## 3. Digest and MAC

`CapabilityTokenDigest` is derived from the unauthenticated canonical body:

```text
digest_preimage =
  "SLEYCAPD" || u32be(1) || u64be(len(capability_body)) ||
  capability_body

CapabilityTokenDigest =
  BLAKE3-256("sley2.capability-token.v1" || digest_preimage)
```

The authenticator uses a distinct keyed preimage:

```text
mac_preimage =
  "SLEYCAPM" || u32be(1) ||
  issuer_id[32] || key_id[32] || CapabilityTokenDigest[32] ||
  u64be(len(capability_body)) || capability_body

authenticator = keyed-BLAKE3-256(host_secret[32], mac_preimage)
```

The serialized token is the same SCB1 record fields 1 through 15 plus field 16,
`authenticator[32]`. Unknown, missing, duplicate, reordered, trailing, or
nonminimal fields fail closed.

## 4. Issuance

Issuance requires:

- an `AcceptedPolicyRoot`;
- a trusted issuer ID, key ID, and 32-byte secret supplied by the host;
- exact workspace/principal/effect/scope/adapter/state-root inputs;
- ordered time: `issued_unix_millis < expiry_unix_millis`;
- policy-root workspace match;
- principal grant exists;
- grant allows the effect-kind tag and adapter ID;
- token budget is nonzero and within the grant ceilings;
- token expiry does not exceed policy expiry when the policy root has one.

No ordinary program API can issue a token.

## 5. Verification and ledger

Verification rechecks, in order, version, trusted issuer, trusted key, MAC,
policy root, workspace, principal, state root, effect ID/kind, scope hash,
adapter identity, time, grant allowlist, and requested budget.

The replay/budget ledger is caller-owned deterministic memory. A use supplies
an exact per-use nonce and a charge vector. The ledger atomically rejects reused
nonces as `CAP_REPLAY`, rejects cumulative budget exhaustion, and never double
charges one use nonce.

The reference-adapter wrapper charges the complete caller-requested limit
envelope before calling the S20-280 clone-before-commit fixture function. The
deterministic conservative mapping is:

```text
fuel = max_actions
memory_bytes =
  2 * max_state_preimage_bytes +
  max_transcript_preimage_bytes +
  max_random_bytes +
  max_output_bytes +
  max_total_virtual_file_bytes +
  max_virtual_files * 4368
output_bytes = max_output_bytes
effect_count = 1
mutation_count = 0
adapter_calls = 1
```

The `4,368` bytes reserve a worst-case 4,352-byte canonical virtual path
(`255-byte scope + "/" + 4,096-byte request`) plus two encoded length words per
permitted file entry. `max_total_virtual_file_bytes`
already bounds actual file content, including any single-file limit.
`max_calls` is a fixture-state ceiling; every dispatch is independently charged
as one adapter call. All arithmetic is checked, and the resulting vector must
fit both the token budget and the principal's policy ceilings. This is a
ceiling reservation, not post-hoc actual-use accounting, so no output, random,
file, action, state-preimage, or transcript ceiling can escape a zero or smaller
token dimension.

A fixture failure after successful authorization consumes the use nonce and
the full limit-envelope reservation but leaves fixture state unchanged.
Failures before charge mutate neither ledger nor fixture.

The old `invoke_reference_adapter` function is preserved as a conformance-only
fixture API and is unauthoritative.

## 6. Stable errors

Numeric codes 38000 through 38019 are frozen in enum order:

- `CAP_VERSION_UNSUPPORTED`;
- `CAP_ISSUER_UNTRUSTED`;
- `CAP_KEY_UNTRUSTED`;
- `CAP_AUTHENTICATOR_INVALID`;
- `CAP_POLICY_ROOT_MISMATCH`;
- `CAP_WORKSPACE_MISMATCH`;
- `CAP_PRINCIPAL_MISMATCH`;
- `CAP_STATE_ROOT_MISMATCH`;
- `CAP_EFFECT_MISMATCH`;
- `CAP_SCOPE_MISMATCH`;
- `CAP_ADAPTER_MISMATCH`;
- `CAP_EXPIRED`;
- `CAP_TIME_INVALID`;
- `CAP_BUDGET_ZERO`;
- `CAP_BUDGET_EXCEEDED`;
- `CAP_GRANT_DENIED`;
- `CAP_REPLAY`;
- `CAP_LEDGER_EXHAUSTED`;
- `CAP_CANONICAL_INVALID`;
- `CAP_INTERNAL_INVARIANT`.

Exact SCB1 failures are preserved for malformed canonical token bytes.

## 7. Acceptance and explicit gaps

Acceptance requires token canonicality, T22 forgery rejection, T23 replay and
expiry rejection, T24 scope/workspace/effect/adapter confusion rejection, and
authorized adapter atomicity tests.

This profile does not complete candidate admission, transaction commit, VM
effect opcodes, live host confinement, process isolation, sessions, provider
access, policy transitions, deployment, or Sley 2.0 GA.
