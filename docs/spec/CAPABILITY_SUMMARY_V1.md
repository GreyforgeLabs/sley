# Capability Summary v1

Status: S20-345 normative proposal-binding contract; not authority.

The session capability summary is a canonical projection of authenticated
capability-token bodies made available by a trusted host/session boundary. A
candidate carries only its digest. Candidate content cannot authenticate,
mint, widen, narrow, or consume a capability.

```text
summary_preimage = "SLEYCAS1" || uvar(1) || len(summary_record) || summary_record
CapabilitySummaryDigest =
  BLAKE3-256("sley2.capability-summary.v1" || summary_preimage)
```

The summary record has six required fields:

| Tag | Field | Type |
|---:|---|---|
| 1 | format_version | `UInt32`, exactly `1` |
| 2 | principal_id | `PrincipalId` |
| 3 | workspace_id | `WorkspaceId` |
| 4 | policy_root_id | `PolicyRootId` |
| 5 | state_root | `StateRoot` |
| 6 | grants | `List<GrantSummary>` sorted by complete encoded bytes |

Each `GrantSummary` is the exact eleven-field Record below. It contains no host
secret, authenticator/MAC, raw token bytes, use nonce, spent-ledger state,
prompt, label, or provider data.

| Tag | Field | Type |
|---:|---|---|
| 1 | token_digest | `CapabilityTokenDigest` |
| 2 | issuer_id | `CapabilityIssuerId` |
| 3 | key_id | `CapabilityKeyId` |
| 4 | effect_id | `EntityId` |
| 5 | effect_kind_tag | `UInt32` |
| 6 | scope_hash | `ValueHash` |
| 7 | adapter_id | `ReferenceAdapterId` |
| 8 | budget | six-field `CapabilityResourceBudget` Record |
| 9 | issued_unix_millis | `UInt64` |
| 10 | expiry_unix_millis | `UInt64` |
| 11 | token_nonce | `CapabilityTokenNonce` |

The budget record tags 1 through 6 are, in order, `max_fuel`,
`max_memory_bytes`, `max_output_bytes`, `max_effect_count`,
`max_mutation_count`, and `max_adapter_calls`, all `UInt64`.

Grant summaries are sorted by complete canonical bytes and duplicate token
digests are forbidden. Empty summaries are canonical and mean no proposed
capability. All outer principal/workspace/policy/root fields must agree with
every grant body.

During S20-360, a trusted validation context must independently rebuild this
summary from authenticated, unexpired, exact-root tokens and compare the digest
before policy judgment. A digest match is necessary but never sufficient:
individual capability verification, scope, budget, replay, and use-ledger
checks still apply. S20-330 must later bind the authenticated session; until
then S20-350 can only construct an unauthoritative proposal record.

## Fixed empty-summary vector

For principal bytes `01*32`, workspace bytes `02*32`, policy-root bytes
`03*32`, state-root bytes `04*32`, and no grants, the exact
`CapabilitySummaryDigest` is:

```text
1ee37d0d27650d460d7acffd6402ab5889b5673512e56930208972f39c2acf62
```

`sley-policy::build_capability_summary_projection` implements this projection.
It performs binding and duplicate-digest checks but deliberately performs no
MAC, expiry, scope, ledger, or candidate-authority judgment; S20-360 owns those
checks with trusted key material.
