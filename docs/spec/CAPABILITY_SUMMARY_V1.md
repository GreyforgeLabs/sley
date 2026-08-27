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

The record fields are `format_version=1`, `principal_id`, `workspace_id`,
`policy_root_id`, `state_root`, and a canonically sorted set of `GrantSummary`.
Each grant contains the exact capability-token digest, issuer ID, key ID,
effect ID/kind, scope hash, adapter ID, six-field resource budget, issue time,
expiry, and token nonce. It contains no host secret, authenticator/MAC, raw
token bytes, use nonce, spent-ledger state, prompt, label, or provider data.

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
