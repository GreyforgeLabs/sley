# ADR-0013: Restricted complete-query capsule identity

Status: accepted for the S20-320 restricted epoch-1 profile

## Decision

Register `sley2.restricted-query-capsule.v1` with opaque
`RestrictedQueryCapsuleId`. It identifies only an exact restricted evidence
envelope derived from one successful `RestrictedQueryResponse`.

Do not use the already-reserved `ContextCapsuleId`. The master context capsule
requires session, workspace, verified root, type/effect/contract/test facts,
diagnostics, mutation affordances, lawful omissions, and continuation. Those
facts do not exist in the restricted S20-310 lineage.

## Rationale

A distinct domain makes the incomplete scope mechanically visible and prevents
a complete restricted query from masquerading as the master
`sley-context-capsule-v1`. The envelope can still freeze deterministic entity
dictionaries, relationship indexes, exact source-response binding, and hard
resource limits useful for later capsule work.

## Consequences

- only a successful complete restricted response can construct the envelope;
- omission status is fixed to complete, truncation is fixed false, and
  continuation is fixed absent;
- capsule records have no public decoder/import or authority-bearing use;
- a capsule ID, claimed root, or copied response never establishes canonical
  root/session/workspace provenance;
- full S20-320, S20-330, S20-400, S20-620, M3, M5, and GA remain blocked.
