# Policy and Capability Model

Status: S20-370 protected policy-root implementation complete; S20-380
authenticated capability-token and live enforcement work remains a draft.

ADR-0005 separates judged candidates from policy, epoch, kernel, and oracle
changes. S20-370 and S20-380 own protected roots, authenticated tokens, scope,
expiry, replay, budget, adapter identity, and dual enforcement evidence.

S20-370 now provides a registry-authorized SCB1 `PolicyRoot` contract with one
exact opaque `PrincipalId` key per principal grant, closed effect and mutation
tags, exact adapter identities, bounded resource ceilings, protected entity
bindings, mandatory tests/contracts, expiry data, parent lineage, and a frozen
external-higher-authority-only transition mode. The accepted root and grant
internals are immutable outside `sley-policy`.

Pure policy judgment proves that an ordinary-program state preserves the base
policy root, schema epoch, contract/test roots, workspace, and every protected
entity binding. A separate policy-final plan requires every policy test and
contract to be present in the S20-240 validated inventories and every required
test to be selected.

This evidence does not authenticate the upstream report or candidate; S20-360
must do that in the monotonic pipeline. No API authenticates policy
transitions, issues tokens, reads time, enforces live scope/budgets, applies
mutations, commits, writes receipts, or advances refs. S20-380 and S20-390 own
those remaining boundaries, and the current registered epoch remains a
contract-specific conformance epoch pending production-epoch assembly.
