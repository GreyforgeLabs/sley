# Policy and Capability Model

Status: S20-370 protected policy-root and S20-380 narrow local authenticated
capability-token enforcement implementations complete. VM-integrated and live
host enforcement remain later work.

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

S20-380 now issues and strictly imports canonical 16-field local capability
tokens, authenticates exact policy/root/principal/workspace/effect/scope/adapter
bindings with a host-supplied keyed BLAKE3 secret, and rechecks explicit host
time. Its caller-owned ledger rejects replay and cumulative budget exhaustion.
The authorized S20-280 wrapper conservatively reserves the complete caller
limit envelope before fixture execution; pre-charge failures mutate nothing,
while post-charge fixture failures retain the charge and preserve fixture
atomicity.

This evidence does not authenticate an upstream candidate or report; S20-360
must do that in the monotonic pipeline. No API authenticates policy
transitions, applies mutations, commits, writes receipts, advances refs,
executes VM adapter opcodes, or confines live host resources. S20-390 and later
runtime packages own those boundaries, and the current registered epoch remains
a contract-specific conformance epoch pending production-epoch assembly.
