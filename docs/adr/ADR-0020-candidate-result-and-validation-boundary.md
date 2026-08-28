# ADR-0020: Candidate result and monotonic validation boundary

Status: accepted for S20-360 implementation

Date: 2026-08-27

## Context

The master goal describes fifteen candidate-validation steps, the M0
transaction draft compressed them to thirteen, and the later S20-345
validation-profile freeze names fourteen exact phase tags. Candidate
construction is now implemented, but its fields remain unauthenticated proposal
data. A result format must preserve invalid-input diagnostics without inventing
a valid `CandidateId`, and no caller-provided pass bit may substitute for
kernel judgment.

## Decision

`VALIDATION_PROFILE_V1.md` is the phase authority. S20-360 runs exactly these
fourteen phases in order:

1. canonical frame;
2. schema and limits;
3. stale base and preimages;
4. identity;
5. graph and references;
6. type;
7. CFG;
8. effects;
9. protected capability and policy;
10. contracts;
11. test planning;
12. supported resource analysis;
13. candidate-root construction;
14. final candidate/result digest generation.

The master goal's separate graph/reference steps are one phase with distinct
terminal states. The M0 draft's combined type/CFG step is split. Every result
carries fourteen ordered phase records: a prefix of passed phases, at most one
failed phase, and a suffix of not-run phases. A later phase cannot execute
after failure or rewrite its decision.

The canonical result binds a raw-attempt digest, optional `CandidateId`, exact
validation profile, validator-owned context digest, decision, phase evidence,
diagnostics, affected closure, required capability-requirement identities,
selected tests, optional candidate root, and explicit trusted validation time.
Malformed or noncanonical candidate bytes have no `CandidateId`; the raw
attempt digest is causal evidence only. A candidate root is present exactly for
`VALID`.

S20-360 consumes an explicit trusted context containing the accepted base
transaction/root and exact object inventory, schema epoch, protected policy,
principal, rebuilt authenticated capability summary, current time, tombstones,
and hard ceilings. Candidate fields are comparisons against that context. The
result carries no secrets, authenticators, session handles, source, paths,
labels-as-identity, provider instructions, apply operation, commit, receipt,
CAS, filesystem access, or ambient clock read.

## Consequences

- S20-360 may return `VALID` only after all fourteen phases execute from
  validator-owned inputs. Unsupported semantic or resource analysis fails
  closed.
- Existing restricted semantic profiles may validate only their explicitly
  supported epoch subset; this does not turn S20-210 through S20-320 into GA.
- Validation is pure. It may build immutable candidate objects and a candidate
  root in memory, but it cannot mutate accepted state or consume a capability
  ledger.
- S20-390 must recheck the exact candidate, base transaction/root, policy,
  expiry, and result before any durable action. A result digest alone grants no
  commit authority.

## Review evidence

Nabu's bounded 2026-08-27 review selected the frozen fourteen-phase profile,
required absent candidate identity for malformed input, rejected
caller-asserted phase evidence, and found no architecture blocker to the
restricted conformance implementation. Vulcan's first adversarial pass found a
P1 length-only phase-evidence preimage; after the full canonical phase
input/output bytes and a regression marker were bound, the focused re-review
passed with no P0-P2 finding. Codex remains implementation owner and
integrator.
