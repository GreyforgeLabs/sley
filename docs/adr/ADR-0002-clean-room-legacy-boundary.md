# ADR-0002: Clean-room legacy boundary

Status: Accepted for M0

## Decision

Sley 1.2.0 is an external frozen oracle and evidence source. Its source tree is
not copied or imported. Relevant concepts are reimplemented from specifications
only after a disposition records purpose, observed evidence, machine-native
relevance, security impact, new equivalent, decision, and acceptance test.

## Consequences

The legacy binary and exact source snapshot are preserved outside disposable
worktrees. Comparison harnesses execute them out of process. No 1.2.1 work is a
2.0 prerequisite.
