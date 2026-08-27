# ADR-0001: Machine-native lineage and no canonical text

Status: Accepted for M0

## Decision

SSMC1 semantic state is the program and SCB1 bytes are its canonical encoding.
Normal creation, mutation, execution, test, repository, and exchange paths use
typed machine contracts. Sley 2 provides no source syntax or accepted textual
program representation.

## Consequences

Debug notation may appear only when visibly labeled derived and is never input.
Source parsers, formatters, conventional LSP, source diffs, line identities,
comments, and human projections are excluded from the GA dependency graph.
