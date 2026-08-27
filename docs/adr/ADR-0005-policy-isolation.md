# ADR-0005: Protected policy and judged-candidate isolation

Status: Accepted for M0

## Decision

Policy is content-addressed, separately protected state. A candidate binds the
exact policy, epoch, kernel/validator contract, and mandatory test oracle used
to judge it but may not modify any of them in the same transaction.

## Consequences

Program validity and runtime capability remain distinct. Prompt text, labels,
documentation, adapter responses, and model output cannot grant authority.
Policy/epoch/oracle changes require separate higher-authority transactions.
