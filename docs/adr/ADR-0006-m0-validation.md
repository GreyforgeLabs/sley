# ADR-0006: M0 validation and fail-closed incomplete gates

Status: Accepted for M0

## Decision

`make quick` validates only the constitutional skeleton and Cargo metadata.
Product profiles exist from repository genesis but return a structured
`NOT_IMPLEMENTED` failure until their work packages supply real coverage.
`make v2` is never reported green based on scaffold checks.

## Consequences

M0 can be committed with honest evidence. Later packages replace the gate
stubs incrementally; no placeholder success can be mistaken for product proof.
