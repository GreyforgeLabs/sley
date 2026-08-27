# ADR-0003: Crate authority and dependency direction

Status: Accepted for M0

## Decision

Each semantic rule has one owning kernel crate. The dependency graph follows
`canon/id/schema -> ssmc -> check -> query/mutate/policy -> txn -> repo/vm ->
protocol -> bridge/cli/conformance/bench`. Adapter contracts are typed VM
boundaries, not semantic authorities.

## Consequences

CLI, JSON, benchmarks, transports, Git, ZJX, Siglum, and model integrations may
not be imported by the kernel. Crates are created when implementation begins so
M0 cannot masquerade as an implemented product.
