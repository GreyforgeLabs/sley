# External Comparison Availability v1

Status: S20-650 complete as an explicit repository-scoped unavailable state.

## Purpose and scope

The optional `zerolang` arm is allowed only when an exact runnable version can
be preserved under controls equivalent to the three mandatory succession arms.
The frozen S20-040 plan labels it `required=false` and
`fixture_status=UNESTABLISHED`.

S20-650 therefore records one of two states:

1. `AVAILABLE_FROZEN`, with exact version, artifact size and digest, equivalent
   fixture, tool-description, environment, and strict-oracle digests; or
2. `EXPLICIT_UNAVAILABLE`, with every missing prerequisite named and all trial
   and claim counters fixed to zero or false.

The current record is the second state. Its scope is only evidence registered
inside this repository. It makes no global availability statement and performs
no network discovery, download, installation, provider call, or spend.

## Frozen unavailable record

`bench/external/availability.json` binds:

- benchmark-plan SHA-256
  `10dae462f0a9520cbe4b3d4fd763897ea2d8af2b3d66915e00db802f8b8560ad`;
- corpus SHA-256
  `7370b6ccb8ccd3f58fa2a90e316edf4bc5a1319b41a55253a2ee14bb5d73988d`;
- arm ID `zerolang`, `required=false`, plan status `UNESTABLISHED`;
- null exact version, artifact, fixture, tool, environment, and oracle fields;
- six matching reason codes;
- zero comparison trials;
- false performance, superiority, public-claim, and global-availability claims.

The unavailable record cannot be treated as a poor score, failure, zero metric,
or evidence favoring another arm. It is excluded from mandatory-arm statistics.

## Reopening

A later change may replace the state only after a reviewed acquisition record
supplies all six prerequisites at once and confirms lawful use. It must preserve
the frozen task intent, strict oracle, model, configuration, budgets, retries,
hardware, cache policy, seeds, and failure-retention rules. Partial registration
remains unavailable; guessing a version or substituting a different oracle is
forbidden.
