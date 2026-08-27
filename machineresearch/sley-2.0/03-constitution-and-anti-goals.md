# Constitution and Anti-Goals

The governing constitution is captured by `README.md`, `ARCHITECTURE.md`,
`SECURITY.md`, `docs/ANTI_GOALS.md`, and ADR-0001 through ADR-0006.

Every anti-goal has an enforcement surface and evidence requirement. The most
important boundary is that SCB1/SSMC1 state is canonical while source text,
debug notation, JSON, Git, caches, models, adapters, and optional Greyforge
products remain non-canonical and non-authoritative.

Known master-goal errata interpreted by this baseline:

- the duplicate “exact parent transaction” in Section 11.3 is redundant, not a
  second distinct branch field;
- M0 requires an SMP1 draft, while S20-400 later freezes the implementable
  contract after query/mutation/transaction schemas exist;
- S20-360’s refined dependencies include protected policy and capability work;
- digest-bearing contracts exclude their digest field from their own digest
  preimage as specified by SCB1/schema;
- StateRoot repository metadata is restricted to explicit interpretation facts
  and excludes refs, branches, ancestry, paths, timestamps, locks, and Git.
