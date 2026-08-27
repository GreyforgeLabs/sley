# Prior Art and Competitor Baseline

Status: S20-040 corpus v1 frozen

The frozen Sley 1.2.0 artifact and raw-file editing are mandatory succession
arms. Zerolang is optional only when an exact runnable version and equivalent
environment can be preserved. No performance or superiority claim exists yet.

Corpus v1 contains one representation-neutral task for each of the 15 mandatory
classes. Its task manifest SHA-256 is
`7370b6ccb8ccd3f58fa2a90e316edf4bc5a1319b41a55253a2ee14bb5d73988d`.
The required arms, 17 run-freeze controls, 25 metrics, fairness rules, failure
retention, and succession thresholds are frozen in `bench/benchmark-plan.json`.

Exact models, budgets, environments, seeds, retry policy, arm fixtures, tool
contracts, and oracles must be bound by digest in a run manifest before the
first trial; those runtime facts do not yet exist. Legacy evidence may inform
fixtures but may not define Sley 2 semantics. No trial has run.

Vulcan independently reviewed S20-040 and returned PASS with no blocking
findings after verifying the deterministic baseline check, all classes and
arms, controls, metrics, thresholds, failure retention, representation
neutrality, corpus digest, and zero-trial claim.
