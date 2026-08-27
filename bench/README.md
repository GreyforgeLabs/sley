# Sley 2 Succession Benchmark

This directory defines representation-neutral task intent and scoring. It is
benchmark metadata, not a Sley program representation and never enters program
identity or kernel judgment.

`corpus/v1/tasks.json` freezes one task for each mandatory class in the master
goal. A later corpus change creates `v2`; it never rewrites v1 after trials.
`benchmark-plan.json` freezes arms, controls, metrics, fairness, thresholds, and
failure retention. Exact model versions, tool contracts, hardware, cache state,
budgets, seeds, and per-arm fixture digests are frozen in a run manifest before
the first trial, because those values do not yet exist at S20-040.

The same task intent, strict semantic oracle, action/context/wall budgets, and
retry policy apply to raw files, frozen Sley 1.2.0, and Sley 2.0. Arm-specific
representations may differ only where the arm intrinsically requires them.
Every attempted trial remains in the denominator.

S20-600 adds a scoped frozen-artifact adapter under `bench/legacy`. It verifies
the exact Sley 1.2.0 archive, embedded release authority, and complete payload;
stages only a private write-bit-stripped copy; and retains one bounded `bin/sley
--version` smoke including failures and exact environment. It does not yet map
or execute benchmark tasks, enforce trial network containment, invoke a model
or oracle, or establish any succession metric. Full S20-600 remains open.

S20-610 adds an offline-only raw-file runner contract under `bench/raw`. It
validates the complete run-freeze controls and stores a create-once manifest plus
append-only digest-chained, explicitly unverified trial claims using injected interfaces. It ships
no external command, provider, model, oracle, workspace-copy, or Sley 1.x
adapter. The raw fixture and every actual benchmark run remain pending explicit
run-specific freeze and approval.
