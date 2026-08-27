# ADR-0018: Frozen legacy artifact adapter

Status: accepted for the scoped S20-600 artifact/version-smoke slice

## Decision

Treat the frozen Sley 1.2.0 release-candidate archive as an external, pinned
oracle artifact. Admit it only after exact outer identity, archive-safety,
embedded authority, and per-file payload verification. Copy it into private
temporary storage, extract it manually, strip write bits from the staged payload, and
allow only the exact `bin/sley --version` smoke with bounded execution and
create-only retained evidence.

Mutable scratch paths are private to the stage. The artifact-defined source
cache may use that scratch space, but no inherited HOME, TMPDIR, cache, or
environment enters the command. The adapter does not use the live Sley 1.2
checkout and does not import legacy source or semantics into the Sley 2 kernel.

## Consequences

- S20-600 now has verified artifact, staging, failure-retention, and runner
  smoke mechanics.
- Two 10-second timeouts, one 30-second timeout, and a successful longer smoke
  are retained as runtime evidence; the slow legacy startup is not hidden.
- The stage is mode-hardened but not mounted read-only. That is sufficient only
  for the exact trusted version command, not trial containment.
- The routine quick gate verifies artifact bytes and adversarial synthetic
  behavior without spending about one minute on the real executable smoke.
- The explicit `legacy-runner-smoke` target reruns the real command when that
  release-boundary evidence is needed.
- No benchmark trial, oracle result, fairness result, or succession metric is
  established. Full S20-600 remains pending the trial-specific surfaces named
  in the normative spec.
