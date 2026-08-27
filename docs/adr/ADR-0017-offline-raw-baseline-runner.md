# ADR-0017: Offline raw baseline evidence runner

Status: accepted for S20-610

## Decision

Implement S20-610 as an offline-only manifest and append-only digest-claim contract.
The runner validates all frozen controls and records explicitly unverified injected observations, but
ships no external command, provider, model, oracle, workspace-copy, network, or
Sley 1.x adapter.

One run manifest anchors a canonical SHA-256 digest chain. Every attempted trial
adds one fsynced JSONL record after revalidating the existing chain. Failure and
timeout records use the same path as accepted records. Shared controls occur
once in the manifest and a comparator rejects drift.

## Consequences

- S20-610 mechanics can be tested without contaminating the benchmark.
- Local chains authenticate claim continuity only; they do not verify artifact
  bytes, oracle/accounting provenance, or resist whole-directory rollback
  without a later external head anchor.
- A real run cannot be claimed until run-specific controls and adapters receive
  separate operator approval.
- The raw arm cannot silently gain model, budget, prompt, retry, hardware,
  cache, oracle, or environment advantages.
- The separate Sley 1.2 deployment tree remains untouched.
- ACT, cross-arm accounting, trials, thresholds, and public claims remain later
  packages.
