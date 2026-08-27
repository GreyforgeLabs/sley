# Raw Baseline Runner v1

Status: S20-610 offline-only normative runner contract.

## Boundary

S20-610 freezes evidence mechanics for the mandatory `raw_files` comparison
arm. It does not execute a model, provider, shell, tool, oracle, benchmark
trial, Sley 1.2 artifact, or Sley 2.0 arm. All execution interfaces are
injected Protocols and no live implementation is supplied.

## Run manifest

Before a first real trial, one create-only canonical JSON manifest must freeze
all seventeen controls named by `bench/benchmark-plan.json`, plus:

- contract `sley2.raw-run-manifest.v1`;
- run ID and UTC-second creation time;
- exact repository commit and corpus version;
- exact benchmark-plan digest;
- execution mode `offline_injected`;
- external-command policy `forbidden`.

Required-arm fixture and tool-description digest maps contain exactly
`raw_files`, `sley_1_2_0`, and `sley_2_0`. Shared model, configuration, task,
budget, retry, hardware, cache, oracle, seed, and environment controls occur
once at the run level, so an arm cannot silently receive different values.
The fairness comparator rejects any shared-control drift.

`trial_count` is the repetition count per frozen task, and `random_seeds`
contains exactly one distinct seed for each repetition. The raw arm's required
trial schedule is the Cartesian product of all 15 frozen task IDs and all
seeds. Duplicate `(task_id, seed)` attempts fail closed; complete verification
requires that exact product, so a harness cannot select only favorable tasks.

Canonical JSON permits only objects with string keys, arrays, strings,
booleans, null, and bounded integers. Floats and noncanonical stored bytes fail
closed. The manifest digest is:

```text
SHA256("sley2.raw-run-manifest.v1\\0" || canonical_manifest_json)
```

## Trial digest claims

Every injected raw-file observation appends one canonical JSONL digest claim.
Its contract is `sley2.raw-trial-digest-claim.v1`. The claim
binds run/trial/arm/task/seed, injected start/end times, outcome and timeout,
prompt/model/tool/candidate/workspace/oracle artifact digests, and all 25 frozen
benchmark metrics. `accepted_change_tokens` is `null`; S20-630 derives it later
from preserved integer token counts.

All artifact digest fields are lowercase SHA-256. Accepted trials require every
artifact digest claim; rejected trials require model-output, tool-call, and
oracle digest claims; timeout and harness-failure records preserve whatever
optional claims existed without inventing them. Start/end UTC seconds must be ordered.
Metric quantities are nonnegative integers: token totals must equal input plus
output, model input cannot exceed the frozen context budget, tool calls cannot
exceed the action budget, and non-timeout wall milliseconds cannot exceed the
wall-time budget. Floats are forbidden; later accounting derives ratios.

The first `previous_record_digest` is the manifest digest. Each subsequent
record names the prior record digest. A record digest is:

```text
SHA256("sley2.raw-trial-digest-claim.v1\\0" ||
       canonical_json(record_without_record_digest))
```

Every claim carries exact status `UNVERIFIED_INJECTED_DIGEST_CLAIMS`; oracle
and accounting status are each `UNVERIFIED_ADAPTER_CLAIM`. The chain verifies
only the bytes and ordering of these claims. It does not establish that an
artifact exists, matches the claimed digest, or came from an approved adapter.
There is no promotion API. A later operator-approved artifact store and
provenance verifier must resolve every digest and authenticate oracle and
accounting outputs before any item becomes benchmark evidence or supports a
result claim.

Appending takes an exclusive file lock, verifies the complete existing chain,
rejects duplicate trial IDs or task/seed pairs and the derived schedule ceiling, writes one
line with `O_APPEND`, and fsyncs it. There is no rewrite or deletion API.
Verification detects noncanonical bytes, truncation, reordering, middle/prefix
deletion while descendants remain, insertion, and field tampering. Complete-run
verification requires exactly the frozen task/seed product. A wholly replaced
local chain cannot prove its own rollback history without a separately retained
head digest; later evidence promotion must anchor the manifest and final head
outside this directory. These limits prevent the local chain from being
misrepresented as WORM storage or verified artifact provenance.

## Stable failures

Numeric codes 61000 through 61015 are frozen as `RAW_MANIFEST_INVALID`,
`RAW_CONTROL_MISMATCH`, `RAW_DIGEST_MISMATCH`, `RAW_TRIAL_LIMIT`,
`RAW_TRIAL_DUPLICATE`, `RAW_CHAIN_INVALID`, `RAW_RECORD_INVALID`,
`RAW_ARM_INVALID`, `RAW_TASK_UNKNOWN`, `RAW_SEED_MISMATCH`,
`RAW_STATUS_INVALID`, `RAW_METRIC_INVALID`,
`RAW_EXTERNAL_EXECUTION_FORBIDDEN`, `RAW_ARTIFACT_MISSING`,
`RAW_APPEND_FAILED`, and `RAW_INTERNAL_INVARIANT`.

## Explicit gaps

The raw fixture remains pending in the frozen benchmark plan. Real run values,
workspace containment, executable adapters, provider/model calls, strict-oracle
execution, actual trials, S20-600/S20-620 arms, S20-630 accounting, statistical
claims, succession thresholds, and publication remain unapproved later work.
