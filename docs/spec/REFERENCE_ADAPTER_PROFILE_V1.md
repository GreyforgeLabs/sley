# Reference Adapter Profile v1

Status: S20-280 restricted epoch-1 normative specification.

This contract freezes deterministic, request-owned reference adapter fixtures.
It is not live host access, not S20-380 capability enforcement, and not VM
integration: `VM_EXEC_RESTRICTED_V1` still rejects `adapter_invoke` and all
effectful Functions.

The restricted profile is useful for typed adapter conformance, replay,
transcript evidence, and later VM integration without granting ambient
authority. It never reads or writes the host filesystem, process environment,
clock, RNG, network, process table, shell, secrets, deployment surface, or
provider.

## 1. Closed reference identities

ADR-0009 registers three dedicated runtime-evidence domains:

- `sley2.reference-adapter-id.v1` -> `ReferenceAdapterId`;
- `sley2.adapter-state.v1` -> `AdapterStateId`;
- `sley2.adapter-transcript.v1` -> `AdapterTranscriptId`.

Reference adapter identity is:

```text
ReferenceAdapterId =
  BLAKE3-256("sley2.reference-adapter-id.v1" ||
             "SLEYRAI1" || u32be(profile_version=1) || u32be(kind))
```

| Kind | Tag | Behavior |
|---|---:|---|
| stdout capture | 1 | append bytes to request-owned stdout buffer |
| stderr capture | 2 | append bytes to request-owned stderr buffer |
| virtual file read | 3 | read request-owned virtual file bytes |
| virtual file write | 4 | replace request-owned virtual file bytes |
| deterministic clock | 5 | consume the next configured `u64` tick |
| deterministic random | 6 | emit a frozen BLAKE3 counter stream |
| explicit environment | 7 | look up request-owned text map |
| generic replay | 8 | consume the next exact typed replay entry |

Every reference import uses ABI version 1 and its exact derived identity.
Labels, paths, dynamic-library names, host discovery, and mutable latest-version
registries never select an adapter.

## 2. Static import/effect boundary

One invocation supplies the exact `AdapterImport`, its sole `EffectDef`,
the selected `TypeEnvironment`, `SchemaEpochId`, and `StateRoot`.

The boundary preserves S20-210/S20-230 rules and then requires:

- `AdapterImport.effects == [effect.entity_id]`;
- `effect.effect_kind == AdapterCall`;
- `import.adapter_id == ReferenceAdapterId(kind)`;
- `import.abi_version == 1`;
- scope/request constants pass `check_constant`, `require_hashable`, and exact
  effect/import type equality;
- response and declared-failure types pass `require_hashable` because every
  transcript binds their canonical `ValueHash`.

The seven concrete fixtures freeze these exact types:

| Kind | Scope | Request | Response | Declared failure |
|---|---|---|---|---|
| stdout/stderr | `Unit` | `Bytes` | `Unit` | `UInt<32>` |
| file read | `Text` | `Text` | `Bytes` | `UInt<32>` |
| file write | `Text` | `Tuple<Text,Bytes>` | `Unit` | `UInt<32>` |
| clock | `Unit` | `Unit` | `UInt<64>` | `UInt<32>` |
| random | `Unit` | `UInt<32>` | `Bytes` | `UInt<32>` |
| environment | `Unit` | `Text` | `Option<Text>` | `UInt<32>` |

Generic replay accepts the exact import/effect types after the common checks;
it does not invent, coerce, decode, or infer a host type.

There is no capability token parameter in this profile. That omission grants
nothing because all state is caller-owned memory. A future live integration
must add protected-policy/capability judgment before it may reuse this typed
boundary.

## 3. Invocation and state

```text
AdapterInvocation {
  kind: ReferenceAdapterKind,
  scope: ConstValue,
  request: ConstValue,
  limits: AdapterLimits,
  cancel_at_action: Option<u64>
}

AdapterLimits {
  max_calls: u64,
  max_actions: u64,
  max_output_bytes: u64,
  max_virtual_files: u64,
  max_virtual_file_bytes: u64,
  max_total_virtual_file_bytes: u64,
  max_random_bytes: u64,
  max_state_preimage_bytes: u64,
  max_transcript_preimage_bytes: u64
}
```

`AdapterFixtureState` owns stdout/stderr bytes, a canonical virtual-file map,
clock ticks/cursor, a 32-byte random seed/counter, a canonical environment map,
ordered replay entries/cursor, call count, and action count. No handle or
borrow escapes one invocation. Cancellation returns without partial mutation.

The public API clones the small control state and plans every mutation before
commit. It computes the pre-state ID, checks cancellation and all limits,
computes the typed outcome and complete post-state, computes the post-state and
transcript IDs, then atomically replaces the caller-owned fixture. Failure
before replacement leaves it byte-for-byte equal to the pre-state.

`state_id(state, types, schema_epoch, max_preimage_bytes)` takes the selected
type environment and schema epoch explicitly. This is required because every
stored replay outcome is revalidated and its canonical `ValueHash` binds that
epoch. A fixture cannot silently hash replay outcomes under an all-zero or
ambient epoch.

## 4. Canonical virtual paths

Virtual file state is a `BTreeMap<String, Vec<u8>>`; it has no symlinks,
mounts, devices, metadata, permissions, or host path conversion.

The scope is one root component and the request is a relative path. Every
component must:

- contain 1 through 255 ASCII bytes;
- begin with lowercase `a-z` or digit;
- contain only lowercase `a-z`, digits, `.`, `_`, or `-`;
- not equal `.` or `..`.

The request uses one `/` between components, contains at most 32 components
and 4,096 bytes, and has no leading/trailing slash, empty component, backslash,
NUL, control, uppercase, non-ASCII, percent escape, or normalization step.
The canonical map key is `scope || "/" || request`. Invalid input is
`ADAPTER_PATH_INVALID`; the implementation never repairs it.

Missing file read returns declared `UInt<32>(1)`. File write replaces or
creates one complete value only after file-count, per-file, total-file, action,
and state-size limits pass.

## 5. Concrete fixture semantics

- stdout/stderr append the exact request bytes. The combined captured-byte
  total is bounded by `max_output_bytes` before append.
- clock returns `ticks[cursor]` and increments the cursor. Exhaustion returns
  declared `UInt<32>(2)` without advancing.
- random reads `n` from `UInt<32>`, requires `n <= max_random_bytes`, and emits
  consecutive 32-byte blocks
  `BLAKE3("sley2.reference-random.v1" || seed || u64be(counter))`, truncated to
  `n`; the counter advances by the number of blocks only on success.
- environment returns `Some(Text(value))` or `None` from the exact canonical
  request-owned map. It never falls back to the host.
- generic replay compares the next entry's import identity, adapter identity,
  ABI version, call index, scope `ValueHash`, and request `ValueHash`. Exact
  match returns the stored success or declared-failure constant and increments
  the cursor. Mismatch or exhaustion does not consume an entry.

These replay entries are derived, request-owned S20-280 fixture records. They
are not the frozen SSMC `TestCase.EffectEnvironment.ReplayBinding` body, do not
make a nonempty TestCase replay environment valid, and do not change S20-240's
fail-closed rule. Mapping fixture entries into canonical TestCase replay needs
a later schema epoch with explicit scope, cursor, call-index, and adapter ABI
bindings.

Every successful or declared-failure invocation increments call count exactly
once. Engine rejection/cancellation does not. Actions are charged for adapter
dispatch and then for each appended output block, file-map lookup/replacement,
clock/random/replay cursor operation, or environment lookup. Before an action,
`cancel_at_action <= state.action_count` returns `ADAPTER_CANCELLED`; otherwise
the action limit is checked before mutation.

## 6. Outcomes, state ID, and transcript

```text
AdapterOutcome = Success(ConstValue) | DeclaredFailure(ConstValue)

AdapterReceipt {
  outcome: AdapterOutcome,
  pre_state: AdapterStateId,
  post_state: AdapterStateId,
  call_index: u64,
  actions_used: u64,
  output_bytes: u64,
  transcript: AdapterTranscriptId
}
```

Every returned value passes `check_constant`, `require_hashable`, and exact
declared response/failure type equality before state replacement.

State preimage uses big-endian fixed integers, `u64be(count)||items` lists, and
`u64be(length)||bytes` byte/text values:

```text
state_preimage =
  "SLEYADS1" || u32be(profile_version=1) ||
  bytes(stdout) || bytes(stderr) ||
  map(text_path, bytes_content, virtual_files) ||
  list(u64be, clock_ticks) || u64be(clock_cursor) ||
  random_seed[32] || u64be(random_counter) ||
  map(text_key, text_value, environment) ||
  list(replay_entry, replay_entries) || u64be(replay_cursor) ||
  u64be(call_count) || u64be(action_count)

AdapterStateId =
  BLAKE3-256("sley2.adapter-state.v1" || state_preimage)
```

Replay entries encode import `EntityId`, raw adapter ID, ABI, call index,
scope/request `ValueHash`, outcome arm tag, and outcome `ValueHash`. Maps use
their `BTreeMap` byte order and are independently checked for canonical
virtual paths/environment keys before hashing.
The supplied `TypeEnvironment` rechecks each replay outcome and the supplied
`SchemaEpochId` derives its outcome hash; the epoch is therefore represented
inside every replay outcome `ValueHash`, not as an extra top-level state field.

```text
transcript_preimage =
  "SLEYADT1" || u32be(profile_version=1) ||
  SchemaEpochId[32] || StateRoot[32] ||
  import_EntityId[32] || effect_EntityId[32] ||
  adapter_id[32] || u32be(abi_version=1) || u32be(kind) ||
  u64be(call_index) || ValueHash(scope)[32] || ValueHash(request)[32] ||
  AdapterStateId(pre)[32] || AdapterStateId(post)[32] ||
  outcome_arm_and_ValueHash ||
  u64be(actions_used) || u64be(output_bytes)

AdapterTranscriptId =
  BLAKE3-256("sley2.adapter-transcript.v1" || transcript_preimage)
```

No wall time, host fact, path outside the virtual key, pointer/layout value,
label, debug text, or capability claim enters either preimage.

## 7. Deterministic order and limits

The exact first-failure order is:

0. preserve the integrated boundary's exact S20-210 type failure before any
   S20-280 preflight; an S20-230 caller must likewise return its own prior
   failure before invoking this API;
1. hard state/request counts and preimage-size preflight;
2. adapter identity, ABI, sole-effect identity/kind, and concrete profile;
3. complete scope/request constant and hashability judgment, then exact types;
4. canonical fixture-state/path/environment/replay validation;
5. pre-state ID;
6. cancellation, call limit, action/output/file/random limits;
7. deterministic handler plan and declared outcome judgment;
8. post-state ID and transcript preflight;
9. atomic in-memory state replacement and receipt.

Hard profile maxima are 4,096 files, 4,096 environment entries, 65,535 replay
entries, 1,000,000 clock ticks, 67,108,864 bytes per state/transcript preimage,
16,777,216 bytes per file, output constant, or random request, and 67,108,864
total virtual-file/captured-output bytes. Request limits may be smaller, never
larger. Existing fixture totals must already fit the request's smaller limits;
changing to a smaller limit never grandfathers oversized state.

## 8. Stable failures

| Numeric | Symbolic code |
|---:|---|
| 28000 | `ADAPTER_PROFILE_UNSUPPORTED` |
| 28001 | `ADAPTER_IDENTITY_MISMATCH` |
| 28002 | `ADAPTER_ABI_MISMATCH` |
| 28003 | `ADAPTER_EFFECT_MISMATCH` |
| 28004 | `ADAPTER_TYPE_MISMATCH` |
| 28005 | `ADAPTER_STATE_INVALID` |
| 28006 | `ADAPTER_PATH_INVALID` |
| 28007 | `ADAPTER_REPLAY_MISMATCH` |
| 28008 | `ADAPTER_REPLAY_EXHAUSTED` |
| 28009 | `ADAPTER_RESOURCE_LIMIT` |
| 28010 | `ADAPTER_CANCELLED` |
| 28011 | `ADAPTER_INTERNAL_INVARIANT` |

Earlier `TYPE_*`, `FINGERPRINT_*`, and S20-230 errors are preserved where the
integrated caller supplies them. This crate owns no policy/capability success.

## 9. Acceptance and explicit gaps

- fixed vectors freeze all eight reference IDs, one state ID, and one
  transcript ID/preimage;
- positive fixtures cover every concrete adapter and replay success/failure;
- traversal, separator, Unicode/case, identity/ABI swap, response injection,
  replay order/exhaustion, output/file/random floods, cancellation, and
  mutation-on-error corpora fail deterministically without state change;
- at least 128 repeated invocations from equal state/request produce equal
  outcome, post-state, counters, and transcript;
- strict lint and independent review have no open P0/P1/P2.

Full S20-280 GA remains blocked on effect/adapter opcode lowering/execution,
protected policy roots, authenticated root/scope/adapter-bound capabilities,
runtime budget enforcement across VM and adapter, live cancellation/handle
cleanup, process isolation, authorized confined host file/environment access,
and S20-290 persistent effect/capability/replay report evidence. Network,
arbitrary process/shell, secrets, deployment, and spend remain outside Sley 2.0
GA rather than deferred adapter features.
