# VM Execution Profile v1

Status: S20-270 restricted epoch-1 normative specification.

This contract freezes deterministic execution of the successful
`O0-restricted-v1` result from S20-260. It is `VM_EXEC_RESTRICTED_V1`, not the
full SSMC1 VM, not an adapter runtime, and not the persistent execution/test
report surface owned by S20-290.

The restriction is necessary because only `bool_not` (102), `bool_and` (103),
and `bool_or` (104) have complete operation-signature judgment in the current
lowering path. The executor supports all five frozen terminators and arbitrary
S20-210-valid persistable input values needed for branch or variant payload
flow, but it creates only Boolean operation results.

## 1. Integrated authority boundary

The only public execution entry point consumes a `LoweringInput` plus an owned
`ExecutionRequest`. It calls `lower_function` internally and preserves the
complete earlier `TYPE_*`, `GRAPH_*`, `CFG_*`, and `VM_LOWER_*` result before
inspecting execution inputs.

Callers cannot execute raw bytecode bytes or a caller-constructed
`BytecodeFunction`/`LoweredFunction`. S20-260 bytecode remains derived and
disposable. A future cache may reuse bytes only after repeating the same
epoch/root/function/profile validation and authenticating the cached bytes;
this profile performs no cache-hit load.

The request contains:

```text
ExecutionRequest {
  inputs: List<ConstValue>,
  limits: ExecutionLimits
}

ExecutionLimits {
  max_instructions: u64,
  max_fuel: u64,
  max_value_units: u64,
  max_output_units: u64,
  cancel_at_fuel: Option<u64>
}
```

Inputs are in `Function.parameters` order. Count mismatch fails before input
content inspection. Each input is checked by `TypeEnvironment::check_constant`
and must exactly equal its declared Function-parameter type. The exact earlier
`TYPE_*` failure is preserved for an invalid constant; a valid constant of the
wrong declared type is `VM_EXEC_INPUT_TYPE_MISMATCH`. Handles, capabilities,
local cells, open type parameters, and every other nonpersistable value fail in
S20-210 and never become runtime values here.

Restricted-v1 accepts at most 262,144 ordered inputs and at most 67,108,864
aggregate validated input `value_units`. After the count check, each input in
order passes constant judgment, hashability, exact declared type, checked unit
accumulation, and value hashing. Crossing either hard profile cap returns the
pre-execution `VM_EXEC_RESOURCE_LIMIT` code with no outcome because the complete
ordered input-hash set was not accepted. The request's smaller
`max_value_units` remains an observed runtime limit after all inputs pass this
hard profile gate.

## 2. Runtime values and registers

Runtime values are immutable, reference-counted views of validated
`ConstValue`. Register count and register types come only from the successful
S20-260 result. Function input registers are initialized in order. Every other
register is initially empty and is populated only by block-argument binding or
one executed Boolean instruction.

An instruction reads all operands before writing results. `bool_and` and
`bool_or` therefore read both already-computed register values; this execution
rule is strict and does not introduce source-language short-circuit control
flow.

```text
bool_not(a)    = Bool(!a)
bool_and(a,b)  = Bool(a && b)
bool_or(a,b)   = Bool(a || b)
```

An absent register, wrong runtime value form, bad slot, bad arity, or type
mismatch after successful lowering is `VM_EXEC_INTERNAL_INVARIANT`. It is never
reinterpreted or repaired at runtime.

## 3. Terminators

- `Return(r)` succeeds with the exact immutable value in `r`, which must equal
  the Function result type.
- `Branch(edge)` reads all source arguments first, then simultaneously binds
  them to the target block parameter registers and jumps.
- `CondBranch` requires `Bool`; `true` selects the true edge and `false` the
  false edge, using the same simultaneous binding rule.
- `VariantSwitch` accepts named `Variant`, `Option`, or `Result` values. It
  selects the exact `MemberId`, `None`, `Some`, `Ok`, or `Err` case. A
  `CasePayload` argument binds the selected payload; requesting a payload from
  `None` or a payload-free named case is an internal invariant failure.
- `Trap` terminates with `VM_EXEC_TRAP`, the exact frozen trap tag, and the
  optional persistable payload value.

Case comparisons occur in the canonical case order preserved by lowering.
Missing or duplicate cases cannot pass S20-220; observing either during
execution is an internal invariant failure.

## 4. Deterministic budgets and cancellation

`instruction_count` counts executed Boolean instructions only. Fuel charges
before each action:

| Action | Fuel |
|---|---:|
| Boolean instruction | 1 |
| terminator dispatch | 1 |
| ordinary edge argument bind | 1 |
| switch case comparison | 1 |
| selected case-payload bind | 1 additional |

Before an action, cancellation is observed when
`cancel_at_fuel <= fuel_used`; cancellation therefore wins over a resource
failure for that not-yet-started action. Otherwise the executor checks the
relevant instruction and fuel ceilings before mutation. A zero cancellation
point cancels before the first instruction or terminator. A zero fuel limit
without cancellation terminates at the first charged action. Legal loops are
therefore bounded without host time.

This restricted profile has no asynchronous host token. `cancel_at_fuel` is a
deterministic cancellation schedule for conformance and replay. Live bounded
cancellation tokens and cleanup are later runtime/protocol work.

`value_units` is a deterministic semantic resource measure, not host RSS. Let
`U(T)` be type units, `D(data)` be data units, and
`V(value)=1+U(value.type)+D(value.data)`. All addition is checked and validated
recursion retains the S20-210 depth limit.

```text
U(Unit|Bool|F32|F64|Bytes|Text) = 1
U(SInt|UInt|BuiltinFailure) = 3
U(Tuple(items)) = 1 + count(items) + sum(U(item))
U(Named(def,args)) = 33 + count(args) + sum(U(arg))
U(Vector|Option|LocalCell(item)) = 1 + U(item)
U(OrderedMap(key,value)|Result(key,value)) = 1 + U(key) + U(value)
U(FunctionRef(params,result,effects)) =
  1 + count(params) + sum(U(param)) + U(result) + 33*count(effects)
U(AdapterHandle|CapabilityToken) = 33
U(TypeParameter) = 5

D(Unit) = 1
D(Bool) = 2
D(SInt|UInt) = 17
D(F32|BuiltinFailure) = 5
D(F64) = 9
D(Bytes|Text(payload)) = 1 + byte_length(payload)
D(Sequence(items)) = 1 + count(items) + sum(V(item))
D(Record(def,fields)) = 33 + count(fields) + sum(32 + V(field.value))
D(Variant(def,member,None)) = 65
D(Variant(def,member,Some(payload))) = 66 + V(payload)
D(Map(entries)) = 1 + count(entries) + sum(V(key) + V(value))
D(Option(None)) = 1
D(Option(Some(value))|Result(Ok(value))|Result(Err(value))) = 2 + V(value)
D(FunctionRef(function,args)) = 33 + count(args) + sum(U(arg))
```

The initial live total contains every input value plus one unit per bytecode
register slot and one unit per byte of the S20-260 derived artifact. If this
total exceeds `max_value_units`, execution produces an observed
`ResourceLimit(value units)` outcome with zero instructions, zero fuel, and
`peak_value_units=initial_live_total`; it is not a pre-execution error.

A newly created Boolean result is charged before allocation. Selected payloads
are immutable reference views into an already-live validated value and receive
no second semantic value charge. Reference copies do not duplicate value
units. Restricted-v1 runtime allocations are arena-lived until termination;
they are not released when registers are overwritten. If a new allocation
would cross the request limit, it is not allocated and the live/peak total does
not include the attempted value. `peak_value_units` therefore records the
checked monotonic arena total and cannot depend on host reference-count timing.

The output limit uses the returned or trap-payload value's `value_units`.
There is no stdout, stderr, effect, adapter, replay, environment, clock, random,
file, or network output in this profile. Full report-byte and adapter-output
accounting remains S20-280/S20-290 work.

## 5. Termination and stable failures

Successful execution and runtime termination produce one `ExecutionOutcome`:

```text
ExecutionOutcome {
  state_root: StateRoot,
  schema_epoch: SchemaEpochId,
  function: EntityId,
  cache_key: BytecodeCacheKey,
  termination: Success(ConstValue) |
               ResourceLimit(ResourceKind) |
               Cancelled |
               Trap { trap_tag, payload } |
               InternalInvariant,
  instruction_count: u64,
  fuel_used: u64,
  peak_value_units: u64,
  observation_id: ObservationId
}
```

Pre-execution input failures return no outcome. Runtime resource, cancellation,
trap, and internal-invariant terminations do produce an observation digest.
The hard input-count/input-unit profile gate is the only pre-execution use of
`VM_EXEC_RESOURCE_LIMIT`.

| Numeric | Symbolic code |
|---:|---|
| 27000 | `VM_EXEC_INPUT_COUNT_MISMATCH` |
| 27001 | `VM_EXEC_INPUT_TYPE_MISMATCH` |
| 27002 | `VM_EXEC_RESOURCE_LIMIT` |
| 27003 | `VM_EXEC_CANCELLED` |
| 27004 | `VM_EXEC_TRAP` |
| 27005 | `VM_EXEC_INTERNAL_INVARIANT` |

`ResourceKind` is closed: instruction (1), fuel (2), value units (3), and
output units (4). Earlier lowering/type failures retain their owning codes.

The exact order is:

1. integrated S20-210/S20-220/S20-260 lowering result;
2. input count, then the hard 262,144-input profile cap;
3. each input in order: complete `check_constant`, require
   `canonical_hash=true`, exact declared type, checked aggregate input units,
   then canonical value hash;
4. deterministic initial live-total calculation and the request's value limit;
5. for every action: cancellation, instruction ceiling when applicable, fuel,
   value allocation, action semantics, and output ceiling when terminating;
6. internal invariant only for state impossible after successful prior phases.

## 6. Observation digest

S20-270 depends on S20-250's canonical `ValueHash` rule for every validated
input, successful result, and trap payload. After `check_constant`, execution
calls `TypeEnvironment::require_hashable` before the low-level
`hash_validated_value` encoder. The exact earlier `TYPE_*` or
`FINGERPRINT_*` failure is preserved. This dependency is value encoding only;
it does not claim complete-root fingerprint/impact GA.

```text
observation_preimage =
  "SLEYOBS1" || u32be(profile_version=1) ||
  SchemaEpochId[32] || ssmc1_field_schema_hash[32] ||
  ssmc1_decoder_limits_hash[32] || StateRoot[32] ||
  Function_EntityId[32] || BytecodeCacheKey[32] ||
  u32be(vm_major=1) || u32be(vm_minor=0) || u32be(vm_patch=0) ||
  u32be(execution_profile=1) ||
  list(ValueHash[32], input_hashes) ||
  u64be(max_instructions) || u64be(max_fuel) ||
  u64be(max_value_units) || u64be(max_output_units) ||
  option(u64be, cancel_at_fuel) ||
  termination ||
  u64be(instruction_count) || u64be(fuel_used) ||
  u64be(peak_value_units) ||
  u64be(effect_call_count=0) || u64be(capability_use_count=0) ||
  u64be(adapter_version_count=0) || u64be(replay_reference_count=0)

termination(Success) = u32be(1) || ValueHash[32]
termination(ResourceLimit) = u32be(2) || u32be(resource_kind)
termination(Cancelled) = u32be(3)
termination(Trap) = u32be(4) || u32be(trap_tag) || option(ValueHash[32], payload)
termination(InternalInvariant) = u32be(5)

ObservationId =
  BLAKE3-256("sley2.observation.v1" || observation_preimage)
```

Lists use `u64be(count)`. Options use `u32be(1)` for none and
`u32be(2)||item` for some. No wall time, host thread/scheduling fact, path,
debug text, cache-hit state, pointer/layout value, or persistent report ID
enters the digest.

The canonical observation preimage is capped at 67,108,864 bytes before
allocation. The accepted input cap makes the ordered hash list fit this bound;
overflow or impossible drift preserves the S20-250 resource failure.

S20-290 owns the canonical execution/test report entity, report digest,
measured wall-time metadata, resource-evidence schema, and persisted report
references. S20-270 returns only this in-memory outcome and observation ID.

## 7. Acceptance and explicit gaps

- exact fixtures cover all three Boolean opcodes and all five terminators;
- named variant, Option, and Result switches cover payload and no-payload cases;
- input count/type/constant failures preserve exact precedence;
- loop, instruction, fuel, value, output, cancellation, trap, and impossible
  runtime-state fixtures terminate deterministically without panic;
- at least 128 repeated executions produce equal value, counts, termination,
  and observation ID;
- semantic input/control/limit changes alter the observation ID;
- raw/caller-constructed bytecode has no execution API;
- strict lint and independent review have no open P0/P1/P2.

Full S20-270 GA remains blocked on complete judgment/lowering/execution for the
other 52 opcodes, generic specialization and calls, constants/globals, local
cells, deterministic floating rules, effects, capabilities, adapters, replay,
live cancellation/cleanup, exact host-independent byte memory/output budgets,
complete root/module loading, and S20-290 report entities.
