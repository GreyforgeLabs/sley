# Contract and Test Profile v1

Status: S20-240 restricted epoch-1 normative specification.

This contract freezes the smallest non-ambiguous fail-closed judgment for the
SSMC1 epoch-1 `Contract`, `TestCase`, `contract_assert`, and `test_observe`
shapes. It consumes S20-210 type judgment, S20-220 CFG/value-use judgment, and
S20-230 exact effect closure. Earlier failures retain their exact phase/code.

This is deliberately a restricted epoch-1 profile, not the complete GA
contract/test model. The frozen SSMC1 fields do not contain a TypeDef value
source, effect/capability/resource evidence sources, replay cursor/scope,
adapter configuration type, or observation execution semantics. Epoch 1
therefore rejects those forms rather than assigning meaning by convention.
A future schema epoch must add explicit fields/variants without renumbering or
reinterpreting epoch-1 tags.

This phase validates canonical entities and produces a deterministic
provisional test plan. It does not execute predicates/tests, prove resource
ceilings, validate runtime capabilities/policy, replay adapters, observe a VM,
construct a candidate root, or emit an execution/test report.

## 1. Closed model

### 1.1 Contract kinds

The frozen `ContractKind` tags remain:

| Tag | Kind | Epoch-1 restricted profile |
|---:|---|---|
| 1 | `Precondition` | supported |
| 2 | `Postcondition` | supported |
| 3 | `Invariant` | rejected |
| 4 | `EffectBound` | rejected |
| 5 | `CapabilityBound` | rejected |
| 6 | `ResultPredicate` | supported |
| 7 | `ResourceCeiling` | rejected |

Unsupported tags decode structurally but fail semantic judgment. No future
implementation may reinterpret that failure as acceptance under epoch 1.

### 1.2 Contract target and predicate

A supported contract targets exactly one Function entity. Target TypeDef,
global, test, adapter, contract, or other entity kinds fail.

The predicate resolves to one Function in the same closed request and must:

- have zero type parameters;
- have exact S20-230 least effect closure empty;
- declare no attached contracts;
- return exactly `Bool`;
- have every parameter bound exactly once by `Contract.bindings`.

The target must also have zero type parameters because the epoch-1 Contract
body has no type-argument binding. Target and predicate may not be the same
function. Predicate contract-emptiness prevents contract dependency cycles in
this restricted profile; there is no recursive fallback or implicit oracle.

### 1.3 Contract bindings

Bindings are ordered by `predicate_parameter` and must be the exact sequence
`0..predicate.parameter_count`. The checker never sorts or repairs them.

Source types are:

- `Parameter(id)`: the exact declared type of a parameter owned by the target
  function;
- `Result`: the target's complete declared result type;
- `Error`: only the error-arm type when the target result is exactly
  `Result<Ok,Error>`;
- `Global(id)`: the exact type of a resolved immutable GlobalValue whose
  initializer is a valid Constant with the same exact type.

Each source type must equal the corresponding predicate parameter type. There
is no implicit coercion or generic instantiation.

`Precondition` permits only `Parameter` and `Global` sources.
`Postcondition` permits `Parameter`, `Result`, `Error`, and `Global`. If any
`Error` source is present, the contract is an error-arm postcondition evaluated
only for `Err`; `Result` and `Error` sources may not be mixed in one contract.
`ResultPredicate` permits `Parameter`, `Result`, and `Global`, forbids `Error`,
and requires at least one `Result` source.

Multiple predicate parameters may intentionally bind the same source. The
predicate-parameter sequence, not source uniqueness, determines canonicality.

### 1.4 Globals and constants

A Constant entity contains its `EntityId` and one S20-210-valid persistable
`ConstValue`. A GlobalValue contains its `EntityId`, exact closed persistable
type, initializer Constant identity, and visibility. The initializer value
type must equal the global type. These records implement the already-frozen
SSMC1 kind-9/kind-10 bodies only; globals are immutable and never ambient.

### 1.5 Contract resource limits

Supported contract kinds require `resource_limits=None`. `ResourceCeiling` and
every nonempty contract resource-limit record fail as unsupported because the
epoch-1 binding union has no resource-evidence source. The checker never treats
zero as unlimited or silently ignores a supplied ceiling.

### 1.6 Attachments and invariants

Every Function's raw-ID-sorted `contracts` set must exactly equal the supplied
supported Contract identities whose `target` is that function. Missing,
surplus, duplicate, unsorted, or cross-target attachments fail.

Every TypeDefinition `invariants` set must be empty. The schema has no
`ContractSource::Value`, so nonempty TypeDef invariants are explicitly
unsupported in epoch 1.

## 2. Contract assertion opcode

After all contracts validate, `contract_assert` is supported with these exact
rules:

- immediate is `Entity(contract)` and resolves to one supported Contract;
- enclosing function equals `contract.target`;
- operands equal the predicate parameters in exact order and type;
- there is exactly one result of
  `Result<Unit,BuiltinFailure(ContractViolation)>`.

The operation is statically typed only. S20-270 owns predicate execution and
S20-290 owns report evidence. No assertion is assumed true during checking.

## 3. Restricted test cases

### 3.1 Target and inputs

A TestCase targets exactly one zero-type-parameter Function. The target's exact
S20-230 least effect closure must be empty. Inputs are S20-210-valid persistable
constants whose count/order/types exactly match the target parameters.

### 3.2 Effect environment

The only accepted environment is exactly `Replay([])`. Nonempty replay and all
`DeterministicAdapters` configurations fail. This restriction is required
because epoch 1 has no replay scope/cursor semantics and `AdapterImport` has no
configuration type. S20-280/S20-290 or a later schema epoch must define those
before effectful tests can pass.

### 3.3 Expected outcome

`ExpectedOutcome::Value(value)` requires one S20-210-valid persistable constant
whose type exactly equals the target result type.

`ExpectedOutcome::FailureCode(code)` accepts only `1..=4`, the exact frozen
`TrapCode` tags (`Unreachable`, `ResourceExhausted`,
`AdapterContractViolation`, `InternalInvariant`). No validation, VM,
cancellation, host, or future failure namespace is inferred from `UInt32`.

### 3.4 Observations and `test_observe`

Expected observations must be empty, and `test_observe` is rejected in every
supplied function. Epoch 1 freezes its structural tag but does not define
execution multiplicity, path ordering, or report matching. The checker does
not pretend an observation oracle exists.

### 3.5 Test resource limits

All six required `u64` limits (`fuel`, `memory_bytes`, `output_bytes`,
`effect_count`, `call_depth`, `wall_timeout_millis`) are retained exactly.
Zero means a literal zero budget, never unlimited. S20-240 validates presence
and representation only; S20-270/S20-290 own enforcement and evidence.

## 4. Deterministic provisional selection

Test planning receives:

- the complete raw-ID-sorted TestCase set for the selected root;
- a raw-ID-sorted unique set of affected Function identities;
- a raw-ID-sorted unique set of externally required TestCase identities.

Every affected function and required test must resolve in the same closed
request. The selected test set is the raw-ID-sorted union of:

- every TestCase whose target is in `affected_functions`;
- every explicitly required test.

The output carries `POLICY_INCOMPLETE`: required-test identities are caller
input, not authenticated S20-370 policy. This plan is deterministic and usable
for local analysis, but it is not a final candidate-validation test plan and
cannot authorize commit. S20-370/S20-360 must reselect under the protected
policy root.

## 5. Validation request and order

One closed request supplies the S20-230 function/effect program plus complete
raw-ID-sorted sets of TypeDefinitions, Constants, GlobalValues, Contracts, and
TestCases. Entity identities are globally distinct. Lookup never falls back to
another root, cache, label, path, repository, host, or latest version.
The TypeDefinition identity set must exactly equal the selected S20-210
`TypeEnvironment` inventory; an omitted definition cannot hide a nonempty
invariant set.

Deterministic first-failure order:

1. closed request counts, identities, and raw-ID input sets;
2. preserved S20-210/S20-220/S20-230 judgment for all functions/effects;
3. Constant and GlobalValue type/initializer judgment;
4. TypeDef invariant-profile boundary;
5. Contract kind, target, predicate, resource, and binding judgment in raw-ID
   Contract order;
6. exact Function contract-attachment comparison in raw-ID Function order;
7. `contract_assert` typing in function/block/ordinal order;
8. global `test_observe` rejection;
9. TestCase target/input/environment/outcome/observation judgment in raw-ID
   TestCase order;
10. provisional selection input and raw-ID output construction.

The checker returns the first failure and leaves every input immutable.

## 6. Limits

| Limit | Maximum |
|---|---:|
| TypeDefinitions | 65,535 |
| Constants | 65,535 |
| GlobalValues | 65,535 |
| Contracts | 65,535 |
| TestCases | 65,535 |
| predicate bindings per Contract | 65,535 |
| total predicate bindings | 1,000,000 |
| inputs per TestCase | 65,535 |
| total test inputs | 1,000,000 |
| Function contract attachments | 65,535 |
| total contract attachments | 1,000,000 |
| affected functions | 65,535 |
| externally required tests | 65,535 |
| selected tests | 65,535 |
| charged contract/test lookup and comparison work | 50,000,000 |

S20-230's stricter function/operation/closure limits also apply. Checked
arithmetic, allocation bounds, and work charging fail closed.

## 7. Stable failures

| Numeric | Symbolic code |
|---:|---|
| 24000 | `CONTRACT_UNRESOLVED_ENTITY` |
| 24001 | `CONTRACT_WRONG_ENTITY_KIND` |
| 24002 | `CONTRACT_SET_NOT_CANONICAL` |
| 24003 | `CONTRACT_INVARIANT_UNSUPPORTED` |
| 24004 | `CONTRACT_KIND_UNSUPPORTED` |
| 24005 | `CONTRACT_TARGET_INVALID` |
| 24006 | `CONTRACT_PREDICATE_INVALID` |
| 24007 | `CONTRACT_BINDING_INVALID` |
| 24008 | `CONTRACT_ATTACHMENT_MISMATCH` |
| 24009 | `CONTRACT_ASSERT_TYPE` |
| 24010 | `TEST_PLAN_TARGET_INVALID` |
| 24011 | `TEST_PLAN_INPUT_TYPE` |
| 24012 | `TEST_PLAN_EFFECT_ENVIRONMENT_UNSUPPORTED` |
| 24013 | `TEST_PLAN_EXPECTED_TYPE` |
| 24014 | `TEST_PLAN_FAILURE_CODE_INVALID` |
| 24015 | `TEST_PLAN_OBSERVATION_UNSUPPORTED` |
| 24016 | `TEST_PLAN_SELECTION_INVALID` |
| 24017 | `CONTRACT_TEST_PLAN_RESOURCE_LIMIT` |

Malformed Constant/Global/function types and prior function graph/effect
failures preserve their exact `TYPE_*`, `GRAPH_*`/`CFG_*`, or `EFFECT_*` code.
The S20-240 codes apply only after earlier judgment succeeds.
`TEST_PLAN_*` is the static entity/selection namespace; runtime execution,
determinism, observation, and oracle failures retain the reserved `TEST_*`
namespace owned by S20-270/S20-290.

## 8. Acceptance and explicit gap

- positive fixtures cover precondition, postcondition, error-arm
  postcondition, result predicate, global binding, typed contract assertion,
  pure value/trap tests, and deterministic provisional selection;
- negative fixtures cover every stable code and every explicitly unsupported
  epoch-1 form;
- predicate contract cycles, effectful predicates/targets, ambiguous replay,
  observations, attachment drift, and hostile limits fail without panic;
- input inventory perturbation outside semantic lists gives identical results;
- a seeded unresolved binding/selection smoke corpus terminates;
- independent Ariadne/Vulcan review has no open P0, P1, or P2 finding.

Passing this profile completes only restricted epoch-1 S20-240 entity
validation and provisional planning. Full GA remains blocked on a later schema
epoch for TypeDef invariants, effect/capability/resource contracts, effectful
tests, adapter configuration/replay sequencing, observations, final protected-
policy selection, VM execution, and deterministic test reports.
