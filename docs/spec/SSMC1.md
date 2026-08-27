# Sley Semantic Machine Code v1 (SSMC1)

Status: M0 normative draft; entity and opcode numbers are not frozen.

SSMC1 is the canonical language and semantic graph. It is not source, a syntax
tree, debug text, CPU code, Wasm, or arbitrary bytes. Normal lifecycle actions
must never generate or consume Sley source text.

## Entities

The first epoch defines distinct `Workspace`, `Package`, `Namespace`,
`TypeDef`, `Function`, `Parameter`, `Block`, `Operation`, `Constant`,
`GlobalValue`, `EffectDef`, `CapabilityRequirement`, `Contract`, `TestCase`,
`AdapterImport`, `EntryPoint`, `PolicyBinding`, and `DependencyBinding`
entities. Each logical entity has a stable `EntityId`; each version is an
immutable object addressed by `ObjectId`. Labels are optional normalized
metadata and never identity.

## Functions and control flow

A function binds ordered parameters, explicit result and error types, explicit
effects, contracts, entry block, and a block graph. Blocks have typed
parameters. Every block ends in `return`, unconditional branch, conditional
branch, variant switch, or typed trap. Loops are backedges. The checker rejects
missing terminators, target argument mismatch, use-before-definition,
dominance failure, invalid reachability, and malformed cycles.

## Operations

Epoch 1 reserves typed operation families for constants; tuple, record,
variant, vector, and ordered-map construction and projection; explicit-failure
collection access; integer and deterministic floating arithmetic; comparisons
and booleans; direct function calls; contract assertions; effect requests;
typed adapter invocation; capability narrowing; test observations; local cells;
and defined value hashing. There are no hidden exceptions or untyped calls.

## Effects

Every effect operation names an effect kind and resource scope. The initial
profile includes stdout/stderr capture, confined file read/write, deterministic
clock/randomness, explicit environment lookup, and typed replayed adapter call.
Network, process, secret, deployment, and spend effects are not GA requirements.
Static effect validity is distinct from runtime capability.

## Contracts and tests

Contracts and tests are canonical entities. Tests bind target, canonical input,
deterministic adapters or replay, expected value or failure, observations, and
resource ceilings. Contract predicates are typed SSMC facts, not prose.

## Fingerprints

Semantic fingerprints ignore labels, object layout, cache state, repository
ancestry, debug metadata, and optimization. The exact fingerprint inputs and
domain separator are frozen with the epoch and serve search and impact
analysis; they do not replace `ObjectId` or `StateRoot`.

## Explicit exclusions

No classes, inheritance, implicit dispatch, reflection, eval, macros, textual
preprocessing, hidden exceptions, ambient globals, raw pointers, dynamic
imports, unrestricted metaprogramming, or source locations as identity.
