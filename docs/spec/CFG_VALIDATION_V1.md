# CFG and Value-Use Validation v1

Status: S20-220 normative specification.

## 1. Scope and phase boundary

S20-220 validates one already S20-200-structured, S20-210-typed function graph.
It owns exact function/block/parameter/operation inventory, ownership and
ordinals, same-function edges, terminator edge types, value resolution,
same-block definition order, cross-block dominance, reachability policy, and
bounded handling of legal loops.

It does not reinterpret the 55 opcode semantic signatures, grant effects or
capabilities, judge contracts/tests, compute fingerprints, lower bytecode,
execute a VM, construct repository state, or commit a candidate. In the full
pipeline, opcode/type judgment precedes this CFG phase and a later failure
cannot turn an earlier type failure into success.

## 2. Closed graph input

The shared `sley-ssmc` model implements the exact S20-200 records for:

- `FunctionGraph`: function identity, declaration parameter count, ordered
  function parameters, result type, entry block, and ordered blocks;
- `Parameter`: identity, owner, function/block role, ordinal, and type;
- `Block`: identity, owning function, ordered parameters, ordered operations,
  one closed terminator, and reachability marker;
- `Operation`: identity, owning block, ordinal, frozen opcode tag, ordered
  operands, ordered result types, and frozen immediate;
- `ValueRef`: parameter identity or operation/result-index pair;
- the five terminators, target/switch edges, switch keys/arguments, and trap
  codes from `SSMC1_EPOCH1_SCHEMA.txt`.

The function identity, every parameter identity, block identity, and operation
identity is distinct. The entry block belongs to the function and occurs
exactly once in `FunctionGraph.blocks`. Every listed block occurs exactly once
in the supplied block inventory; every listed parameter/operation occurs
exactly once in both its owner list and supplied inventory; no unlisted extra
entity is accepted.

Every owner field equals its containing function/block. Every ordinal is the
zero-based position in the owner's ordered list. Every parameter/result type is
well formed under the function's declaration parameter count. Function and
block parameter roles cannot be interchanged.

## 3. Edges and reachability

Every edge target is a listed block in the same function. Required block
reachability is exact:

- the entry is `Required`;
- a block reachable from the entry is `Required`;
- a block not reachable from the entry is
  `ExplicitlyUnreachable`;
- either mismatch is `CFG_REACHABILITY`.

An explicitly unreachable block remains structurally and type valid. Every use
inside it—including operation operands, terminator operands, and switch-edge
arguments—may refer only to function parameters, its own block parameters, and
earlier/own-block operation results. A cross-block operation result is
`CFG_UNREACHABLE_VALUE`. Its outgoing edges are still target/type checked but
do not make their targets reachable.

Loops are legal backedges and are never rejected merely for being cycles.
Reachability and dominance algorithms are iterative and bounded; hostile
cycles cannot recurse, hang, or become success after budget exhaustion.

## 4. Values, uses, and dominance

Function parameters dominate every block. A block parameter is visible only
inside its owning block. An operation result is defined by the operation's
identity and zero-based result index.

Within one block, an operation operand may use only a result whose defining
operation ordinal is lower than the use ordinal. A terminator occurs after all
listed operations and may use any result in its block. A self/later use is
`CFG_USE_BEFORE_DEFINITION`.

Across reachable blocks, an operation result is usable only when its defining
block dominates the use block: every entry-to-use path passes through the
definition block. Backedges do not weaken this rule. Passing a value through a
target block parameter is the canonical phi mechanism.

Missing parameter/operation identities return `CFG_VALUE_UNRESOLVED`; an
invalid result index returns `CFG_RESULT_INDEX`.

## 5. Terminators

- `return` carries one value exactly equal to the function result type.
- `branch` arguments exactly match the target's ordered block parameters.
- `cond_branch` requires `Bool`; both edges independently match targets.
- `trap` may carry no value or one value whose type is persistable.
- `variant_switch` requires a named variant, `Option`, or `Result`.

Named-variant switch keys are `Member(MemberId)` only. `Option` uses exactly
`Builtin(None)` and `Builtin(Some)`; `Result` uses exactly
`Builtin(Ok)` and `Builtin(Err)`. Cases are strictly ordered by their
canonical case-key order, duplicate-free, exhaustive, and have no default.
`CasePayload` is legal only for a payload-bearing selected case and has that
case's exact instantiated type when matched against the target parameter.
Every ordinary switch argument is resolved at the source-block terminator.

## 6. Exact resource contract

The validator applies the stricter S20-220 request profile:

| Limit | Maximum |
|---|---:|
| blocks per function | 4,096 |
| CFG edges, including each switch case | 16,384 |
| parameters per function or block | 65,535 |
| operations per function | 1,000,000 |
| operands or results per operation | 65,535 |
| total parameters plus operation results | 1,000,000 |
| total operation/terminator value uses | 262,144 |
| dominator bitset word operations | 50,000,000 |
| dominance convergence rounds | 4,096 |

Counts and inventory limits are checked before graph traversal. Each branch is
one edge, conditional branch two, and each switch case one. Dominator work is
charged once per predecessor-bitset word intersection/comparison. Exceeding
any limit returns `CFG_RESOURCE_LIMIT`; partial reachability/dominance state is
discarded and never reported as valid.

The iterative dominator result is independent of input map construction order.
Function/block declared order controls deterministic diagnostic precedence.

## 7. Stable failures

| Numeric | Symbolic code |
|---:|---|
| 22000 | `GRAPH_DUPLICATE_ENTITY` |
| 22001 | `GRAPH_INVENTORY_MISMATCH` |
| 22002 | `GRAPH_OWNER_MISMATCH` |
| 22003 | `GRAPH_ORDINAL_MISMATCH` |
| 22004 | `GRAPH_UNRESOLVED_REFERENCE` |
| 22005 | `CFG_ENTRY_INVALID` |
| 22006 | `CFG_TARGET_INVALID` |
| 22007 | `CFG_TARGET_ARGUMENTS` |
| 22008 | `CFG_RETURN_TYPE` |
| 22009 | `CFG_BOOL_REQUIRED` |
| 22010 | `CFG_SWITCH_TYPE` |
| 22011 | `CFG_SWITCH_CASES` |
| 22012 | `CFG_SWITCH_PAYLOAD` |
| 22013 | `CFG_VALUE_UNRESOLVED` |
| 22014 | `CFG_RESULT_INDEX` |
| 22015 | `CFG_USE_BEFORE_DEFINITION` |
| 22016 | `CFG_DOMINANCE` |
| 22017 | `CFG_REACHABILITY` |
| 22018 | `CFG_UNREACHABLE_VALUE` |
| 22019 | `CFG_TRAP_PAYLOAD` |
| 22020 | `CFG_RESOURCE_LIMIT` |

Earlier `SSMC_*` and `TYPE_*` failures retain their phase and code; the CFG
validator does not collapse them into success or invent a corrected type.

## 8. Deterministic validation order

1. closed count limits and duplicate identities;
2. exact inventory, owner, role, and ordinal agreement;
3. parameter/result type well-formedness;
4. entry, target, and edge-count structure;
5. reachability marker agreement;
6. bounded dominator construction;
7. operation operands in block/ordinal order;
8. terminators and switch-key/payload judgment in function block order.

The first failure in this order is returned. Unknown, ambiguity, internal
failure, or resource exhaustion is never a valid graph.

## 9. S20-220 acceptance

- positive fixtures cover straight-line, branch, conditional, switch, and
  loop/backedge functions;
- negative fixtures cover every stable code, owner/ordinal/inventory mismatch,
  bad target args, unreachable markers, unresolved/result-index uses,
  use-before-definition, dominance, switch domain/order/exhaustiveness/payload,
  and nonpersistable traps;
- hostile cyclic/pathological graphs terminate under the exact work limit;
- insertion-order perturbation produces the same result;
- focused unit/property tests, fuzz-smoke seeds, and strict lint pass;
- no opcode, effect, contract, fingerprint, VM, source, repository, or commit
  completion is claimed.
