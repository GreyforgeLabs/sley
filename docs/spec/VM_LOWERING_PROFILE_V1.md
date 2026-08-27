# VM Lowering Profile v1

Status: S20-260 restricted epoch-1 normative specification.

This contract freezes deterministic lowering from a successful S20-210/S20-220
Function CFG judgment into derived register bytecode. It is an `O0-restricted-v1`
profile, not full S20-260 GA and not VM execution.

The restriction is necessary because S20-210 and S20-220 validate types, graph
inventory, CFG, and value uses but explicitly do not validate the complete
semantic signatures of all 55 opcodes. This profile supports all five frozen
terminators and exactly `bool_not` (102), `bool_and` (103), and `bool_or` (104).
Every other opcode fails with `VM_LOWER_OPCODE_UNSUPPORTED`; no runtime meaning
is assigned by copying an unvalidated tag.

## 1. Accepted Function profile

The lowering request contains one `FunctionGraph`, its complete Parameter,
Block, and Operation inventories, the selected `TypeEnvironment`, exact
`StateRoot`, and exact `SchemaEpochId`. It first preserves the complete
S20-210/S20-220 result from `validate_function_graph`.

The Function must have:

- zero type parameters and therefore no entry type arguments;
- an empty declared effect set;
- an empty Contract attachment set;
- only the three supported Boolean operations;
- `Immediate::None` on every supported operation;
- exact Boolean signatures: `bool_not` is `(Bool)->Bool`; `bool_and` and
  `bool_or` are `(Bool,Bool)->Bool`;
- no implicit coercion, specialization, optimization, or external lookup.

All five terminators retain their successful S20-220 meaning. Required and
explicitly-unreachable blocks are both preserved in Function block-list order.

## 2. O0 derived bytecode

Bytecode is derived, disposable evidence. It is not SSMC1, SCB1 canonical
state, an ObjectId, a StateRoot, a repository object, or architecture code.

```text
BytecodeFunction {
  function: EntityId,
  parameter_registers: List<Register>,
  register_types: List<TypeExpr>,
  result_type: TypeExpr,
  entry_block: BlockSlot,
  blocks: List<BytecodeBlock>
}

BytecodeBlock {
  slot: BlockSlot,
  parameter_registers: List<Register>,
  instructions: List<Instruction>,
  terminator: BytecodeTerminator,
  reachability: Reachability
}

Instruction {
  opcode: 102 | 103 | 104,
  operands: List<Register>,
  results: List<Register>
}
```

Dense registers are assigned deterministically:

1. Function parameters in `Function.parameters` order;
2. for every block in `Function.blocks` order, its parameters in list order;
3. then that block's Operation results in Operation order and result order.

Block slots are positions in `Function.blocks`. Value references and
terminator targets are rewritten to registers and block slots. No local
Parameter, Block, or Operation EntityId enters the derived instruction stream.
`register_types` is parallel to the complete dense register space and records
each Function parameter, Block parameter, and Operation result type at its
assigned register.

Return, branch, conditional branch, variant switch, and trap retain exact
argument order, case order, case-payload markers, trap code, and optional
payload. O0 performs no folding, dead-code removal, branch simplification,
inlining, monomorphization, register coalescing, block reordering, or semantic
rewrite.

### 2.1 Canonical byte encoding

The bytecode artifact uses fixed big-endian primitives. `u32`, `u64`, and
fixed-32 values are exact-width; a list is `u64be(count) || item...`; an option
is `u32be(1)` for none or `u32be(2) || item` for some. `TypeExpr` uses Appendix
A of `FINGERPRINT_IMPACT_PROFILE_V1.md`, with every entity reference encoded as
`u32be(1) || EntityId` because bytecode has no self-reference abbreviation.

```text
bytecode =
  "SLEYBC01" || u32be(format_version=1) ||
  function_EntityId[32] ||
  list(u32be, parameter_registers) ||
  list(type_expr, register_types) ||
  type_expr(result_type) ||
  u32be(entry_block_slot) ||
  list(block, blocks)

block =
  u32be(slot) ||
  list(u32be, parameter_registers) ||
  list(instruction, instructions) ||
  terminator ||
  u32be(reachability_tag)

instruction =
  u32be(opcode_tag) ||
  list(u32be, operand_registers) ||
  list(u32be, result_registers)

target_edge = u32be(target_block_slot) || list(u32be, argument_registers)
switch_argument(Value) = u32be(1) || u32be(register)
switch_argument(CasePayload) = u32be(2)
switch_edge = u32be(target_block_slot) || list(switch_argument, arguments)
case_key(Member) = u32be(1) || MemberId[32]
case_key(Builtin) = u32be(2) || u32be(builtin_case_tag)

terminator(Return) = u32be(1) || u32be(value_register)
terminator(Branch) = u32be(2) || target_edge
terminator(CondBranch) =
  u32be(3) || u32be(condition_register) || true_edge || false_edge
terminator(VariantSwitch) =
  u32be(4) || u32be(value_register) ||
  list(case_key || switch_edge, cases)
terminator(Trap) =
  u32be(5) || u32be(trap_code_tag) || option(u32be, payload_register)
```

The artifact contains no cache key, label, ObjectId, source/path/debug data,
host layout, padding, or trailing bytes. Decoder implementation and execution
remain S20-270 work; S20-260 freezes and tests encoder bytes only.

## 3. Exact cache key

ADR-0008 registers the dedicated hash domain
`sley2.vm-bytecode-cache-key.v1` and opaque `BytecodeCacheKey` type.

```text
cache_preimage =
  "SLEYBCK1" ||
  u32be(profile_version=1) ||
  SchemaEpochId[32] ||
  ssmc1_field_schema_hash[32] ||
  ssmc1_decoder_limits_hash[32] ||
  StateRoot[32] ||
  entry_Function_EntityId[32] ||
  u32be(vm_major=1) || u32be(vm_minor=0) || u32be(vm_patch=0) ||
  u32be(lowering_profile=1) ||
  u32be(lowerer_major=1) || u32be(lowerer_minor=0) ||
  u32be(lowerer_patch=0) ||
  u64be(entry_type_argument_count=0) ||
  u64be(adapter_abi_entry_count=0) ||
  u64be(execution_abi_flags=0)

BytecodeCacheKey =
  BLAKE3-256("sley2.vm-bytecode-cache-key.v1" || cache_preimage)
```

The field-schema hash is
`044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73`.
The decoder-limits hash is
`389791b170bc9d8575f7e6f338e4f9e9f2b75f35d7a2e52c7cb106cb2cd6136a`.
The empty generic/adapter/flag fields are encoded, not omitted. Later profiles
must change the lowering profile and preimage rules before accepting them.

The cache key selects derived bytes only. A cache hit never substitutes for
schema/type/CFG validation, root binding, capability judgment, or execution.

## 4. Deterministic order and limits

Input inventory slice order is irrelevant; semantic lists define output order.
Repeated lowering produces equal bytecode and cache keys.

| Limit | Maximum |
|---|---:|
| blocks | 4,096 |
| operations/instructions | 1,000,000 |
| registers | 1,000,000 |
| operands/results per instruction | 65,535 |
| CFG value uses | 262,144 (preserved S20-220 cap) |
| CFG edges | 16,384 (preserved S20-220 cap) |
| dominator work | 50,000,000 |
| lowering work | 100,000,000 |
| encoded bytecode artifact | 67,108,864 bytes |

Counts and checked arithmetic are enforced before allocation or append.
Lowering charges one unit per inventory entity, register assignment, value
rewrite, instruction, switch case, edge argument, and emitted terminator.
Exhaustion returns no partial successful bytecode or cache key.

## 5. Deterministic validation order

The integrated lowering API returns the first failure in this exact order:

1. preserved S20-210/S20-220 `TYPE_*`, `GRAPH_*`, or `CFG_*` failure from
   `validate_function_graph`;
2. unsupported requested VM/lowerer/profile version, entry type arguments,
   adapter ABI entries, or execution ABI flags (`VM_LOWER_CACHE_KEY_UNSUPPORTED`);
3. nonzero Function type parameters or nonempty effects/contracts
   (`VM_LOWER_PROFILE_UNSUPPORTED`);
4. lowering count/work/resource preflight (`VM_LOWER_RESOURCE_LIMIT`);
5. each Operation in Function block-list and Operation-list order: unsupported
   opcode, then non-None immediate, then operand/result Boolean signature;
6. deterministic local register/block rewrite; an impossible missing local
   after successful prior validation is `VM_LOWER_LOCAL_REFERENCE_INVALID`;
7. canonical artifact/cache preimage size/work preflight and encoding.

The canonical byte encoder is private to the integrated lowering path. There is
no public constructor for unvalidated `BytecodeFunction` bytes and no second
competing semantic judgment.

## 6. Stable failures

| Numeric | Symbolic code |
|---:|---|
| 26000 | `VM_LOWER_PROFILE_UNSUPPORTED` |
| 26001 | `VM_LOWER_OPCODE_UNSUPPORTED` |
| 26002 | `VM_LOWER_SIGNATURE_MISMATCH` |
| 26003 | `VM_LOWER_IMMEDIATE_MISMATCH` |
| 26004 | `VM_LOWER_LOCAL_REFERENCE_INVALID` |
| 26005 | `VM_LOWER_CACHE_KEY_UNSUPPORTED` |
| 26006 | `VM_LOWER_RESOURCE_LIMIT` |

Earlier `TYPE_*`, `GRAPH_*`, and `CFG_*` failures are preserved exactly by the
integrated lowering result. The integrated derived-bytecode path owns only the
seven `VM_LOWER_*` failures above.

## 7. Acceptance and explicit gaps

- fixed vectors freeze the cache preimage/key and one lowered Function;
- all five terminators and three Boolean instructions have positive fixtures;
- every other opcode, generic/effect/contract Function, and non-None immediate
  fails closed;
- local EntityId and inventory-slice perturbation preserves bytecode/key;
- semantic order/type/opcode/terminator changes alter bytecode;
- at least 128 repeated/perturbed requests are deterministic;
- strict limits and malformed local references terminate without panic;
- independent review has no open P0/P1/P2.

Full S20-260 GA remains blocked on complete semantic signature judgment for the
other 52 opcodes, generic entry arguments, adapter ABI sets, execution ABI
flags, and complete-root module lowering. S20-270 execution is not claimed.
