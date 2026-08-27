#![allow(unsafe_code)]
#![no_main]

use core::slice;

use sley_check::{TypeEnvironment, cfg::validate_function_graph};
use sley_id::EntityId;
use sley_ssmc::{
    Block, BranchTerminator, BuiltinCase, CaseKey, CondBranchTerminator, Immediate, IntegerWidth,
    Opcode, Operation, OperationResultRef, Parameter, ParameterRole, Reachability,
    ReturnTerminator, SwitchArgument, SwitchCase, SwitchEdge, TargetEdge, Terminator, TrapCode,
    TrapTerminator, TypeExpr, ValueRef, VariantSwitchTerminator, Visibility,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4096;
const TEMPLATE_COUNT: u8 = 4;
const MAX_MUTATIONS: usize = 8;
const MUTATION_COUNT: u8 = 33;

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, len: usize) -> i32 {
    if len == 0 {
        return 0;
    }
    let input = unsafe { slice::from_raw_parts(data, len) };
    fuzz_one(input);
    0
}

fn fuzz_one(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let mut cursor = Cursor::new(input);
    let mut graph = graph_template(cursor.byte() % TEMPLATE_COUNT);
    let mutation_count = cursor.bounded(MAX_MUTATIONS);
    for _ in 0..mutation_count {
        apply_mutation(&mut graph, &mut cursor);
    }

    let types = TypeEnvironment::new(Vec::new()).expect("empty type environment is valid");
    let first = graph.validate(&types);
    let second = graph.validate(&types);
    assert_eq!(first, second, "graph/CFG judgment was not deterministic");
    if mutation_count == 0 {
        assert!(first.is_ok(), "a graph/CFG base template drifted invalid");
    }
}

#[derive(Clone)]
struct GraphCase {
    function: sley_ssmc::FunctionGraph,
    parameters: Vec<Parameter>,
    blocks: Vec<Block>,
    operations: Vec<Operation>,
}

impl GraphCase {
    fn validate(
        &self,
        types: &TypeEnvironment,
    ) -> sley_check::cfg::CfgResult<sley_check::cfg::CfgReport> {
        validate_function_graph(
            types,
            &self.function,
            &self.parameters,
            &self.blocks,
            &self.operations,
        )
    }

    fn known_ids(&self) -> Vec<EntityId> {
        core::iter::once(self.function.entity_id)
            .chain(self.parameters.iter().map(|value| value.entity_id))
            .chain(self.blocks.iter().map(|value| value.entity_id))
            .chain(self.operations.iter().map(|value| value.entity_id))
            .collect()
    }
}

fn graph_template(selector: u8) -> GraphCase {
    match selector {
        0 => return_template(),
        1 => branch_template(),
        2 => conditional_template(),
        3 => operation_template(),
        _ => unreachable!(),
    }
}

fn return_template() -> GraphCase {
    let function = id(1);
    let parameter = id(2);
    let block = id(3);
    GraphCase {
        function: function_body(
            function,
            vec![parameter],
            TypeExpr::Unit,
            block,
            vec![block],
        ),
        parameters: vec![function_parameter(parameter, function, 0, TypeExpr::Unit)],
        blocks: vec![Block {
            entity_id: block,
            function,
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::Parameter(parameter),
            }),
            reachability: Reachability::Required,
        }],
        operations: Vec::new(),
    }
}

fn branch_template() -> GraphCase {
    let function = id(10);
    let input = id(11);
    let entry = id(12);
    let target = id(13);
    let block_parameter_id = id(14);
    GraphCase {
        function: function_body(
            function,
            vec![input],
            TypeExpr::Bool,
            entry,
            vec![entry, target],
        ),
        parameters: vec![
            function_parameter(input, function, 0, TypeExpr::Bool),
            block_parameter(block_parameter_id, target, 0, TypeExpr::Bool),
        ],
        blocks: vec![
            Block {
                entity_id: entry,
                function,
                parameters: Vec::new(),
                operations: Vec::new(),
                terminator: Terminator::Branch(BranchTerminator {
                    edge: TargetEdge {
                        target,
                        arguments: vec![ValueRef::Parameter(input)],
                    },
                }),
                reachability: Reachability::Required,
            },
            Block {
                entity_id: target,
                function,
                parameters: vec![block_parameter_id],
                operations: Vec::new(),
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(block_parameter_id),
                }),
                reachability: Reachability::Required,
            },
        ],
        operations: Vec::new(),
    }
}

fn conditional_template() -> GraphCase {
    let function = id(20);
    let condition = id(21);
    let value = id(22);
    let entry = id(23);
    let target = id(24);
    let block_parameter_id = id(25);
    let edge = TargetEdge {
        target,
        arguments: vec![ValueRef::Parameter(value)],
    };
    GraphCase {
        function: function_body(
            function,
            vec![condition, value],
            TypeExpr::Unit,
            entry,
            vec![entry, target],
        ),
        parameters: vec![
            function_parameter(condition, function, 0, TypeExpr::Bool),
            function_parameter(value, function, 1, TypeExpr::Unit),
            block_parameter(block_parameter_id, target, 0, TypeExpr::Unit),
        ],
        blocks: vec![
            Block {
                entity_id: entry,
                function,
                parameters: Vec::new(),
                operations: Vec::new(),
                terminator: Terminator::CondBranch(CondBranchTerminator {
                    condition: ValueRef::Parameter(condition),
                    if_true: edge.clone(),
                    if_false: edge,
                }),
                reachability: Reachability::Required,
            },
            Block {
                entity_id: target,
                function,
                parameters: vec![block_parameter_id],
                operations: Vec::new(),
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(block_parameter_id),
                }),
                reachability: Reachability::Required,
            },
        ],
        operations: Vec::new(),
    }
}

fn operation_template() -> GraphCase {
    let function = id(30);
    let block = id(31);
    let operation = id(32);
    GraphCase {
        function: function_body(function, Vec::new(), TypeExpr::Bool, block, vec![block]),
        parameters: Vec::new(),
        blocks: vec![Block {
            entity_id: block,
            function,
            parameters: Vec::new(),
            operations: vec![operation],
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::OperationResult(OperationResultRef {
                    operation,
                    result_index: 0,
                }),
            }),
            reachability: Reachability::Required,
        }],
        operations: vec![Operation {
            entity_id: operation,
            block,
            ordinal: 0,
            opcode: Opcode::ConstantRef,
            operands: Vec::new(),
            result_types: vec![TypeExpr::Bool],
            immediate: Immediate::Entity(id(900)),
        }],
    }
}

fn function_body(
    entity_id: EntityId,
    parameters: Vec<EntityId>,
    result_type: TypeExpr,
    entry_block: EntityId,
    blocks: Vec<EntityId>,
) -> sley_ssmc::FunctionGraph {
    sley_ssmc::FunctionGraph {
        entity_id,
        type_parameters: Vec::new(),
        parameters,
        result_type,
        effects: Vec::new(),
        entry_block,
        blocks,
        contracts: Vec::new(),
        visibility: Visibility::Private,
    }
}

fn function_parameter(
    entity_id: EntityId,
    owner: EntityId,
    ordinal: u32,
    value_type: TypeExpr,
) -> Parameter {
    Parameter {
        entity_id,
        owner,
        role: ParameterRole::Function,
        ordinal,
        value_type,
    }
}

fn block_parameter(
    entity_id: EntityId,
    owner: EntityId,
    ordinal: u32,
    value_type: TypeExpr,
) -> Parameter {
    Parameter {
        entity_id,
        owner,
        role: ParameterRole::Block,
        ordinal,
        value_type,
    }
}

fn apply_mutation(graph: &mut GraphCase, cursor: &mut Cursor<'_>) {
    let known_ids = graph.known_ids();
    match cursor.byte() % MUTATION_COUNT {
        0 => graph.function.entity_id = selected_id(&known_ids, cursor),
        1 => graph
            .function
            .parameters
            .push(selected_id(&known_ids, cursor)),
        2 => graph.function.parameters.reverse(),
        3 => graph.function.result_type = small_type(cursor),
        4 => graph.function.entry_block = selected_id(&known_ids, cursor),
        5 => graph.function.blocks.push(selected_id(&known_ids, cursor)),
        6 => graph.function.blocks.reverse(),
        7 => graph.function.effects = id_list(&known_ids, cursor),
        8 => graph.function.contracts = id_list(&known_ids, cursor),
        9 => {
            if let Some(parameter) = selected_mut(&mut graph.parameters, cursor) {
                parameter.entity_id = selected_id(&known_ids, cursor);
            }
        }
        10 => {
            if let Some(parameter) = selected_mut(&mut graph.parameters, cursor) {
                parameter.owner = selected_id(&known_ids, cursor);
            }
        }
        11 => {
            if let Some(parameter) = selected_mut(&mut graph.parameters, cursor) {
                parameter.role = match parameter.role {
                    ParameterRole::Function => ParameterRole::Block,
                    ParameterRole::Block => ParameterRole::Function,
                };
            }
        }
        12 => {
            if let Some(parameter) = selected_mut(&mut graph.parameters, cursor) {
                parameter.ordinal = cursor.u32();
            }
        }
        13 => {
            if let Some(parameter) = selected_mut(&mut graph.parameters, cursor) {
                parameter.value_type = small_type(cursor);
            }
        }
        14 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.entity_id = selected_id(&known_ids, cursor);
            }
        }
        15 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.function = selected_id(&known_ids, cursor);
            }
        }
        16 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.parameters.push(selected_id(&known_ids, cursor));
            }
        }
        17 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.operations.push(selected_id(&known_ids, cursor));
            }
        }
        18 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.reachability = match block.reachability {
                    Reachability::Required => Reachability::ExplicitlyUnreachable,
                    Reachability::ExplicitlyUnreachable => Reachability::Required,
                };
            }
        }
        19 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.terminator = Terminator::Return(ReturnTerminator {
                    value: value_ref(&known_ids, cursor),
                });
            }
        }
        20 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.terminator = Terminator::Branch(BranchTerminator {
                    edge: target_edge(&known_ids, cursor),
                });
            }
        }
        21 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.terminator = Terminator::CondBranch(CondBranchTerminator {
                    condition: value_ref(&known_ids, cursor),
                    if_true: target_edge(&known_ids, cursor),
                    if_false: target_edge(&known_ids, cursor),
                });
            }
        }
        22 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.terminator = Terminator::Trap(TrapTerminator {
                    code: trap_code(cursor.byte()),
                    payload: cursor
                        .byte()
                        .is_multiple_of(2)
                        .then(|| value_ref(&known_ids, cursor)),
                });
            }
        }
        23 => {
            if let Some(operation) = selected_mut(&mut graph.operations, cursor) {
                operation.entity_id = selected_id(&known_ids, cursor);
            }
        }
        24 => {
            if let Some(operation) = selected_mut(&mut graph.operations, cursor) {
                operation.block = selected_id(&known_ids, cursor);
            }
        }
        25 => {
            if let Some(operation) = selected_mut(&mut graph.operations, cursor) {
                operation.ordinal = cursor.u32();
            }
        }
        26 => {
            if let Some(operation) = selected_mut(&mut graph.operations, cursor) {
                operation.operands.push(value_ref(&known_ids, cursor));
            }
        }
        27 => {
            if let Some(operation) = selected_mut(&mut graph.operations, cursor) {
                operation.result_types.push(small_type(cursor));
            }
        }
        28 => {
            if let Some(parameter) = graph
                .parameters
                .get(cursor.index(graph.parameters.len()))
                .cloned()
            {
                graph.parameters.push(parameter);
            }
        }
        29 => {
            if let Some(block) = graph.blocks.get(cursor.index(graph.blocks.len())).cloned() {
                graph.blocks.push(block);
            }
        }
        30 => {
            if let Some(operation) = graph
                .operations
                .get(cursor.index(graph.operations.len()))
                .cloned()
            {
                graph.operations.push(operation);
            }
        }
        31 => graph.operations.reverse(),
        32 => {
            if let Some(block) = selected_mut(&mut graph.blocks, cursor) {
                block.terminator = variant_switch(&known_ids, cursor);
            }
        }
        _ => unreachable!(),
    }
}

fn selected_mut<'a, T>(values: &'a mut [T], cursor: &mut Cursor<'_>) -> Option<&'a mut T> {
    let index = cursor.index(values.len());
    values.get_mut(index)
}

fn selected_id(known_ids: &[EntityId], cursor: &mut Cursor<'_>) -> EntityId {
    if !known_ids.is_empty() && cursor.byte().is_multiple_of(2) {
        known_ids[cursor.index(known_ids.len())]
    } else {
        id(cursor.u32())
    }
}

fn id_list(known_ids: &[EntityId], cursor: &mut Cursor<'_>) -> Vec<EntityId> {
    (0..cursor.bounded(4))
        .map(|_| selected_id(known_ids, cursor))
        .collect()
}

fn target_edge(known_ids: &[EntityId], cursor: &mut Cursor<'_>) -> TargetEdge {
    TargetEdge {
        target: selected_id(known_ids, cursor),
        arguments: (0..cursor.bounded(3))
            .map(|_| value_ref(known_ids, cursor))
            .collect(),
    }
}

fn value_ref(known_ids: &[EntityId], cursor: &mut Cursor<'_>) -> ValueRef {
    if cursor.byte().is_multiple_of(2) {
        ValueRef::Parameter(selected_id(known_ids, cursor))
    } else {
        ValueRef::OperationResult(OperationResultRef {
            operation: selected_id(known_ids, cursor),
            result_index: u32::from(cursor.byte() % 4),
        })
    }
}

fn variant_switch(known_ids: &[EntityId], cursor: &mut Cursor<'_>) -> Terminator {
    let cases = (0..cursor.bounded(4))
        .map(|_| SwitchCase {
            case_key: CaseKey::Builtin(match cursor.byte() % 4 {
                0 => BuiltinCase::None,
                1 => BuiltinCase::Some,
                2 => BuiltinCase::Ok,
                3 => BuiltinCase::Err,
                _ => unreachable!(),
            }),
            edge: SwitchEdge {
                target: selected_id(known_ids, cursor),
                arguments: (0..cursor.bounded(3))
                    .map(|_| {
                        if cursor.byte().is_multiple_of(2) {
                            SwitchArgument::Value(value_ref(known_ids, cursor))
                        } else {
                            SwitchArgument::CasePayload
                        }
                    })
                    .collect(),
            },
        })
        .collect();
    Terminator::VariantSwitch(VariantSwitchTerminator {
        value: value_ref(known_ids, cursor),
        cases,
    })
}

fn small_type(cursor: &mut Cursor<'_>) -> TypeExpr {
    match cursor.byte() % 8 {
        0 => TypeExpr::Unit,
        1 => TypeExpr::Bool,
        2 => TypeExpr::SInt(IntegerWidth::from_bits(8)),
        3 => TypeExpr::UInt(IntegerWidth::from_bits(64)),
        4 => TypeExpr::Option(Box::new(TypeExpr::Bool)),
        5 => TypeExpr::Result {
            ok: Box::new(TypeExpr::Unit),
            error: Box::new(TypeExpr::BuiltinFailure(
                sley_ssmc::BuiltinFailureKind::Arithmetic,
            )),
        },
        6 => TypeExpr::TypeParameter(u32::from(cursor.byte() % 4)),
        7 => TypeExpr::AdapterHandle(id(cursor.u32())),
        _ => unreachable!(),
    }
}

fn trap_code(value: u8) -> TrapCode {
    match value % 4 {
        0 => TrapCode::Unreachable,
        1 => TrapCode::ResourceExhausted,
        2 => TrapCode::AdapterContractViolation,
        3 => TrapCode::InternalInvariant,
        _ => unreachable!(),
    }
}

fn id(value: u32) -> EntityId {
    let mut bytes = [0_u8; 32];
    for (offset, chunk) in bytes.chunks_exact_mut(4).enumerate() {
        let mixed = value.wrapping_add(u32::try_from(offset).unwrap_or(0));
        chunk.copy_from_slice(&mixed.to_be_bytes());
    }
    EntityId::from_bytes(bytes)
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.input[self.offset % self.input.len()];
        self.offset = self.offset.wrapping_add(1);
        value
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    fn bounded(&mut self, maximum: usize) -> usize {
        usize::from(self.byte()) % (maximum + 1)
    }

    fn index(&mut self, length: usize) -> usize {
        if length == 0 {
            0
        } else {
            usize::from(self.byte()) % length
        }
    }
}
