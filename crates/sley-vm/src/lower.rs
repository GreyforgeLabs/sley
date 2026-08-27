//! Restricted S20-260 O0 register lowering and canonical byte encoding.

use core::fmt;
use std::collections::BTreeMap;

use sley_check::{
    TypeEnvironment,
    cfg::{CfgValidationError, validate_function_graph},
};
use sley_id::{BytecodeCacheKey, EntityId};
use sley_ssmc::{
    Block, CaseKey, FunctionGraph, Immediate, Opcode, Operation, Parameter, SwitchArgument,
    Terminator, TypeExpr, ValueRef,
};

use crate::{CacheProfile, LowerError, LowerErrorCode, derive_cache_key};

/// Dense bytecode register.
pub type Register = u32;
/// Dense bytecode block slot.
pub type BlockSlot = u32;
/// Maximum registers in one lowered Function.
pub const MAX_REGISTERS: usize = 1_000_000;
/// Maximum blocks in one lowered Function.
pub const MAX_LOWERED_BLOCKS: usize = 4_096;
/// Maximum instructions in one lowered Function.
pub const MAX_INSTRUCTIONS: usize = 1_000_000;
/// Maximum operands or results on one instruction.
pub const MAX_INSTRUCTION_VALUES: usize = 65_535;
/// Maximum lowering work units.
pub const MAX_LOWERING_WORK: u64 = 100_000_000;
/// Maximum encoded derived bytecode bytes.
pub const MAX_BYTECODE_BYTES: usize = 67_108_864;

/// One restricted Boolean instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    /// Frozen SSMC opcode tag.
    pub opcode: u32,
    /// Ordered source registers.
    pub operands: Vec<Register>,
    /// Ordered result registers.
    pub results: Vec<Register>,
}

/// Ordinary lowered target edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeTargetEdge {
    /// Dense target block slot.
    pub target: BlockSlot,
    /// Ordered argument registers.
    pub arguments: Vec<Register>,
}

/// Lowered switch argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BytecodeSwitchArgument {
    /// Ordinary register value.
    Value(Register),
    /// Selected case payload.
    CasePayload,
}

/// One lowered switch case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeSwitchCase {
    /// Exact frozen case key.
    pub case_key: CaseKey,
    /// Target and arguments.
    pub edge: BytecodeSwitchEdge,
}

/// Lowered switch edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeSwitchEdge {
    /// Dense target block slot.
    pub target: BlockSlot,
    /// Ordered ordinary/case-payload arguments.
    pub arguments: Vec<BytecodeSwitchArgument>,
}

/// Closed lowered terminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BytecodeTerminator {
    /// Return one register.
    Return(Register),
    /// Unconditional branch.
    Branch(BytecodeTargetEdge),
    /// Conditional branch.
    CondBranch {
        /// Boolean condition register.
        condition: Register,
        /// True edge.
        if_true: BytecodeTargetEdge,
        /// False edge.
        if_false: BytecodeTargetEdge,
    },
    /// Exhaustive variant switch.
    VariantSwitch {
        /// Selected register.
        value: Register,
        /// Canonically ordered cases.
        cases: Vec<BytecodeSwitchCase>,
    },
    /// Explicit trap.
    Trap {
        /// Frozen trap tag.
        code: u32,
        /// Optional payload register.
        payload: Option<Register>,
    },
}

/// One lowered block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeBlock {
    /// Dense semantic block slot.
    pub slot: BlockSlot,
    /// Ordered block-parameter registers.
    pub parameter_registers: Vec<Register>,
    /// Ordered instructions.
    pub instructions: Vec<Instruction>,
    /// Exact lowered terminator.
    pub terminator: BytecodeTerminator,
    /// Frozen reachability tag.
    pub reachability: u32,
}

/// One complete restricted bytecode Function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeFunction {
    /// Stable Function identity.
    pub function: EntityId,
    /// Ordered Function-parameter registers.
    pub parameter_registers: Vec<Register>,
    /// Type of every dense register.
    pub register_types: Vec<TypeExpr>,
    /// Exact Function result type.
    pub result_type: TypeExpr,
    /// Dense entry block slot.
    pub entry_block: BlockSlot,
    /// Blocks in semantic Function order.
    pub blocks: Vec<BytecodeBlock>,
}

/// Successful derived lowering output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoweredFunction {
    /// Typed bytecode model.
    pub bytecode: BytecodeFunction,
    /// Exact canonical derived bytes.
    pub bytes: Vec<u8>,
    /// Root/profile-bound cache key.
    pub cache_key: BytecodeCacheKey,
    /// Charged lowering work.
    pub lowering_work: u64,
}

/// Complete integrated lowering request.
#[derive(Clone, Copy, Debug)]
pub struct LoweringInput<'a> {
    /// Selected type environment.
    pub types: &'a TypeEnvironment,
    /// Function graph.
    pub function: &'a FunctionGraph,
    /// Complete Parameter inventory.
    pub parameters: &'a [Parameter],
    /// Complete Block inventory.
    pub blocks: &'a [Block],
    /// Complete Operation inventory.
    pub operations: &'a [Operation],
    /// Exact schema epoch.
    pub schema_epoch: sley_id::SchemaEpochId,
    /// Exact state root.
    pub state_root: sley_id::StateRoot,
    /// Requested cache/lowering profile.
    pub profile: CacheProfile,
}

/// Integrated earlier or lowering failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoweringError {
    /// Exact S20-210/S20-220 failure.
    Cfg(CfgValidationError),
    /// Exact S20-260 failure.
    Lower(LowerError),
}

impl fmt::Display for LoweringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cfg(value) => value.fmt(formatter),
            Self::Lower(value) => value.fmt(formatter),
        }
    }
}

impl std::error::Error for LoweringError {}

impl From<CfgValidationError> for LoweringError {
    fn from(value: CfgValidationError) -> Self {
        Self::Cfg(value)
    }
}

impl From<LowerError> for LoweringError {
    fn from(value: LowerError) -> Self {
        Self::Lower(value)
    }
}

/// Validates and lowers one restricted Function.
///
/// # Errors
///
/// Returns the first failure in the frozen S20-260 order.
pub fn lower_function(input: LoweringInput<'_>) -> Result<LoweredFunction, LoweringError> {
    validate_function_graph(
        input.types,
        input.function,
        input.parameters,
        input.blocks,
        input.operations,
    )?;
    let cache_key = derive_cache_key(
        input.schema_epoch,
        input.state_root,
        input.function.entity_id,
        input.profile,
    )?;
    if !input.function.type_parameters.is_empty()
        || !input.function.effects.is_empty()
        || !input.function.contracts.is_empty()
    {
        return lower_fail(LowerErrorCode::ProfileUnsupported);
    }
    let mut work = preflight_resources(input)?;
    let maps = Maps::build(input, &mut work)?;
    validate_operations(input, &maps, &mut work)?;
    let bytecode = emit_function(input, &maps, &mut work)?;
    let bytes = encode_function(&bytecode)?;
    Ok(LoweredFunction {
        bytecode,
        bytes,
        cache_key,
        lowering_work: work,
    })
}

fn preflight_resources(input: LoweringInput<'_>) -> Result<u64, LoweringError> {
    if input.blocks.len() > MAX_LOWERED_BLOCKS || input.operations.len() > MAX_INSTRUCTIONS {
        return lower_fail(LowerErrorCode::ResourceLimit);
    }
    let mut registers = input.parameters.len();
    for operation in input.operations {
        if operation.operands.len() > MAX_INSTRUCTION_VALUES
            || operation.result_types.len() > MAX_INSTRUCTION_VALUES
        {
            return lower_fail(LowerErrorCode::ResourceLimit);
        }
        registers = registers
            .checked_add(operation.result_types.len())
            .ok_or_else(resource_error)?;
    }
    if registers > MAX_REGISTERS {
        return lower_fail(LowerErrorCode::ResourceLimit);
    }
    let count = 1_usize
        .checked_add(input.parameters.len())
        .and_then(|value| value.checked_add(input.blocks.len()))
        .and_then(|value| value.checked_add(input.operations.len()))
        .ok_or_else(resource_error)?;
    let work = u64::try_from(count).map_err(|_| resource_error())?;
    if work > MAX_LOWERING_WORK {
        lower_fail(LowerErrorCode::ResourceLimit)
    } else {
        Ok(work)
    }
}

struct Maps<'a> {
    parameters: BTreeMap<EntityId, (&'a Parameter, Register)>,
    blocks: BTreeMap<EntityId, (&'a Block, BlockSlot)>,
    operations: BTreeMap<EntityId, (&'a Operation, Vec<Register>)>,
    register_types: Vec<TypeExpr>,
    function_parameters: Vec<Register>,
}

impl<'a> Maps<'a> {
    fn build(input: LoweringInput<'a>, work: &mut u64) -> Result<Self, LoweringError> {
        let parameter_inventory: BTreeMap<_, _> = input
            .parameters
            .iter()
            .map(|value| (value.entity_id, value))
            .collect();
        let block_inventory: BTreeMap<_, _> = input
            .blocks
            .iter()
            .map(|value| (value.entity_id, value))
            .collect();
        let operation_inventory: BTreeMap<_, _> = input
            .operations
            .iter()
            .map(|value| (value.entity_id, value))
            .collect();
        let mut parameters = BTreeMap::new();
        let mut blocks = BTreeMap::new();
        let mut operations = BTreeMap::new();
        let mut register_types = Vec::new();
        let mut function_parameters = Vec::new();

        for id in &input.function.parameters {
            let value = parameter_inventory
                .get(id)
                .copied()
                .ok_or_else(local_error)?;
            let register = allocate_register(&mut register_types, value.value_type.clone(), work)?;
            parameters.insert(*id, (value, register));
            function_parameters.push(register);
        }
        for (slot, id) in input.function.blocks.iter().copied().enumerate() {
            let block = block_inventory.get(&id).copied().ok_or_else(local_error)?;
            let slot = u32::try_from(slot).map_err(|_| resource_error())?;
            blocks.insert(id, (block, slot));
            for parameter_id in &block.parameters {
                let value = parameter_inventory
                    .get(parameter_id)
                    .copied()
                    .ok_or_else(local_error)?;
                let register =
                    allocate_register(&mut register_types, value.value_type.clone(), work)?;
                parameters.insert(*parameter_id, (value, register));
            }
            for operation_id in &block.operations {
                let operation = operation_inventory
                    .get(operation_id)
                    .copied()
                    .ok_or_else(local_error)?;
                let mut results = Vec::with_capacity(operation.result_types.len());
                for result_type in &operation.result_types {
                    results.push(allocate_register(
                        &mut register_types,
                        result_type.clone(),
                        work,
                    )?);
                }
                operations.insert(*operation_id, (operation, results));
            }
        }
        if parameters.len() != input.parameters.len()
            || blocks.len() != input.blocks.len()
            || operations.len() != input.operations.len()
        {
            return lower_fail(LowerErrorCode::LocalReferenceInvalid);
        }
        Ok(Self {
            parameters,
            blocks,
            operations,
            register_types,
            function_parameters,
        })
    }

    fn register(&self, value: ValueRef) -> Result<Register, LoweringError> {
        match value {
            ValueRef::Parameter(id) => self
                .parameters
                .get(&id)
                .map(|(_, register)| *register)
                .ok_or_else(local_error),
            ValueRef::OperationResult(value) => self
                .operations
                .get(&value.operation)
                .and_then(|(_, results)| {
                    usize::try_from(value.result_index)
                        .ok()
                        .and_then(|i| results.get(i))
                })
                .copied()
                .ok_or_else(local_error),
        }
    }

    fn value_type(&self, value: ValueRef) -> Result<&TypeExpr, LoweringError> {
        let register = usize::try_from(self.register(value)?).map_err(|_| local_error())?;
        self.register_types.get(register).ok_or_else(local_error)
    }

    fn block_slot(&self, id: EntityId) -> Result<BlockSlot, LoweringError> {
        self.blocks
            .get(&id)
            .map(|(_, slot)| *slot)
            .ok_or_else(local_error)
    }
}

fn allocate_register(
    types: &mut Vec<TypeExpr>,
    value_type: TypeExpr,
    work: &mut u64,
) -> Result<Register, LoweringError> {
    if types.len() >= MAX_REGISTERS {
        return lower_fail(LowerErrorCode::ResourceLimit);
    }
    let register = u32::try_from(types.len()).map_err(|_| resource_error())?;
    charge(work, 1)?;
    types.push(value_type);
    Ok(register)
}

fn validate_operations(
    input: LoweringInput<'_>,
    maps: &Maps<'_>,
    work: &mut u64,
) -> Result<(), LoweringError> {
    for block_id in &input.function.blocks {
        let block = maps.blocks.get(block_id).ok_or_else(local_error)?.0;
        for operation_id in &block.operations {
            let operation = maps.operations.get(operation_id).ok_or_else(local_error)?.0;
            let expected_operands = match operation.opcode {
                Opcode::BoolNot => 1,
                Opcode::BoolAnd | Opcode::BoolOr => 2,
                _ => return lower_fail(LowerErrorCode::OpcodeUnsupported),
            };
            if operation.immediate != Immediate::None {
                return lower_fail(LowerErrorCode::ImmediateMismatch);
            }
            if operation.operands.len() != expected_operands
                || operation.result_types.as_slice() != [TypeExpr::Bool]
            {
                return lower_fail(LowerErrorCode::SignatureMismatch);
            }
            for operand in &operation.operands {
                if maps.value_type(*operand)? != &TypeExpr::Bool {
                    return lower_fail(LowerErrorCode::SignatureMismatch);
                }
                charge(work, 1)?;
            }
            charge(work, 1)?;
        }
    }
    Ok(())
}

fn emit_function(
    input: LoweringInput<'_>,
    maps: &Maps<'_>,
    work: &mut u64,
) -> Result<BytecodeFunction, LoweringError> {
    let mut blocks = Vec::with_capacity(input.function.blocks.len());
    for block_id in &input.function.blocks {
        let (block, slot) = maps.blocks.get(block_id).ok_or_else(local_error)?;
        let parameter_registers = block
            .parameters
            .iter()
            .map(|id| {
                maps.parameters
                    .get(id)
                    .map(|(_, register)| *register)
                    .ok_or_else(local_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut instructions = Vec::with_capacity(block.operations.len());
        for operation_id in &block.operations {
            let (operation, results) = maps.operations.get(operation_id).ok_or_else(local_error)?;
            let operands = operation
                .operands
                .iter()
                .map(|value| maps.register(*value))
                .collect::<Result<Vec<_>, _>>()?;
            charge(
                work,
                u64::try_from(operands.len()).map_err(|_| resource_error())?,
            )?;
            instructions.push(Instruction {
                opcode: operation.opcode.tag(),
                operands,
                results: results.clone(),
            });
        }
        let terminator = lower_terminator(&block.terminator, maps, work)?;
        blocks.push(BytecodeBlock {
            slot: *slot,
            parameter_registers,
            instructions,
            terminator,
            reachability: block.reachability.tag(),
        });
    }
    Ok(BytecodeFunction {
        function: input.function.entity_id,
        parameter_registers: maps.function_parameters.clone(),
        register_types: maps.register_types.clone(),
        result_type: input.function.result_type.clone(),
        entry_block: maps.block_slot(input.function.entry_block)?,
        blocks,
    })
}

fn lower_terminator(
    value: &Terminator,
    maps: &Maps<'_>,
    work: &mut u64,
) -> Result<BytecodeTerminator, LoweringError> {
    charge(work, 1)?;
    match value {
        Terminator::Return(value) => Ok(BytecodeTerminator::Return(maps.register(value.value)?)),
        Terminator::Branch(value) => Ok(BytecodeTerminator::Branch(lower_edge(
            &value.edge,
            maps,
            work,
        )?)),
        Terminator::CondBranch(value) => Ok(BytecodeTerminator::CondBranch {
            condition: maps.register(value.condition)?,
            if_true: lower_edge(&value.if_true, maps, work)?,
            if_false: lower_edge(&value.if_false, maps, work)?,
        }),
        Terminator::VariantSwitch(value) => {
            let mut cases = Vec::with_capacity(value.cases.len());
            for case in &value.cases {
                charge(work, 1)?;
                let mut arguments = Vec::with_capacity(case.edge.arguments.len());
                for argument in &case.edge.arguments {
                    charge(work, 1)?;
                    arguments.push(match argument {
                        SwitchArgument::Value(value) => {
                            BytecodeSwitchArgument::Value(maps.register(*value)?)
                        }
                        SwitchArgument::CasePayload => BytecodeSwitchArgument::CasePayload,
                    });
                }
                cases.push(BytecodeSwitchCase {
                    case_key: case.case_key,
                    edge: BytecodeSwitchEdge {
                        target: maps.block_slot(case.edge.target)?,
                        arguments,
                    },
                });
            }
            Ok(BytecodeTerminator::VariantSwitch {
                value: maps.register(value.value)?,
                cases,
            })
        }
        Terminator::Trap(value) => Ok(BytecodeTerminator::Trap {
            code: value.code.tag(),
            payload: value
                .payload
                .map(|payload| maps.register(payload))
                .transpose()?,
        }),
    }
}

fn lower_edge(
    value: &sley_ssmc::TargetEdge,
    maps: &Maps<'_>,
    work: &mut u64,
) -> Result<BytecodeTargetEdge, LoweringError> {
    let arguments = value
        .arguments
        .iter()
        .map(|argument| maps.register(*argument))
        .collect::<Result<Vec<_>, _>>()?;
    charge(
        work,
        u64::try_from(arguments.len()).map_err(|_| resource_error())?,
    )?;
    Ok(BytecodeTargetEdge {
        target: maps.block_slot(value.target)?,
        arguments,
    })
}

fn encode_function(value: &BytecodeFunction) -> Result<Vec<u8>, LoweringError> {
    let mut output = Encoder::new();
    output.raw(b"SLEYBC01")?;
    output.u32(1)?;
    output.raw(value.function.as_bytes())?;
    output.registers(&value.parameter_registers)?;
    output.len(value.register_types.len())?;
    for value_type in &value.register_types {
        output.type_expr(value_type, 1)?;
    }
    output.type_expr(&value.result_type, 1)?;
    output.u32(value.entry_block)?;
    output.len(value.blocks.len())?;
    for block in &value.blocks {
        output.u32(block.slot)?;
        output.registers(&block.parameter_registers)?;
        output.len(block.instructions.len())?;
        for instruction in &block.instructions {
            output.u32(instruction.opcode)?;
            output.registers(&instruction.operands)?;
            output.registers(&instruction.results)?;
        }
        output.terminator(&block.terminator)?;
        output.u32(block.reachability)?;
    }
    Ok(output.bytes)
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), LoweringError> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(resource_error)?;
        if next > MAX_BYTECODE_BYTES {
            return lower_fail(LowerErrorCode::ResourceLimit);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn u16(&mut self, value: u16) -> Result<(), LoweringError> {
        self.raw(&value.to_be_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<(), LoweringError> {
        self.raw(&value.to_be_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), LoweringError> {
        self.raw(&value.to_be_bytes())
    }
    fn len(&mut self, value: usize) -> Result<(), LoweringError> {
        self.u64(u64::try_from(value).map_err(|_| resource_error())?)
    }
    fn registers(&mut self, values: &[Register]) -> Result<(), LoweringError> {
        self.len(values.len())?;
        for value in values {
            self.u32(*value)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn type_expr(&mut self, value: &TypeExpr, depth: usize) -> Result<(), LoweringError> {
        if depth > sley_ssmc::MAX_TYPE_DEPTH {
            return lower_fail(LowerErrorCode::ResourceLimit);
        }
        self.u32(value.tag())?;
        match value {
            TypeExpr::Unit
            | TypeExpr::Bool
            | TypeExpr::F32
            | TypeExpr::F64
            | TypeExpr::Bytes
            | TypeExpr::Text => Ok(()),
            TypeExpr::SInt(width) | TypeExpr::UInt(width) => self.u16(width.bits()),
            TypeExpr::Tuple(values) => {
                self.len(values.len())?;
                for value in values {
                    self.type_expr(value, depth + 1)?;
                }
                Ok(())
            }
            TypeExpr::Named(value) => {
                self.entity(value.definition)?;
                self.len(value.arguments.len())?;
                for argument in &value.arguments {
                    self.type_expr(argument, depth + 1)?;
                }
                Ok(())
            }
            TypeExpr::Vector(value) | TypeExpr::Option(value) | TypeExpr::LocalCell(value) => {
                self.type_expr(value, depth + 1)
            }
            TypeExpr::OrderedMap { key, value } => {
                self.type_expr(key, depth + 1)?;
                self.type_expr(value, depth + 1)
            }
            TypeExpr::Result { ok, error } => {
                self.type_expr(ok, depth + 1)?;
                self.type_expr(error, depth + 1)
            }
            TypeExpr::FunctionRef(value) => {
                self.len(value.parameters.len())?;
                for parameter in &value.parameters {
                    self.type_expr(parameter, depth + 1)?;
                }
                self.type_expr(&value.result, depth + 1)?;
                self.len(value.effects.len())?;
                for effect in &value.effects {
                    self.entity(*effect)?;
                }
                Ok(())
            }
            TypeExpr::AdapterHandle(value) | TypeExpr::CapabilityToken(value) => {
                self.entity(*value)
            }
            TypeExpr::TypeParameter(value) => self.u32(*value),
            TypeExpr::BuiltinFailure(value) => self.u16(value.tag()),
        }
    }

    fn entity(&mut self, value: EntityId) -> Result<(), LoweringError> {
        self.u32(1)?;
        self.raw(value.as_bytes())
    }

    fn terminator(&mut self, value: &BytecodeTerminator) -> Result<(), LoweringError> {
        match value {
            BytecodeTerminator::Return(value) => {
                self.u32(1)?;
                self.u32(*value)
            }
            BytecodeTerminator::Branch(value) => {
                self.u32(2)?;
                self.edge(value)
            }
            BytecodeTerminator::CondBranch {
                condition,
                if_true,
                if_false,
            } => {
                self.u32(3)?;
                self.u32(*condition)?;
                self.edge(if_true)?;
                self.edge(if_false)
            }
            BytecodeTerminator::VariantSwitch { value, cases } => {
                self.u32(4)?;
                self.u32(*value)?;
                self.len(cases.len())?;
                for case in cases {
                    self.case_key(case.case_key)?;
                    self.switch_edge(&case.edge)?;
                }
                Ok(())
            }
            BytecodeTerminator::Trap { code, payload } => {
                self.u32(5)?;
                self.u32(*code)?;
                match payload {
                    None => self.u32(1),
                    Some(value) => {
                        self.u32(2)?;
                        self.u32(*value)
                    }
                }
            }
        }
    }

    fn edge(&mut self, value: &BytecodeTargetEdge) -> Result<(), LoweringError> {
        self.u32(value.target)?;
        self.registers(&value.arguments)
    }
    fn switch_edge(&mut self, value: &BytecodeSwitchEdge) -> Result<(), LoweringError> {
        self.u32(value.target)?;
        self.len(value.arguments.len())?;
        for argument in &value.arguments {
            match argument {
                BytecodeSwitchArgument::Value(value) => {
                    self.u32(1)?;
                    self.u32(*value)?;
                }
                BytecodeSwitchArgument::CasePayload => self.u32(2)?,
            }
        }
        Ok(())
    }
    fn case_key(&mut self, value: CaseKey) -> Result<(), LoweringError> {
        match value {
            CaseKey::Member(value) => {
                self.u32(1)?;
                self.raw(value.as_bytes())
            }
            CaseKey::Builtin(value) => {
                self.u32(2)?;
                self.u32(value.tag())
            }
        }
    }
}

fn charge(work: &mut u64, amount: u64) -> Result<(), LoweringError> {
    *work = work.checked_add(amount).ok_or_else(resource_error)?;
    if *work > MAX_LOWERING_WORK {
        lower_fail(LowerErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}
fn local_error() -> LoweringError {
    LowerError::new(LowerErrorCode::LocalReferenceInvalid).into()
}
fn resource_error() -> LoweringError {
    LowerError::new(LowerErrorCode::ResourceLimit).into()
}
fn lower_fail<T>(code: LowerErrorCode) -> Result<T, LoweringError> {
    Err(LowerError::new(code).into())
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;
    use sley_id::{SchemaEpochId, StateRoot};
    use sley_ssmc::{
        BranchTerminator, BuiltinCase, CaseKey, CondBranchTerminator, OperationResultRef,
        ParameterRole, Reachability, ReturnTerminator, SwitchArgument, SwitchCase, SwitchEdge,
        TargetEdge, TrapCode, TrapTerminator, TypeParameterDef, VariantSwitchTerminator,
        Visibility,
    };

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    struct Fixture {
        types: TypeEnvironment,
        function: FunctionGraph,
        parameters: Vec<Parameter>,
        blocks: Vec<Block>,
        operations: Vec<Operation>,
    }

    impl Fixture {
        fn input(&self) -> LoweringInput<'_> {
            LoweringInput {
                types: &self.types,
                function: &self.function,
                parameters: &self.parameters,
                blocks: &self.blocks,
                operations: &self.operations,
                schema_epoch: SchemaEpochId::from_bytes([8; 32]),
                state_root: StateRoot::from_bytes([9; 32]),
                profile: CacheProfile::RESTRICTED_V1,
            }
        }
    }

    fn bool_fixture(opcode: Opcode) -> Fixture {
        let function = id(1);
        let left = id(2);
        let right = id(3);
        let block = id(4);
        let operation = id(5);
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            function: FunctionGraph {
                entity_id: function,
                type_parameters: Vec::new(),
                parameters: vec![left, right],
                result_type: TypeExpr::Bool,
                effects: Vec::new(),
                entry_block: block,
                blocks: vec![block],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                Parameter {
                    entity_id: left,
                    owner: function,
                    role: ParameterRole::Function,
                    ordinal: 0,
                    value_type: TypeExpr::Bool,
                },
                Parameter {
                    entity_id: right,
                    owner: function,
                    role: ParameterRole::Function,
                    ordinal: 1,
                    value_type: TypeExpr::Bool,
                },
            ],
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
                opcode,
                operands: vec![ValueRef::Parameter(left), ValueRef::Parameter(right)],
                result_types: vec![TypeExpr::Bool],
                immediate: Immediate::None,
            }],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn boolean_o0_lowering_has_exact_registers_and_bytes() {
        let fixture = bool_fixture(Opcode::BoolAnd);
        let lowered = lower_function(fixture.input()).unwrap();
        assert_eq!(lowered.bytecode.parameter_registers, vec![0, 1]);
        assert_eq!(lowered.bytecode.register_types, vec![TypeExpr::Bool; 3]);
        assert_eq!(
            lowered.bytecode.blocks[0].instructions,
            vec![Instruction {
                opcode: 103,
                operands: vec![0, 1],
                results: vec![2],
            }]
        );
        assert_eq!(
            hex(&lowered.bytes),
            "534c4559424330310000000101010101010101010101010101010101010101010101010101010101010101010000000000000002000000000000000100000000000000030000000200000002000000020000000200000000000000000000000100000000000000000000000000000000000000010000006700000000000000020000000000000001000000000000000100000002000000010000000200000001"
        );
        for _ in 0..128 {
            assert_eq!(lower_function(fixture.input()).unwrap(), lowered);
        }
    }

    #[test]
    fn unsupported_opcode_precedes_immediate_and_signature() {
        let mut fixture = bool_fixture(Opcode::IntAddChecked);
        fixture.operations[0].immediate = Immediate::Index(7);
        fixture.operations[0].operands.clear();
        let LoweringError::Lower(error) = lower_function(fixture.input()).unwrap_err() else {
            panic!("lowering error");
        };
        assert_eq!(error.code(), LowerErrorCode::OpcodeUnsupported);
    }

    #[test]
    fn immediate_precedes_signature() {
        let mut fixture = bool_fixture(Opcode::BoolAnd);
        fixture.operations[0].immediate = Immediate::Index(7);
        fixture.operations[0].operands.clear();
        let LoweringError::Lower(error) = lower_function(fixture.input()).unwrap_err() else {
            panic!("lowering error");
        };
        assert_eq!(error.code(), LowerErrorCode::ImmediateMismatch);
    }

    #[test]
    fn all_supported_boolean_opcodes_lower() {
        for opcode in [Opcode::BoolNot, Opcode::BoolAnd, Opcode::BoolOr] {
            let mut fixture = bool_fixture(opcode);
            if opcode == Opcode::BoolNot {
                fixture.operations[0].operands.pop();
            }
            assert_eq!(
                lower_function(fixture.input()).unwrap().bytecode.blocks[0].instructions[0].opcode,
                opcode.tag()
            );
        }
    }

    fn add_return_block(fixture: &mut Fixture) -> (EntityId, EntityId) {
        let target = id(6);
        let parameter = id(7);
        fixture.function.blocks.push(target);
        fixture.parameters.push(Parameter {
            entity_id: parameter,
            owner: target,
            role: ParameterRole::Block,
            ordinal: 0,
            value_type: TypeExpr::Bool,
        });
        fixture.blocks.push(Block {
            entity_id: target,
            function: fixture.function.entity_id,
            parameters: vec![parameter],
            operations: Vec::new(),
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::Parameter(parameter),
            }),
            reachability: Reachability::Required,
        });
        (target, parameter)
    }

    #[test]
    fn branch_conditional_and_trap_terminators_lower() {
        let mut branch = bool_fixture(Opcode::BoolAnd);
        let result = ValueRef::OperationResult(OperationResultRef {
            operation: id(5),
            result_index: 0,
        });
        let (target, _) = add_return_block(&mut branch);
        branch.blocks[0].terminator = Terminator::Branch(BranchTerminator {
            edge: TargetEdge {
                target,
                arguments: vec![result],
            },
        });
        assert!(matches!(
            lower_function(branch.input()).unwrap().bytecode.blocks[0].terminator,
            BytecodeTerminator::Branch(_)
        ));

        let mut conditional = bool_fixture(Opcode::BoolAnd);
        let (target, _) = add_return_block(&mut conditional);
        conditional.blocks[0].terminator = Terminator::CondBranch(CondBranchTerminator {
            condition: result,
            if_true: TargetEdge {
                target,
                arguments: vec![result],
            },
            if_false: TargetEdge {
                target,
                arguments: vec![result],
            },
        });
        assert!(matches!(
            lower_function(conditional.input()).unwrap().bytecode.blocks[0].terminator,
            BytecodeTerminator::CondBranch { .. }
        ));

        let mut trap = bool_fixture(Opcode::BoolAnd);
        trap.blocks[0].terminator = Terminator::Trap(TrapTerminator {
            code: TrapCode::InternalInvariant,
            payload: Some(result),
        });
        assert!(matches!(
            lower_function(trap.input()).unwrap().bytecode.blocks[0].terminator,
            BytecodeTerminator::Trap {
                payload: Some(2),
                ..
            }
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn variant_switch_case_payload_is_preserved() {
        let function = id(20);
        let selector = id(21);
        let fallback = id(22);
        let entry = id(23);
        let none_block = id(24);
        let none_value = id(25);
        let some_block = id(26);
        let some_value = id(27);
        let fixture = Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            function: FunctionGraph {
                entity_id: function,
                type_parameters: Vec::new(),
                parameters: vec![selector, fallback],
                result_type: TypeExpr::Bool,
                effects: Vec::new(),
                entry_block: entry,
                blocks: vec![entry, none_block, some_block],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                Parameter {
                    entity_id: selector,
                    owner: function,
                    role: ParameterRole::Function,
                    ordinal: 0,
                    value_type: TypeExpr::Option(Box::new(TypeExpr::Bool)),
                },
                Parameter {
                    entity_id: fallback,
                    owner: function,
                    role: ParameterRole::Function,
                    ordinal: 1,
                    value_type: TypeExpr::Bool,
                },
                Parameter {
                    entity_id: none_value,
                    owner: none_block,
                    role: ParameterRole::Block,
                    ordinal: 0,
                    value_type: TypeExpr::Bool,
                },
                Parameter {
                    entity_id: some_value,
                    owner: some_block,
                    role: ParameterRole::Block,
                    ordinal: 0,
                    value_type: TypeExpr::Bool,
                },
            ],
            blocks: vec![
                Block {
                    entity_id: entry,
                    function,
                    parameters: Vec::new(),
                    operations: Vec::new(),
                    terminator: Terminator::VariantSwitch(VariantSwitchTerminator {
                        value: ValueRef::Parameter(selector),
                        cases: vec![
                            SwitchCase {
                                case_key: CaseKey::Builtin(BuiltinCase::None),
                                edge: SwitchEdge {
                                    target: none_block,
                                    arguments: vec![SwitchArgument::Value(ValueRef::Parameter(
                                        fallback,
                                    ))],
                                },
                            },
                            SwitchCase {
                                case_key: CaseKey::Builtin(BuiltinCase::Some),
                                edge: SwitchEdge {
                                    target: some_block,
                                    arguments: vec![SwitchArgument::CasePayload],
                                },
                            },
                        ],
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: none_block,
                    function,
                    parameters: vec![none_value],
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(none_value),
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: some_block,
                    function,
                    parameters: vec![some_value],
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(some_value),
                    }),
                    reachability: Reachability::Required,
                },
            ],
            operations: Vec::new(),
        };
        let lowered = lower_function(fixture.input()).unwrap();
        let BytecodeTerminator::VariantSwitch { cases, .. } =
            &lowered.bytecode.blocks[0].terminator
        else {
            panic!("variant switch");
        };
        assert_eq!(
            cases[1].edge.arguments,
            vec![BytecodeSwitchArgument::CasePayload]
        );
    }

    #[test]
    fn prior_cfg_and_cache_profile_failures_precede_lower_profile() {
        let mut cfg = bool_fixture(Opcode::BoolAnd);
        cfg.parameters[0].owner = id(99);
        cfg.function.effects.push(id(50));
        assert!(matches!(
            lower_function(cfg.input()).unwrap_err(),
            LoweringError::Cfg(_)
        ));

        let mut cache = bool_fixture(Opcode::BoolAnd);
        cache.function.effects.push(id(50));
        let mut input = cache.input();
        input.profile.execution_abi_flags = 1;
        let LoweringError::Lower(error) = lower_function(input).unwrap_err() else {
            panic!("cache error");
        };
        assert_eq!(error.code(), LowerErrorCode::CacheKeyUnsupported);

        let mut profile = bool_fixture(Opcode::BoolAnd);
        profile.function.type_parameters = vec![TypeParameterDef { ordinal: 0 }];
        let LoweringError::Lower(error) = lower_function(profile.input()).unwrap_err() else {
            panic!("profile error");
        };
        assert_eq!(error.code(), LowerErrorCode::ProfileUnsupported);
    }

    #[test]
    fn resource_preflight_rejects_oversized_instruction_before_lowering_allocation() {
        let mut fixture = bool_fixture(Opcode::BoolAnd);
        fixture.operations[0].result_types =
            vec![TypeExpr::Bool; MAX_INSTRUCTION_VALUES.saturating_add(1)];
        let LoweringError::Lower(error) = preflight_resources(fixture.input()).unwrap_err() else {
            panic!("resource error");
        };
        assert_eq!(error.code(), LowerErrorCode::ResourceLimit);
    }

    #[test]
    fn local_id_and_inventory_slice_perturbation_preserve_output() {
        let first_fixture = bool_fixture(Opcode::BoolAnd);
        let first = lower_function(first_fixture.input()).unwrap();

        let mut second = bool_fixture(Opcode::BoolAnd);
        let old_left = second.parameters[0].entity_id;
        let old_right = second.parameters[1].entity_id;
        second.parameters[0].entity_id = id(12);
        second.parameters[1].entity_id = id(13);
        second.function.parameters = vec![id(12), id(13)];
        for operand in &mut second.operations[0].operands {
            if *operand == ValueRef::Parameter(old_left) {
                *operand = ValueRef::Parameter(id(12));
            } else if *operand == ValueRef::Parameter(old_right) {
                *operand = ValueRef::Parameter(id(13));
            }
        }
        second.blocks[0].entity_id = id(14);
        second.function.entry_block = id(14);
        second.function.blocks = vec![id(14)];
        second.operations[0].block = id(14);
        second.operations[0].entity_id = id(15);
        second.blocks[0].operations = vec![id(15)];
        second.blocks[0].terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::OperationResult(OperationResultRef {
                operation: id(15),
                result_index: 0,
            }),
        });
        second.parameters.reverse();
        assert_eq!(lower_function(second.input()).unwrap(), first);
    }

    #[test]
    fn all_lowering_codes_are_stable() {
        let codes = [
            LowerErrorCode::ProfileUnsupported,
            LowerErrorCode::OpcodeUnsupported,
            LowerErrorCode::SignatureMismatch,
            LowerErrorCode::ImmediateMismatch,
            LowerErrorCode::LocalReferenceInvalid,
            LowerErrorCode::CacheKeyUnsupported,
            LowerErrorCode::ResourceLimit,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 26_000 + u32::try_from(offset).unwrap());
        }
    }
}
