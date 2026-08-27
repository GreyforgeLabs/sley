//! S20-220 bounded CFG and value-use validation.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sley_id::EntityId;
use sley_ssmc::{
    Block, BuiltinCase, CaseKey, FunctionGraph, MAX_TYPE_ARGUMENTS, Operation, Parameter,
    ParameterRole, Reachability, SwitchArgument, TargetEdge, Terminator, TypeDefForm, TypeExpr,
    ValueRef, VariantSwitchTerminator,
};

use crate::{TypeEnvironment, TypeError};

/// Maximum blocks in one S20-220 validation request.
pub const MAX_CFG_BLOCKS: usize = 4_096;
/// Maximum edges, counting every switch case separately.
pub const MAX_CFG_EDGES: usize = 16_384;
/// Maximum operations in one function.
pub const MAX_CFG_OPERATIONS: usize = 1_000_000;
/// Maximum total parameters plus operation results.
pub const MAX_CFG_VALUES: usize = 1_000_000;
/// Maximum operation and terminator value uses.
pub const MAX_CFG_USES: usize = 262_144;
/// Maximum parameters in one function or block.
pub const MAX_CFG_PARAMETERS: usize = 65_535;
/// Maximum operands or results in one operation.
pub const MAX_CFG_OPERATION_VALUES: usize = 65_535;
/// Maximum charged dominator bitset word operations.
pub const MAX_DOMINATOR_WORD_OPERATIONS: u64 = 50_000_000;

/// Stable S20-220 graph/CFG failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CfgErrorCode {
    /// `GRAPH_DUPLICATE_ENTITY`
    GraphDuplicateEntity,
    /// `GRAPH_INVENTORY_MISMATCH`
    GraphInventoryMismatch,
    /// `GRAPH_OWNER_MISMATCH`
    GraphOwnerMismatch,
    /// `GRAPH_ORDINAL_MISMATCH`
    GraphOrdinalMismatch,
    /// `GRAPH_UNRESOLVED_REFERENCE`
    GraphUnresolvedReference,
    /// `CFG_ENTRY_INVALID`
    EntryInvalid,
    /// `CFG_TARGET_INVALID`
    TargetInvalid,
    /// `CFG_TARGET_ARGUMENTS`
    TargetArguments,
    /// `CFG_RETURN_TYPE`
    ReturnType,
    /// `CFG_BOOL_REQUIRED`
    BoolRequired,
    /// `CFG_SWITCH_TYPE`
    SwitchType,
    /// `CFG_SWITCH_CASES`
    SwitchCases,
    /// `CFG_SWITCH_PAYLOAD`
    SwitchPayload,
    /// `CFG_VALUE_UNRESOLVED`
    ValueUnresolved,
    /// `CFG_RESULT_INDEX`
    ResultIndex,
    /// `CFG_USE_BEFORE_DEFINITION`
    UseBeforeDefinition,
    /// `CFG_DOMINANCE`
    Dominance,
    /// `CFG_REACHABILITY`
    Reachability,
    /// `CFG_UNREACHABLE_VALUE`
    UnreachableValue,
    /// `CFG_TRAP_PAYLOAD`
    TrapPayload,
    /// `CFG_RESOURCE_LIMIT`
    ResourceLimit,
}

impl CfgErrorCode {
    /// Returns the exact stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GraphDuplicateEntity => "GRAPH_DUPLICATE_ENTITY",
            Self::GraphInventoryMismatch => "GRAPH_INVENTORY_MISMATCH",
            Self::GraphOwnerMismatch => "GRAPH_OWNER_MISMATCH",
            Self::GraphOrdinalMismatch => "GRAPH_ORDINAL_MISMATCH",
            Self::GraphUnresolvedReference => "GRAPH_UNRESOLVED_REFERENCE",
            Self::EntryInvalid => "CFG_ENTRY_INVALID",
            Self::TargetInvalid => "CFG_TARGET_INVALID",
            Self::TargetArguments => "CFG_TARGET_ARGUMENTS",
            Self::ReturnType => "CFG_RETURN_TYPE",
            Self::BoolRequired => "CFG_BOOL_REQUIRED",
            Self::SwitchType => "CFG_SWITCH_TYPE",
            Self::SwitchCases => "CFG_SWITCH_CASES",
            Self::SwitchPayload => "CFG_SWITCH_PAYLOAD",
            Self::ValueUnresolved => "CFG_VALUE_UNRESOLVED",
            Self::ResultIndex => "CFG_RESULT_INDEX",
            Self::UseBeforeDefinition => "CFG_USE_BEFORE_DEFINITION",
            Self::Dominance => "CFG_DOMINANCE",
            Self::Reachability => "CFG_REACHABILITY",
            Self::UnreachableValue => "CFG_UNREACHABLE_VALUE",
            Self::TrapPayload => "CFG_TRAP_PAYLOAD",
            Self::ResourceLimit => "CFG_RESOURCE_LIMIT",
        }
    }

    /// Returns the exact stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::GraphDuplicateEntity => 22_000,
            Self::GraphInventoryMismatch => 22_001,
            Self::GraphOwnerMismatch => 22_002,
            Self::GraphOrdinalMismatch => 22_003,
            Self::GraphUnresolvedReference => 22_004,
            Self::EntryInvalid => 22_005,
            Self::TargetInvalid => 22_006,
            Self::TargetArguments => 22_007,
            Self::ReturnType => 22_008,
            Self::BoolRequired => 22_009,
            Self::SwitchType => 22_010,
            Self::SwitchCases => 22_011,
            Self::SwitchPayload => 22_012,
            Self::ValueUnresolved => 22_013,
            Self::ResultIndex => 22_014,
            Self::UseBeforeDefinition => 22_015,
            Self::Dominance => 22_016,
            Self::Reachability => 22_017,
            Self::UnreachableValue => 22_018,
            Self::TrapPayload => 22_019,
            Self::ResourceLimit => 22_020,
        }
    }
}

impl fmt::Display for CfgErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable CFG error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CfgError {
    code: CfgErrorCode,
}

impl CfgError {
    /// Constructs an error from its frozen code.
    #[must_use]
    pub const fn new(code: CfgErrorCode) -> Self {
        Self { code }
    }

    /// Returns the frozen code.
    #[must_use]
    pub const fn code(&self) -> CfgErrorCode {
        self.code
    }
}

impl fmt::Display for CfgError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for CfgError {}

/// A CFG-phase or preserved earlier type-phase failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CfgValidationError {
    /// S20-220 graph/CFG failure.
    Cfg(CfgError),
    /// Exact S20-210 type failure.
    Type(TypeError),
}

impl fmt::Display for CfgValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cfg(error) => error.fmt(formatter),
            Self::Type(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CfgValidationError {}

impl From<TypeError> for CfgValidationError {
    fn from(value: TypeError) -> Self {
        Self::Type(value)
    }
}

/// S20-220 validation result.
pub type CfgResult<T> = core::result::Result<T, CfgValidationError>;

/// Deterministic successful CFG summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CfgReport {
    /// Reachable blocks in function-declared order.
    pub reachable_blocks: Vec<EntityId>,
    /// Total CFG edge count.
    pub edges: u32,
    /// Charged dominator word operations.
    pub dominator_word_operations: u64,
}

struct GraphIndex<'a> {
    types: &'a TypeEnvironment,
    function: &'a FunctionGraph,
    parameter_count: u32,
    parameters: BTreeMap<EntityId, &'a Parameter>,
    blocks: BTreeMap<EntityId, &'a Block>,
    operations: BTreeMap<EntityId, &'a Operation>,
    block_indices: BTreeMap<EntityId, usize>,
    reachable: Vec<bool>,
    dominators: Vec<Vec<u64>>,
    dominator_work: u64,
    edges: usize,
}

/// Validates one closed function graph.
///
/// # Errors
///
/// Returns the first deterministic graph/CFG error, or preserves an earlier
/// S20-210 type failure.
pub fn validate_function_graph(
    types: &TypeEnvironment,
    function: &FunctionGraph,
    parameters: &[Parameter],
    blocks: &[Block],
    operations: &[Operation],
) -> CfgResult<CfgReport> {
    let graph = GraphIndex::build(types, function, parameters, blocks, operations)?;
    graph.validate_values_and_terminators()?;
    let reachable_blocks = function
        .blocks
        .iter()
        .zip(&graph.reachable)
        .filter_map(|(id, reachable)| reachable.then_some(*id))
        .collect();
    Ok(CfgReport {
        reachable_blocks,
        edges: u32::try_from(graph.edges).map_err(|_| cfg_error(CfgErrorCode::ResourceLimit))?,
        dominator_word_operations: graph.dominator_work,
    })
}

impl<'a> GraphIndex<'a> {
    fn build(
        types: &'a TypeEnvironment,
        function: &'a FunctionGraph,
        parameters: &'a [Parameter],
        blocks: &'a [Block],
        operations: &'a [Operation],
    ) -> CfgResult<Self> {
        check_top_level_limits(function, parameters, blocks, operations)?;
        let parameter_count = validate_type_parameters(function)?;
        validate_sorted_unique(&function.effects)?;
        validate_sorted_unique(&function.contracts)?;

        let mut all_ids = BTreeSet::new();
        if !all_ids.insert(function.entity_id) {
            return cfg_fail(CfgErrorCode::GraphDuplicateEntity);
        }
        let parameters = index_unique(parameters, &mut all_ids, |value| value.entity_id)?;
        let blocks = index_unique(blocks, &mut all_ids, |value| value.entity_id)?;
        let operations = index_unique(operations, &mut all_ids, |value| value.entity_id)?;

        let block_indices = index_declared_ids(&function.blocks)?;
        if block_indices.len() != blocks.len()
            || block_indices.keys().any(|id| !blocks.contains_key(id))
        {
            return cfg_fail(CfgErrorCode::GraphInventoryMismatch);
        }
        let entry_index = block_indices
            .get(&function.entry_block)
            .copied()
            .ok_or_else(|| cfg_error(CfgErrorCode::EntryInvalid))?;
        if blocks[&function.entry_block].function != function.entity_id {
            return cfg_fail(CfgErrorCode::EntryInvalid);
        }

        let expected_function_parameters = index_declared_ids(&function.parameters)?;
        validate_parameter_inventory(
            function,
            &parameters,
            &blocks,
            &expected_function_parameters,
            types,
            parameter_count,
        )?;
        validate_operation_inventory(function, &blocks, &operations, types, parameter_count)?;
        types.check_type(&function.result_type, parameter_count)?;

        let (successors, edges) = build_successors(function, &blocks, &block_indices)?;
        let reachable = compute_reachability(entry_index, &successors);
        validate_reachability(function, &blocks, &reachable)?;
        let (dominators, dominator_work) =
            compute_dominators(entry_index, &successors, &reachable)?;

        Ok(Self {
            types,
            function,
            parameter_count,
            parameters,
            blocks,
            operations,
            block_indices,
            reachable,
            dominators,
            dominator_work,
            edges,
        })
    }

    fn validate_values_and_terminators(&self) -> CfgResult<()> {
        for block_id in &self.function.blocks {
            let block = self.blocks[block_id];
            for operation_id in &block.operations {
                let operation = self.operations[operation_id];
                for operand in &operation.operands {
                    self.resolve_value(*operand, *block_id, Some(operation.ordinal))?;
                }
            }
        }
        for block_id in &self.function.blocks {
            let block = self.blocks[block_id];
            self.validate_terminator(block)?;
        }
        Ok(())
    }

    fn validate_terminator(&self, block: &Block) -> CfgResult<()> {
        match &block.terminator {
            Terminator::Return(value) => {
                let actual = self.resolve_value(value.value, block.entity_id, None)?;
                if actual == self.function.result_type {
                    Ok(())
                } else {
                    cfg_fail(CfgErrorCode::ReturnType)
                }
            }
            Terminator::Branch(branch) => self.validate_target_edge(block, &branch.edge),
            Terminator::CondBranch(branch) => {
                let condition = self.resolve_value(branch.condition, block.entity_id, None)?;
                if condition != TypeExpr::Bool {
                    return cfg_fail(CfgErrorCode::BoolRequired);
                }
                self.validate_target_edge(block, &branch.if_true)?;
                self.validate_target_edge(block, &branch.if_false)
            }
            Terminator::VariantSwitch(switch) => self.validate_switch(block, switch),
            Terminator::Trap(trap) => {
                if let Some(payload) = trap.payload {
                    let payload = self.resolve_value(payload, block.entity_id, None)?;
                    if contains_type_parameter(&payload) {
                        return cfg_fail(CfgErrorCode::TrapPayload);
                    }
                    if !self.types.traits(&payload)?.persistable {
                        return cfg_fail(CfgErrorCode::TrapPayload);
                    }
                }
                Ok(())
            }
        }
    }

    fn validate_target_edge(&self, source: &Block, edge: &TargetEdge) -> CfgResult<()> {
        let target = self
            .blocks
            .get(&edge.target)
            .copied()
            .ok_or_else(|| cfg_error(CfgErrorCode::TargetInvalid))?;
        if target.function != self.function.entity_id {
            return cfg_fail(CfgErrorCode::TargetInvalid);
        }
        if edge.arguments.len() != target.parameters.len() {
            return cfg_fail(CfgErrorCode::TargetArguments);
        }
        for (argument, parameter_id) in edge.arguments.iter().zip(&target.parameters) {
            let actual = self.resolve_value(*argument, source.entity_id, None)?;
            let expected = &self.parameters[parameter_id].value_type;
            if &actual != expected {
                return cfg_fail(CfgErrorCode::TargetArguments);
            }
        }
        Ok(())
    }

    fn validate_switch(&self, source: &Block, switch: &VariantSwitchTerminator) -> CfgResult<()> {
        let selector = self.resolve_value(switch.value, source.entity_id, None)?;
        let expected = self.expected_switch_cases(&selector)?;
        if switch.cases.len() != expected.len()
            || !switch
                .cases
                .windows(2)
                .all(|pair| pair[0].case_key < pair[1].case_key)
            || switch
                .cases
                .iter()
                .map(|case| case.case_key)
                .ne(expected.iter().map(|(key, _)| *key))
        {
            return cfg_fail(CfgErrorCode::SwitchCases);
        }

        for (case, (_, payload_type)) in switch.cases.iter().zip(expected) {
            let target = self
                .blocks
                .get(&case.edge.target)
                .copied()
                .ok_or_else(|| cfg_error(CfgErrorCode::TargetInvalid))?;
            if target.function != self.function.entity_id {
                return cfg_fail(CfgErrorCode::TargetInvalid);
            }
            if case.edge.arguments.len() != target.parameters.len() {
                return cfg_fail(CfgErrorCode::TargetArguments);
            }
            for (argument, parameter_id) in case.edge.arguments.iter().zip(&target.parameters) {
                let actual = match argument {
                    SwitchArgument::Value(value) => {
                        self.resolve_value(*value, source.entity_id, None)?
                    }
                    SwitchArgument::CasePayload => payload_type
                        .clone()
                        .ok_or_else(|| cfg_error(CfgErrorCode::SwitchPayload))?,
                };
                if actual != self.parameters[parameter_id].value_type {
                    return cfg_fail(CfgErrorCode::TargetArguments);
                }
            }
        }
        Ok(())
    }

    fn expected_switch_cases(
        &self,
        selector: &TypeExpr,
    ) -> CfgResult<Vec<(CaseKey, Option<TypeExpr>)>> {
        let mut cases = match selector {
            TypeExpr::Named(named) => {
                let definition = self.types.definition(named.definition)?;
                let TypeDefForm::Variant(variants) = &definition.form else {
                    return cfg_fail(CfgErrorCode::SwitchType);
                };
                let mut out = Vec::with_capacity(variants.len());
                for variant in variants {
                    let payload = variant
                        .payload_type
                        .as_ref()
                        .map(|payload| {
                            self.types.instantiate_in_scope(
                                payload,
                                &named.arguments,
                                self.parameter_count,
                            )
                        })
                        .transpose()?;
                    out.push((CaseKey::Member(variant.member_id), payload));
                }
                out
            }
            TypeExpr::Option(element) => vec![
                (CaseKey::Builtin(BuiltinCase::None), None),
                (
                    CaseKey::Builtin(BuiltinCase::Some),
                    Some((**element).clone()),
                ),
            ],
            TypeExpr::Result { ok, error } => vec![
                (CaseKey::Builtin(BuiltinCase::Ok), Some((**ok).clone())),
                (CaseKey::Builtin(BuiltinCase::Err), Some((**error).clone())),
            ],
            _ => return cfg_fail(CfgErrorCode::SwitchType),
        };
        cases.sort_by_key(|(key, _)| *key);
        Ok(cases)
    }

    fn resolve_value(
        &self,
        value: ValueRef,
        use_block: EntityId,
        use_ordinal: Option<u32>,
    ) -> CfgResult<TypeExpr> {
        let use_index = self.block_indices[&use_block];
        match value {
            ValueRef::Parameter(id) => {
                let parameter = self
                    .parameters
                    .get(&id)
                    .copied()
                    .ok_or_else(|| cfg_error(CfgErrorCode::ValueUnresolved))?;
                match parameter.role {
                    ParameterRole::Function => Ok(parameter.value_type.clone()),
                    ParameterRole::Block if parameter.owner == use_block => {
                        Ok(parameter.value_type.clone())
                    }
                    ParameterRole::Block if !self.reachable[use_index] => {
                        cfg_fail(CfgErrorCode::UnreachableValue)
                    }
                    ParameterRole::Block => cfg_fail(CfgErrorCode::Dominance),
                }
            }
            ValueRef::OperationResult(result) => {
                let operation = self
                    .operations
                    .get(&result.operation)
                    .copied()
                    .ok_or_else(|| cfg_error(CfgErrorCode::ValueUnresolved))?;
                let result_type = operation
                    .result_types
                    .get(
                        usize::try_from(result.result_index)
                            .map_err(|_| cfg_error(CfgErrorCode::ResultIndex))?,
                    )
                    .cloned()
                    .ok_or_else(|| cfg_error(CfgErrorCode::ResultIndex))?;
                if operation.block == use_block {
                    if use_ordinal.is_some_and(|ordinal| operation.ordinal >= ordinal) {
                        return cfg_fail(CfgErrorCode::UseBeforeDefinition);
                    }
                    return Ok(result_type);
                }
                if !self.reachable[use_index] {
                    return cfg_fail(CfgErrorCode::UnreachableValue);
                }
                let definition_index = self.block_indices[&operation.block];
                if !self.reachable[definition_index]
                    || !bit_is_set(&self.dominators[use_index], definition_index)
                {
                    return cfg_fail(CfgErrorCode::Dominance);
                }
                Ok(result_type)
            }
        }
    }
}

fn cfg_error(code: CfgErrorCode) -> CfgValidationError {
    CfgValidationError::Cfg(CfgError::new(code))
}

fn cfg_fail<T>(code: CfgErrorCode) -> CfgResult<T> {
    Err(cfg_error(code))
}

fn check_top_level_limits(
    function: &FunctionGraph,
    parameters: &[Parameter],
    blocks: &[Block],
    operations: &[Operation],
) -> CfgResult<()> {
    if function.blocks.len() > MAX_CFG_BLOCKS
        || blocks.len() > MAX_CFG_BLOCKS
        || function.parameters.len() > MAX_CFG_PARAMETERS
        || function.type_parameters.len() > MAX_TYPE_ARGUMENTS
        || operations.len() > MAX_CFG_OPERATIONS
    {
        return cfg_fail(CfgErrorCode::ResourceLimit);
    }
    let mut values = parameters.len();
    let mut uses = 0_usize;
    for operation in operations {
        if operation.operands.len() > MAX_CFG_OPERATION_VALUES
            || operation.result_types.len() > MAX_CFG_OPERATION_VALUES
        {
            return cfg_fail(CfgErrorCode::ResourceLimit);
        }
        values = values
            .checked_add(operation.result_types.len())
            .ok_or_else(|| cfg_error(CfgErrorCode::ResourceLimit))?;
        uses = uses
            .checked_add(operation.operands.len())
            .ok_or_else(|| cfg_error(CfgErrorCode::ResourceLimit))?;
    }
    for block in blocks {
        uses = uses
            .checked_add(terminator_use_count(&block.terminator)?)
            .ok_or_else(|| cfg_error(CfgErrorCode::ResourceLimit))?;
    }
    if values > MAX_CFG_VALUES
        || uses > MAX_CFG_USES
        || blocks
            .iter()
            .any(|block| block.parameters.len() > MAX_CFG_PARAMETERS)
    {
        return cfg_fail(CfgErrorCode::ResourceLimit);
    }
    Ok(())
}

fn terminator_use_count(terminator: &Terminator) -> CfgResult<usize> {
    match terminator {
        Terminator::Return(_) => Ok(1),
        Terminator::Branch(branch) => Ok(branch.edge.arguments.len()),
        Terminator::CondBranch(branch) => 1_usize
            .checked_add(branch.if_true.arguments.len())
            .and_then(|count| count.checked_add(branch.if_false.arguments.len()))
            .ok_or_else(|| cfg_error(CfgErrorCode::ResourceLimit)),
        Terminator::VariantSwitch(switch) => {
            let mut count = 1_usize;
            for case in &switch.cases {
                count = count
                    .checked_add(case.edge.arguments.len())
                    .ok_or_else(|| cfg_error(CfgErrorCode::ResourceLimit))?;
            }
            Ok(count)
        }
        Terminator::Trap(trap) => Ok(usize::from(trap.payload.is_some())),
    }
}

fn validate_type_parameters(function: &FunctionGraph) -> CfgResult<u32> {
    for (index, parameter) in function.type_parameters.iter().enumerate() {
        if usize::try_from(parameter.ordinal).ok() != Some(index) {
            return cfg_fail(CfgErrorCode::GraphOrdinalMismatch);
        }
    }
    u32::try_from(function.type_parameters.len())
        .map_err(|_| cfg_error(CfgErrorCode::ResourceLimit))
}

fn validate_sorted_unique(values: &[EntityId]) -> CfgResult<()> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        cfg_fail(CfgErrorCode::GraphInventoryMismatch)
    }
}

fn index_unique<'a, T>(
    values: &'a [T],
    all_ids: &mut BTreeSet<EntityId>,
    id: impl Fn(&T) -> EntityId,
) -> CfgResult<BTreeMap<EntityId, &'a T>> {
    let mut output = BTreeMap::new();
    for value in values {
        let entity_id = id(value);
        if !all_ids.insert(entity_id) || output.insert(entity_id, value).is_some() {
            return cfg_fail(CfgErrorCode::GraphDuplicateEntity);
        }
    }
    Ok(output)
}

fn index_declared_ids(values: &[EntityId]) -> CfgResult<BTreeMap<EntityId, usize>> {
    let mut output = BTreeMap::new();
    for (index, id) in values.iter().copied().enumerate() {
        if output.insert(id, index).is_some() {
            return cfg_fail(CfgErrorCode::GraphDuplicateEntity);
        }
    }
    Ok(output)
}

fn validate_parameter_inventory(
    function: &FunctionGraph,
    parameters: &BTreeMap<EntityId, &Parameter>,
    blocks: &BTreeMap<EntityId, &Block>,
    function_parameters: &BTreeMap<EntityId, usize>,
    types: &TypeEnvironment,
    parameter_count: u32,
) -> CfgResult<()> {
    let mut expected = BTreeSet::new();
    for (id, ordinal) in function_parameters {
        expected.insert(*id);
        let parameter = parameters
            .get(id)
            .copied()
            .ok_or_else(|| cfg_error(CfgErrorCode::GraphUnresolvedReference))?;
        if parameter.owner != function.entity_id || parameter.role != ParameterRole::Function {
            return cfg_fail(CfgErrorCode::GraphOwnerMismatch);
        }
        if usize::try_from(parameter.ordinal).ok() != Some(*ordinal) {
            return cfg_fail(CfgErrorCode::GraphOrdinalMismatch);
        }
        types.check_type(&parameter.value_type, parameter_count)?;
    }
    for block_id in &function.blocks {
        let block = blocks[block_id];
        if block.function != function.entity_id {
            return cfg_fail(CfgErrorCode::GraphOwnerMismatch);
        }
        let declared = index_declared_ids(&block.parameters)?;
        for (id, ordinal) in declared {
            expected.insert(id);
            let parameter = parameters
                .get(&id)
                .copied()
                .ok_or_else(|| cfg_error(CfgErrorCode::GraphUnresolvedReference))?;
            if parameter.owner != block.entity_id || parameter.role != ParameterRole::Block {
                return cfg_fail(CfgErrorCode::GraphOwnerMismatch);
            }
            if usize::try_from(parameter.ordinal).ok() != Some(ordinal) {
                return cfg_fail(CfgErrorCode::GraphOrdinalMismatch);
            }
            types.check_type(&parameter.value_type, parameter_count)?;
        }
    }
    if expected.len() != parameters.len() || expected.iter().any(|id| !parameters.contains_key(id))
    {
        return cfg_fail(CfgErrorCode::GraphInventoryMismatch);
    }
    Ok(())
}

fn validate_operation_inventory(
    function: &FunctionGraph,
    blocks: &BTreeMap<EntityId, &Block>,
    operations: &BTreeMap<EntityId, &Operation>,
    types: &TypeEnvironment,
    parameter_count: u32,
) -> CfgResult<()> {
    let mut expected = BTreeSet::new();
    for block_id in &function.blocks {
        let block = blocks[block_id];
        let declared = index_declared_ids(&block.operations)?;
        for (id, ordinal) in declared {
            expected.insert(id);
            let operation = operations
                .get(&id)
                .copied()
                .ok_or_else(|| cfg_error(CfgErrorCode::GraphUnresolvedReference))?;
            if operation.block != block.entity_id {
                return cfg_fail(CfgErrorCode::GraphOwnerMismatch);
            }
            if usize::try_from(operation.ordinal).ok() != Some(ordinal) {
                return cfg_fail(CfgErrorCode::GraphOrdinalMismatch);
            }
            for result in &operation.result_types {
                types.check_type(result, parameter_count)?;
            }
        }
    }
    if expected.len() != operations.len() || expected.iter().any(|id| !operations.contains_key(id))
    {
        return cfg_fail(CfgErrorCode::GraphInventoryMismatch);
    }
    Ok(())
}

fn build_successors(
    function: &FunctionGraph,
    blocks: &BTreeMap<EntityId, &Block>,
    indices: &BTreeMap<EntityId, usize>,
) -> CfgResult<(Vec<Vec<usize>>, usize)> {
    if blocks[&function.entry_block].reachability != Reachability::Required {
        return cfg_fail(CfgErrorCode::EntryInvalid);
    }
    let mut successors = vec![Vec::new(); function.blocks.len()];
    let mut edges = 0_usize;
    for block_id in &function.blocks {
        let source = indices[block_id];
        let targets: Vec<EntityId> = match &blocks[block_id].terminator {
            Terminator::Return(_) | Terminator::Trap(_) => Vec::new(),
            Terminator::Branch(branch) => vec![branch.edge.target],
            Terminator::CondBranch(branch) => {
                vec![branch.if_true.target, branch.if_false.target]
            }
            Terminator::VariantSwitch(switch) => {
                switch.cases.iter().map(|case| case.edge.target).collect()
            }
        };
        edges = edges
            .checked_add(targets.len())
            .ok_or_else(|| cfg_error(CfgErrorCode::ResourceLimit))?;
        if edges > MAX_CFG_EDGES {
            return cfg_fail(CfgErrorCode::ResourceLimit);
        }
        for target in targets {
            let target = indices
                .get(&target)
                .copied()
                .ok_or_else(|| cfg_error(CfgErrorCode::TargetInvalid))?;
            successors[source].push(target);
        }
    }
    Ok((successors, edges))
}

fn compute_reachability(entry: usize, successors: &[Vec<usize>]) -> Vec<bool> {
    let mut reachable = vec![false; successors.len()];
    let mut queue = VecDeque::from([entry]);
    reachable[entry] = true;
    while let Some(block) = queue.pop_front() {
        for target in &successors[block] {
            if !reachable[*target] {
                reachable[*target] = true;
                queue.push_back(*target);
            }
        }
    }
    reachable
}

fn validate_reachability(
    function: &FunctionGraph,
    blocks: &BTreeMap<EntityId, &Block>,
    reachable: &[bool],
) -> CfgResult<()> {
    for (id, is_reachable) in function.blocks.iter().zip(reachable) {
        let declared = blocks[id].reachability;
        if (*is_reachable && declared != Reachability::Required)
            || (!*is_reachable && declared != Reachability::ExplicitlyUnreachable)
        {
            return cfg_fail(CfgErrorCode::Reachability);
        }
    }
    Ok(())
}

fn compute_dominators(
    entry: usize,
    successors: &[Vec<usize>],
    reachable: &[bool],
) -> CfgResult<(Vec<Vec<u64>>, u64)> {
    let count = successors.len();
    let words = count.div_ceil(64);
    let mut predecessors = vec![Vec::new(); count];
    for (source, targets) in successors.iter().enumerate() {
        if reachable[source] {
            for target in targets {
                if reachable[*target] {
                    predecessors[*target].push(source);
                }
            }
        }
    }
    let mut reachable_bits = vec![0_u64; words];
    for (index, is_reachable) in reachable.iter().enumerate() {
        if *is_reachable {
            set_bit(&mut reachable_bits, index);
        }
    }
    let mut dominators = vec![vec![0_u64; words]; count];
    for index in 0..count {
        if index == entry {
            set_bit(&mut dominators[index], index);
        } else if reachable[index] {
            dominators[index].clone_from(&reachable_bits);
        }
    }

    let mut work = 0_u64;
    for _round in 0..MAX_CFG_BLOCKS {
        let mut changed = false;
        for block in 0..count {
            if block == entry || !reachable[block] {
                continue;
            }
            let Some((first, rest)) = predecessors[block].split_first() else {
                return cfg_fail(CfgErrorCode::Reachability);
            };
            let mut next = dominators[*first].clone();
            charge_work(&mut work, u64::try_from(words).unwrap_or(u64::MAX))?;
            for predecessor in rest {
                for (word, predecessor_word) in next.iter_mut().zip(&dominators[*predecessor]) {
                    *word &= *predecessor_word;
                }
                charge_work(&mut work, u64::try_from(words).unwrap_or(u64::MAX))?;
            }
            set_bit(&mut next, block);
            charge_work(&mut work, u64::try_from(words).unwrap_or(u64::MAX))?;
            if next != dominators[block] {
                dominators[block] = next;
                changed = true;
            }
        }
        if !changed {
            return Ok((dominators, work));
        }
    }
    cfg_fail(CfgErrorCode::ResourceLimit)
}

fn charge_work(work: &mut u64, amount: u64) -> CfgResult<()> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| cfg_error(CfgErrorCode::ResourceLimit))?;
    if *work > MAX_DOMINATOR_WORD_OPERATIONS {
        cfg_fail(CfgErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn set_bit(bits: &mut [u64], index: usize) {
    bits[index / 64] |= 1_u64 << (index % 64);
}

fn bit_is_set(bits: &[u64], index: usize) -> bool {
    bits[index / 64] & (1_u64 << (index % 64)) != 0
}

fn contains_type_parameter(value: &TypeExpr) -> bool {
    match value {
        TypeExpr::TypeParameter(_) => true,
        TypeExpr::Tuple(values) => values.iter().any(contains_type_parameter),
        TypeExpr::Named(named) => named.arguments.iter().any(contains_type_parameter),
        TypeExpr::Vector(value) | TypeExpr::Option(value) | TypeExpr::LocalCell(value) => {
            contains_type_parameter(value)
        }
        TypeExpr::OrderedMap { key, value } => {
            contains_type_parameter(key) || contains_type_parameter(value)
        }
        TypeExpr::Result { ok, error } => {
            contains_type_parameter(ok) || contains_type_parameter(error)
        }
        TypeExpr::FunctionRef(function) => {
            function.parameters.iter().any(contains_type_parameter)
                || contains_type_parameter(&function.result)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TypeErrorCode;
    use sley_ssmc::{
        BranchTerminator, CondBranchTerminator, FunctionRefValue, Immediate, IntegerWidth, Opcode,
        OperationResultRef, ReturnTerminator, SwitchCase, SwitchEdge, TrapCode, TrapTerminator,
        TypeDefinition, TypeParameterDef, VariantCase, Visibility,
    };

    #[derive(Clone)]
    struct Fixture {
        types: TypeEnvironment,
        function: FunctionGraph,
        parameters: Vec<Parameter>,
        blocks: Vec<Block>,
        operations: Vec<Operation>,
    }

    impl Fixture {
        fn validate(&self) -> CfgResult<CfgReport> {
            validate_function_graph(
                &self.types,
                &self.function,
                &self.parameters,
                &self.blocks,
                &self.operations,
            )
        }
    }

    fn id(value: u32) -> EntityId {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&value.to_be_bytes());
        EntityId::from_bytes(bytes)
    }

    fn function_parameter(
        entity_id: EntityId,
        function: EntityId,
        value_type: TypeExpr,
    ) -> Parameter {
        Parameter {
            entity_id,
            owner: function,
            role: ParameterRole::Function,
            ordinal: 0,
            value_type,
        }
    }

    fn block_parameter(
        entity_id: EntityId,
        block: EntityId,
        ordinal: u32,
        value_type: TypeExpr,
    ) -> Parameter {
        Parameter {
            entity_id,
            owner: block,
            role: ParameterRole::Block,
            ordinal,
            value_type,
        }
    }

    fn operation(
        entity_id: EntityId,
        block: EntityId,
        ordinal: u32,
        operands: Vec<ValueRef>,
        result_type: TypeExpr,
    ) -> Operation {
        Operation {
            entity_id,
            block,
            ordinal,
            opcode: Opcode::ConstantRef,
            operands,
            result_types: vec![result_type],
            immediate: Immediate::Entity(id(900)),
        }
    }

    fn base_fixture() -> Fixture {
        let function_id = id(1);
        let parameter_id = id(2);
        let block_id = id(3);
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            function: FunctionGraph {
                entity_id: function_id,
                type_parameters: Vec::new(),
                parameters: vec![parameter_id],
                result_type: TypeExpr::Unit,
                effects: Vec::new(),
                entry_block: block_id,
                blocks: vec![block_id],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![function_parameter(
                parameter_id,
                function_id,
                TypeExpr::Unit,
            )],
            blocks: vec![Block {
                entity_id: block_id,
                function: function_id,
                parameters: Vec::new(),
                operations: Vec::new(),
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(parameter_id),
                }),
                reachability: Reachability::Required,
            }],
            operations: Vec::new(),
        }
    }

    fn branch_fixture() -> Fixture {
        let function_id = id(1);
        let input = id(2);
        let entry = id(3);
        let target = id(4);
        let block_value = id(5);
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            function: FunctionGraph {
                entity_id: function_id,
                type_parameters: Vec::new(),
                parameters: vec![input],
                result_type: TypeExpr::Bool,
                effects: Vec::new(),
                entry_block: entry,
                blocks: vec![entry, target],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                function_parameter(input, function_id, TypeExpr::Bool),
                block_parameter(block_value, target, 0, TypeExpr::Bool),
            ],
            blocks: vec![
                Block {
                    entity_id: entry,
                    function: function_id,
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
                    function: function_id,
                    parameters: vec![block_value],
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(block_value),
                    }),
                    reachability: Reachability::Required,
                },
            ],
            operations: Vec::new(),
        }
    }

    fn option_switch_fixture() -> Fixture {
        let function_id = id(1);
        let selector = id(2);
        let unit = id(3);
        let entry = id(4);
        let none_block = id(5);
        let some_block = id(6);
        let payload = id(7);
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            function: FunctionGraph {
                entity_id: function_id,
                type_parameters: Vec::new(),
                parameters: vec![selector, unit],
                result_type: TypeExpr::Unit,
                effects: Vec::new(),
                entry_block: entry,
                blocks: vec![entry, none_block, some_block],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                function_parameter(
                    selector,
                    function_id,
                    TypeExpr::Option(Box::new(TypeExpr::Bool)),
                ),
                Parameter {
                    entity_id: unit,
                    owner: function_id,
                    role: ParameterRole::Function,
                    ordinal: 1,
                    value_type: TypeExpr::Unit,
                },
                block_parameter(payload, some_block, 0, TypeExpr::Bool),
            ],
            blocks: vec![
                Block {
                    entity_id: entry,
                    function: function_id,
                    parameters: Vec::new(),
                    operations: Vec::new(),
                    terminator: Terminator::VariantSwitch(VariantSwitchTerminator {
                        value: ValueRef::Parameter(selector),
                        cases: vec![
                            SwitchCase {
                                case_key: CaseKey::Builtin(BuiltinCase::None),
                                edge: SwitchEdge {
                                    target: none_block,
                                    arguments: Vec::new(),
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
                    function: function_id,
                    parameters: Vec::new(),
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(unit),
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: some_block,
                    function: function_id,
                    parameters: vec![payload],
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(unit),
                    }),
                    reachability: Reachability::Required,
                },
            ],
            operations: Vec::new(),
        }
    }

    fn cfg_code(result: CfgResult<CfgReport>) -> CfgErrorCode {
        match result.unwrap_err() {
            CfgValidationError::Cfg(error) => error.code(),
            CfgValidationError::Type(error) => panic!("unexpected type error: {error}"),
        }
    }

    #[test]
    fn stable_cfg_codes_are_frozen() {
        let codes = [
            CfgErrorCode::GraphDuplicateEntity,
            CfgErrorCode::GraphInventoryMismatch,
            CfgErrorCode::GraphOwnerMismatch,
            CfgErrorCode::GraphOrdinalMismatch,
            CfgErrorCode::GraphUnresolvedReference,
            CfgErrorCode::EntryInvalid,
            CfgErrorCode::TargetInvalid,
            CfgErrorCode::TargetArguments,
            CfgErrorCode::ReturnType,
            CfgErrorCode::BoolRequired,
            CfgErrorCode::SwitchType,
            CfgErrorCode::SwitchCases,
            CfgErrorCode::SwitchPayload,
            CfgErrorCode::ValueUnresolved,
            CfgErrorCode::ResultIndex,
            CfgErrorCode::UseBeforeDefinition,
            CfgErrorCode::Dominance,
            CfgErrorCode::Reachability,
            CfgErrorCode::UnreachableValue,
            CfgErrorCode::TrapPayload,
            CfgErrorCode::ResourceLimit,
        ];
        assert_eq!(
            codes.map(CfgErrorCode::numeric),
            std::array::from_fn(|index| {
                22_000 + u32::try_from(index).expect("code index fits u32")
            })
        );
        assert!(codes.iter().all(|code| {
            code.as_str().starts_with("CFG_") || code.as_str().starts_with("GRAPH_")
        }));
    }

    #[test]
    fn straight_line_and_operation_result_validate() {
        let mut fixture = base_fixture();
        let operation_id = id(4);
        fixture.blocks[0].operations.push(operation_id);
        fixture.operations.push(operation(
            operation_id,
            fixture.blocks[0].entity_id,
            0,
            Vec::new(),
            TypeExpr::Unit,
        ));
        fixture.blocks[0].terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::OperationResult(OperationResultRef {
                operation: operation_id,
                result_index: 0,
            }),
        });
        assert_eq!(
            fixture.validate().unwrap(),
            CfgReport {
                reachable_blocks: vec![id(3)],
                edges: 0,
                dominator_word_operations: 0,
            }
        );
    }

    #[test]
    fn branch_arguments_and_inventory_input_order_are_deterministic() {
        let first = branch_fixture();
        let mut second = first.clone();
        second.parameters.reverse();
        second.blocks.reverse();
        assert_eq!(first.validate().unwrap(), second.validate().unwrap());
        assert_eq!(first.validate().unwrap().edges, 1);
    }

    #[test]
    fn operation_use_failures_precede_all_terminator_failures() {
        let mut fixture = branch_fixture();
        let operation_id = id(6);
        let target = fixture.function.blocks[1];
        fixture.blocks[0].terminator = Terminator::Branch(BranchTerminator {
            edge: TargetEdge {
                target,
                arguments: Vec::new(),
            },
        });
        fixture.blocks[1].operations.push(operation_id);
        fixture.operations.push(operation(
            operation_id,
            target,
            0,
            vec![ValueRef::Parameter(id(99))],
            TypeExpr::Unit,
        ));

        assert_eq!(cfg_code(fixture.validate()), CfgErrorCode::ValueUnresolved);
    }

    #[test]
    fn conditional_and_legal_backedge_loop_terminate() {
        let function_id = id(1);
        let input = id(2);
        let entry = id(3);
        let header = id(4);
        let header_value = id(5);
        let body = id(6);
        let body_value = id(7);
        let exit = id(8);
        let exit_value = id(9);
        let fixture = Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            function: FunctionGraph {
                entity_id: function_id,
                type_parameters: Vec::new(),
                parameters: vec![input],
                result_type: TypeExpr::Bool,
                effects: Vec::new(),
                entry_block: entry,
                blocks: vec![entry, header, body, exit],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                function_parameter(input, function_id, TypeExpr::Bool),
                block_parameter(header_value, header, 0, TypeExpr::Bool),
                block_parameter(body_value, body, 0, TypeExpr::Bool),
                block_parameter(exit_value, exit, 0, TypeExpr::Bool),
            ],
            blocks: vec![
                Block {
                    entity_id: entry,
                    function: function_id,
                    parameters: Vec::new(),
                    operations: Vec::new(),
                    terminator: Terminator::Branch(BranchTerminator {
                        edge: TargetEdge {
                            target: header,
                            arguments: vec![ValueRef::Parameter(input)],
                        },
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: header,
                    function: function_id,
                    parameters: vec![header_value],
                    operations: Vec::new(),
                    terminator: Terminator::CondBranch(CondBranchTerminator {
                        condition: ValueRef::Parameter(header_value),
                        if_true: TargetEdge {
                            target: body,
                            arguments: vec![ValueRef::Parameter(header_value)],
                        },
                        if_false: TargetEdge {
                            target: exit,
                            arguments: vec![ValueRef::Parameter(header_value)],
                        },
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: body,
                    function: function_id,
                    parameters: vec![body_value],
                    operations: Vec::new(),
                    terminator: Terminator::Branch(BranchTerminator {
                        edge: TargetEdge {
                            target: header,
                            arguments: vec![ValueRef::Parameter(body_value)],
                        },
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: exit,
                    function: function_id,
                    parameters: vec![exit_value],
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(exit_value),
                    }),
                    reachability: Reachability::Required,
                },
            ],
            operations: Vec::new(),
        };
        let report = fixture.validate().unwrap();
        assert_eq!(report.reachable_blocks, vec![entry, header, body, exit]);
        assert_eq!(report.edges, 4);
        assert!(report.dominator_word_operations > 0);
    }

    #[test]
    fn explicitly_unreachable_local_block_is_valid() {
        let mut fixture = base_fixture();
        let unreachable = id(4);
        fixture.function.blocks.push(unreachable);
        fixture.blocks.push(Block {
            entity_id: unreachable,
            function: fixture.function.entity_id,
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: Terminator::Trap(TrapTerminator {
                code: TrapCode::Unreachable,
                payload: None,
            }),
            reachability: Reachability::ExplicitlyUnreachable,
        });
        assert_eq!(fixture.validate().unwrap().reachable_blocks, vec![id(3)]);
    }

    #[test]
    fn duplicate_entity_and_extra_inventory_fail() {
        let mut duplicate = base_fixture();
        duplicate.parameters[0].entity_id = duplicate.blocks[0].entity_id;
        assert_eq!(
            cfg_code(duplicate.validate()),
            CfgErrorCode::GraphDuplicateEntity
        );

        let mut extra = base_fixture();
        extra.parameters.push(function_parameter(
            id(9),
            extra.function.entity_id,
            TypeExpr::Unit,
        ));
        assert_eq!(
            cfg_code(extra.validate()),
            CfgErrorCode::GraphInventoryMismatch
        );
    }

    #[test]
    fn owner_ordinal_and_unresolved_inventory_fail_exactly() {
        let mut owner = base_fixture();
        owner.parameters[0].owner = id(99);
        assert_eq!(cfg_code(owner.validate()), CfgErrorCode::GraphOwnerMismatch);

        let mut ordinal = base_fixture();
        ordinal.parameters[0].ordinal = 1;
        assert_eq!(
            cfg_code(ordinal.validate()),
            CfgErrorCode::GraphOrdinalMismatch
        );

        let mut unresolved = base_fixture();
        unresolved.parameters.clear();
        assert_eq!(
            cfg_code(unresolved.validate()),
            CfgErrorCode::GraphUnresolvedReference
        );
    }

    #[test]
    fn entry_and_target_must_be_listed_same_function_blocks() {
        let mut entry = base_fixture();
        entry.function.entry_block = id(99);
        assert_eq!(cfg_code(entry.validate()), CfgErrorCode::EntryInvalid);

        let mut target = branch_fixture();
        let Terminator::Branch(branch) = &mut target.blocks[0].terminator else {
            panic!("branch fixture");
        };
        branch.edge.target = id(99);
        assert_eq!(cfg_code(target.validate()), CfgErrorCode::TargetInvalid);
    }

    #[test]
    fn edge_arguments_return_and_condition_are_exactly_typed() {
        let mut edge = branch_fixture();
        let Terminator::Branch(branch) = &mut edge.blocks[0].terminator else {
            panic!("branch fixture");
        };
        branch.edge.arguments.clear();
        assert_eq!(cfg_code(edge.validate()), CfgErrorCode::TargetArguments);

        let mut returned = base_fixture();
        returned.function.result_type = TypeExpr::Bool;
        assert_eq!(cfg_code(returned.validate()), CfgErrorCode::ReturnType);

        let mut condition = branch_fixture();
        condition.blocks[0].terminator = Terminator::CondBranch(CondBranchTerminator {
            condition: ValueRef::Parameter(condition.function.parameters[0]),
            if_true: TargetEdge {
                target: condition.function.blocks[1],
                arguments: vec![ValueRef::Parameter(condition.function.parameters[0])],
            },
            if_false: TargetEdge {
                target: condition.function.blocks[1],
                arguments: vec![ValueRef::Parameter(condition.function.parameters[0])],
            },
        });
        condition.parameters[0].value_type = TypeExpr::Unit;
        condition.function.result_type = TypeExpr::Bool;
        assert_eq!(cfg_code(condition.validate()), CfgErrorCode::BoolRequired);
    }

    #[test]
    fn option_switch_payload_and_cases_validate() {
        let fixture = option_switch_fixture();
        assert_eq!(fixture.validate().unwrap().edges, 2);
    }

    #[test]
    fn named_variant_switch_uses_member_domain() {
        let definition_id = id(20);
        let case = sley_ssmc::MemberId::from_bytes([7; 32]);
        let definition = TypeDefinition {
            entity_id: definition_id,
            type_parameters: Vec::new(),
            form: TypeDefForm::Variant(vec![VariantCase {
                member_id: case,
                payload_type: None,
            }]),
            invariants: Vec::new(),
            visibility: Visibility::Private,
        };
        let mut fixture = option_switch_fixture();
        fixture.types = TypeEnvironment::new(vec![definition]).unwrap();
        fixture.parameters[0].value_type = TypeExpr::Named(sley_ssmc::NamedType {
            definition: definition_id,
            arguments: Vec::new(),
        });
        let Terminator::VariantSwitch(switch) = &mut fixture.blocks[0].terminator else {
            panic!("switch fixture");
        };
        switch.cases = vec![SwitchCase {
            case_key: CaseKey::Member(case),
            edge: SwitchEdge {
                target: fixture.function.blocks[1],
                arguments: Vec::new(),
            },
        }];
        fixture.function.blocks.pop();
        fixture.blocks.pop();
        fixture.parameters.pop();
        assert_eq!(fixture.validate().unwrap().edges, 1);
    }

    #[test]
    fn switch_type_case_domain_order_and_exhaustiveness_fail() {
        let mut wrong_type = option_switch_fixture();
        wrong_type.parameters[0].value_type = TypeExpr::Bool;
        assert_eq!(cfg_code(wrong_type.validate()), CfgErrorCode::SwitchType);

        let mut wrong_cases = option_switch_fixture();
        let Terminator::VariantSwitch(switch) = &mut wrong_cases.blocks[0].terminator else {
            panic!("switch fixture");
        };
        switch.cases.reverse();
        assert_eq!(cfg_code(wrong_cases.validate()), CfgErrorCode::SwitchCases);

        let mut missing = option_switch_fixture();
        let Terminator::VariantSwitch(switch) = &mut missing.blocks[0].terminator else {
            panic!("switch fixture");
        };
        switch.cases.pop();
        missing.blocks[2].reachability = Reachability::ExplicitlyUnreachable;
        assert_eq!(cfg_code(missing.validate()), CfgErrorCode::SwitchCases);
    }

    #[test]
    fn payload_free_switch_case_rejects_case_payload() {
        let mut fixture = option_switch_fixture();
        let Terminator::VariantSwitch(switch) = &mut fixture.blocks[0].terminator else {
            panic!("switch fixture");
        };
        switch.cases[0]
            .edge
            .arguments
            .push(SwitchArgument::CasePayload);
        fixture.blocks[1].parameters.push(id(8));
        fixture.parameters.push(block_parameter(
            id(8),
            fixture.blocks[1].entity_id,
            0,
            TypeExpr::Bool,
        ));
        assert_eq!(cfg_code(fixture.validate()), CfgErrorCode::SwitchPayload);
    }

    #[test]
    fn unresolved_result_index_and_use_before_definition_fail() {
        let mut unresolved = base_fixture();
        unresolved.blocks[0].terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::OperationResult(OperationResultRef {
                operation: id(99),
                result_index: 0,
            }),
        });
        assert_eq!(
            cfg_code(unresolved.validate()),
            CfgErrorCode::ValueUnresolved
        );

        let mut result_index = base_fixture();
        let op = operation(id(4), id(3), 0, Vec::new(), TypeExpr::Unit);
        result_index.blocks[0].operations.push(id(4));
        result_index.operations.push(op);
        result_index.blocks[0].terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::OperationResult(OperationResultRef {
                operation: id(4),
                result_index: 1,
            }),
        });
        assert_eq!(cfg_code(result_index.validate()), CfgErrorCode::ResultIndex);

        let mut use_before = base_fixture();
        use_before.blocks[0].operations = vec![id(4), id(5)];
        use_before.operations = vec![
            operation(
                id(4),
                id(3),
                0,
                vec![ValueRef::OperationResult(OperationResultRef {
                    operation: id(5),
                    result_index: 0,
                })],
                TypeExpr::Unit,
            ),
            operation(id(5), id(3), 1, Vec::new(), TypeExpr::Unit),
        ];
        assert_eq!(
            cfg_code(use_before.validate()),
            CfgErrorCode::UseBeforeDefinition
        );
    }

    #[test]
    fn diamond_cross_block_result_must_dominate_use() {
        let function_id = id(1);
        let condition = id(2);
        let entry = id(3);
        let left = id(4);
        let right = id(5);
        let merge = id(6);
        let left_op = id(7);
        let fixture = Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            function: FunctionGraph {
                entity_id: function_id,
                type_parameters: Vec::new(),
                parameters: vec![condition],
                result_type: TypeExpr::Unit,
                effects: Vec::new(),
                entry_block: entry,
                blocks: vec![entry, left, right, merge],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![function_parameter(condition, function_id, TypeExpr::Bool)],
            blocks: vec![
                Block {
                    entity_id: entry,
                    function: function_id,
                    parameters: Vec::new(),
                    operations: Vec::new(),
                    terminator: Terminator::CondBranch(CondBranchTerminator {
                        condition: ValueRef::Parameter(condition),
                        if_true: TargetEdge {
                            target: left,
                            arguments: Vec::new(),
                        },
                        if_false: TargetEdge {
                            target: right,
                            arguments: Vec::new(),
                        },
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: left,
                    function: function_id,
                    parameters: Vec::new(),
                    operations: vec![left_op],
                    terminator: Terminator::Branch(BranchTerminator {
                        edge: TargetEdge {
                            target: merge,
                            arguments: Vec::new(),
                        },
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: right,
                    function: function_id,
                    parameters: Vec::new(),
                    operations: Vec::new(),
                    terminator: Terminator::Branch(BranchTerminator {
                        edge: TargetEdge {
                            target: merge,
                            arguments: Vec::new(),
                        },
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: merge,
                    function: function_id,
                    parameters: Vec::new(),
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::OperationResult(OperationResultRef {
                            operation: left_op,
                            result_index: 0,
                        }),
                    }),
                    reachability: Reachability::Required,
                },
            ],
            operations: vec![operation(left_op, left, 0, Vec::new(), TypeExpr::Unit)],
        };
        assert_eq!(cfg_code(fixture.validate()), CfgErrorCode::Dominance);
    }

    #[test]
    fn reachability_marker_and_unreachable_cross_block_value_fail() {
        let mut marker = base_fixture();
        marker.blocks[0].reachability = Reachability::ExplicitlyUnreachable;
        assert_eq!(cfg_code(marker.validate()), CfgErrorCode::EntryInvalid);

        let mut cross = base_fixture();
        let op_id = id(4);
        let unreachable = id(5);
        cross.blocks[0].operations.push(op_id);
        cross.operations.push(operation(
            op_id,
            cross.blocks[0].entity_id,
            0,
            Vec::new(),
            TypeExpr::Unit,
        ));
        cross.function.blocks.push(unreachable);
        cross.blocks.push(Block {
            entity_id: unreachable,
            function: cross.function.entity_id,
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::OperationResult(OperationResultRef {
                    operation: op_id,
                    result_index: 0,
                }),
            }),
            reachability: Reachability::ExplicitlyUnreachable,
        });
        assert_eq!(cfg_code(cross.validate()), CfgErrorCode::UnreachableValue);
    }

    #[test]
    fn non_entry_reachability_marker_mismatch_uses_reachability_code() {
        let mut fixture = branch_fixture();
        fixture.blocks[1].reachability = Reachability::ExplicitlyUnreachable;
        assert_eq!(cfg_code(fixture.validate()), CfgErrorCode::Reachability);
    }

    #[test]
    fn nonpersistable_or_unproven_trap_payload_fails() {
        let mut fixture = base_fixture();
        fixture.parameters[0].value_type = TypeExpr::CapabilityToken(fixture.function.entity_id);
        fixture.blocks[0].terminator = Terminator::Trap(TrapTerminator {
            code: TrapCode::Unreachable,
            payload: Some(ValueRef::Parameter(fixture.function.parameters[0])),
        });
        fixture.function.result_type = TypeExpr::Unit;
        assert_eq!(cfg_code(fixture.validate()), CfgErrorCode::TrapPayload);

        let mut generic = base_fixture();
        generic.function.type_parameters = vec![TypeParameterDef { ordinal: 0 }];
        generic.parameters[0].value_type = TypeExpr::TypeParameter(0);
        generic.blocks[0].terminator = Terminator::Trap(TrapTerminator {
            code: TrapCode::Unreachable,
            payload: Some(ValueRef::Parameter(generic.function.parameters[0])),
        });
        assert_eq!(cfg_code(generic.validate()), CfgErrorCode::TrapPayload);
    }

    #[test]
    fn count_and_edge_limits_fail_before_traversal() {
        let mut blocks = base_fixture();
        blocks.function.blocks = (0..=MAX_CFG_BLOCKS)
            .map(|index| id(u32::try_from(index + 100).expect("block index fits")))
            .collect();
        assert_eq!(cfg_code(blocks.validate()), CfgErrorCode::ResourceLimit);

        let mut edges = option_switch_fixture();
        let Terminator::VariantSwitch(switch) = &mut edges.blocks[0].terminator else {
            panic!("switch fixture");
        };
        let target = edges.function.blocks[1];
        switch.cases = (0..=MAX_CFG_EDGES)
            .map(|_| SwitchCase {
                case_key: CaseKey::Builtin(BuiltinCase::None),
                edge: SwitchEdge {
                    target,
                    arguments: Vec::new(),
                },
            })
            .collect();
        assert_eq!(cfg_code(edges.validate()), CfgErrorCode::ResourceLimit);
    }

    #[test]
    fn earlier_type_failure_is_preserved() {
        let mut fixture = base_fixture();
        fixture.function.result_type = TypeExpr::UInt(IntegerWidth::from_bits(24));
        match fixture.validate().unwrap_err() {
            CfgValidationError::Type(error) => {
                assert_eq!(error.code(), TypeErrorCode::WidthInvalid);
            }
            CfgValidationError::Cfg(error) => panic!("unexpected CFG error: {error}"),
        }
    }

    #[test]
    fn function_reference_immediate_does_not_affect_cfg_judgment() {
        let mut fixture = base_fixture();
        let op_id = id(4);
        fixture.blocks[0].operations.push(op_id);
        fixture.operations.push(Operation {
            entity_id: op_id,
            block: fixture.blocks[0].entity_id,
            ordinal: 0,
            opcode: Opcode::FunctionRef,
            operands: Vec::new(),
            result_types: vec![TypeExpr::FunctionRef(sley_ssmc::FunctionType {
                parameters: Vec::new(),
                result: Box::new(TypeExpr::Unit),
                effects: Vec::new(),
            })],
            immediate: Immediate::Function(FunctionRefValue {
                function: id(99),
                type_arguments: Vec::new(),
            }),
        });
        fixture.blocks[0].terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::Parameter(fixture.function.parameters[0]),
        });
        fixture.validate().unwrap();
    }

    #[test]
    fn seeded_unresolved_reference_fuzz_smoke_never_accepts() {
        for seed in 100_u32..228 {
            let mut fixture = base_fixture();
            fixture.blocks[0].terminator = Terminator::Return(ReturnTerminator {
                value: ValueRef::OperationResult(OperationResultRef {
                    operation: id(seed),
                    result_index: seed % 4,
                }),
            });
            assert_eq!(
                cfg_code(fixture.validate()),
                CfgErrorCode::ValueUnresolved,
                "seed {seed}"
            );
        }
    }
}
