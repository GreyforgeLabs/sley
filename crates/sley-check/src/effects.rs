//! S20-230 deterministic static effect closure and scope validation.

use core::{cmp::Ordering, fmt};
use std::collections::{BTreeMap, BTreeSet};

use sley_id::EntityId;
use sley_ssmc::{
    AdapterImport, Block, BuiltinFailureKind, CapabilityRequirement, ConstData, ConstValue,
    EffectDefinition, EffectKind, FunctionGraph, Immediate, Opcode, Operation, Parameter,
    ResultConst, Terminator, TypeExpr, ValueRef,
};

use crate::{
    TypeEnvironment, TypeError,
    cfg::{CfgValidationError, validate_function_graph},
};

/// Maximum functions in one effect-program request.
pub const MAX_EFFECT_FUNCTIONS: usize = 4_096;
/// Maximum effect definitions in one request.
pub const MAX_EFFECT_DEFINITIONS: usize = 4_096;
/// Maximum capability requirements in one request.
pub const MAX_CAPABILITY_REQUIREMENTS: usize = 4_096;
/// Maximum adapter imports in one request.
pub const MAX_ADAPTER_IMPORTS: usize = 4_096;
/// Maximum known contract identities in one request.
pub const MAX_EFFECT_CONTRACTS: usize = 65_535;
/// Maximum function-owned entities across the request.
pub const MAX_EFFECT_GRAPH_ENTITIES: usize = 2_000_000;
/// Maximum operations across all supplied functions.
pub const MAX_EFFECT_OPERATIONS: usize = 1_000_000;
/// Maximum CFG value uses across all supplied functions.
pub const MAX_EFFECT_CFG_USES: usize = 2_000_000;
/// Maximum CFG edges across all supplied functions.
pub const MAX_EFFECT_CFG_EDGES: usize = 65_535;
/// Maximum summed prior-phase dominator work.
pub const MAX_EFFECT_DOMINATOR_WORK: u64 = 50_000_000;
/// Maximum distinct direct-call operations.
pub const MAX_EFFECT_CALL_EDGES: usize = 16_384;
/// Maximum effect identities in one declared set.
pub const MAX_EFFECT_SET: usize = 4_096;
/// Maximum allowed scopes in one requirement.
pub const MAX_ALLOWED_SCOPES: usize = 65_535;
/// Maximum allowed scopes across the request.
pub const MAX_TOTAL_ALLOWED_SCOPES: usize = 1_000_000;
/// Maximum constraint contracts in one requirement.
pub const MAX_CONSTRAINT_CONTRACTS: usize = 65_535;
/// Maximum constraint-contract memberships across the request.
pub const MAX_TOTAL_CONSTRAINT_CONTRACTS: usize = 1_000_000;
/// Maximum closure memberships across all functions.
pub const MAX_EFFECT_CLOSURE_MEMBERSHIPS: usize = 1_000_000;
/// Maximum closure convergence rounds.
pub const MAX_EFFECT_CLOSURE_ROUNDS: usize = 4_096;
/// Maximum charged closure set/edge operations.
pub const MAX_EFFECT_CLOSURE_WORK: u64 = 50_000_000;

/// Stable S20-230 effect-system failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectErrorCode {
    /// `EFFECT_UNRESOLVED_ENTITY`
    UnresolvedEntity,
    /// `EFFECT_WRONG_ENTITY_KIND`
    WrongEntityKind,
    /// `EFFECT_SET_NOT_CANONICAL`
    SetNotCanonical,
    /// `EFFECT_CLOSURE_MISMATCH`
    ClosureMismatch,
    /// `EFFECT_CALL_TYPE`
    CallType,
    /// `EFFECT_REQUEST_TYPE`
    RequestType,
    /// `ADAPTER_EFFECT_CARDINALITY`
    AdapterEffectCardinality,
    /// `ADAPTER_EFFECT_KIND`
    AdapterEffectKind,
    /// `ADAPTER_INVOKE_TYPE`
    AdapterInvokeType,
    /// `CAPABILITY_REQUIREMENT_TYPE`
    CapabilityRequirementType,
    /// `CAPABILITY_SCOPE_CONST_TYPE`
    CapabilityScopeConstType,
    /// `CAPABILITY_SCOPE_CONST_CANONICAL`
    CapabilityScopeConstCanonical,
    /// `CONSTRAINT_CONTRACT_BOUNDARY`
    ConstraintContractBoundary,
    /// `EFFECT_RESOURCE_LIMIT`
    ResourceLimit,
}

impl EffectErrorCode {
    /// Returns the exact stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnresolvedEntity => "EFFECT_UNRESOLVED_ENTITY",
            Self::WrongEntityKind => "EFFECT_WRONG_ENTITY_KIND",
            Self::SetNotCanonical => "EFFECT_SET_NOT_CANONICAL",
            Self::ClosureMismatch => "EFFECT_CLOSURE_MISMATCH",
            Self::CallType => "EFFECT_CALL_TYPE",
            Self::RequestType => "EFFECT_REQUEST_TYPE",
            Self::AdapterEffectCardinality => "ADAPTER_EFFECT_CARDINALITY",
            Self::AdapterEffectKind => "ADAPTER_EFFECT_KIND",
            Self::AdapterInvokeType => "ADAPTER_INVOKE_TYPE",
            Self::CapabilityRequirementType => "CAPABILITY_REQUIREMENT_TYPE",
            Self::CapabilityScopeConstType => "CAPABILITY_SCOPE_CONST_TYPE",
            Self::CapabilityScopeConstCanonical => "CAPABILITY_SCOPE_CONST_CANONICAL",
            Self::ConstraintContractBoundary => "CONSTRAINT_CONTRACT_BOUNDARY",
            Self::ResourceLimit => "EFFECT_RESOURCE_LIMIT",
        }
    }

    /// Returns the exact stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::UnresolvedEntity => 23_000,
            Self::WrongEntityKind => 23_001,
            Self::SetNotCanonical => 23_002,
            Self::ClosureMismatch => 23_003,
            Self::CallType => 23_004,
            Self::RequestType => 23_005,
            Self::AdapterEffectCardinality => 23_006,
            Self::AdapterEffectKind => 23_007,
            Self::AdapterInvokeType => 23_008,
            Self::CapabilityRequirementType => 23_009,
            Self::CapabilityScopeConstType => 23_010,
            Self::CapabilityScopeConstCanonical => 23_011,
            Self::ConstraintContractBoundary => 23_012,
            Self::ResourceLimit => 23_013,
        }
    }
}

impl fmt::Display for EffectErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable effect error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectError {
    code: EffectErrorCode,
}

impl EffectError {
    /// Constructs an error from its frozen code.
    #[must_use]
    pub const fn new(code: EffectErrorCode) -> Self {
        Self { code }
    }

    /// Returns the frozen code.
    #[must_use]
    pub const fn code(&self) -> EffectErrorCode {
        self.code
    }
}

impl fmt::Display for EffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for EffectError {}

/// An effect-phase or preserved earlier failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectValidationError {
    /// Exact S20-210 failure outside a function CFG request.
    Type(TypeError),
    /// Exact S20-210/S20-220 function-graph failure.
    Cfg(CfgValidationError),
    /// S20-230 effect failure.
    Effect(EffectError),
}

impl fmt::Display for EffectValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(error) => error.fmt(formatter),
            Self::Cfg(error) => error.fmt(formatter),
            Self::Effect(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for EffectValidationError {}

impl From<TypeError> for EffectValidationError {
    fn from(value: TypeError) -> Self {
        Self::Type(value)
    }
}

impl From<CfgValidationError> for EffectValidationError {
    fn from(value: CfgValidationError) -> Self {
        Self::Cfg(value)
    }
}

/// S20-230 validation result.
pub type EffectResult<T> = core::result::Result<T, EffectValidationError>;

/// One complete function-owned validation unit.
#[derive(Clone, Copy, Debug)]
pub struct FunctionUnit<'a> {
    /// Function graph.
    pub function: &'a FunctionGraph,
    /// Complete function and block parameter inventory.
    pub parameters: &'a [Parameter],
    /// Complete block inventory.
    pub blocks: &'a [Block],
    /// Complete operation inventory.
    pub operations: &'a [Operation],
}

/// One exact computed function closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionEffectClosure {
    /// Function identity.
    pub function: EntityId,
    /// Raw-ID-sorted least effect closure.
    pub effects: Vec<EntityId>,
}

/// Deterministic successful effect-program summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectReport {
    /// Exact closure for every function in raw-ID order.
    pub functions: Vec<FunctionEffectClosure>,
    /// Number of direct-call operations.
    pub call_edges: u32,
    /// Closure propagation rounds performed.
    pub closure_rounds: u32,
    /// Charged closure set/edge operations.
    pub closure_work: u64,
}

struct ProgramIndex<'a> {
    units: &'a [FunctionUnit<'a>],
    functions: BTreeMap<EntityId, usize>,
    effects: BTreeMap<EntityId, &'a EffectDefinition>,
    requirements: BTreeMap<EntityId, &'a CapabilityRequirement>,
    adapters: BTreeMap<EntityId, &'a AdapterImport>,
    contracts: BTreeSet<EntityId>,
    all_ids: BTreeSet<EntityId>,
}

struct FunctionScan {
    local_effects: BTreeSet<EntityId>,
    callees: BTreeSet<usize>,
}

/// Validates one closed effect-program request.
///
/// # Errors
///
/// Returns the first deterministic S20-210, S20-220, or S20-230 failure.
pub fn validate_effect_program(
    types: &TypeEnvironment,
    units: &[FunctionUnit<'_>],
    effects: &[EffectDefinition],
    requirements: &[CapabilityRequirement],
    adapters: &[AdapterImport],
    known_contracts: &[EntityId],
) -> EffectResult<EffectReport> {
    let index = build_program_index(units, effects, requirements, adapters, known_contracts)?;

    let mut total_edges = 0_usize;
    let mut total_dominator_work = 0_u64;
    for unit in units {
        let report = validate_function_graph(
            types,
            unit.function,
            unit.parameters,
            unit.blocks,
            unit.operations,
        )?;
        total_edges = total_edges
            .checked_add(
                usize::try_from(report.edges)
                    .map_err(|_| effect_error(EffectErrorCode::ResourceLimit))?,
            )
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
        total_dominator_work = total_dominator_work
            .checked_add(report.dominator_word_operations)
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
        if total_edges > MAX_EFFECT_CFG_EDGES || total_dominator_work > MAX_EFFECT_DOMINATOR_WORK {
            return effect_fail(EffectErrorCode::ResourceLimit);
        }
    }

    validate_effect_definitions(types, &index)?;
    validate_declared_effect_sets(&index)?;
    validate_adapters(types, &index)?;
    validate_requirements(types, &index)?;

    let (scans, call_edges) = scan_operations(types, &index)?;
    let (closures, closure_rounds, closure_work) = compute_closures(&scans)?;

    for (unit, closure) in units.iter().zip(&closures) {
        if unit.function.effects.len() != closure.len()
            || !unit.function.effects.iter().eq(closure.iter())
        {
            return effect_fail(EffectErrorCode::ClosureMismatch);
        }
    }

    Ok(EffectReport {
        functions: units
            .iter()
            .zip(closures)
            .map(|(unit, effects)| FunctionEffectClosure {
                function: unit.function.entity_id,
                effects: effects.into_iter().collect(),
            })
            .collect(),
        call_edges: u32::try_from(call_edges)
            .map_err(|_| effect_error(EffectErrorCode::ResourceLimit))?,
        closure_rounds: u32::try_from(closure_rounds)
            .map_err(|_| effect_error(EffectErrorCode::ResourceLimit))?,
        closure_work,
    })
}

fn effect_error(code: EffectErrorCode) -> EffectValidationError {
    EffectValidationError::Effect(EffectError::new(code))
}

fn effect_fail<T>(code: EffectErrorCode) -> EffectResult<T> {
    Err(effect_error(code))
}

fn build_program_index<'a>(
    units: &'a [FunctionUnit<'a>],
    effects: &'a [EffectDefinition],
    requirements: &'a [CapabilityRequirement],
    adapters: &'a [AdapterImport],
    known_contracts: &'a [EntityId],
) -> EffectResult<ProgramIndex<'a>> {
    if units.len() > MAX_EFFECT_FUNCTIONS
        || effects.len() > MAX_EFFECT_DEFINITIONS
        || requirements.len() > MAX_CAPABILITY_REQUIREMENTS
        || adapters.len() > MAX_ADAPTER_IMPORTS
        || known_contracts.len() > MAX_EFFECT_CONTRACTS
    {
        return effect_fail(EffectErrorCode::ResourceLimit);
    }
    ensure_sorted_by(units, |unit| unit.function.entity_id)?;
    ensure_sorted_by(effects, |effect| effect.entity_id)?;
    ensure_sorted_by(requirements, |requirement| requirement.entity_id)?;
    ensure_sorted_by(adapters, |adapter| adapter.entity_id)?;
    ensure_sorted_unique(known_contracts)?;

    let mut all_ids = BTreeSet::new();
    let mut functions = BTreeMap::new();
    let mut graph_entities = 0_usize;
    let mut operation_count = 0_usize;
    let mut cfg_uses = 0_usize;
    for (index, unit) in units.iter().enumerate() {
        insert_global(&mut all_ids, unit.function.entity_id)?;
        functions.insert(unit.function.entity_id, index);
        graph_entities = graph_entities
            .checked_add(1)
            .and_then(|count| count.checked_add(unit.parameters.len()))
            .and_then(|count| count.checked_add(unit.blocks.len()))
            .and_then(|count| count.checked_add(unit.operations.len()))
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
        operation_count = operation_count
            .checked_add(unit.operations.len())
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
        for parameter in unit.parameters {
            insert_global(&mut all_ids, parameter.entity_id)?;
        }
        for block in unit.blocks {
            insert_global(&mut all_ids, block.entity_id)?;
            cfg_uses = cfg_uses
                .checked_add(terminator_uses(&block.terminator)?)
                .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
        }
        for operation in unit.operations {
            insert_global(&mut all_ids, operation.entity_id)?;
            cfg_uses = cfg_uses
                .checked_add(operation.operands.len())
                .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
        }
    }
    if graph_entities > MAX_EFFECT_GRAPH_ENTITIES
        || operation_count > MAX_EFFECT_OPERATIONS
        || cfg_uses > MAX_EFFECT_CFG_USES
    {
        return effect_fail(EffectErrorCode::ResourceLimit);
    }

    let effects = index_entities(effects, &mut all_ids, |value| value.entity_id)?;
    let requirements = index_entities(requirements, &mut all_ids, |value| value.entity_id)?;
    let adapters = index_entities(adapters, &mut all_ids, |value| value.entity_id)?;
    let mut contracts = BTreeSet::new();
    for contract in known_contracts {
        insert_global(&mut all_ids, *contract)?;
        contracts.insert(*contract);
    }

    let mut allowed_scopes = 0_usize;
    let mut constraint_contracts = 0_usize;
    for requirement in requirements.values() {
        if requirement.allowed_scopes.len() > MAX_ALLOWED_SCOPES
            || requirement.constraint_contracts.len() > MAX_CONSTRAINT_CONTRACTS
        {
            return effect_fail(EffectErrorCode::ResourceLimit);
        }
        allowed_scopes = allowed_scopes
            .checked_add(requirement.allowed_scopes.len())
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
        constraint_contracts = constraint_contracts
            .checked_add(requirement.constraint_contracts.len())
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
    }
    if allowed_scopes > MAX_TOTAL_ALLOWED_SCOPES
        || constraint_contracts > MAX_TOTAL_CONSTRAINT_CONTRACTS
    {
        return effect_fail(EffectErrorCode::ResourceLimit);
    }

    for unit in units {
        if unit.function.effects.len() > MAX_EFFECT_SET {
            return effect_fail(EffectErrorCode::ResourceLimit);
        }
    }
    if adapters
        .values()
        .any(|adapter| adapter.effects.len() > MAX_EFFECT_SET)
    {
        return effect_fail(EffectErrorCode::ResourceLimit);
    }

    Ok(ProgramIndex {
        units,
        functions,
        effects,
        requirements,
        adapters,
        contracts,
        all_ids,
    })
}

fn terminator_uses(terminator: &Terminator) -> EffectResult<usize> {
    match terminator {
        Terminator::Return(_) => Ok(1),
        Terminator::Branch(branch) => Ok(branch.edge.arguments.len()),
        Terminator::CondBranch(branch) => 1_usize
            .checked_add(branch.if_true.arguments.len())
            .and_then(|count| count.checked_add(branch.if_false.arguments.len()))
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit)),
        Terminator::VariantSwitch(switch) => {
            let mut count = 1_usize;
            for case in &switch.cases {
                count = count
                    .checked_add(case.edge.arguments.len())
                    .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
            }
            Ok(count)
        }
        Terminator::Trap(trap) => Ok(usize::from(trap.payload.is_some())),
    }
}

fn insert_global(ids: &mut BTreeSet<EntityId>, id: EntityId) -> EffectResult<()> {
    if ids.insert(id) {
        Ok(())
    } else {
        effect_fail(EffectErrorCode::SetNotCanonical)
    }
}

fn index_entities<'a, T, F>(
    values: &'a [T],
    all_ids: &mut BTreeSet<EntityId>,
    id: F,
) -> EffectResult<BTreeMap<EntityId, &'a T>>
where
    F: Fn(&T) -> EntityId,
{
    let mut result = BTreeMap::new();
    for value in values {
        let entity_id = id(value);
        insert_global(all_ids, entity_id)?;
        result.insert(entity_id, value);
    }
    Ok(result)
}

fn ensure_sorted_by<T, F>(values: &[T], key: F) -> EffectResult<()>
where
    F: Fn(&T) -> EntityId,
{
    if values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])) {
        Ok(())
    } else {
        effect_fail(EffectErrorCode::SetNotCanonical)
    }
}

fn ensure_sorted_unique(values: &[EntityId]) -> EffectResult<()> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        effect_fail(EffectErrorCode::SetNotCanonical)
    }
}

fn validate_effect_definitions(
    types: &TypeEnvironment,
    index: &ProgramIndex<'_>,
) -> EffectResult<()> {
    for effect in index.effects.values() {
        types.check_closed_type(&effect.scope_type)?;
        types.require_persistable(&effect.scope_type)?;
        types.check_closed_type(&effect.request_type)?;
        types.check_closed_type(&effect.response_type)?;
        types.check_closed_type(&effect.failure_type)?;
    }
    Ok(())
}

fn validate_declared_effect_sets(index: &ProgramIndex<'_>) -> EffectResult<()> {
    for unit in index.units {
        for effect in &unit.function.effects {
            lookup(&index.effects, *effect, &index.all_ids)?;
        }
    }
    Ok(())
}

fn validate_adapters(types: &TypeEnvironment, index: &ProgramIndex<'_>) -> EffectResult<()> {
    for adapter in index.adapters.values() {
        ensure_sorted_unique(&adapter.effects)?;
        if adapter.effects.len() != 1 {
            return effect_fail(EffectErrorCode::AdapterEffectCardinality);
        }
        let effect = lookup(&index.effects, adapter.effects[0], &index.all_ids)?;
        if effect.effect_kind != EffectKind::AdapterCall {
            return effect_fail(EffectErrorCode::AdapterEffectKind);
        }
        types.check_closed_type(&adapter.request_type)?;
        types.check_closed_type(&adapter.response_type)?;
        types.check_closed_type(&adapter.failure_type)?;
    }
    Ok(())
}

fn validate_requirements(types: &TypeEnvironment, index: &ProgramIndex<'_>) -> EffectResult<()> {
    for requirement in index.requirements.values() {
        let effect = lookup(&index.effects, requirement.effect, &index.all_ids)?;
        ensure_sorted_unique(&requirement.constraint_contracts)?;
        for contract in &requirement.constraint_contracts {
            if !index.contracts.contains(contract) {
                return effect_fail(EffectErrorCode::ConstraintContractBoundary);
            }
        }
        let mut previous = None;
        for scope in &requirement.allowed_scopes {
            types.check_constant(scope)?;
            if scope.value_type != effect.scope_type {
                return effect_fail(EffectErrorCode::CapabilityScopeConstType);
            }
            if previous.is_some_and(|value| compare_const_values(value, scope) != Ordering::Less) {
                return effect_fail(EffectErrorCode::CapabilityScopeConstCanonical);
            }
            previous = Some(scope);
        }
    }
    Ok(())
}

fn lookup<'a, T>(
    values: &'a BTreeMap<EntityId, T>,
    id: EntityId,
    all_ids: &BTreeSet<EntityId>,
) -> EffectResult<&'a T> {
    if let Some(value) = values.get(&id) {
        Ok(value)
    } else if all_ids.contains(&id) {
        effect_fail(EffectErrorCode::WrongEntityKind)
    } else {
        effect_fail(EffectErrorCode::UnresolvedEntity)
    }
}

fn scan_operations(
    types: &TypeEnvironment,
    index: &ProgramIndex<'_>,
) -> EffectResult<(Vec<FunctionScan>, usize)> {
    let mut scans = Vec::with_capacity(index.units.len());
    let mut call_edges = 0_usize;
    for unit in index.units {
        let parameters: BTreeMap<_, _> = unit
            .parameters
            .iter()
            .map(|parameter| (parameter.entity_id, parameter))
            .collect();
        let blocks: BTreeMap<_, _> = unit
            .blocks
            .iter()
            .map(|block| (block.entity_id, block))
            .collect();
        let operations: BTreeMap<_, _> = unit
            .operations
            .iter()
            .map(|operation| (operation.entity_id, operation))
            .collect();
        let mut scan = FunctionScan {
            local_effects: BTreeSet::new(),
            callees: BTreeSet::new(),
        };
        for block_id in &unit.function.blocks {
            let block = blocks
                .get(block_id)
                .ok_or_else(|| effect_error(EffectErrorCode::UnresolvedEntity))?;
            for operation_id in &block.operations {
                let operation = operations
                    .get(operation_id)
                    .ok_or_else(|| effect_error(EffectErrorCode::UnresolvedEntity))?;
                match operation.opcode {
                    Opcode::CallDirect => {
                        validate_call(
                            types,
                            index,
                            unit,
                            operation,
                            &parameters,
                            &operations,
                            &mut scan,
                        )?;
                        call_edges = call_edges
                            .checked_add(1)
                            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
                        if call_edges > MAX_EFFECT_CALL_EDGES {
                            return effect_fail(EffectErrorCode::ResourceLimit);
                        }
                    }
                    Opcode::EffectRequest => {
                        validate_request(index, operation, &parameters, &operations, &mut scan)?;
                    }
                    Opcode::AdapterInvoke => validate_adapter_invoke(
                        index,
                        operation,
                        &parameters,
                        &operations,
                        &mut scan,
                    )?,
                    Opcode::CapabilityNarrow => {
                        validate_capability_narrow(index, operation, &parameters, &operations)?;
                    }
                    _ => {}
                }
            }
        }
        scans.push(scan);
    }
    Ok((scans, call_edges))
}

fn validate_call(
    types: &TypeEnvironment,
    index: &ProgramIndex<'_>,
    calling_unit: &FunctionUnit<'_>,
    operation: &Operation,
    parameters: &BTreeMap<EntityId, &Parameter>,
    operations: &BTreeMap<EntityId, &Operation>,
    scan: &mut FunctionScan,
) -> EffectResult<()> {
    let Immediate::Function(reference) = &operation.immediate else {
        return effect_fail(EffectErrorCode::CallType);
    };
    let callee_index = if let Some(index_value) = index.functions.get(&reference.function) {
        *index_value
    } else if index.all_ids.contains(&reference.function) {
        return effect_fail(EffectErrorCode::WrongEntityKind);
    } else {
        return effect_fail(EffectErrorCode::UnresolvedEntity);
    };
    let target_unit = &index.units[callee_index];
    if reference.type_arguments.len() != target_unit.function.type_parameters.len()
        || operation.operands.len() != target_unit.function.parameters.len()
        || operation.result_types.len() != 1
    {
        return effect_fail(EffectErrorCode::CallType);
    }
    let caller_parameter_count = u32::try_from(calling_unit.function.type_parameters.len())
        .map_err(|_| effect_error(EffectErrorCode::ResourceLimit))?;
    let target_parameters: BTreeMap<_, _> = target_unit
        .parameters
        .iter()
        .map(|parameter| (parameter.entity_id, parameter))
        .collect();
    for (operand, parameter_id) in operation
        .operands
        .iter()
        .zip(&target_unit.function.parameters)
    {
        let expected = target_parameters
            .get(parameter_id)
            .ok_or_else(|| effect_error(EffectErrorCode::UnresolvedEntity))?;
        let expected = types.instantiate_in_scope(
            &expected.value_type,
            &reference.type_arguments,
            caller_parameter_count,
        )?;
        if resolve_value_type(*operand, parameters, operations)? != &expected {
            return effect_fail(EffectErrorCode::CallType);
        }
    }
    let result = types.instantiate_in_scope(
        &target_unit.function.result_type,
        &reference.type_arguments,
        caller_parameter_count,
    )?;
    if operation.result_types[0] != result {
        return effect_fail(EffectErrorCode::CallType);
    }
    scan.callees.insert(callee_index);
    Ok(())
}

fn validate_request(
    index: &ProgramIndex<'_>,
    operation: &Operation,
    parameters: &BTreeMap<EntityId, &Parameter>,
    operations: &BTreeMap<EntityId, &Operation>,
    scan: &mut FunctionScan,
) -> EffectResult<()> {
    let Immediate::Entity(effect_id) = operation.immediate else {
        return effect_fail(EffectErrorCode::RequestType);
    };
    let effect = lookup(&index.effects, effect_id, &index.all_ids)?;
    if operation.operands.len() != 2 || operation.result_types.len() != 1 {
        return effect_fail(EffectErrorCode::RequestType);
    }
    let expected_result = TypeExpr::Result {
        ok: Box::new(effect.response_type.clone()),
        error: Box::new(effect.failure_type.clone()),
    };
    if resolve_value_type(operation.operands[0], parameters, operations)? != &effect.scope_type
        || resolve_value_type(operation.operands[1], parameters, operations)?
            != &effect.request_type
        || operation.result_types[0] != expected_result
    {
        return effect_fail(EffectErrorCode::RequestType);
    }
    scan.local_effects.insert(effect_id);
    Ok(())
}

fn validate_adapter_invoke(
    index: &ProgramIndex<'_>,
    operation: &Operation,
    parameters: &BTreeMap<EntityId, &Parameter>,
    operations: &BTreeMap<EntityId, &Operation>,
    scan: &mut FunctionScan,
) -> EffectResult<()> {
    let Immediate::Entity(adapter_id) = operation.immediate else {
        return effect_fail(EffectErrorCode::AdapterInvokeType);
    };
    let adapter = lookup(&index.adapters, adapter_id, &index.all_ids)?;
    if operation.operands.len() != 2
        || operation.result_types.len() != 1
        || adapter.effects.len() != 1
    {
        return effect_fail(EffectErrorCode::AdapterInvokeType);
    }
    let effect = lookup(&index.effects, adapter.effects[0], &index.all_ids)?;
    let expected_result = TypeExpr::Result {
        ok: Box::new(adapter.response_type.clone()),
        error: Box::new(adapter.failure_type.clone()),
    };
    if resolve_value_type(operation.operands[0], parameters, operations)? != &effect.scope_type
        || resolve_value_type(operation.operands[1], parameters, operations)?
            != &adapter.request_type
        || operation.result_types[0] != expected_result
    {
        return effect_fail(EffectErrorCode::AdapterInvokeType);
    }
    scan.local_effects.insert(effect.entity_id);
    Ok(())
}

fn validate_capability_narrow(
    index: &ProgramIndex<'_>,
    operation: &Operation,
    parameters: &BTreeMap<EntityId, &Parameter>,
    operations: &BTreeMap<EntityId, &Operation>,
) -> EffectResult<()> {
    let Immediate::Entity(requirement_id) = operation.immediate else {
        return effect_fail(EffectErrorCode::CapabilityRequirementType);
    };
    let requirement = lookup(&index.requirements, requirement_id, &index.all_ids)?;
    let effect = lookup(&index.effects, requirement.effect, &index.all_ids)?;
    if operation.operands.len() != 2 || operation.result_types.len() != 1 {
        return effect_fail(EffectErrorCode::CapabilityRequirementType);
    }
    let token = TypeExpr::CapabilityToken(requirement_id);
    let expected_result = TypeExpr::Result {
        ok: Box::new(token.clone()),
        error: Box::new(TypeExpr::BuiltinFailure(BuiltinFailureKind::Capability)),
    };
    if resolve_value_type(operation.operands[0], parameters, operations)? != &token
        || resolve_value_type(operation.operands[1], parameters, operations)? != &effect.scope_type
        || operation.result_types[0] != expected_result
    {
        return effect_fail(EffectErrorCode::CapabilityRequirementType);
    }
    Ok(())
}

fn resolve_value_type<'a>(
    value: ValueRef,
    parameters: &'a BTreeMap<EntityId, &Parameter>,
    operations: &'a BTreeMap<EntityId, &Operation>,
) -> EffectResult<&'a TypeExpr> {
    match value {
        ValueRef::Parameter(id) => parameters
            .get(&id)
            .map(|parameter| &parameter.value_type)
            .ok_or_else(|| effect_error(EffectErrorCode::UnresolvedEntity)),
        ValueRef::OperationResult(result) => operations
            .get(&result.operation)
            .and_then(|operation| {
                usize::try_from(result.result_index)
                    .ok()
                    .and_then(|index| operation.result_types.get(index))
            })
            .ok_or_else(|| effect_error(EffectErrorCode::UnresolvedEntity)),
    }
}

fn compute_closures(scans: &[FunctionScan]) -> EffectResult<(Vec<BTreeSet<EntityId>>, usize, u64)> {
    let mut closures: Vec<_> = scans
        .iter()
        .map(|scan| scan.local_effects.clone())
        .collect();
    check_closure_memberships(&closures)?;
    let mut work = 0_u64;
    for round in 1..=MAX_EFFECT_CLOSURE_ROUNDS {
        charge_work(
            &mut work,
            closures.iter().try_fold(0_u64, |count, closure| {
                count
                    .checked_add(
                        u64::try_from(closure.len())
                            .map_err(|_| effect_error(EffectErrorCode::ResourceLimit))?,
                    )
                    .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))
            })?,
        )?;
        let previous = closures.clone();
        let mut changed = false;
        for (function, scan) in scans.iter().enumerate() {
            for callee in &scan.callees {
                charge_work(&mut work, 1)?;
                for effect in &previous[*callee] {
                    charge_work(&mut work, 1)?;
                    changed |= closures[function].insert(*effect);
                }
            }
        }
        check_closure_memberships(&closures)?;
        if !changed || closure_is_fixed(scans, &closures, &mut work)? {
            return Ok((closures, round, work));
        }
    }
    effect_fail(EffectErrorCode::ResourceLimit)
}

fn closure_is_fixed(
    scans: &[FunctionScan],
    closures: &[BTreeSet<EntityId>],
    work: &mut u64,
) -> EffectResult<bool> {
    for (function, scan) in scans.iter().enumerate() {
        for callee in &scan.callees {
            charge_work(work, 1)?;
            for effect in &closures[*callee] {
                charge_work(work, 1)?;
                if !closures[function].contains(effect) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn check_closure_memberships(closures: &[BTreeSet<EntityId>]) -> EffectResult<()> {
    let total = closures.iter().try_fold(0_usize, |count, closure| {
        count
            .checked_add(closure.len())
            .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))
    })?;
    if total > MAX_EFFECT_CLOSURE_MEMBERSHIPS {
        effect_fail(EffectErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn charge_work(work: &mut u64, amount: u64) -> EffectResult<()> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| effect_error(EffectErrorCode::ResourceLimit))?;
    if *work > MAX_EFFECT_CLOSURE_WORK {
        effect_fail(EffectErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn compare_const_values(left: &ConstValue, right: &ConstValue) -> Ordering {
    compare_types(&left.value_type, &right.value_type)
        .then_with(|| compare_const_data(&left.data, &right.data))
}

fn compare_types(left: &TypeExpr, right: &TypeExpr) -> Ordering {
    left.tag()
        .cmp(&right.tag())
        .then_with(|| match (left, right) {
            (TypeExpr::SInt(left), TypeExpr::SInt(right))
            | (TypeExpr::UInt(left), TypeExpr::UInt(right)) => left.bits().cmp(&right.bits()),
            (TypeExpr::Tuple(left), TypeExpr::Tuple(right)) => {
                compare_lists(left, right, compare_types)
            }
            (TypeExpr::Named(left), TypeExpr::Named(right)) => left
                .definition
                .cmp(&right.definition)
                .then_with(|| compare_lists(&left.arguments, &right.arguments, compare_types)),
            (TypeExpr::Vector(left), TypeExpr::Vector(right))
            | (TypeExpr::Option(left), TypeExpr::Option(right))
            | (TypeExpr::LocalCell(left), TypeExpr::LocalCell(right)) => compare_types(left, right),
            (
                TypeExpr::OrderedMap {
                    key: left_key,
                    value: left_value,
                },
                TypeExpr::OrderedMap {
                    key: right_key,
                    value: right_value,
                },
            ) => compare_types(left_key, right_key)
                .then_with(|| compare_types(left_value, right_value)),
            (
                TypeExpr::Result {
                    ok: left_ok,
                    error: left_error,
                },
                TypeExpr::Result {
                    ok: right_ok,
                    error: right_error,
                },
            ) => compare_types(left_ok, right_ok)
                .then_with(|| compare_types(left_error, right_error)),
            (TypeExpr::FunctionRef(left), TypeExpr::FunctionRef(right)) => {
                compare_lists(&left.parameters, &right.parameters, compare_types)
                    .then_with(|| compare_types(&left.result, &right.result))
                    .then_with(|| left.effects.cmp(&right.effects))
            }
            (TypeExpr::AdapterHandle(left), TypeExpr::AdapterHandle(right))
            | (TypeExpr::CapabilityToken(left), TypeExpr::CapabilityToken(right)) => {
                left.cmp(right)
            }
            (TypeExpr::TypeParameter(left), TypeExpr::TypeParameter(right)) => left.cmp(right),
            (TypeExpr::BuiltinFailure(left), TypeExpr::BuiltinFailure(right)) => {
                left.tag().cmp(&right.tag())
            }
            _ => Ordering::Equal,
        })
}

fn compare_const_data(left: &ConstData, right: &ConstData) -> Ordering {
    left.tag()
        .cmp(&right.tag())
        .then_with(|| match (left, right) {
            (ConstData::Bool(left), ConstData::Bool(right)) => left.cmp(right),
            (ConstData::SInt(left), ConstData::SInt(right)) => left.cmp(right),
            (ConstData::UInt(left), ConstData::UInt(right)) => left.cmp(right),
            (ConstData::F32Bits(left), ConstData::F32Bits(right)) => left.cmp(right),
            (ConstData::F64Bits(left), ConstData::F64Bits(right)) => left.cmp(right),
            (ConstData::Bytes(left), ConstData::Bytes(right)) => left.cmp(right),
            (ConstData::Text(left), ConstData::Text(right)) => {
                left.as_bytes().cmp(right.as_bytes())
            }
            (ConstData::Sequence(left), ConstData::Sequence(right)) => {
                compare_lists(left, right, compare_const_values)
            }
            (ConstData::Record(left), ConstData::Record(right)) => {
                left.definition.cmp(&right.definition).then_with(|| {
                    compare_lists(&left.fields, &right.fields, |left, right| {
                        left.member_id
                            .cmp(&right.member_id)
                            .then_with(|| compare_const_values(&left.value, &right.value))
                    })
                })
            }
            (ConstData::Variant(left), ConstData::Variant(right)) => left
                .definition
                .cmp(&right.definition)
                .then_with(|| left.member_id.cmp(&right.member_id))
                .then_with(|| {
                    compare_options(
                        left.payload.as_deref(),
                        right.payload.as_deref(),
                        compare_const_values,
                    )
                }),
            (ConstData::Map(left), ConstData::Map(right)) => {
                compare_lists(left, right, |left, right| {
                    compare_const_values(&left.key, &right.key)
                        .then_with(|| compare_const_values(&left.value, &right.value))
                })
            }
            (ConstData::Option(left), ConstData::Option(right)) => {
                compare_options(left.as_deref(), right.as_deref(), compare_const_values)
            }
            (ConstData::Result(left), ConstData::Result(right)) => compare_results(left, right),
            (ConstData::FunctionRef(left), ConstData::FunctionRef(right)) => {
                left.function.cmp(&right.function).then_with(|| {
                    compare_lists(&left.type_arguments, &right.type_arguments, compare_types)
                })
            }
            (ConstData::BuiltinFailure(left), ConstData::BuiltinFailure(right)) => left
                .kind
                .tag()
                .cmp(&right.kind.tag())
                .then_with(|| left.code.cmp(&right.code)),
            _ => Ordering::Equal,
        })
}

fn compare_results(left: &ResultConst, right: &ResultConst) -> Ordering {
    left.tag()
        .cmp(&right.tag())
        .then_with(|| match (left, right) {
            (ResultConst::Ok(left), ResultConst::Ok(right))
            | (ResultConst::Err(left), ResultConst::Err(right)) => {
                compare_const_values(left, right)
            }
            _ => Ordering::Equal,
        })
}

fn compare_lists<T, F>(left: &[T], right: &[T], compare: F) -> Ordering
where
    F: Fn(&T, &T) -> Ordering,
{
    for (left, right) in left.iter().zip(right) {
        let order = compare(left, right);
        if order != Ordering::Equal {
            return order;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_options<T, F>(left: Option<&T>, right: Option<&T>, compare: F) -> Ordering
where
    F: Fn(&T, &T) -> Ordering,
{
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare(left, right),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TypeEnvironment, TypeErrorCode,
        cfg::{CfgErrorCode, CfgValidationError},
    };
    use sley_ssmc::{
        FunctionRefValue, OperationResultRef, ParameterRole, Reachability, ReturnTerminator,
        TypeParameterDef, Visibility,
    };

    #[derive(Clone)]
    struct OwnedFunction {
        function: FunctionGraph,
        parameters: Vec<Parameter>,
        blocks: Vec<Block>,
        operations: Vec<Operation>,
    }

    struct Fixture {
        types: TypeEnvironment,
        functions: Vec<OwnedFunction>,
        effects: Vec<EffectDefinition>,
        requirements: Vec<CapabilityRequirement>,
        adapters: Vec<AdapterImport>,
        contracts: Vec<EntityId>,
    }

    impl Fixture {
        fn validate(&self) -> EffectResult<EffectReport> {
            let units: Vec<_> = self
                .functions
                .iter()
                .map(|function| FunctionUnit {
                    function: &function.function,
                    parameters: &function.parameters,
                    blocks: &function.blocks,
                    operations: &function.operations,
                })
                .collect();
            validate_effect_program(
                &self.types,
                &units,
                &self.effects,
                &self.requirements,
                &self.adapters,
                &self.contracts,
            )
        }
    }

    fn id(value: u32) -> EntityId {
        let mut bytes = [0_u8; 32];
        bytes[28..].copy_from_slice(&value.to_be_bytes());
        EntityId::from_bytes(bytes)
    }

    fn parameter(entity: u32, owner: u32, ordinal: u32, value_type: TypeExpr) -> Parameter {
        Parameter {
            entity_id: id(entity),
            owner: id(owner),
            role: ParameterRole::Function,
            ordinal,
            value_type,
        }
    }

    fn effect(entity: u32, kind: EffectKind) -> EffectDefinition {
        EffectDefinition {
            entity_id: id(entity),
            effect_kind: kind,
            scope_type: TypeExpr::Unit,
            request_type: TypeExpr::Unit,
            response_type: TypeExpr::Unit,
            failure_type: TypeExpr::Unit,
            visibility: Visibility::Private,
        }
    }

    fn unit_constant() -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Unit,
            data: ConstData::Unit,
        }
    }

    fn empty_owned_function(function: u32, input: u32, block: u32) -> OwnedFunction {
        OwnedFunction {
            function: FunctionGraph {
                entity_id: id(function),
                type_parameters: Vec::new(),
                parameters: vec![id(input)],
                result_type: TypeExpr::Unit,
                effects: Vec::new(),
                entry_block: id(block),
                blocks: vec![id(block)],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![parameter(input, function, 0, TypeExpr::Unit)],
            blocks: vec![Block {
                entity_id: id(block),
                function: id(function),
                parameters: Vec::new(),
                operations: Vec::new(),
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(id(input)),
                }),
                reachability: Reachability::Required,
            }],
            operations: Vec::new(),
        }
    }

    fn empty_fixture() -> Fixture {
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            functions: vec![empty_owned_function(1, 2, 3)],
            effects: Vec::new(),
            requirements: Vec::new(),
            adapters: Vec::new(),
            contracts: Vec::new(),
        }
    }

    fn request_fixture() -> Fixture {
        let effect_id = id(20);
        let operation_id = id(5);
        let mut function = OwnedFunction {
            function: FunctionGraph {
                entity_id: id(1),
                type_parameters: Vec::new(),
                parameters: vec![id(2), id(3)],
                result_type: TypeExpr::Unit,
                effects: vec![effect_id],
                entry_block: id(4),
                blocks: vec![id(4)],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                parameter(2, 1, 0, TypeExpr::Unit),
                parameter(3, 1, 1, TypeExpr::Unit),
            ],
            blocks: vec![Block {
                entity_id: id(4),
                function: id(1),
                parameters: Vec::new(),
                operations: vec![operation_id],
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(id(2)),
                }),
                reachability: Reachability::Required,
            }],
            operations: Vec::new(),
        };
        function.operations.push(Operation {
            entity_id: operation_id,
            block: id(4),
            ordinal: 0,
            opcode: Opcode::EffectRequest,
            operands: vec![ValueRef::Parameter(id(2)), ValueRef::Parameter(id(3))],
            result_types: vec![TypeExpr::Result {
                ok: Box::new(TypeExpr::Unit),
                error: Box::new(TypeExpr::Unit),
            }],
            immediate: Immediate::Entity(effect_id),
        });
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            functions: vec![function],
            effects: vec![effect(20, EffectKind::StdoutWrite)],
            requirements: Vec::new(),
            adapters: Vec::new(),
            contracts: Vec::new(),
        }
    }

    fn adapter_fixture() -> Fixture {
        let mut fixture = request_fixture();
        fixture.effects[0].effect_kind = EffectKind::AdapterCall;
        fixture.adapters.push(AdapterImport {
            entity_id: id(21),
            adapter_id: [7; 32],
            abi_version: 1,
            request_type: TypeExpr::Unit,
            response_type: TypeExpr::Unit,
            failure_type: TypeExpr::Unit,
            effects: vec![id(20)],
        });
        fixture.functions[0].operations[0].opcode = Opcode::AdapterInvoke;
        fixture.functions[0].operations[0].immediate = Immediate::Entity(id(21));
        fixture
    }

    fn capability_fixture() -> Fixture {
        let requirement_id = id(21);
        let token = TypeExpr::CapabilityToken(requirement_id);
        let mut function = OwnedFunction {
            function: FunctionGraph {
                entity_id: id(1),
                type_parameters: Vec::new(),
                parameters: vec![id(2), id(3)],
                result_type: TypeExpr::Unit,
                effects: Vec::new(),
                entry_block: id(4),
                blocks: vec![id(4)],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                parameter(2, 1, 0, token.clone()),
                parameter(3, 1, 1, TypeExpr::Unit),
            ],
            blocks: vec![Block {
                entity_id: id(4),
                function: id(1),
                parameters: Vec::new(),
                operations: vec![id(5)],
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(id(3)),
                }),
                reachability: Reachability::Required,
            }],
            operations: Vec::new(),
        };
        function.operations.push(Operation {
            entity_id: id(5),
            block: id(4),
            ordinal: 0,
            opcode: Opcode::CapabilityNarrow,
            operands: vec![ValueRef::Parameter(id(2)), ValueRef::Parameter(id(3))],
            result_types: vec![TypeExpr::Result {
                ok: Box::new(token),
                error: Box::new(TypeExpr::BuiltinFailure(BuiltinFailureKind::Capability)),
            }],
            immediate: Immediate::Entity(requirement_id),
        });
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            functions: vec![function],
            effects: vec![effect(20, EffectKind::StdoutWrite)],
            requirements: vec![CapabilityRequirement {
                entity_id: requirement_id,
                effect: id(20),
                allowed_scopes: vec![unit_constant()],
                constraint_contracts: Vec::new(),
            }],
            adapters: Vec::new(),
            contracts: Vec::new(),
        }
    }

    fn call_operation(entity: u32, block: u32, target: u32, operands: Vec<ValueRef>) -> Operation {
        Operation {
            entity_id: id(entity),
            block: id(block),
            ordinal: 0,
            opcode: Opcode::CallDirect,
            operands,
            result_types: vec![TypeExpr::Unit],
            immediate: Immediate::Function(FunctionRefValue {
                function: id(target),
                type_arguments: Vec::new(),
            }),
        }
    }

    fn transitive_call_fixture() -> Fixture {
        let mut caller = OwnedFunction {
            function: FunctionGraph {
                entity_id: id(1),
                type_parameters: Vec::new(),
                parameters: vec![id(2), id(3)],
                result_type: TypeExpr::Unit,
                effects: vec![id(20)],
                entry_block: id(4),
                blocks: vec![id(4)],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                parameter(2, 1, 0, TypeExpr::Unit),
                parameter(3, 1, 1, TypeExpr::Unit),
            ],
            blocks: vec![Block {
                entity_id: id(4),
                function: id(1),
                parameters: Vec::new(),
                operations: vec![id(5)],
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::OperationResult(OperationResultRef {
                        operation: id(5),
                        result_index: 0,
                    }),
                }),
                reachability: Reachability::Required,
            }],
            operations: Vec::new(),
        };
        caller.operations.push(call_operation(
            5,
            4,
            10,
            vec![ValueRef::Parameter(id(2)), ValueRef::Parameter(id(3))],
        ));

        let mut target = request_fixture().functions.remove(0);
        target.function.entity_id = id(10);
        target.function.parameters = vec![id(11), id(12)];
        target.function.entry_block = id(13);
        target.function.blocks = vec![id(13)];
        target.parameters = vec![
            parameter(11, 10, 0, TypeExpr::Unit),
            parameter(12, 10, 1, TypeExpr::Unit),
        ];
        target.blocks[0].entity_id = id(13);
        target.blocks[0].function = id(10);
        target.blocks[0].operations = vec![id(14)];
        target.blocks[0].terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::Parameter(id(11)),
        });
        target.operations[0].entity_id = id(14);
        target.operations[0].block = id(13);
        target.operations[0].operands =
            vec![ValueRef::Parameter(id(11)), ValueRef::Parameter(id(12))];

        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            functions: vec![caller, target],
            effects: vec![effect(20, EffectKind::StdoutWrite)],
            requirements: Vec::new(),
            adapters: Vec::new(),
            contracts: Vec::new(),
        }
    }

    fn mutual_recursion_fixture() -> Fixture {
        let mut first = empty_owned_function(1, 2, 3);
        first.blocks[0].operations = vec![id(4)];
        first.operations = vec![call_operation(4, 3, 10, vec![ValueRef::Parameter(id(2))])];
        let mut second = empty_owned_function(10, 11, 12);
        second.blocks[0].operations = vec![id(13)];
        second.operations = vec![call_operation(13, 12, 1, vec![ValueRef::Parameter(id(11))])];
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            functions: vec![first, second],
            effects: Vec::new(),
            requirements: Vec::new(),
            adapters: Vec::new(),
            contracts: Vec::new(),
        }
    }

    fn self_recursive_effect_fixture() -> Fixture {
        let mut fixture = request_fixture();
        fixture.functions[0].blocks[0].operations.push(id(6));
        fixture.functions[0].operations.push(Operation {
            entity_id: id(6),
            block: id(4),
            ordinal: 1,
            opcode: Opcode::CallDirect,
            operands: vec![ValueRef::Parameter(id(2)), ValueRef::Parameter(id(3))],
            result_types: vec![TypeExpr::Unit],
            immediate: Immediate::Function(FunctionRefValue {
                function: id(1),
                type_arguments: Vec::new(),
            }),
        });
        fixture
    }

    fn effect_code(result: EffectResult<EffectReport>) -> EffectErrorCode {
        match result.unwrap_err() {
            EffectValidationError::Effect(error) => error.code(),
            error => panic!("unexpected earlier error: {error}"),
        }
    }

    #[test]
    fn stable_effect_codes_are_frozen() {
        let codes = [
            EffectErrorCode::UnresolvedEntity,
            EffectErrorCode::WrongEntityKind,
            EffectErrorCode::SetNotCanonical,
            EffectErrorCode::ClosureMismatch,
            EffectErrorCode::CallType,
            EffectErrorCode::RequestType,
            EffectErrorCode::AdapterEffectCardinality,
            EffectErrorCode::AdapterEffectKind,
            EffectErrorCode::AdapterInvokeType,
            EffectErrorCode::CapabilityRequirementType,
            EffectErrorCode::CapabilityScopeConstType,
            EffectErrorCode::CapabilityScopeConstCanonical,
            EffectErrorCode::ConstraintContractBoundary,
            EffectErrorCode::ResourceLimit,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(
                code.numeric(),
                23_000 + u32::try_from(offset).expect("offset fits")
            );
            assert!(!code.as_str().is_empty());
        }
    }

    #[test]
    fn empty_request_and_direct_effect_request_validate() {
        let empty = empty_fixture().validate().unwrap();
        assert!(empty.functions[0].effects.is_empty());
        let request = request_fixture().validate().unwrap();
        assert_eq!(request.functions[0].effects, vec![id(20)]);
        assert_eq!(request.call_edges, 0);
    }

    #[test]
    fn adapter_and_capability_narrow_validate_without_runtime_authority() {
        assert_eq!(
            adapter_fixture().validate().unwrap().functions[0].effects,
            vec![id(20)]
        );
        assert!(
            capability_fixture().validate().unwrap().functions[0]
                .effects
                .is_empty()
        );
    }

    #[test]
    fn transitive_call_and_mutual_recursion_compute_least_closure() {
        let transitive = transitive_call_fixture().validate().unwrap();
        assert_eq!(transitive.call_edges, 1);
        assert_eq!(transitive.functions[0].effects, vec![id(20)]);
        assert_eq!(transitive.functions[1].effects, vec![id(20)]);

        let mutual = mutual_recursion_fixture().validate().unwrap();
        assert_eq!(mutual.call_edges, 2);
        assert!(
            mutual
                .functions
                .iter()
                .all(|function| function.effects.is_empty())
        );
        assert!(mutual.closure_rounds > 0);

        let recursive = self_recursive_effect_fixture().validate().unwrap();
        assert_eq!(recursive.call_edges, 1);
        assert_eq!(recursive.functions[0].effects, vec![id(20)]);
    }

    #[test]
    fn recursive_cycle_cannot_self_justify_unused_effect() {
        let mut fixture = mutual_recursion_fixture();
        fixture.effects.push(effect(20, EffectKind::StdoutWrite));
        for function in &mut fixture.functions {
            function.function.effects.push(id(20));
        }
        assert_eq!(
            effect_code(fixture.validate()),
            EffectErrorCode::ClosureMismatch
        );
    }

    #[test]
    fn inventory_order_is_independent_but_semantic_sets_are_canonical() {
        let first = transitive_call_fixture();
        let mut second = transitive_call_fixture();
        second.functions[1].parameters.reverse();
        assert_eq!(first.validate().unwrap(), second.validate().unwrap());

        let mut set = empty_fixture();
        set.contracts = vec![id(31), id(30)];
        assert_eq!(
            effect_code(set.validate()),
            EffectErrorCode::SetNotCanonical
        );
    }

    #[test]
    fn unresolved_and_wrong_kind_immediates_fail_exactly() {
        let mut unresolved = request_fixture();
        unresolved.functions[0].operations[0].immediate = Immediate::Entity(id(99));
        assert_eq!(
            effect_code(unresolved.validate()),
            EffectErrorCode::UnresolvedEntity
        );

        let mut wrong = adapter_fixture();
        wrong.functions[0].operations[0].opcode = Opcode::EffectRequest;
        assert_eq!(
            effect_code(wrong.validate()),
            EffectErrorCode::WrongEntityKind
        );
    }

    #[test]
    fn missing_or_extra_declarations_fail_exactly() {
        let mut missing = request_fixture();
        missing.functions[0].function.effects.clear();
        assert_eq!(
            effect_code(missing.validate()),
            EffectErrorCode::ClosureMismatch
        );

        let mut extra = empty_fixture();
        extra.effects.push(effect(20, EffectKind::StdoutWrite));
        extra.functions[0].function.effects.push(id(20));
        assert_eq!(
            effect_code(extra.validate()),
            EffectErrorCode::ClosureMismatch
        );
    }

    #[test]
    fn noncanonical_function_effect_set_preserves_cfg_inventory_failure() {
        let mut fixture = request_fixture();
        fixture.effects.push(effect(21, EffectKind::FileRead));
        fixture.functions[0].function.effects = vec![id(21), id(20)];
        match fixture.validate().unwrap_err() {
            EffectValidationError::Cfg(CfgValidationError::Cfg(error)) => {
                assert_eq!(error.code(), CfgErrorCode::GraphInventoryMismatch);
            }
            error => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn call_and_request_shapes_fail_exactly() {
        let mut call = transitive_call_fixture();
        call.functions[0].operations[0].immediate = Immediate::None;
        assert_eq!(effect_code(call.validate()), EffectErrorCode::CallType);

        let mut request = request_fixture();
        request.functions[0].operations[0].operands.pop();
        assert_eq!(
            effect_code(request.validate()),
            EffectErrorCode::RequestType
        );
    }

    #[test]
    fn adapter_cardinality_kind_and_invoke_type_fail_exactly() {
        let mut cardinality = adapter_fixture();
        cardinality.adapters[0].effects.clear();
        assert_eq!(
            effect_code(cardinality.validate()),
            EffectErrorCode::AdapterEffectCardinality
        );

        let mut kind = adapter_fixture();
        kind.effects[0].effect_kind = EffectKind::FileRead;
        assert_eq!(
            effect_code(kind.validate()),
            EffectErrorCode::AdapterEffectKind
        );

        let mut invoke = adapter_fixture();
        invoke.functions[0].operations[0].result_types[0] = TypeExpr::Unit;
        assert_eq!(
            effect_code(invoke.validate()),
            EffectErrorCode::AdapterInvokeType
        );
    }

    #[test]
    fn capability_shape_scope_type_order_and_contract_boundary_fail_exactly() {
        let mut shape = capability_fixture();
        shape.functions[0].operations[0].result_types[0] = TypeExpr::Unit;
        assert_eq!(
            effect_code(shape.validate()),
            EffectErrorCode::CapabilityRequirementType
        );

        let mut scope_type = capability_fixture();
        scope_type.requirements[0].allowed_scopes[0] = ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(false),
        };
        assert_eq!(
            effect_code(scope_type.validate()),
            EffectErrorCode::CapabilityScopeConstType
        );

        let mut canonical = capability_fixture();
        canonical.requirements[0]
            .allowed_scopes
            .push(unit_constant());
        assert_eq!(
            effect_code(canonical.validate()),
            EffectErrorCode::CapabilityScopeConstCanonical
        );

        let mut contract = capability_fixture();
        contract.requirements[0].constraint_contracts.push(id(30));
        assert_eq!(
            effect_code(contract.validate()),
            EffectErrorCode::ConstraintContractBoundary
        );
        contract.contracts.push(id(30));
        contract.validate().unwrap();
    }

    #[test]
    fn limits_and_earlier_type_and_cfg_errors_are_preserved() {
        let mut limit = empty_fixture();
        limit.functions[0].function.effects = vec![id(20); MAX_EFFECT_SET + 1];
        assert_eq!(
            effect_code(limit.validate()),
            EffectErrorCode::ResourceLimit
        );

        let mut type_error = request_fixture();
        type_error.effects[0].scope_type = TypeExpr::CapabilityToken(id(50));
        match type_error.validate().unwrap_err() {
            EffectValidationError::Type(error) => {
                assert_eq!(error.code(), TypeErrorCode::NotPersistable);
            }
            error => panic!("unexpected error: {error}"),
        }

        let mut cfg_error = empty_fixture();
        cfg_error.functions[0].blocks[0].reachability = Reachability::ExplicitlyUnreachable;
        assert!(matches!(
            cfg_error.validate().unwrap_err(),
            EffectValidationError::Cfg(_)
        ));
    }

    #[test]
    fn generic_direct_call_instantiates_in_caller_scope() {
        let mut fixture = transitive_call_fixture();
        fixture.functions[1].function.type_parameters = vec![TypeParameterDef { ordinal: 0 }];
        fixture.functions[1].parameters[0].value_type = TypeExpr::TypeParameter(0);
        fixture.functions[1].function.result_type = TypeExpr::TypeParameter(0);
        fixture.functions[1].operations[0].operands =
            vec![ValueRef::Parameter(id(12)), ValueRef::Parameter(id(12))];
        fixture.functions[1].blocks[0].terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::Parameter(id(11)),
        });
        let call = &mut fixture.functions[0].operations[0];
        let Immediate::Function(reference) = &mut call.immediate else {
            panic!("call immediate");
        };
        reference.type_arguments.push(TypeExpr::Unit);
        fixture.validate().unwrap();
    }

    #[test]
    fn seeded_unresolved_call_smoke_never_accepts_or_panics() {
        for seed in 100_u32..228 {
            let mut fixture = transitive_call_fixture();
            let Immediate::Function(reference) = &mut fixture.functions[0].operations[0].immediate
            else {
                panic!("call immediate");
            };
            reference.function = id(seed);
            assert_eq!(
                effect_code(fixture.validate()),
                EffectErrorCode::UnresolvedEntity,
                "seed {seed}"
            );
        }
    }

    #[test]
    fn structural_scope_order_covers_tags_and_nested_payloads() {
        let false_value = ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(false),
        };
        let true_value = ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(true),
        };
        assert_eq!(
            compare_const_values(&false_value, &true_value),
            Ordering::Less
        );

        let short = ConstValue {
            value_type: TypeExpr::Bytes,
            data: ConstData::Bytes(vec![1]),
        };
        let long = ConstValue {
            value_type: TypeExpr::Bytes,
            data: ConstData::Bytes(vec![1, 0]),
        };
        assert_eq!(compare_const_values(&short, &long), Ordering::Less);

        let none = ConstValue {
            value_type: TypeExpr::Option(Box::new(TypeExpr::Unit)),
            data: ConstData::Option(None),
        };
        let some = ConstValue {
            value_type: TypeExpr::Option(Box::new(TypeExpr::Unit)),
            data: ConstData::Option(Some(Box::new(unit_constant()))),
        };
        assert_eq!(compare_const_values(&none, &some), Ordering::Less);
    }
}
