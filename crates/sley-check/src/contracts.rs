//! S20-240 restricted epoch-1 contract/test validation and planning.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use sley_id::EntityId;
use sley_ssmc::{
    AdapterImport, BuiltinFailureKind, CapabilityRequirement, ConstantDefinition,
    ContractDefinition, ContractKind, ContractSource, EffectDefinition, EffectEnvironment,
    ExpectedOutcome, GlobalValueDefinition, Immediate, Opcode, Operation, Parameter,
    TestCaseDefinition, TypeDefinition, TypeExpr, ValueRef,
};

use crate::{
    TypeEnvironment, TypeError,
    effects::{EffectValidationError, FunctionUnit, validate_effect_program},
};

/// Maximum `TypeDefinition` entities in one S20-240 request.
pub const MAX_CONTRACT_TYPE_DEFINITIONS: usize = 65_535;
/// Maximum Constant entities in one request.
pub const MAX_CONTRACT_CONSTANTS: usize = 65_535;
/// Maximum `GlobalValue` entities in one request.
pub const MAX_CONTRACT_GLOBALS: usize = 65_535;
/// Maximum Contract entities in one request.
pub const MAX_CONTRACTS: usize = 65_535;
/// Maximum `TestCase` entities in one request.
pub const MAX_TEST_CASES: usize = 65_535;
/// Maximum predicate bindings in one Contract.
pub const MAX_CONTRACT_BINDINGS: usize = 65_535;
/// Maximum predicate bindings across one request.
pub const MAX_TOTAL_CONTRACT_BINDINGS: usize = 1_000_000;
/// Maximum inputs in one `TestCase`.
pub const MAX_TEST_INPUTS: usize = 65_535;
/// Maximum test inputs across one request.
pub const MAX_TOTAL_TEST_INPUTS: usize = 1_000_000;
/// Maximum Function contract attachments.
pub const MAX_FUNCTION_CONTRACTS: usize = 65_535;
/// Maximum Function contract attachments across one request.
pub const MAX_TOTAL_FUNCTION_CONTRACTS: usize = 1_000_000;
/// Maximum affected functions in one provisional plan.
pub const MAX_AFFECTED_FUNCTIONS: usize = 65_535;
/// Maximum externally required tests in one provisional plan.
pub const MAX_REQUIRED_TESTS: usize = 65_535;
/// Maximum selected tests in one provisional plan.
pub const MAX_SELECTED_TESTS: usize = 65_535;
/// Maximum charged lookup/comparison operations.
pub const MAX_CONTRACT_TEST_WORK: u64 = 50_000_000;

/// Stable S20-240 contract/test-plan failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractTestErrorCode {
    /// `CONTRACT_UNRESOLVED_ENTITY`
    UnresolvedEntity,
    /// `CONTRACT_WRONG_ENTITY_KIND`
    WrongEntityKind,
    /// `CONTRACT_SET_NOT_CANONICAL`
    SetNotCanonical,
    /// `CONTRACT_INVARIANT_UNSUPPORTED`
    InvariantUnsupported,
    /// `CONTRACT_KIND_UNSUPPORTED`
    KindUnsupported,
    /// `CONTRACT_TARGET_INVALID`
    TargetInvalid,
    /// `CONTRACT_PREDICATE_INVALID`
    PredicateInvalid,
    /// `CONTRACT_BINDING_INVALID`
    BindingInvalid,
    /// `CONTRACT_ATTACHMENT_MISMATCH`
    AttachmentMismatch,
    /// `CONTRACT_ASSERT_TYPE`
    AssertType,
    /// `TEST_PLAN_TARGET_INVALID`
    TestTargetInvalid,
    /// `TEST_PLAN_INPUT_TYPE`
    TestInputType,
    /// `TEST_PLAN_EFFECT_ENVIRONMENT_UNSUPPORTED`
    TestEffectEnvironmentUnsupported,
    /// `TEST_PLAN_EXPECTED_TYPE`
    TestExpectedType,
    /// `TEST_PLAN_FAILURE_CODE_INVALID`
    TestFailureCodeInvalid,
    /// `TEST_PLAN_OBSERVATION_UNSUPPORTED`
    TestObservationUnsupported,
    /// `TEST_PLAN_SELECTION_INVALID`
    TestSelectionInvalid,
    /// `CONTRACT_TEST_PLAN_RESOURCE_LIMIT`
    ResourceLimit,
}

impl ContractTestErrorCode {
    /// Returns the exact stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnresolvedEntity => "CONTRACT_UNRESOLVED_ENTITY",
            Self::WrongEntityKind => "CONTRACT_WRONG_ENTITY_KIND",
            Self::SetNotCanonical => "CONTRACT_SET_NOT_CANONICAL",
            Self::InvariantUnsupported => "CONTRACT_INVARIANT_UNSUPPORTED",
            Self::KindUnsupported => "CONTRACT_KIND_UNSUPPORTED",
            Self::TargetInvalid => "CONTRACT_TARGET_INVALID",
            Self::PredicateInvalid => "CONTRACT_PREDICATE_INVALID",
            Self::BindingInvalid => "CONTRACT_BINDING_INVALID",
            Self::AttachmentMismatch => "CONTRACT_ATTACHMENT_MISMATCH",
            Self::AssertType => "CONTRACT_ASSERT_TYPE",
            Self::TestTargetInvalid => "TEST_PLAN_TARGET_INVALID",
            Self::TestInputType => "TEST_PLAN_INPUT_TYPE",
            Self::TestEffectEnvironmentUnsupported => "TEST_PLAN_EFFECT_ENVIRONMENT_UNSUPPORTED",
            Self::TestExpectedType => "TEST_PLAN_EXPECTED_TYPE",
            Self::TestFailureCodeInvalid => "TEST_PLAN_FAILURE_CODE_INVALID",
            Self::TestObservationUnsupported => "TEST_PLAN_OBSERVATION_UNSUPPORTED",
            Self::TestSelectionInvalid => "TEST_PLAN_SELECTION_INVALID",
            Self::ResourceLimit => "CONTRACT_TEST_PLAN_RESOURCE_LIMIT",
        }
    }

    /// Returns the exact stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::UnresolvedEntity => 24_000,
            Self::WrongEntityKind => 24_001,
            Self::SetNotCanonical => 24_002,
            Self::InvariantUnsupported => 24_003,
            Self::KindUnsupported => 24_004,
            Self::TargetInvalid => 24_005,
            Self::PredicateInvalid => 24_006,
            Self::BindingInvalid => 24_007,
            Self::AttachmentMismatch => 24_008,
            Self::AssertType => 24_009,
            Self::TestTargetInvalid => 24_010,
            Self::TestInputType => 24_011,
            Self::TestEffectEnvironmentUnsupported => 24_012,
            Self::TestExpectedType => 24_013,
            Self::TestFailureCodeInvalid => 24_014,
            Self::TestObservationUnsupported => 24_015,
            Self::TestSelectionInvalid => 24_016,
            Self::ResourceLimit => 24_017,
        }
    }
}

impl fmt::Display for ContractTestErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable S20-240 error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractTestError {
    code: ContractTestErrorCode,
}

impl ContractTestError {
    /// Constructs an error from its frozen code.
    #[must_use]
    pub const fn new(code: ContractTestErrorCode) -> Self {
        Self { code }
    }

    /// Returns the frozen code.
    #[must_use]
    pub const fn code(&self) -> ContractTestErrorCode {
        self.code
    }
}

impl fmt::Display for ContractTestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for ContractTestError {}

/// An S20-240 or preserved earlier failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractTestValidationError {
    /// Exact S20-210 failure from Constant/Global validation.
    Type(TypeError),
    /// Exact S20-210/S20-220/S20-230 function/effect failure.
    Effect(EffectValidationError),
    /// S20-240 contract/test-plan failure.
    ContractTest(ContractTestError),
}

impl fmt::Display for ContractTestValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(error) => error.fmt(formatter),
            Self::Effect(error) => error.fmt(formatter),
            Self::ContractTest(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ContractTestValidationError {}

impl From<TypeError> for ContractTestValidationError {
    fn from(value: TypeError) -> Self {
        Self::Type(value)
    }
}

impl From<EffectValidationError> for ContractTestValidationError {
    fn from(value: EffectValidationError) -> Self {
        Self::Effect(value)
    }
}

/// S20-240 validation result.
pub type ContractTestResult<T> = core::result::Result<T, ContractTestValidationError>;

/// Provisional planning finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestPlanFinality {
    /// Protected S20-370 policy has not finalized required tests.
    PolicyIncomplete,
}

/// Deterministic successful restricted-profile report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractTestReport {
    /// Validated Contract identities in raw-ID order.
    pub contracts: Vec<EntityId>,
    /// Validated `TestCase` identities in raw-ID order.
    pub tests: Vec<EntityId>,
    /// Provisionally selected `TestCase` identities in raw-ID order.
    pub selected_tests: Vec<EntityId>,
    /// Explicit non-final policy state.
    pub selection_finality: TestPlanFinality,
    /// Number of typed contract assertions.
    pub contract_assertions: u32,
    /// Charged S20-240 lookup/comparison work.
    pub work: u64,
}

struct ContractIndex<'a> {
    units: &'a [FunctionUnit<'a>],
    functions: BTreeMap<EntityId, usize>,
    closures: BTreeMap<EntityId, Vec<EntityId>>,
    constants: BTreeMap<EntityId, &'a ConstantDefinition>,
    globals: BTreeMap<EntityId, &'a GlobalValueDefinition>,
    contracts: BTreeMap<EntityId, &'a ContractDefinition>,
    tests: BTreeMap<EntityId, &'a TestCaseDefinition>,
    all_ids: BTreeSet<EntityId>,
}

/// Validates the restricted epoch-1 contract/test profile and builds one
/// deterministic policy-incomplete test plan.
///
/// # Errors
///
/// Returns the first deterministic preserved earlier or S20-240 failure.
#[allow(clippy::too_many_arguments)]
pub fn validate_contract_test_program<'a>(
    types: &TypeEnvironment,
    units: &'a [FunctionUnit<'a>],
    effects: &'a [EffectDefinition],
    requirements: &'a [CapabilityRequirement],
    adapters: &'a [AdapterImport],
    type_definitions: &'a [TypeDefinition],
    constants: &'a [ConstantDefinition],
    globals: &'a [GlobalValueDefinition],
    contracts: &'a [ContractDefinition],
    tests: &'a [TestCaseDefinition],
    affected_functions: &[EntityId],
    required_tests: &[EntityId],
) -> ContractTestResult<ContractTestReport> {
    let mut index = build_index(
        units,
        effects,
        requirements,
        adapters,
        type_definitions,
        constants,
        globals,
        contracts,
        tests,
        affected_functions,
        required_tests,
    )?;
    if !types.definition_ids().eq(type_definitions
        .iter()
        .map(|definition| definition.entity_id))
    {
        return contract_fail(ContractTestErrorCode::SetNotCanonical);
    }
    let contract_ids: Vec<_> = contracts
        .iter()
        .map(|contract| contract.entity_id)
        .collect();
    let effect_report =
        validate_effect_program(types, units, effects, requirements, adapters, &contract_ids)?;
    index.closures = effect_report
        .functions
        .into_iter()
        .map(|function| (function.function, function.effects))
        .collect();

    let mut work = 0_u64;
    validate_constants_and_globals(types, &index, &mut work)?;
    validate_invariant_profile(type_definitions, &mut work)?;
    validate_contracts(&index, &mut work)?;
    validate_attachments(&index, &mut work)?;
    let contract_assertions = validate_contract_assertions(&index, &mut work)?;
    reject_test_observations(&index, &mut work)?;
    validate_tests(types, &index, &mut work)?;
    let selected_tests = select_tests(&index, affected_functions, required_tests, &mut work)?;

    Ok(ContractTestReport {
        contracts: index.contracts.keys().copied().collect(),
        tests: index.tests.keys().copied().collect(),
        selected_tests,
        selection_finality: TestPlanFinality::PolicyIncomplete,
        contract_assertions: u32::try_from(contract_assertions)
            .map_err(|_| contract_error(ContractTestErrorCode::ResourceLimit))?,
        work,
    })
}

fn contract_error(code: ContractTestErrorCode) -> ContractTestValidationError {
    ContractTestValidationError::ContractTest(ContractTestError::new(code))
}

fn contract_fail<T>(code: ContractTestErrorCode) -> ContractTestResult<T> {
    Err(contract_error(code))
}

#[allow(clippy::too_many_arguments)]
fn build_index<'a>(
    units: &'a [FunctionUnit<'a>],
    effects: &'a [EffectDefinition],
    requirements: &'a [CapabilityRequirement],
    adapters: &'a [AdapterImport],
    type_definitions: &'a [TypeDefinition],
    constants: &'a [ConstantDefinition],
    globals: &'a [GlobalValueDefinition],
    contracts: &'a [ContractDefinition],
    tests: &'a [TestCaseDefinition],
    affected_functions: &[EntityId],
    required_tests: &[EntityId],
) -> ContractTestResult<ContractIndex<'a>> {
    if type_definitions.len() > MAX_CONTRACT_TYPE_DEFINITIONS
        || constants.len() > MAX_CONTRACT_CONSTANTS
        || globals.len() > MAX_CONTRACT_GLOBALS
        || contracts.len() > MAX_CONTRACTS
        || tests.len() > MAX_TEST_CASES
        || affected_functions.len() > MAX_AFFECTED_FUNCTIONS
        || required_tests.len() > MAX_REQUIRED_TESTS
    {
        return contract_fail(ContractTestErrorCode::ResourceLimit);
    }
    ensure_sorted_by(units, |unit| unit.function.entity_id)?;
    ensure_sorted_by(type_definitions, |value| value.entity_id)?;
    ensure_sorted_by(constants, |value| value.entity_id)?;
    ensure_sorted_by(globals, |value| value.entity_id)?;
    ensure_sorted_by(contracts, |value| value.entity_id)?;
    ensure_sorted_by(tests, |value| value.entity_id)?;
    ensure_sorted_unique(affected_functions)?;
    ensure_sorted_unique(required_tests)?;

    let mut total_bindings = 0_usize;
    for contract in contracts {
        if contract.bindings.len() > MAX_CONTRACT_BINDINGS {
            return contract_fail(ContractTestErrorCode::ResourceLimit);
        }
        total_bindings = total_bindings
            .checked_add(contract.bindings.len())
            .ok_or_else(|| contract_error(ContractTestErrorCode::ResourceLimit))?;
    }
    let mut total_inputs = 0_usize;
    for test in tests {
        if test.inputs.len() > MAX_TEST_INPUTS {
            return contract_fail(ContractTestErrorCode::ResourceLimit);
        }
        total_inputs = total_inputs
            .checked_add(test.inputs.len())
            .ok_or_else(|| contract_error(ContractTestErrorCode::ResourceLimit))?;
    }
    let mut total_attachments = 0_usize;
    for unit in units {
        if unit.function.contracts.len() > MAX_FUNCTION_CONTRACTS {
            return contract_fail(ContractTestErrorCode::ResourceLimit);
        }
        total_attachments = total_attachments
            .checked_add(unit.function.contracts.len())
            .ok_or_else(|| contract_error(ContractTestErrorCode::ResourceLimit))?;
    }
    if total_bindings > MAX_TOTAL_CONTRACT_BINDINGS
        || total_inputs > MAX_TOTAL_TEST_INPUTS
        || total_attachments > MAX_TOTAL_FUNCTION_CONTRACTS
    {
        return contract_fail(ContractTestErrorCode::ResourceLimit);
    }

    let mut all_ids = BTreeSet::new();
    let mut functions = BTreeMap::new();
    for (position, unit) in units.iter().enumerate() {
        insert_id(&mut all_ids, unit.function.entity_id)?;
        functions.insert(unit.function.entity_id, position);
        for parameter in unit.parameters {
            insert_id(&mut all_ids, parameter.entity_id)?;
        }
        for block in unit.blocks {
            insert_id(&mut all_ids, block.entity_id)?;
        }
        for operation in unit.operations {
            insert_id(&mut all_ids, operation.entity_id)?;
        }
    }
    for effect in effects {
        insert_id(&mut all_ids, effect.entity_id)?;
    }
    for requirement in requirements {
        insert_id(&mut all_ids, requirement.entity_id)?;
    }
    for adapter in adapters {
        insert_id(&mut all_ids, adapter.entity_id)?;
    }
    for definition in type_definitions {
        insert_id(&mut all_ids, definition.entity_id)?;
    }
    let constants = index_entities(constants, &mut all_ids, |value| value.entity_id)?;
    let globals = index_entities(globals, &mut all_ids, |value| value.entity_id)?;
    let contracts = index_entities(contracts, &mut all_ids, |value| value.entity_id)?;
    let tests = index_entities(tests, &mut all_ids, |value| value.entity_id)?;

    Ok(ContractIndex {
        units,
        functions,
        closures: BTreeMap::new(),
        constants,
        globals,
        contracts,
        tests,
        all_ids,
    })
}

fn ensure_sorted_by<T, F>(values: &[T], key: F) -> ContractTestResult<()>
where
    F: Fn(&T) -> EntityId,
{
    if values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])) {
        Ok(())
    } else {
        contract_fail(ContractTestErrorCode::SetNotCanonical)
    }
}

fn ensure_sorted_unique(values: &[EntityId]) -> ContractTestResult<()> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        contract_fail(ContractTestErrorCode::SetNotCanonical)
    }
}

fn insert_id(ids: &mut BTreeSet<EntityId>, id: EntityId) -> ContractTestResult<()> {
    if ids.insert(id) {
        Ok(())
    } else {
        contract_fail(ContractTestErrorCode::SetNotCanonical)
    }
}

fn index_entities<'a, T, F>(
    values: &'a [T],
    all_ids: &mut BTreeSet<EntityId>,
    id: F,
) -> ContractTestResult<BTreeMap<EntityId, &'a T>>
where
    F: Fn(&T) -> EntityId,
{
    let mut output = BTreeMap::new();
    for value in values {
        let entity_id = id(value);
        insert_id(all_ids, entity_id)?;
        output.insert(entity_id, value);
    }
    Ok(output)
}

fn lookup<'a, T>(
    values: &'a BTreeMap<EntityId, T>,
    id: EntityId,
    all_ids: &BTreeSet<EntityId>,
) -> ContractTestResult<&'a T> {
    if let Some(value) = values.get(&id) {
        Ok(value)
    } else if all_ids.contains(&id) {
        contract_fail(ContractTestErrorCode::WrongEntityKind)
    } else {
        contract_fail(ContractTestErrorCode::UnresolvedEntity)
    }
}

fn function_index(index: &ContractIndex<'_>, id: EntityId) -> ContractTestResult<usize> {
    if let Some(position) = index.functions.get(&id) {
        Ok(*position)
    } else if index.all_ids.contains(&id) {
        contract_fail(ContractTestErrorCode::WrongEntityKind)
    } else {
        contract_fail(ContractTestErrorCode::UnresolvedEntity)
    }
}

fn validate_constants_and_globals(
    types: &TypeEnvironment,
    index: &ContractIndex<'_>,
    work: &mut u64,
) -> ContractTestResult<()> {
    for constant in index.constants.values() {
        charge(work, 1)?;
        types.check_constant(&constant.value)?;
    }
    for global in index.globals.values() {
        charge(work, 1)?;
        types.check_closed_type(&global.value_type)?;
        types.require_persistable(&global.value_type)?;
        let initializer = lookup(&index.constants, global.initializer, &index.all_ids)?;
        if initializer.value.value_type != global.value_type {
            return contract_fail(ContractTestErrorCode::BindingInvalid);
        }
    }
    Ok(())
}

fn validate_invariant_profile(
    definitions: &[TypeDefinition],
    work: &mut u64,
) -> ContractTestResult<()> {
    for definition in definitions {
        charge(work, 1)?;
        if !definition.invariants.is_empty() {
            return contract_fail(ContractTestErrorCode::InvariantUnsupported);
        }
    }
    Ok(())
}

fn validate_contracts(index: &ContractIndex<'_>, work: &mut u64) -> ContractTestResult<()> {
    for contract in index.contracts.values() {
        charge(work, 1)?;
        if contract.resource_limits.is_some() {
            return contract_fail(ContractTestErrorCode::KindUnsupported);
        }
        if !matches!(
            contract.contract_kind,
            ContractKind::Precondition
                | ContractKind::Postcondition
                | ContractKind::ResultPredicate
        ) {
            return contract_fail(ContractTestErrorCode::KindUnsupported);
        }
        let target_position = function_index(index, contract.target)?;
        let predicate_position = function_index(index, contract.predicate)?;
        let target = &index.units[target_position];
        let predicate = &index.units[predicate_position];
        if target.function.entity_id == predicate.function.entity_id
            || !target.function.type_parameters.is_empty()
        {
            return contract_fail(ContractTestErrorCode::TargetInvalid);
        }
        let predicate_closure = index
            .closures
            .get(&predicate.function.entity_id)
            .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity))?;
        if !predicate.function.type_parameters.is_empty()
            || !predicate_closure.is_empty()
            || !predicate.function.contracts.is_empty()
            || predicate.function.result_type != TypeExpr::Bool
        {
            return contract_fail(ContractTestErrorCode::PredicateInvalid);
        }
        validate_bindings(index, contract, target, predicate, work)?;
    }
    Ok(())
}

fn validate_bindings(
    index: &ContractIndex<'_>,
    contract: &ContractDefinition,
    target: &FunctionUnit<'_>,
    predicate: &FunctionUnit<'_>,
    work: &mut u64,
) -> ContractTestResult<()> {
    if contract.bindings.len() != predicate.function.parameters.len() {
        return contract_fail(ContractTestErrorCode::BindingInvalid);
    }
    let target_parameters: BTreeMap<_, _> = target
        .parameters
        .iter()
        .filter(|parameter| target.function.parameters.contains(&parameter.entity_id))
        .map(|parameter| (parameter.entity_id, parameter))
        .collect();
    let predicate_parameters: BTreeMap<_, _> = predicate
        .parameters
        .iter()
        .map(|parameter| (parameter.entity_id, parameter))
        .collect();
    let mut has_result = false;
    let mut has_error = false;
    for (ordinal, binding) in contract.bindings.iter().enumerate() {
        charge(work, 1)?;
        if usize::try_from(binding.predicate_parameter).ok() != Some(ordinal) {
            return contract_fail(ContractTestErrorCode::BindingInvalid);
        }
        let predicate_id = predicate.function.parameters[ordinal];
        let predicate_type = &predicate_parameters
            .get(&predicate_id)
            .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity))?
            .value_type;
        let source_type = match binding.source {
            ContractSource::Parameter(id) => {
                &target_parameters
                    .get(&id)
                    .ok_or_else(|| contract_error(ContractTestErrorCode::BindingInvalid))?
                    .value_type
            }
            ContractSource::Result => {
                has_result = true;
                &target.function.result_type
            }
            ContractSource::Error => {
                has_error = true;
                let TypeExpr::Result { error, .. } = &target.function.result_type else {
                    return contract_fail(ContractTestErrorCode::BindingInvalid);
                };
                error
            }
            ContractSource::Global(id) => &lookup(&index.globals, id, &index.all_ids)?.value_type,
        };
        if predicate_type != source_type {
            return contract_fail(ContractTestErrorCode::BindingInvalid);
        }
    }
    match contract.contract_kind {
        ContractKind::Precondition if has_result || has_error => {
            contract_fail(ContractTestErrorCode::BindingInvalid)
        }
        ContractKind::Postcondition if has_result && has_error => {
            contract_fail(ContractTestErrorCode::BindingInvalid)
        }
        ContractKind::ResultPredicate if !has_result || has_error => {
            contract_fail(ContractTestErrorCode::BindingInvalid)
        }
        _ => Ok(()),
    }
}

fn validate_attachments(index: &ContractIndex<'_>, work: &mut u64) -> ContractTestResult<()> {
    let mut expected: BTreeMap<EntityId, Vec<EntityId>> = BTreeMap::new();
    for contract in index.contracts.values() {
        expected
            .entry(contract.target)
            .or_default()
            .push(contract.entity_id);
    }
    for unit in index.units {
        charge(work, 1)?;
        let expected = expected
            .get(&unit.function.entity_id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if unit.function.contracts != expected {
            return contract_fail(ContractTestErrorCode::AttachmentMismatch);
        }
    }
    Ok(())
}

fn validate_contract_assertions(
    index: &ContractIndex<'_>,
    work: &mut u64,
) -> ContractTestResult<usize> {
    let mut assertions = 0_usize;
    for unit in index.units {
        let operations: BTreeMap<_, _> = unit
            .operations
            .iter()
            .map(|operation| (operation.entity_id, operation))
            .collect();
        let parameters: BTreeMap<_, _> = unit
            .parameters
            .iter()
            .map(|parameter| (parameter.entity_id, parameter))
            .collect();
        for operation in ordered_operations(unit, &operations)? {
            if operation.opcode != Opcode::ContractAssert {
                continue;
            }
            charge(work, 1)?;
            assertions = assertions
                .checked_add(1)
                .ok_or_else(|| contract_error(ContractTestErrorCode::ResourceLimit))?;
            let Immediate::Entity(contract_id) = operation.immediate else {
                return contract_fail(ContractTestErrorCode::AssertType);
            };
            let contract = lookup(&index.contracts, contract_id, &index.all_ids)?;
            if contract.target != unit.function.entity_id {
                return contract_fail(ContractTestErrorCode::AssertType);
            }
            let predicate_position = function_index(index, contract.predicate)?;
            let predicate = &index.units[predicate_position];
            if operation.operands.len() != predicate.function.parameters.len()
                || operation.result_types.len() != 1
            {
                return contract_fail(ContractTestErrorCode::AssertType);
            }
            let predicate_parameters: BTreeMap<_, _> = predicate
                .parameters
                .iter()
                .map(|parameter| (parameter.entity_id, parameter))
                .collect();
            for (operand, predicate_id) in operation
                .operands
                .iter()
                .zip(&predicate.function.parameters)
            {
                let expected = &predicate_parameters
                    .get(predicate_id)
                    .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity))?
                    .value_type;
                if resolve_value_type(*operand, &parameters, &operations)? != expected {
                    return contract_fail(ContractTestErrorCode::AssertType);
                }
            }
            let expected_result = TypeExpr::Result {
                ok: Box::new(TypeExpr::Unit),
                error: Box::new(TypeExpr::BuiltinFailure(
                    BuiltinFailureKind::ContractViolation,
                )),
            };
            if operation.result_types[0] != expected_result {
                return contract_fail(ContractTestErrorCode::AssertType);
            }
        }
    }
    Ok(assertions)
}

fn reject_test_observations(index: &ContractIndex<'_>, work: &mut u64) -> ContractTestResult<()> {
    for unit in index.units {
        for operation in unit.operations {
            charge(work, 1)?;
            if operation.opcode == Opcode::TestObserve {
                return contract_fail(ContractTestErrorCode::TestObservationUnsupported);
            }
        }
    }
    Ok(())
}

fn validate_tests(
    types: &TypeEnvironment,
    index: &ContractIndex<'_>,
    work: &mut u64,
) -> ContractTestResult<()> {
    for test in index.tests.values() {
        charge(work, 1)?;
        let target_position = function_index(index, test.target)?;
        let target = &index.units[target_position];
        let closure = index
            .closures
            .get(&target.function.entity_id)
            .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity))?;
        if !target.function.type_parameters.is_empty() || !closure.is_empty() {
            return contract_fail(ContractTestErrorCode::TestTargetInvalid);
        }
        if test.inputs.len() != target.function.parameters.len() {
            return contract_fail(ContractTestErrorCode::TestInputType);
        }
        let target_parameters: BTreeMap<_, _> = target
            .parameters
            .iter()
            .map(|parameter| (parameter.entity_id, parameter))
            .collect();
        for (input, parameter_id) in test.inputs.iter().zip(&target.function.parameters) {
            types.check_constant(input)?;
            let expected = &target_parameters
                .get(parameter_id)
                .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity))?
                .value_type;
            if &input.value_type != expected {
                return contract_fail(ContractTestErrorCode::TestInputType);
            }
        }
        if !matches!(&test.effect_environment, EffectEnvironment::Replay(values) if values.is_empty())
        {
            return contract_fail(ContractTestErrorCode::TestEffectEnvironmentUnsupported);
        }
        match &test.expected {
            ExpectedOutcome::Value(value) => {
                types.check_constant(value)?;
                if value.value_type != target.function.result_type {
                    return contract_fail(ContractTestErrorCode::TestExpectedType);
                }
            }
            ExpectedOutcome::FailureCode(code) if !(1..=4).contains(code) => {
                return contract_fail(ContractTestErrorCode::TestFailureCodeInvalid);
            }
            ExpectedOutcome::FailureCode(_) => {}
        }
        if !test.observations.is_empty() {
            return contract_fail(ContractTestErrorCode::TestObservationUnsupported);
        }
    }
    Ok(())
}

fn select_tests(
    index: &ContractIndex<'_>,
    affected_functions: &[EntityId],
    required_tests: &[EntityId],
    work: &mut u64,
) -> ContractTestResult<Vec<EntityId>> {
    let mut affected = BTreeSet::new();
    for function in affected_functions {
        charge(work, 1)?;
        function_index(index, *function)
            .map_err(|_| contract_error(ContractTestErrorCode::TestSelectionInvalid))?;
        affected.insert(*function);
    }
    let mut required = BTreeSet::new();
    for test in required_tests {
        charge(work, 1)?;
        if !index.tests.contains_key(test) {
            return contract_fail(ContractTestErrorCode::TestSelectionInvalid);
        }
        required.insert(*test);
    }
    let mut selected = Vec::new();
    for test in index.tests.values() {
        charge(work, 1)?;
        if affected.contains(&test.target) || required.contains(&test.entity_id) {
            selected.push(test.entity_id);
        }
    }
    if selected.len() > MAX_SELECTED_TESTS {
        contract_fail(ContractTestErrorCode::ResourceLimit)
    } else {
        Ok(selected)
    }
}

fn ordered_operations<'a>(
    unit: &'a FunctionUnit<'a>,
    operations: &'a BTreeMap<EntityId, &'a Operation>,
) -> ContractTestResult<Vec<&'a Operation>> {
    let blocks: BTreeMap<_, _> = unit
        .blocks
        .iter()
        .map(|block| (block.entity_id, block))
        .collect();
    let mut output = Vec::new();
    for block_id in &unit.function.blocks {
        let block = blocks
            .get(block_id)
            .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity))?;
        for operation_id in &block.operations {
            output.push(
                *operations
                    .get(operation_id)
                    .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity))?,
            );
        }
    }
    Ok(output)
}

fn resolve_value_type<'a>(
    value: ValueRef,
    parameters: &'a BTreeMap<EntityId, &Parameter>,
    operations: &'a BTreeMap<EntityId, &Operation>,
) -> ContractTestResult<&'a TypeExpr> {
    match value {
        ValueRef::Parameter(id) => parameters
            .get(&id)
            .map(|parameter| &parameter.value_type)
            .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity)),
        ValueRef::OperationResult(result) => operations
            .get(&result.operation)
            .and_then(|operation| {
                usize::try_from(result.result_index)
                    .ok()
                    .and_then(|position| operation.result_types.get(position))
            })
            .ok_or_else(|| contract_error(ContractTestErrorCode::UnresolvedEntity)),
    }
}

fn charge(work: &mut u64, amount: u64) -> ContractTestResult<()> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| contract_error(ContractTestErrorCode::ResourceLimit))?;
    if *work > MAX_CONTRACT_TEST_WORK {
        contract_fail(ContractTestErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TypeEnvironment, TypeErrorCode};
    use sley_ssmc::{
        Block, ConstData, ConstValue, ContractBinding, ExpectedObservation, FunctionGraph,
        OperationResultRef, ParameterRole, Reachability, ResourceLimits, ReturnTerminator,
        TypeDefForm, TypeParameterDef, Visibility,
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
        type_definitions: Vec<TypeDefinition>,
        constants: Vec<ConstantDefinition>,
        globals: Vec<GlobalValueDefinition>,
        contracts: Vec<ContractDefinition>,
        tests: Vec<TestCaseDefinition>,
        affected: Vec<EntityId>,
        required: Vec<EntityId>,
    }

    impl Fixture {
        fn validate(&self) -> ContractTestResult<ContractTestReport> {
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
            validate_contract_test_program(
                &self.types,
                &units,
                &self.effects,
                &self.requirements,
                &self.adapters,
                &self.type_definitions,
                &self.constants,
                &self.globals,
                &self.contracts,
                &self.tests,
                &self.affected,
                &self.required,
            )
        }
    }

    fn id(value: u32) -> EntityId {
        let mut bytes = [0_u8; 32];
        bytes[28..].copy_from_slice(&value.to_be_bytes());
        EntityId::from_bytes(bytes)
    }

    fn parameter(entity: u32, owner: u32, value_type: TypeExpr) -> Parameter {
        Parameter {
            entity_id: id(entity),
            owner: id(owner),
            role: ParameterRole::Function,
            ordinal: 0,
            value_type,
        }
    }

    fn unit_constant() -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Unit,
            data: ConstData::Unit,
        }
    }

    fn zero_limits() -> ResourceLimits {
        ResourceLimits {
            fuel: 0,
            memory_bytes: 0,
            output_bytes: 0,
            effect_count: 0,
            call_depth: 0,
            wall_timeout_millis: 0,
        }
    }

    fn target_function() -> OwnedFunction {
        let assertion_result = TypeExpr::Result {
            ok: Box::new(TypeExpr::Unit),
            error: Box::new(TypeExpr::BuiltinFailure(
                BuiltinFailureKind::ContractViolation,
            )),
        };
        OwnedFunction {
            function: FunctionGraph {
                entity_id: id(1),
                type_parameters: Vec::new(),
                parameters: vec![id(2)],
                result_type: TypeExpr::Unit,
                effects: Vec::new(),
                entry_block: id(3),
                blocks: vec![id(3)],
                contracts: vec![id(20)],
                visibility: sley_ssmc::Visibility::Private,
            },
            parameters: vec![parameter(2, 1, TypeExpr::Unit)],
            blocks: vec![Block {
                entity_id: id(3),
                function: id(1),
                parameters: Vec::new(),
                operations: vec![id(4)],
                terminator: sley_ssmc::Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(id(2)),
                }),
                reachability: Reachability::Required,
            }],
            operations: vec![Operation {
                entity_id: id(4),
                block: id(3),
                ordinal: 0,
                opcode: Opcode::ContractAssert,
                operands: vec![ValueRef::Parameter(id(2))],
                result_types: vec![assertion_result],
                immediate: Immediate::Entity(id(20)),
            }],
        }
    }

    fn predicate_function(parameter_type: TypeExpr) -> OwnedFunction {
        let direct_bool = parameter_type == TypeExpr::Bool;
        let operations = if direct_bool {
            Vec::new()
        } else {
            vec![Operation {
                entity_id: id(13),
                block: id(12),
                ordinal: 0,
                opcode: Opcode::ConstantRef,
                operands: Vec::new(),
                result_types: vec![TypeExpr::Bool],
                immediate: Immediate::Entity(id(90)),
            }]
        };
        OwnedFunction {
            function: FunctionGraph {
                entity_id: id(10),
                type_parameters: Vec::new(),
                parameters: vec![id(11)],
                result_type: TypeExpr::Bool,
                effects: Vec::new(),
                entry_block: id(12),
                blocks: vec![id(12)],
                contracts: Vec::new(),
                visibility: sley_ssmc::Visibility::Private,
            },
            parameters: vec![parameter(11, 10, parameter_type)],
            blocks: vec![Block {
                entity_id: id(12),
                function: id(10),
                parameters: Vec::new(),
                operations: if direct_bool {
                    Vec::new()
                } else {
                    vec![id(13)]
                },
                terminator: sley_ssmc::Terminator::Return(ReturnTerminator {
                    value: if direct_bool {
                        ValueRef::Parameter(id(11))
                    } else {
                        ValueRef::OperationResult(OperationResultRef {
                            operation: id(13),
                            result_index: 0,
                        })
                    },
                }),
                reachability: Reachability::Required,
            }],
            operations,
        }
    }

    fn base_fixture() -> Fixture {
        Fixture {
            types: TypeEnvironment::new(Vec::new()).unwrap(),
            functions: vec![target_function(), predicate_function(TypeExpr::Unit)],
            effects: Vec::new(),
            requirements: Vec::new(),
            adapters: Vec::new(),
            type_definitions: Vec::new(),
            constants: Vec::new(),
            globals: Vec::new(),
            contracts: vec![ContractDefinition {
                entity_id: id(20),
                target: id(1),
                contract_kind: ContractKind::Precondition,
                predicate: id(10),
                bindings: vec![ContractBinding {
                    predicate_parameter: 0,
                    source: ContractSource::Parameter(id(2)),
                }],
                resource_limits: None,
            }],
            tests: vec![TestCaseDefinition {
                entity_id: id(30),
                target: id(1),
                inputs: vec![unit_constant()],
                effect_environment: EffectEnvironment::Replay(Vec::new()),
                expected: ExpectedOutcome::Value(unit_constant()),
                observations: Vec::new(),
                resource_limits: zero_limits(),
            }],
            affected: vec![id(1)],
            required: Vec::new(),
        }
    }

    fn test_only_fixture() -> Fixture {
        let mut fixture = base_fixture();
        fixture.functions[0].function.contracts.clear();
        fixture.functions[0].blocks[0].operations.clear();
        fixture.functions[0].operations.clear();
        fixture.contracts.clear();
        fixture
    }

    fn code(result: ContractTestResult<ContractTestReport>) -> ContractTestErrorCode {
        match result.unwrap_err() {
            ContractTestValidationError::ContractTest(error) => error.code(),
            error => panic!("unexpected earlier error: {error}"),
        }
    }

    #[test]
    fn stable_contract_test_codes_are_frozen() {
        let codes = [
            ContractTestErrorCode::UnresolvedEntity,
            ContractTestErrorCode::WrongEntityKind,
            ContractTestErrorCode::SetNotCanonical,
            ContractTestErrorCode::InvariantUnsupported,
            ContractTestErrorCode::KindUnsupported,
            ContractTestErrorCode::TargetInvalid,
            ContractTestErrorCode::PredicateInvalid,
            ContractTestErrorCode::BindingInvalid,
            ContractTestErrorCode::AttachmentMismatch,
            ContractTestErrorCode::AssertType,
            ContractTestErrorCode::TestTargetInvalid,
            ContractTestErrorCode::TestInputType,
            ContractTestErrorCode::TestEffectEnvironmentUnsupported,
            ContractTestErrorCode::TestExpectedType,
            ContractTestErrorCode::TestFailureCodeInvalid,
            ContractTestErrorCode::TestObservationUnsupported,
            ContractTestErrorCode::TestSelectionInvalid,
            ContractTestErrorCode::ResourceLimit,
        ];
        for (offset, value) in codes.into_iter().enumerate() {
            assert_eq!(
                value.numeric(),
                24_000 + u32::try_from(offset).expect("offset fits")
            );
            assert!(!value.as_str().is_empty());
        }
    }

    #[test]
    fn precondition_assert_value_test_and_selection_validate() {
        let report = base_fixture().validate().unwrap();
        assert_eq!(report.contracts, vec![id(20)]);
        assert_eq!(report.tests, vec![id(30)]);
        assert_eq!(report.selected_tests, vec![id(30)]);
        assert_eq!(
            report.selection_finality,
            TestPlanFinality::PolicyIncomplete
        );
        assert_eq!(report.contract_assertions, 1);
    }

    #[test]
    fn global_result_and_error_bindings_validate() {
        let mut global = base_fixture();
        global.constants.push(ConstantDefinition {
            entity_id: id(40),
            value: unit_constant(),
        });
        global.globals.push(GlobalValueDefinition {
            entity_id: id(41),
            value_type: TypeExpr::Unit,
            initializer: id(40),
            visibility: Visibility::Private,
        });
        global.contracts[0].bindings[0].source = ContractSource::Global(id(41));
        global.validate().unwrap();

        let mut result = base_fixture();
        result.contracts[0].contract_kind = ContractKind::ResultPredicate;
        result.contracts[0].bindings[0].source = ContractSource::Result;
        result.validate().unwrap();

        let mut error_arm = base_fixture();
        let result_type = TypeExpr::Result {
            ok: Box::new(TypeExpr::Unit),
            error: Box::new(TypeExpr::Bool),
        };
        error_arm.functions[0].function.result_type = result_type.clone();
        error_arm.functions[0].parameters[0].value_type = result_type;
        error_arm.functions[0].blocks[0].operations.clear();
        error_arm.functions[0].operations.clear();
        error_arm.functions[1] = predicate_function(TypeExpr::Bool);
        error_arm.contracts[0].contract_kind = ContractKind::Postcondition;
        error_arm.contracts[0].bindings[0].source = ContractSource::Error;
        error_arm.tests.clear();
        error_arm.affected.clear();
        error_arm.validate().unwrap();
    }

    #[test]
    fn unresolved_wrong_kind_and_noncanonical_inputs_fail_exactly() {
        let mut unresolved = base_fixture();
        unresolved.contracts[0].predicate = id(99);
        assert_eq!(
            code(unresolved.validate()),
            ContractTestErrorCode::UnresolvedEntity
        );

        let mut wrong = base_fixture();
        wrong.contracts[0].predicate = id(20);
        assert_eq!(
            code(wrong.validate()),
            ContractTestErrorCode::WrongEntityKind
        );

        let mut order = base_fixture();
        order.affected = vec![id(10), id(1)];
        assert_eq!(
            code(order.validate()),
            ContractTestErrorCode::SetNotCanonical
        );
    }

    #[test]
    fn invariant_kind_target_predicate_and_binding_fail_exactly() {
        let mut invariant = base_fixture();
        invariant.type_definitions.push(TypeDefinition {
            entity_id: id(50),
            type_parameters: Vec::new(),
            form: TypeDefForm::Record(Vec::new()),
            invariants: vec![id(20)],
            visibility: Visibility::Private,
        });
        invariant.types = TypeEnvironment::new(invariant.type_definitions.clone()).unwrap();
        assert_eq!(
            code(invariant.validate()),
            ContractTestErrorCode::InvariantUnsupported
        );

        let mut kind = base_fixture();
        kind.contracts[0].contract_kind = ContractKind::EffectBound;
        assert_eq!(
            code(kind.validate()),
            ContractTestErrorCode::KindUnsupported
        );

        let mut target = base_fixture();
        target.functions[0].function.type_parameters = vec![TypeParameterDef { ordinal: 0 }];
        assert_eq!(
            code(target.validate()),
            ContractTestErrorCode::TargetInvalid
        );

        let mut predicate = base_fixture();
        predicate.functions[1].function.result_type = TypeExpr::Unit;
        predicate.functions[1].blocks[0].operations.clear();
        predicate.functions[1].operations.clear();
        predicate.functions[1].blocks[0].terminator =
            sley_ssmc::Terminator::Return(ReturnTerminator {
                value: ValueRef::Parameter(id(11)),
            });
        assert_eq!(
            code(predicate.validate()),
            ContractTestErrorCode::PredicateInvalid
        );

        let mut binding = base_fixture();
        binding.contracts[0].bindings.clear();
        assert_eq!(
            code(binding.validate()),
            ContractTestErrorCode::BindingInvalid
        );
    }

    #[test]
    fn attachment_and_assertion_fail_exactly() {
        let mut attachment = base_fixture();
        attachment.functions[0].function.contracts.clear();
        assert_eq!(
            code(attachment.validate()),
            ContractTestErrorCode::AttachmentMismatch
        );

        let mut assertion = base_fixture();
        assertion.functions[0].operations[0].result_types[0] = TypeExpr::Unit;
        assert_eq!(
            code(assertion.validate()),
            ContractTestErrorCode::AssertType
        );
    }

    #[test]
    fn test_target_input_environment_expected_failure_and_observation_fail_exactly() {
        let mut target = test_only_fixture();
        target.functions[0].function.type_parameters = vec![TypeParameterDef { ordinal: 0 }];
        assert_eq!(
            code(target.validate()),
            ContractTestErrorCode::TestTargetInvalid
        );

        let mut input = test_only_fixture();
        input.tests[0].inputs[0] = ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(false),
        };
        assert_eq!(code(input.validate()), ContractTestErrorCode::TestInputType);

        let mut environment = test_only_fixture();
        environment.tests[0].effect_environment =
            EffectEnvironment::DeterministicAdapters(Vec::new());
        assert_eq!(
            code(environment.validate()),
            ContractTestErrorCode::TestEffectEnvironmentUnsupported
        );

        let mut expected = test_only_fixture();
        expected.tests[0].expected = ExpectedOutcome::Value(ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(false),
        });
        assert_eq!(
            code(expected.validate()),
            ContractTestErrorCode::TestExpectedType
        );

        let mut failure = test_only_fixture();
        failure.tests[0].expected = ExpectedOutcome::FailureCode(5);
        assert_eq!(
            code(failure.validate()),
            ContractTestErrorCode::TestFailureCodeInvalid
        );
        failure.tests[0].expected = ExpectedOutcome::FailureCode(4);
        failure.validate().unwrap();

        let mut observation = test_only_fixture();
        observation.tests[0].observations.push(ExpectedObservation {
            observation_id: [1; 32],
            value: unit_constant(),
        });
        assert_eq!(
            code(observation.validate()),
            ContractTestErrorCode::TestObservationUnsupported
        );
    }

    #[test]
    fn selection_resource_and_earlier_errors_fail_or_preserve_exactly() {
        let mut selection = test_only_fixture();
        selection.affected = vec![id(99)];
        assert_eq!(
            code(selection.validate()),
            ContractTestErrorCode::TestSelectionInvalid
        );

        let mut resource = base_fixture();
        resource.contracts[0].bindings = vec![
            ContractBinding {
                predicate_parameter: 0,
                source: ContractSource::Parameter(id(2)),
            };
            MAX_CONTRACT_BINDINGS + 1
        ];
        assert_eq!(
            code(resource.validate()),
            ContractTestErrorCode::ResourceLimit
        );

        let mut type_error = test_only_fixture();
        type_error.tests[0].inputs[0] = ConstValue {
            value_type: TypeExpr::Unit,
            data: ConstData::Bool(false),
        };
        match type_error.validate().unwrap_err() {
            ContractTestValidationError::Type(error) => {
                assert_eq!(error.code(), TypeErrorCode::ConstShape);
            }
            error => panic!("unexpected error: {error}"),
        }

        let mut effect_error = test_only_fixture();
        effect_error.functions[0].blocks[0].reachability = Reachability::ExplicitlyUnreachable;
        assert!(matches!(
            effect_error.validate().unwrap_err(),
            ContractTestValidationError::Effect(_)
        ));
    }

    #[test]
    fn resource_contract_replay_and_test_observe_are_explicitly_unsupported() {
        let mut resource_contract = base_fixture();
        resource_contract.contracts[0].resource_limits = Some(zero_limits());
        assert_eq!(
            code(resource_contract.validate()),
            ContractTestErrorCode::KindUnsupported
        );

        let mut replay = test_only_fixture();
        replay.tests[0].effect_environment =
            EffectEnvironment::Replay(vec![sley_ssmc::ReplayBinding {
                adapter_import: id(70),
                request: Vec::new(),
                response: sley_ssmc::ResultConst::Ok(Box::new(unit_constant())),
            }]);
        assert_eq!(
            code(replay.validate()),
            ContractTestErrorCode::TestEffectEnvironmentUnsupported
        );

        let mut observe = test_only_fixture();
        observe.functions[0].blocks[0].operations.push(id(4));
        observe.functions[0].operations.push(Operation {
            entity_id: id(4),
            block: id(3),
            ordinal: 0,
            opcode: Opcode::TestObserve,
            operands: vec![ValueRef::Parameter(id(2))],
            result_types: vec![TypeExpr::Unit],
            immediate: Immediate::Observation([1; 32]),
        });
        assert_eq!(
            code(observe.validate()),
            ContractTestErrorCode::TestObservationUnsupported
        );
    }

    #[test]
    fn required_tests_are_selected_but_remain_policy_incomplete() {
        let mut fixture = test_only_fixture();
        fixture.affected.clear();
        fixture.required.push(id(30));
        let report = fixture.validate().unwrap();
        assert_eq!(report.selected_tests, vec![id(30)]);
        assert_eq!(
            report.selection_finality,
            TestPlanFinality::PolicyIncomplete
        );
    }

    #[test]
    fn seeded_unresolved_selection_smoke_never_accepts_or_panics() {
        for seed in 100_u32..228 {
            let mut fixture = test_only_fixture();
            fixture.affected = vec![id(seed)];
            assert_eq!(
                code(fixture.validate()),
                ContractTestErrorCode::TestSelectionInvalid,
                "seed {seed}"
            );
        }
    }
}
