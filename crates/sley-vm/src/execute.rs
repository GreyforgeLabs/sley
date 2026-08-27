//! Restricted S20-270 deterministic execution profile.

use core::fmt;
use std::sync::Arc;

use sley_check::TypeError;
use sley_id::{BytecodeCacheKey, EntityId, ObservationId, SchemaEpochId, StateRoot, ValueHash};
use sley_ssmc::{
    BuiltinCase, CaseKey, ConstData, ConstValue, ResultConst, TypeExpr,
    fingerprint::{FingerprintError, FingerprintErrorCode, hash_validated_value},
};

use crate::{
    BytecodeSwitchArgument, BytecodeSwitchEdge, BytecodeTargetEdge, BytecodeTerminator,
    CacheProfile, LoweringError, LoweringInput, Register, SSMC1_DECODER_LIMITS_HASH,
    SSMC1_FIELD_SCHEMA_HASH, lower::lower_function,
};

/// Maximum canonical S20-270 observation preimage bytes.
pub const MAX_OBSERVATION_PREIMAGE_BYTES: usize = 67_108_864;
/// Maximum ordered inputs accepted by restricted execution.
pub const MAX_EXECUTION_INPUTS: usize = 262_144;
/// Maximum validated input semantic value units before execution.
pub const MAX_EXECUTION_INPUT_VALUE_UNITS: u64 = 67_108_864;

/// One restricted-v1 execution request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionRequest {
    /// Function inputs in declaration-parameter order.
    pub inputs: Vec<ConstValue>,
    /// Deterministic execution limits.
    pub limits: ExecutionLimits,
}

/// Deterministic restricted-v1 execution limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLimits {
    /// Maximum executed Boolean instructions.
    pub max_instructions: u64,
    /// Maximum charged fuel.
    pub max_fuel: u64,
    /// Maximum monotonic semantic value units.
    pub max_value_units: u64,
    /// Maximum returned or trap-payload value units.
    pub max_output_units: u64,
    /// Optional deterministic cancellation fuel point.
    pub cancel_at_fuel: Option<u64>,
}

/// Closed S20-270 runtime resource kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    /// Instruction ceiling.
    Instruction,
    /// Fuel ceiling.
    Fuel,
    /// Semantic value-unit ceiling.
    ValueUnits,
    /// Output value-unit ceiling.
    OutputUnits,
}

impl ResourceKind {
    /// Returns the exact frozen observation/report tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Instruction => 1,
            Self::Fuel => 2,
            Self::ValueUnits => 3,
            Self::OutputUnits => 4,
        }
    }
}

/// Stable S20-270 runtime status failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStatusCode {
    /// `VM_EXEC_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `VM_EXEC_CANCELLED`.
    Cancelled,
    /// `VM_EXEC_TRAP`.
    Trap,
    /// `VM_EXEC_INTERNAL_INVARIANT`.
    InternalInvariant,
}

impl ExecutionStatusCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceLimit => "VM_EXEC_RESOURCE_LIMIT",
            Self::Cancelled => "VM_EXEC_CANCELLED",
            Self::Trap => "VM_EXEC_TRAP",
            Self::InternalInvariant => "VM_EXEC_INTERNAL_INVARIANT",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::ResourceLimit => 27_002,
            Self::Cancelled => 27_003,
            Self::Trap => 27_004,
            Self::InternalInvariant => 27_005,
        }
    }
}

impl fmt::Display for ExecutionStatusCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Restricted-v1 execution termination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionTermination {
    /// Returned value.
    Success(ConstValue),
    /// Deterministic resource limit.
    ResourceLimit(ResourceKind),
    /// Deterministic cancellation point.
    Cancelled,
    /// Explicit SSMC trap.
    Trap {
        /// Exact frozen trap tag.
        trap_tag: u32,
        /// Optional persistable payload.
        payload: Option<ConstValue>,
    },
    /// Impossible runtime state after prior successful judgments.
    InternalInvariant,
}

impl ExecutionTermination {
    /// Returns the stable runtime status code, if this is not success.
    #[must_use]
    pub const fn status_code(&self) -> Option<ExecutionStatusCode> {
        match self {
            Self::Success(_) => None,
            Self::ResourceLimit(_) => Some(ExecutionStatusCode::ResourceLimit),
            Self::Cancelled => Some(ExecutionStatusCode::Cancelled),
            Self::Trap { .. } => Some(ExecutionStatusCode::Trap),
            Self::InternalInvariant => Some(ExecutionStatusCode::InternalInvariant),
        }
    }
}

/// Complete in-memory restricted-v1 execution outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    /// Exact request state root.
    pub state_root: StateRoot,
    /// Exact request schema epoch.
    pub schema_epoch: SchemaEpochId,
    /// Executed Function identity.
    pub function: EntityId,
    /// Root/profile-bound bytecode cache key.
    pub cache_key: BytecodeCacheKey,
    /// Final termination.
    pub termination: ExecutionTermination,
    /// Count of executed Boolean instructions only.
    pub instruction_count: u64,
    /// Charged fuel.
    pub fuel_used: u64,
    /// Peak monotonic semantic value units.
    pub peak_value_units: u64,
    /// Deterministic observation digest.
    pub observation_id: ObservationId,
}

/// Stable S20-270 execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionErrorCode {
    /// `VM_EXEC_INPUT_COUNT_MISMATCH`.
    InputCountMismatch,
    /// `VM_EXEC_INPUT_TYPE_MISMATCH`.
    InputTypeMismatch,
}

impl ExecutionErrorCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputCountMismatch => "VM_EXEC_INPUT_COUNT_MISMATCH",
            Self::InputTypeMismatch => "VM_EXEC_INPUT_TYPE_MISMATCH",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::InputCountMismatch => 27_000,
            Self::InputTypeMismatch => 27_001,
        }
    }
}

impl fmt::Display for ExecutionErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Public pre-execution failure preserving earlier judgments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// Exact S20-210/S20-220/S20-260 failure.
    Lowering(LoweringError),
    /// Exact S20-210 type failure.
    Type(TypeError),
    /// Exact S20-250 value-hash failure.
    Fingerprint(FingerprintError),
    /// Stable S20-270 pre-execution resource failure.
    Status(ExecutionStatusCode),
    /// Exact S20-270 pre-execution failure.
    Exec(ExecutionErrorCode),
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lowering(value) => value.fmt(formatter),
            Self::Type(value) => value.fmt(formatter),
            Self::Fingerprint(value) => value.fmt(formatter),
            Self::Status(value) => value.fmt(formatter),
            Self::Exec(value) => value.fmt(formatter),
        }
    }
}

impl std::error::Error for ExecutionError {}

impl From<LoweringError> for ExecutionError {
    fn from(value: LoweringError) -> Self {
        Self::Lowering(value)
    }
}

impl From<TypeError> for ExecutionError {
    fn from(value: TypeError) -> Self {
        Self::Type(value)
    }
}

impl From<FingerprintError> for ExecutionError {
    fn from(value: FingerprintError) -> Self {
        Self::Fingerprint(value)
    }
}

#[derive(Clone, Debug)]
struct RuntimeValue {
    root: Arc<ConstValue>,
    payload_depth: usize,
}

impl RuntimeValue {
    fn new(value: ConstValue) -> Self {
        Self {
            root: Arc::new(value),
            payload_depth: 0,
        }
    }

    fn value(&self) -> RuntimeResult<&ConstValue> {
        let mut value = self.root.as_ref();
        for _ in 0..self.payload_depth {
            value = match &value.data {
                ConstData::Variant(variant) => variant.payload.as_deref().ok_or(RuntimeFault)?,
                ConstData::Option(Some(payload))
                | ConstData::Result(ResultConst::Ok(payload) | ResultConst::Err(payload)) => {
                    payload
                }
                _ => return Err(RuntimeFault),
            };
        }
        Ok(value)
    }

    fn payload_view(&self) -> RuntimeResult<Self> {
        let value = self.value()?;
        match &value.data {
            ConstData::Variant(variant) if variant.payload.is_some() => {}
            ConstData::Option(Some(_))
            | ConstData::Result(ResultConst::Ok(_) | ResultConst::Err(_)) => {}
            _ => return Err(RuntimeFault),
        }
        Ok(Self {
            root: Arc::clone(&self.root),
            payload_depth: self.payload_depth.checked_add(1).ok_or(RuntimeFault)?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct RuntimeFault;

type RuntimeResult<T> = Result<T, RuntimeFault>;

struct ValidatedInputs {
    hashes: Vec<ValueHash>,
    value_units: u64,
}

/// Validates exact S20-270 Function inputs and returns their ordered hashes.
///
/// This is the report/conformance evidence boundary for input count, complete
/// constant/type/hashability judgment, exact parameter types, and aggregate
/// input value-unit limits.
///
/// # Errors
///
/// Preserves the exact S20-210/S20-250/S20-270 input failure.
pub fn validated_execution_input_hashes(
    input: LoweringInput<'_>,
    request: &ExecutionRequest,
) -> Result<Vec<ValueHash>, ExecutionError> {
    Ok(validate_inputs(input, request)?.hashes)
}

/// Returns the S20-270 saturating semantic value units for one constant.
#[must_use]
pub fn execution_value_units(value: &ConstValue) -> u64 {
    value_units_const(value)
}

#[derive(Clone, Debug)]
struct Runtime {
    registers: Vec<Option<RuntimeValue>>,
    block: usize,
    instruction_count: u64,
    fuel_used: u64,
    live_value_units: u64,
    peak_value_units: u64,
}

/// Executes one restricted-v1 Function through the integrated lowering authority boundary.
///
/// # Errors
///
/// Returns only preserved lowering/type/fingerprint failures or pre-execution
/// input failures. Runtime terminations are represented as `ExecutionOutcome`.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
pub fn execute_function(
    input: LoweringInput<'_>,
    request: ExecutionRequest,
) -> Result<ExecutionOutcome, ExecutionError> {
    let lowered = lower_function(input)?;
    let validated_inputs = validate_inputs(input, &request)?;
    let initial_live_total = initial_value_units(
        &lowered.bytecode.register_types,
        &lowered.bytes,
        validated_inputs.value_units,
    );
    let ExecutionRequest { inputs, limits } = request;

    let mut runtime = Runtime {
        registers: vec![None; lowered.bytecode.register_types.len()],
        block: usize::try_from(lowered.bytecode.entry_block).unwrap_or(usize::MAX),
        instruction_count: 0,
        fuel_used: 0,
        live_value_units: initial_live_total,
        peak_value_units: initial_live_total,
    };

    if runtime.peak_value_units > limits.max_value_units {
        return finish(
            input,
            limits,
            lowered.cache_key,
            &validated_inputs.hashes,
            ExecutionTermination::ResourceLimit(ResourceKind::ValueUnits),
            runtime.instruction_count,
            runtime.fuel_used,
            runtime.peak_value_units,
        );
    }

    for (index, value) in inputs.into_iter().enumerate() {
        let Some(register) = lowered
            .bytecode
            .parameter_registers
            .get(index)
            .and_then(|value| usize::try_from(*value).ok())
        else {
            return observed_invariant(
                input,
                limits,
                lowered.cache_key,
                &validated_inputs.hashes,
                &runtime,
            );
        };
        if write_register(&mut runtime, register, RuntimeValue::new(value)).is_err() {
            return observed_invariant(
                input,
                limits,
                lowered.cache_key,
                &validated_inputs.hashes,
                &runtime,
            );
        }
    }

    let termination = match run(
        &mut runtime,
        limits,
        &lowered.bytecode.blocks,
        &lowered.bytecode.result_type,
    ) {
        Ok(termination) => termination,
        Err(RuntimeFault) => ExecutionTermination::InternalInvariant,
    };
    finish_runtime(
        input,
        limits,
        lowered.cache_key,
        &validated_inputs.hashes,
        &runtime,
        termination,
    )
}

fn run(
    runtime: &mut Runtime,
    limits: ExecutionLimits,
    blocks: &[crate::BytecodeBlock],
    result_type: &TypeExpr,
) -> RuntimeResult<ExecutionTermination> {
    loop {
        let block = blocks.get(runtime.block).ok_or(RuntimeFault)?;
        for instruction in &block.instructions {
            if let Some(termination) =
                charge_action(runtime, &limits, Some(ResourceKind::Instruction))
            {
                return Ok(termination);
            }
            let operands = read_bool_operands(runtime, &instruction.operands)?;
            if instruction.results.len() != 1 {
                return Err(RuntimeFault);
            }
            let result_units = value_units_const(&ConstValue {
                value_type: TypeExpr::Bool,
                data: ConstData::Bool(false),
            });
            if !charge_value(runtime, result_units, limits.max_value_units) {
                return Ok(ExecutionTermination::ResourceLimit(
                    ResourceKind::ValueUnits,
                ));
            }
            let value = match (instruction.opcode, operands.as_slice()) {
                (102, [value]) => !value,
                (103, [left, right]) => *left && *right,
                (104, [left, right]) => *left || *right,
                _ => return Err(RuntimeFault),
            };
            let result = ConstValue {
                value_type: TypeExpr::Bool,
                data: ConstData::Bool(value),
            };
            runtime.instruction_count = runtime.instruction_count.saturating_add(1);
            let register = usize::try_from(instruction.results[0]).map_err(|_| RuntimeFault)?;
            write_register(runtime, register, RuntimeValue::new(result))?;
        }

        let Some(termination) =
            dispatch_terminator(&limits, runtime, &block.terminator, blocks, result_type)?
        else {
            continue;
        };
        return Ok(termination);
    }
}

fn validate_inputs(
    input: LoweringInput<'_>,
    request: &ExecutionRequest,
) -> Result<ValidatedInputs, ExecutionError> {
    if request.inputs.len() != input.function.parameters.len() {
        return Err(ExecutionError::Exec(ExecutionErrorCode::InputCountMismatch));
    }
    enforce_input_count(request.inputs.len())?;
    let mut hashes = Vec::with_capacity(request.inputs.len());
    let mut value_units = 0_u64;
    for (index, value) in request.inputs.iter().enumerate() {
        input.types.check_constant(value)?;
        input.types.require_hashable(&value.value_type)?;
        let parameter_type = input
            .parameters
            .iter()
            .find(|parameter| parameter.entity_id == input.function.parameters[index])
            .map(|parameter| &parameter.value_type)
            .ok_or(ExecutionError::Exec(ExecutionErrorCode::InputTypeMismatch))?;
        if &value.value_type != parameter_type {
            return Err(ExecutionError::Exec(ExecutionErrorCode::InputTypeMismatch));
        }
        value_units = add_input_units(value_units, value_units_const(value))?;
        hashes.push(hash_validated_value(input.schema_epoch, value)?);
    }
    Ok(ValidatedInputs {
        hashes,
        value_units,
    })
}

fn enforce_input_count(count: usize) -> Result<(), ExecutionError> {
    if count > MAX_EXECUTION_INPUTS {
        Err(preexecution_resource_error())
    } else {
        Ok(())
    }
}

fn add_input_units(current: u64, amount: u64) -> Result<u64, ExecutionError> {
    current
        .checked_add(amount)
        .filter(|value| *value <= MAX_EXECUTION_INPUT_VALUE_UNITS)
        .ok_or_else(preexecution_resource_error)
}

fn preexecution_resource_error() -> ExecutionError {
    ExecutionError::Status(ExecutionStatusCode::ResourceLimit)
}

fn dispatch_terminator(
    limits: &ExecutionLimits,
    runtime: &mut Runtime,
    terminator: &BytecodeTerminator,
    blocks: &[crate::BytecodeBlock],
    result_type: &TypeExpr,
) -> RuntimeResult<Option<ExecutionTermination>> {
    if let Some(termination) = charge_action(runtime, limits, None) {
        return Ok(Some(termination));
    }
    match terminator {
        BytecodeTerminator::Return(register) => {
            let value = read_register(runtime, *register)?.value()?.clone();
            if &value.value_type != result_type {
                return Ok(Some(ExecutionTermination::InternalInvariant));
            }
            if value_units_const(&value) > limits.max_output_units {
                return Ok(Some(ExecutionTermination::ResourceLimit(
                    ResourceKind::OutputUnits,
                )));
            }
            Ok(Some(ExecutionTermination::Success(value)))
        }
        BytecodeTerminator::Branch(edge) => {
            if let Some(termination) = bind_edge(runtime, blocks, edge, limits)? {
                return Ok(Some(termination));
            }
            Ok(None)
        }
        BytecodeTerminator::CondBranch {
            condition,
            if_true,
            if_false,
        } => {
            let ConstData::Bool(condition) = read_register(runtime, *condition)?.value()?.data
            else {
                return Ok(Some(ExecutionTermination::InternalInvariant));
            };
            let edge = if condition { if_true } else { if_false };
            if let Some(termination) = bind_edge(runtime, blocks, edge, limits)? {
                return Ok(Some(termination));
            }
            Ok(None)
        }
        BytecodeTerminator::VariantSwitch { value, cases } => {
            let selected = read_register(runtime, *value)?.clone();
            let (case_key, payload) = selected_case(&selected)?;
            for case in cases {
                if let Some(termination) = charge_action(runtime, limits, None) {
                    return Ok(Some(termination));
                }
                if case.case_key == case_key {
                    return bind_switch_edge(runtime, blocks, &case.edge, payload.as_ref(), limits);
                }
            }
            Ok(Some(ExecutionTermination::InternalInvariant))
        }
        BytecodeTerminator::Trap { code, payload } => {
            let payload = payload
                .map(|register| {
                    read_register(runtime, register).and_then(|value| value.value().cloned())
                })
                .transpose()?;
            if payload
                .as_ref()
                .is_some_and(|value| value_units_const(value) > limits.max_output_units)
            {
                return Ok(Some(ExecutionTermination::ResourceLimit(
                    ResourceKind::OutputUnits,
                )));
            }
            Ok(Some(ExecutionTermination::Trap {
                trap_tag: *code,
                payload,
            }))
        }
    }
}

fn bind_edge(
    runtime: &mut Runtime,
    blocks: &[crate::BytecodeBlock],
    edge: &BytecodeTargetEdge,
    limits: &ExecutionLimits,
) -> RuntimeResult<Option<ExecutionTermination>> {
    let mut values = Vec::with_capacity(edge.arguments.len());
    for register in &edge.arguments {
        if let Some(termination) = charge_action(runtime, limits, None) {
            return Ok(Some(termination));
        }
        values.push(read_register(runtime, *register)?.clone());
    }
    bind_values(runtime, blocks, edge.target, values)?;
    Ok(None)
}

fn bind_switch_edge(
    runtime: &mut Runtime,
    blocks: &[crate::BytecodeBlock],
    edge: &BytecodeSwitchEdge,
    payload: Option<&RuntimeValue>,
    limits: &ExecutionLimits,
) -> RuntimeResult<Option<ExecutionTermination>> {
    let mut values = Vec::with_capacity(edge.arguments.len());
    for argument in &edge.arguments {
        if let Some(termination) = charge_action(runtime, limits, None) {
            return Ok(Some(termination));
        }
        match argument {
            BytecodeSwitchArgument::Value(register) => {
                values.push(read_register(runtime, *register).cloned()?);
            }
            BytecodeSwitchArgument::CasePayload => {
                if let Some(termination) = charge_action(runtime, limits, None) {
                    return Ok(Some(termination));
                }
                let Some(payload) = payload.cloned() else {
                    return Ok(Some(ExecutionTermination::InternalInvariant));
                };
                values.push(payload);
            }
        }
    }
    bind_values(runtime, blocks, edge.target, values)?;
    Ok(None)
}

fn bind_values(
    runtime: &mut Runtime,
    blocks: &[crate::BytecodeBlock],
    target: u32,
    values: Vec<RuntimeValue>,
) -> RuntimeResult<()> {
    let target = usize::try_from(target).map_err(|_| RuntimeFault)?;
    let block = blocks.get(target).ok_or(RuntimeFault)?;
    if block.parameter_registers.len() != values.len() {
        return Err(RuntimeFault);
    }
    for (register, value) in block.parameter_registers.iter().zip(values) {
        let register = usize::try_from(*register).map_err(|_| RuntimeFault)?;
        write_register(runtime, register, value)?;
    }
    runtime.block = target;
    Ok(())
}

fn selected_case(value: &RuntimeValue) -> RuntimeResult<(CaseKey, Option<RuntimeValue>)> {
    match &value.value()?.data {
        ConstData::Variant(variant) => Ok((
            CaseKey::Member(variant.member_id),
            variant
                .payload
                .as_ref()
                .map(|_| value.payload_view())
                .transpose()?,
        )),
        ConstData::Option(None) => Ok((CaseKey::Builtin(BuiltinCase::None), None)),
        ConstData::Option(Some(_)) => Ok((
            CaseKey::Builtin(BuiltinCase::Some),
            Some(value.payload_view()?),
        )),
        ConstData::Result(ResultConst::Ok(_)) => Ok((
            CaseKey::Builtin(BuiltinCase::Ok),
            Some(value.payload_view()?),
        )),
        ConstData::Result(ResultConst::Err(_)) => Ok((
            CaseKey::Builtin(BuiltinCase::Err),
            Some(value.payload_view()?),
        )),
        _ => Err(RuntimeFault),
    }
}

fn charge_action(
    runtime: &mut Runtime,
    limits: &ExecutionLimits,
    instruction: Option<ResourceKind>,
) -> Option<ExecutionTermination> {
    if limits
        .cancel_at_fuel
        .is_some_and(|cancel_at| cancel_at <= runtime.fuel_used)
    {
        return Some(ExecutionTermination::Cancelled);
    }
    if instruction.is_some() && runtime.instruction_count >= limits.max_instructions {
        return Some(ExecutionTermination::ResourceLimit(
            ResourceKind::Instruction,
        ));
    }
    if runtime.fuel_used >= limits.max_fuel {
        return Some(ExecutionTermination::ResourceLimit(ResourceKind::Fuel));
    }
    runtime.fuel_used = runtime.fuel_used.saturating_add(1);
    None
}

fn charge_value(runtime: &mut Runtime, amount: u64, max_value_units: u64) -> bool {
    let Some(next) = runtime.live_value_units.checked_add(amount) else {
        return false;
    };
    if next > max_value_units {
        return false;
    }
    runtime.live_value_units = next;
    runtime.peak_value_units = runtime.peak_value_units.max(next);
    true
}

fn read_bool_operands(runtime: &Runtime, registers: &[Register]) -> RuntimeResult<Vec<bool>> {
    let mut values = Vec::with_capacity(registers.len());
    for register in registers {
        match &read_register(runtime, *register)?.value()?.data {
            ConstData::Bool(value) => values.push(*value),
            _ => return Err(RuntimeFault),
        }
    }
    Ok(values)
}

fn read_register(runtime: &Runtime, register: Register) -> RuntimeResult<&RuntimeValue> {
    let register = usize::try_from(register).map_err(|_| RuntimeFault)?;
    runtime
        .registers
        .get(register)
        .and_then(Option::as_ref)
        .ok_or(RuntimeFault)
}

fn write_register(
    runtime: &mut Runtime,
    register: usize,
    value: RuntimeValue,
) -> RuntimeResult<()> {
    let slot = runtime.registers.get_mut(register).ok_or(RuntimeFault)?;
    *slot = Some(value);
    Ok(())
}

fn observed_invariant(
    input: LoweringInput<'_>,
    limits: ExecutionLimits,
    cache_key: BytecodeCacheKey,
    input_hashes: &[ValueHash],
    runtime: &Runtime,
) -> Result<ExecutionOutcome, ExecutionError> {
    finish_runtime(
        input,
        limits,
        cache_key,
        input_hashes,
        runtime,
        ExecutionTermination::InternalInvariant,
    )
}

fn finish_runtime(
    input: LoweringInput<'_>,
    limits: ExecutionLimits,
    cache_key: BytecodeCacheKey,
    input_hashes: &[ValueHash],
    runtime: &Runtime,
    termination: ExecutionTermination,
) -> Result<ExecutionOutcome, ExecutionError> {
    finish(
        input,
        limits,
        cache_key,
        input_hashes,
        termination,
        runtime.instruction_count,
        runtime.fuel_used,
        runtime.peak_value_units,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish(
    input: LoweringInput<'_>,
    limits: ExecutionLimits,
    cache_key: BytecodeCacheKey,
    input_hashes: &[ValueHash],
    termination: ExecutionTermination,
    instruction_count: u64,
    fuel_used: u64,
    peak_value_units: u64,
) -> Result<ExecutionOutcome, ExecutionError> {
    let observation_id = derive_observation_id(
        input,
        limits,
        cache_key,
        input_hashes,
        &termination,
        instruction_count,
        fuel_used,
        peak_value_units,
    )?;
    Ok(ExecutionOutcome {
        state_root: input.state_root,
        schema_epoch: input.schema_epoch,
        function: input.function.entity_id,
        cache_key,
        termination,
        instruction_count,
        fuel_used,
        peak_value_units,
        observation_id,
    })
}

/// Rederives one S20-270 observation through the VM semantic authority.
///
/// Callers must supply input hashes produced only after the S20-210/S20-250
/// checks required by `VM_EXEC_RESTRICTED_V1`.
///
/// # Errors
///
/// Preserves exact type/fingerprint failures or returns a bounded resource
/// failure when the canonical observation preimage cannot be encoded.
#[allow(clippy::too_many_arguments)]
pub fn derive_observation_id(
    input: LoweringInput<'_>,
    limits: ExecutionLimits,
    cache_key: BytecodeCacheKey,
    input_hashes: &[ValueHash],
    termination: &ExecutionTermination,
    instruction_count: u64,
    fuel_used: u64,
    peak_value_units: u64,
) -> Result<ObservationId, ExecutionError> {
    Ok(ObservationId::derive(observation_preimage(
        input,
        limits,
        cache_key,
        input_hashes,
        termination,
        instruction_count,
        fuel_used,
        peak_value_units,
    )?))
}

#[allow(clippy::too_many_arguments)]
fn observation_preimage(
    input: LoweringInput<'_>,
    limits: ExecutionLimits,
    cache_key: BytecodeCacheKey,
    input_hashes: &[ValueHash],
    termination: &ExecutionTermination,
    instruction_count: u64,
    fuel_used: u64,
    peak_value_units: u64,
) -> Result<Vec<u8>, ExecutionError> {
    let capacity = input_hashes
        .len()
        .checked_mul(32)
        .and_then(|value| value.checked_add(512))
        .filter(|value| *value <= MAX_OBSERVATION_PREIMAGE_BYTES)
        .ok_or_else(|| {
            ExecutionError::Fingerprint(FingerprintError::new(FingerprintErrorCode::ResourceLimit))
        })?;
    let mut preimage = Vec::with_capacity(capacity);
    raw(&mut preimage, b"SLEYOBS1");
    push_u32(&mut preimage, 1);
    raw(&mut preimage, input.schema_epoch.as_bytes());
    raw(&mut preimage, &SSMC1_FIELD_SCHEMA_HASH);
    raw(&mut preimage, &SSMC1_DECODER_LIMITS_HASH);
    raw(&mut preimage, input.state_root.as_bytes());
    raw(&mut preimage, input.function.entity_id.as_bytes());
    raw(&mut preimage, cache_key.as_bytes());
    for part in CacheProfile::RESTRICTED_V1.vm_version {
        push_u32(&mut preimage, part);
    }
    push_u32(&mut preimage, 1);
    push_len(&mut preimage, input_hashes.len());
    for hash in input_hashes {
        raw(&mut preimage, hash.as_bytes());
    }
    push_u64(&mut preimage, limits.max_instructions);
    push_u64(&mut preimage, limits.max_fuel);
    push_u64(&mut preimage, limits.max_value_units);
    push_u64(&mut preimage, limits.max_output_units);
    match limits.cancel_at_fuel {
        None => push_u32(&mut preimage, 1),
        Some(value) => {
            push_u32(&mut preimage, 2);
            push_u64(&mut preimage, value);
        }
    }
    encode_termination(&mut preimage, input, termination)?;
    push_u64(&mut preimage, instruction_count);
    push_u64(&mut preimage, fuel_used);
    push_u64(&mut preimage, peak_value_units);
    push_u64(&mut preimage, 0);
    push_u64(&mut preimage, 0);
    push_u64(&mut preimage, 0);
    push_u64(&mut preimage, 0);
    debug_assert!(preimage.len() <= MAX_OBSERVATION_PREIMAGE_BYTES);
    Ok(preimage)
}

fn encode_termination(
    preimage: &mut Vec<u8>,
    input: LoweringInput<'_>,
    termination: &ExecutionTermination,
) -> Result<(), ExecutionError> {
    match termination {
        ExecutionTermination::Success(value) => {
            push_u32(preimage, 1);
            input.types.require_hashable(&value.value_type)?;
            raw(
                preimage,
                hash_validated_value(input.schema_epoch, value)?.as_bytes(),
            );
        }
        ExecutionTermination::ResourceLimit(kind) => {
            push_u32(preimage, 2);
            push_u32(preimage, kind.tag());
        }
        ExecutionTermination::Cancelled => push_u32(preimage, 3),
        ExecutionTermination::Trap { trap_tag, payload } => {
            push_u32(preimage, 4);
            push_u32(preimage, *trap_tag);
            match payload {
                None => push_u32(preimage, 1),
                Some(value) => {
                    push_u32(preimage, 2);
                    input.types.require_hashable(&value.value_type)?;
                    raw(
                        preimage,
                        hash_validated_value(input.schema_epoch, value)?.as_bytes(),
                    );
                }
            }
        }
        ExecutionTermination::InternalInvariant => push_u32(preimage, 5),
    }
    Ok(())
}

fn initial_value_units(types: &[TypeExpr], bytes: &[u8], input_units: u64) -> u64 {
    input_units
        .saturating_add(u64::try_from(types.len()).unwrap_or(u64::MAX))
        .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

fn value_units_const(value: &ConstValue) -> u64 {
    1_u64
        .saturating_add(value_units_type(&value.value_type))
        .saturating_add(value_units_data(&value.data))
}

fn value_units_type(value: &TypeExpr) -> u64 {
    match value {
        TypeExpr::SInt(_) | TypeExpr::UInt(_) | TypeExpr::BuiltinFailure(_) => 3,
        TypeExpr::Unit
        | TypeExpr::Bool
        | TypeExpr::F32
        | TypeExpr::F64
        | TypeExpr::Bytes
        | TypeExpr::Text => 1,
        TypeExpr::Tuple(items) => 1_u64
            .saturating_add(u64::try_from(items.len()).unwrap_or(u64::MAX))
            .saturating_add(items.iter().map(value_units_type).fold(0, saturating_add)),
        TypeExpr::Named(named) => 33_u64
            .saturating_add(u64::try_from(named.arguments.len()).unwrap_or(u64::MAX))
            .saturating_add(
                named
                    .arguments
                    .iter()
                    .map(value_units_type)
                    .fold(0, saturating_add),
            ),
        TypeExpr::Vector(item) | TypeExpr::Option(item) | TypeExpr::LocalCell(item) => {
            1_u64.saturating_add(value_units_type(item))
        }
        TypeExpr::OrderedMap { key, value }
        | TypeExpr::Result {
            ok: key,
            error: value,
        } => 1_u64
            .saturating_add(value_units_type(key))
            .saturating_add(value_units_type(value)),
        TypeExpr::FunctionRef(function) => 1_u64
            .saturating_add(u64::try_from(function.parameters.len()).unwrap_or(u64::MAX))
            .saturating_add(
                function
                    .parameters
                    .iter()
                    .map(value_units_type)
                    .fold(0, saturating_add),
            )
            .saturating_add(value_units_type(&function.result))
            .saturating_add(u64::try_from(function.effects.len()).unwrap_or(u64::MAX))
            .saturating_add(
                u64::try_from(function.effects.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(32),
            ),
        TypeExpr::AdapterHandle(_) | TypeExpr::CapabilityToken(_) => 33,
        TypeExpr::TypeParameter(_) => 5,
    }
}

fn value_units_data(value: &ConstData) -> u64 {
    match value {
        ConstData::Bool(_) => 2,
        ConstData::SInt(_) | ConstData::UInt(_) => 17,
        ConstData::F32Bits(_) | ConstData::BuiltinFailure(_) => 5,
        ConstData::F64Bits(_) => 9,
        ConstData::Bytes(bytes) => {
            1_u64.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        }
        ConstData::Text(text) => {
            1_u64.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX))
        }
        ConstData::Sequence(values) => 1_u64
            .saturating_add(u64::try_from(values.len()).unwrap_or(u64::MAX))
            .saturating_add(values.iter().map(value_units_const).fold(0, saturating_add)),
        ConstData::Record(record) => 33_u64
            .saturating_add(u64::try_from(record.fields.len()).unwrap_or(u64::MAX))
            .saturating_add(
                record
                    .fields
                    .iter()
                    .map(|field| 32_u64.saturating_add(value_units_const(&field.value)))
                    .fold(0, saturating_add),
            ),
        ConstData::Variant(variant) => 65_u64.saturating_add(
            variant
                .payload
                .as_deref()
                .map_or(0, |value| 1_u64.saturating_add(value_units_const(value))),
        ),
        ConstData::Map(entries) => 1_u64
            .saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX))
            .saturating_add(
                entries
                    .iter()
                    .map(|entry| {
                        value_units_const(&entry.key)
                            .saturating_add(value_units_const(&entry.value))
                    })
                    .fold(0, saturating_add),
            ),
        ConstData::Unit | ConstData::Option(None) => 1,
        ConstData::Option(Some(value)) => 2_u64.saturating_add(value_units_const(value)),
        ConstData::Result(ResultConst::Ok(value) | ResultConst::Err(value)) => {
            2_u64.saturating_add(value_units_const(value))
        }
        ConstData::FunctionRef(reference) => 33_u64
            .saturating_add(u64::try_from(reference.type_arguments.len()).unwrap_or(u64::MAX))
            .saturating_add(
                reference
                    .type_arguments
                    .iter()
                    .map(value_units_type)
                    .fold(0, saturating_add),
            ),
    }
}

const fn saturating_add(left: u64, right: u64) -> u64 {
    left.saturating_add(right)
}

fn raw(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(bytes);
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_len(output: &mut Vec<u8>, value: usize) {
    push_u64(output, u64::try_from(value).unwrap_or(u64::MAX));
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;
    use sley_check::TypeEnvironment;
    use sley_id::{SchemaEpochId, StateRoot};
    use sley_ssmc::{
        Block, BranchTerminator, BuiltinCase, CaseKey, CondBranchTerminator, FunctionGraph,
        Immediate, MemberId, NamedType, Opcode, Operation, OperationResultRef, Parameter,
        ParameterRole, Reachability, ReturnTerminator, SwitchArgument, SwitchCase, SwitchEdge,
        TargetEdge, Terminator, TrapCode, TrapTerminator, TypeDefForm, TypeDefinition, ValueRef,
        VariantCase, VariantConst, VariantSwitchTerminator, Visibility,
    };

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn bool_value(value: bool) -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(value),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
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

    #[allow(clippy::too_many_lines)]
    fn two_case_switch_fixture(
        types: TypeEnvironment,
        selector_type: TypeExpr,
        first_key: CaseKey,
        second_key: CaseKey,
        first_has_payload: bool,
    ) -> Fixture {
        let function = id(20);
        let selector = id(21);
        let fallback = id(22);
        let entry = id(23);
        let first_block = id(24);
        let first_value = id(25);
        let second_block = id(26);
        let second_value = id(27);
        Fixture {
            types,
            function: FunctionGraph {
                entity_id: function,
                type_parameters: Vec::new(),
                parameters: vec![selector, fallback],
                result_type: TypeExpr::Bool,
                effects: Vec::new(),
                entry_block: entry,
                blocks: vec![entry, first_block, second_block],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameters: vec![
                Parameter {
                    entity_id: selector,
                    owner: function,
                    role: ParameterRole::Function,
                    ordinal: 0,
                    value_type: selector_type,
                },
                Parameter {
                    entity_id: fallback,
                    owner: function,
                    role: ParameterRole::Function,
                    ordinal: 1,
                    value_type: TypeExpr::Bool,
                },
                Parameter {
                    entity_id: first_value,
                    owner: first_block,
                    role: ParameterRole::Block,
                    ordinal: 0,
                    value_type: TypeExpr::Bool,
                },
                Parameter {
                    entity_id: second_value,
                    owner: second_block,
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
                                case_key: first_key,
                                edge: SwitchEdge {
                                    target: first_block,
                                    arguments: vec![if first_has_payload {
                                        SwitchArgument::CasePayload
                                    } else {
                                        SwitchArgument::Value(ValueRef::Parameter(fallback))
                                    }],
                                },
                            },
                            SwitchCase {
                                case_key: second_key,
                                edge: SwitchEdge {
                                    target: second_block,
                                    arguments: vec![SwitchArgument::CasePayload],
                                },
                            },
                        ],
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: first_block,
                    function,
                    parameters: vec![first_value],
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(first_value),
                    }),
                    reachability: Reachability::Required,
                },
                Block {
                    entity_id: second_block,
                    function,
                    parameters: vec![second_value],
                    operations: Vec::new(),
                    terminator: Terminator::Return(ReturnTerminator {
                        value: ValueRef::Parameter(second_value),
                    }),
                    reachability: Reachability::Required,
                },
            ],
            operations: Vec::new(),
        }
    }

    fn limits() -> ExecutionLimits {
        ExecutionLimits {
            max_instructions: 100,
            max_fuel: 100,
            max_value_units: 10_000,
            max_output_units: 100,
            cancel_at_fuel: None,
        }
    }

    #[test]
    fn executes_all_boolean_opcodes_and_repeats_deterministically() {
        let cases = [
            (Opcode::BoolNot, vec![true, false], false),
            (Opcode::BoolAnd, vec![true, false], false),
            (Opcode::BoolOr, vec![true, false], true),
        ];
        for (opcode, inputs, expected) in cases {
            let mut fixture = bool_fixture(opcode);
            if opcode == Opcode::BoolNot {
                fixture.operations[0].operands.pop();
            }
            let request = ExecutionRequest {
                inputs: inputs.into_iter().map(bool_value).collect(),
                limits: limits(),
            };
            let first = execute_function(fixture.input(), request.clone()).unwrap();
            assert_eq!(
                first.termination,
                ExecutionTermination::Success(bool_value(expected))
            );
            assert_eq!(first.instruction_count, 1);
            assert_eq!(first.fuel_used, 2);
            for _ in 0..128 {
                assert_eq!(
                    execute_function(fixture.input(), request.clone()).unwrap(),
                    first
                );
            }
        }
    }

    #[test]
    fn input_failures_precede_runtime() {
        let fixture = bool_fixture(Opcode::BoolAnd);
        let error = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true)],
                limits: limits(),
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            ExecutionError::Exec(ExecutionErrorCode::InputCountMismatch)
        );

        let error = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![
                    ConstValue {
                        value_type: TypeExpr::Unit,
                        data: ConstData::Unit,
                    },
                    bool_value(true),
                ],
                limits: limits(),
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            ExecutionError::Exec(ExecutionErrorCode::InputTypeMismatch)
        );
    }

    #[test]
    fn branch_conditional_trap_resource_and_cancel_terminate_deterministically() {
        let mut branch = bool_fixture(Opcode::BoolAnd);
        let result = ValueRef::OperationResult(OperationResultRef {
            operation: id(5),
            result_index: 0,
        });
        let target = id(6);
        let parameter = id(7);
        branch.function.blocks.push(target);
        branch.parameters.push(Parameter {
            entity_id: parameter,
            owner: target,
            role: ParameterRole::Block,
            ordinal: 0,
            value_type: TypeExpr::Bool,
        });
        branch.blocks.push(Block {
            entity_id: target,
            function: branch.function.entity_id,
            parameters: vec![parameter],
            operations: Vec::new(),
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::Parameter(parameter),
            }),
            reachability: Reachability::Required,
        });
        branch.blocks[0].terminator = Terminator::Branch(BranchTerminator {
            edge: TargetEdge {
                target,
                arguments: vec![result],
            },
        });
        let request = ExecutionRequest {
            inputs: vec![bool_value(true), bool_value(true)],
            limits: limits(),
        };
        let branch_outcome = execute_function(branch.input(), request).unwrap();
        assert_eq!(
            branch_outcome.termination,
            ExecutionTermination::Success(bool_value(true))
        );
        assert_eq!(branch_outcome.fuel_used, 4);

        let mut cond = bool_fixture(Opcode::BoolAnd);
        cond.blocks[0].terminator = Terminator::CondBranch(CondBranchTerminator {
            condition: result,
            if_true: TargetEdge {
                target: cond.blocks[0].entity_id,
                arguments: Vec::new(),
            },
            if_false: TargetEdge {
                target: cond.blocks[0].entity_id,
                arguments: Vec::new(),
            },
        });
        let mut request = ExecutionRequest {
            inputs: vec![bool_value(true), bool_value(false)],
            limits: limits(),
        };
        request.limits.max_instructions = 1;
        assert_eq!(
            execute_function(cond.input(), request).unwrap().termination,
            ExecutionTermination::ResourceLimit(ResourceKind::Instruction)
        );

        let mut trap = bool_fixture(Opcode::BoolAnd);
        trap.blocks[0].terminator = Terminator::Trap(TrapTerminator {
            code: TrapCode::InternalInvariant,
            payload: Some(result),
        });
        let request = ExecutionRequest {
            inputs: vec![bool_value(true), bool_value(true)],
            limits: limits(),
        };
        assert_eq!(
            execute_function(trap.input(), request).unwrap().termination,
            ExecutionTermination::Trap {
                trap_tag: 4,
                payload: Some(bool_value(true)),
            }
        );

        let mut request = ExecutionRequest {
            inputs: vec![bool_value(true), bool_value(true)],
            limits: limits(),
        };
        request.limits.cancel_at_fuel = Some(0);
        assert_eq!(
            execute_function(bool_fixture(Opcode::BoolAnd).input(), request)
                .unwrap()
                .termination,
            ExecutionTermination::Cancelled
        );
    }

    #[test]
    fn option_switch_binds_payload_and_no_payload_edges_with_exact_fuel() {
        let fixture = two_case_switch_fixture(
            TypeEnvironment::new(Vec::new()).unwrap(),
            TypeExpr::Option(Box::new(TypeExpr::Bool)),
            CaseKey::Builtin(BuiltinCase::None),
            CaseKey::Builtin(BuiltinCase::Some),
            false,
        );
        let some = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![
                    ConstValue {
                        value_type: TypeExpr::Option(Box::new(TypeExpr::Bool)),
                        data: ConstData::Option(Some(Box::new(bool_value(true)))),
                    },
                    bool_value(false),
                ],
                limits: limits(),
            },
        )
        .unwrap();
        assert_eq!(
            some.termination,
            ExecutionTermination::Success(bool_value(true))
        );
        assert_eq!(some.fuel_used, 6);

        let none = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![
                    ConstValue {
                        value_type: TypeExpr::Option(Box::new(TypeExpr::Bool)),
                        data: ConstData::Option(None),
                    },
                    bool_value(false),
                ],
                limits: limits(),
            },
        )
        .unwrap();
        assert_eq!(
            none.termination,
            ExecutionTermination::Success(bool_value(false))
        );
        assert_eq!(none.fuel_used, 4);
    }

    #[test]
    fn result_and_named_variant_switch_payloads_are_reference_views() {
        let result_type = TypeExpr::Result {
            ok: Box::new(TypeExpr::Bool),
            error: Box::new(TypeExpr::Bool),
        };
        let result_fixture = two_case_switch_fixture(
            TypeEnvironment::new(Vec::new()).unwrap(),
            result_type.clone(),
            CaseKey::Builtin(BuiltinCase::Ok),
            CaseKey::Builtin(BuiltinCase::Err),
            true,
        );
        let result = execute_function(
            result_fixture.input(),
            ExecutionRequest {
                inputs: vec![
                    ConstValue {
                        value_type: result_type,
                        data: ConstData::Result(ResultConst::Ok(Box::new(bool_value(true)))),
                    },
                    bool_value(false),
                ],
                limits: limits(),
            },
        )
        .unwrap();
        assert_eq!(
            result.termination,
            ExecutionTermination::Success(bool_value(true))
        );

        let definition = id(40);
        let empty_case = MemberId::from_bytes([41; 32]);
        let payload_case = MemberId::from_bytes([42; 32]);
        let named_type = TypeExpr::Named(NamedType {
            definition,
            arguments: Vec::new(),
        });
        let named_fixture = two_case_switch_fixture(
            TypeEnvironment::new(vec![TypeDefinition {
                entity_id: definition,
                type_parameters: Vec::new(),
                form: TypeDefForm::Variant(vec![
                    VariantCase {
                        member_id: empty_case,
                        payload_type: None,
                    },
                    VariantCase {
                        member_id: payload_case,
                        payload_type: Some(TypeExpr::Bool),
                    },
                ]),
                invariants: Vec::new(),
                visibility: Visibility::Private,
            }])
            .unwrap(),
            named_type.clone(),
            CaseKey::Member(empty_case),
            CaseKey::Member(payload_case),
            false,
        );
        let named = execute_function(
            named_fixture.input(),
            ExecutionRequest {
                inputs: vec![
                    ConstValue {
                        value_type: named_type,
                        data: ConstData::Variant(VariantConst {
                            definition,
                            member_id: payload_case,
                            payload: Some(Box::new(bool_value(true))),
                        }),
                    },
                    bool_value(false),
                ],
                limits: limits(),
            },
        )
        .unwrap();
        assert_eq!(
            named.termination,
            ExecutionTermination::Success(bool_value(true))
        );

        let runtime = RuntimeValue::new(ConstValue {
            value_type: TypeExpr::Option(Box::new(TypeExpr::Bool)),
            data: ConstData::Option(Some(Box::new(bool_value(true)))),
        });
        let (_, payload) = selected_case(&runtime).unwrap();
        let payload = payload.unwrap();
        assert!(Arc::ptr_eq(&runtime.root, &payload.root));
        assert_eq!(payload.payload_depth, 1);
    }

    #[test]
    fn observation_changes_with_semantic_inputs_and_limits() {
        let fixture = bool_fixture(Opcode::BoolOr);
        let first = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(false), bool_value(false)],
                limits: limits(),
            },
        )
        .unwrap();
        let second = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true), bool_value(false)],
                limits: limits(),
            },
        )
        .unwrap();
        assert_ne!(first.observation_id, second.observation_id);

        let mut changed_limits = limits();
        changed_limits.max_fuel += 1;
        let third = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(false), bool_value(false)],
                limits: changed_limits,
            },
        )
        .unwrap();
        assert_ne!(first.observation_id, third.observation_id);
    }

    #[test]
    fn observation_preimage_and_id_are_exact() {
        let fixture = bool_fixture(Opcode::BoolAnd);
        let request = ExecutionRequest {
            inputs: vec![bool_value(true), bool_value(false)],
            limits: limits(),
        };
        let lowered = lower_function(fixture.input()).unwrap();
        let validated_inputs = validate_inputs(fixture.input(), &request).unwrap();
        let outcome = execute_function(fixture.input(), request.clone()).unwrap();
        let preimage = observation_preimage(
            fixture.input(),
            request.limits,
            lowered.cache_key,
            &validated_inputs.hashes,
            &outcome.termination,
            outcome.instruction_count,
            outcome.fuel_used,
            outcome.peak_value_units,
        )
        .unwrap();
        assert_eq!(preimage.len(), 420);
        assert_eq!(
            hex(&preimage),
            concat!(
                "534c45594f42533100000001",
                "0808080808080808080808080808080808080808080808080808080808080808",
                "044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73",
                "389791b170bc9d8575f7e6f338e4f9e9f2b75f35d7a2e52c7cb106cb2cd6136a",
                "0909090909090909090909090909090909090909090909090909090909090909",
                "0101010101010101010101010101010101010101010101010101010101010101",
                "9949b487f7cba7d92ad65d1ce3cdaf3d0e9edce9d42cd0ec4aca3b10bcaa66d1",
                "00000001000000000000000000000001",
                "0000000000000002",
                "4bf8c7213335bae04af6f2861450a7374bfd7826e164afe82b607c6bb38c38eb",
                "b35fb3d3c1d6f5059a700fbcc41eda49354d0ae8be1cdd94ddfa33de5510d877",
                "0000000000000064000000000000006400000000000027100000000000000064",
                "00000001",
                "00000001b35fb3d3c1d6f5059a700fbcc41eda49354d0ae8be1cdd94ddfa33de5510d877",
                "0000000000000001000000000000000200000000000000af",
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(outcome.observation_id, ObservationId::derive(preimage));
    }

    #[test]
    fn resource_and_cancellation_precedence_is_exact() {
        let fixture = bool_fixture(Opcode::BoolAnd);

        assert_eq!(
            enforce_input_count(MAX_EXECUTION_INPUTS.saturating_add(1)).unwrap_err(),
            ExecutionError::Status(ExecutionStatusCode::ResourceLimit)
        );
        assert_eq!(
            add_input_units(MAX_EXECUTION_INPUT_VALUE_UNITS, 1).unwrap_err(),
            ExecutionError::Status(ExecutionStatusCode::ResourceLimit)
        );

        let mut cancelled_limits = limits();
        cancelled_limits.cancel_at_fuel = Some(0);
        cancelled_limits.max_fuel = 0;
        cancelled_limits.max_instructions = 0;
        let cancelled = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true), bool_value(true)],
                limits: cancelled_limits,
            },
        )
        .unwrap();
        assert_eq!(cancelled.termination, ExecutionTermination::Cancelled);
        assert_eq!(cancelled.fuel_used, 0);
        assert_eq!(cancelled.instruction_count, 0);

        let mut instruction_limits = limits();
        instruction_limits.max_instructions = 0;
        let instruction = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true), bool_value(true)],
                limits: instruction_limits,
            },
        )
        .unwrap();
        assert_eq!(
            instruction.termination,
            ExecutionTermination::ResourceLimit(ResourceKind::Instruction)
        );
        assert_eq!(instruction.fuel_used, 0);

        let mut fuel_limits = limits();
        fuel_limits.max_fuel = 0;
        let fuel = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true), bool_value(true)],
                limits: fuel_limits,
            },
        )
        .unwrap();
        assert_eq!(
            fuel.termination,
            ExecutionTermination::ResourceLimit(ResourceKind::Fuel)
        );

        let mut value_limits = limits();
        value_limits.max_value_units = 0;
        let value = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true), bool_value(true)],
                limits: value_limits,
            },
        )
        .unwrap();
        assert_eq!(
            value.termination,
            ExecutionTermination::ResourceLimit(ResourceKind::ValueUnits)
        );
        assert_eq!(value.fuel_used, 0);
        assert_eq!(value.instruction_count, 0);
        assert!(value.peak_value_units > 0);

        let mut output_limits = limits();
        output_limits.max_output_units = 0;
        let output = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true), bool_value(true)],
                limits: output_limits,
            },
        )
        .unwrap();
        assert_eq!(
            output.termination,
            ExecutionTermination::ResourceLimit(ResourceKind::OutputUnits)
        );
        assert_eq!(output.instruction_count, 1);
        assert_eq!(output.fuel_used, 2);
    }

    #[test]
    fn lowering_failures_are_preserved_and_runtime_faults_are_internal() {
        let fixture = bool_fixture(Opcode::IntAddChecked);
        let error = execute_function(
            fixture.input(),
            ExecutionRequest {
                inputs: vec![bool_value(true), bool_value(true)],
                limits: limits(),
            },
        )
        .unwrap_err();
        let ExecutionError::Lowering(LoweringError::Lower(error)) = error else {
            panic!("lowering failure");
        };
        assert_eq!(error.code(), crate::LowerErrorCode::OpcodeUnsupported);

        let mut runtime = Runtime {
            registers: vec![None],
            block: 0,
            instruction_count: 0,
            fuel_used: 0,
            live_value_units: 1,
            peak_value_units: 1,
        };
        let blocks = vec![crate::BytecodeBlock {
            slot: 0,
            parameter_registers: Vec::new(),
            instructions: Vec::new(),
            terminator: BytecodeTerminator::Return(0),
            reachability: 1,
        }];
        assert!(run(&mut runtime, limits(), &blocks, &TypeExpr::Bool).is_err());
    }

    #[test]
    fn execution_codes_are_stable() {
        assert_eq!(ExecutionErrorCode::InputCountMismatch.numeric(), 27_000);
        assert_eq!(ExecutionErrorCode::InputTypeMismatch.numeric(), 27_001);
        let statuses = [
            ExecutionStatusCode::ResourceLimit,
            ExecutionStatusCode::Cancelled,
            ExecutionStatusCode::Trap,
            ExecutionStatusCode::InternalInvariant,
        ];
        for (offset, status) in statuses.into_iter().enumerate() {
            assert_eq!(status.numeric(), 27_002 + u32::try_from(offset).unwrap());
        }
    }
}
