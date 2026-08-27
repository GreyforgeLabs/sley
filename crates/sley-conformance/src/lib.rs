#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;

use sley_check::{
    TypeEnvironment, TypeError,
    cfg::CfgValidationError,
    contracts::{ContractTestReport, TestPlanFinality},
};
use sley_id::{
    BytecodeCacheKey, EntityId, ExecutionReportId, ObservationId, SchemaEpochId, StateRoot,
    TestReportId, ValueHash,
};
use sley_ssmc::{
    ConstValue, ExpectedOutcome, TestCaseDefinition,
    fingerprint::{FingerprintError, hash_validated_value},
};
use sley_vm::{
    CacheProfile, ExecutionError, ExecutionLimits, ExecutionOutcome, ExecutionRequest,
    ExecutionTermination, LowerError, LoweringError, LoweringInput,
    MAX_EXECUTION_INPUT_VALUE_UNITS, MAX_EXECUTION_INPUTS, ResourceKind, SSMC1_DECODER_LIMITS_HASH,
    SSMC1_FIELD_SCHEMA_HASH, derive_cache_key, derive_observation_id, execution_value_units,
    validated_execution_input_hashes,
};

/// Maximum canonical restricted report-envelope preimage bytes.
pub const MAX_REPORT_PREIMAGE_BYTES: u64 = 67_108_864;
/// Maximum selected `TestCase` entries in one restricted test envelope.
pub const MAX_REPORT_TEST_ENTRIES: usize = 65_535;

const PROFILE_VERSION: u32 = 1;
const EXECUTION_PROFILE: u32 = 1;

/// Stable S20-290 restricted report construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportErrorCode {
    /// `REPORT_PROFILE_UNSUPPORTED`.
    ProfileUnsupported,
    /// `REPORT_CONTEXT_MISMATCH`.
    ContextMismatch,
    /// `REPORT_CACHE_KEY_MISMATCH`.
    CacheKeyMismatch,
    /// `REPORT_OBSERVATION_MISMATCH`.
    ObservationMismatch,
    /// `TEST_REPORT_PLAN_INVALID`.
    TestPlanInvalid,
    /// `TEST_REPORT_EXECUTION_MISMATCH`.
    TestExecutionMismatch,
    /// `REPORT_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `REPORT_INTERNAL_INVARIANT`.
    InternalInvariant,
}

impl ReportErrorCode {
    /// Returns the frozen symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileUnsupported => "REPORT_PROFILE_UNSUPPORTED",
            Self::ContextMismatch => "REPORT_CONTEXT_MISMATCH",
            Self::CacheKeyMismatch => "REPORT_CACHE_KEY_MISMATCH",
            Self::ObservationMismatch => "REPORT_OBSERVATION_MISMATCH",
            Self::TestPlanInvalid => "TEST_REPORT_PLAN_INVALID",
            Self::TestExecutionMismatch => "TEST_REPORT_EXECUTION_MISMATCH",
            Self::ResourceLimit => "REPORT_RESOURCE_LIMIT",
            Self::InternalInvariant => "REPORT_INTERNAL_INVARIANT",
        }
    }

    /// Returns the frozen numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::ProfileUnsupported => 29_000,
            Self::ContextMismatch => 29_001,
            Self::CacheKeyMismatch => 29_002,
            Self::ObservationMismatch => 29_003,
            Self::TestPlanInvalid => 29_004,
            Self::TestExecutionMismatch => 29_005,
            Self::ResourceLimit => 29_006,
            Self::InternalInvariant => 29_007,
        }
    }
}

impl fmt::Display for ReportErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable S20-290 report failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportError(ReportErrorCode);

impl ReportError {
    /// Constructs one failure from its frozen code.
    #[must_use]
    pub const fn new(code: ReportErrorCode) -> Self {
        Self(code)
    }

    /// Returns the frozen code.
    #[must_use]
    pub const fn code(&self) -> ReportErrorCode {
        self.0
    }
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ReportError {}

/// Preserved earlier or S20-290 report validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReportValidationError {
    /// Exact S20-210 type failure.
    Type(TypeError),
    /// Exact S20-250 value-hash failure.
    Fingerprint(FingerprintError),
    /// Exact S20-260 cache-profile failure.
    Lower(LowerError),
    /// Exact S20-270 observation derivation failure.
    Execution(ExecutionError),
    /// S20-290-owned report failure.
    Report(ReportError),
}

impl fmt::Display for ReportValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(error) => error.fmt(formatter),
            Self::Fingerprint(error) => error.fmt(formatter),
            Self::Lower(error) => error.fmt(formatter),
            Self::Execution(error) => error.fmt(formatter),
            Self::Report(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReportValidationError {}

impl From<TypeError> for ReportValidationError {
    fn from(error: TypeError) -> Self {
        Self::Type(error)
    }
}

impl From<FingerprintError> for ReportValidationError {
    fn from(error: FingerprintError) -> Self {
        Self::Fingerprint(error)
    }
}

impl From<LowerError> for ReportValidationError {
    fn from(error: LowerError) -> Self {
        Self::Lower(error)
    }
}

impl From<ExecutionError> for ReportValidationError {
    fn from(error: ExecutionError) -> Self {
        match error {
            ExecutionError::Type(error) => Self::Type(error),
            ExecutionError::Fingerprint(error) => Self::Fingerprint(error),
            other => Self::Execution(other),
        }
    }
}

impl From<ReportError> for ReportValidationError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

/// S20-290 report result.
pub type Result<T> = core::result::Result<T, ReportValidationError>;

/// Stable owning phase for a rejected execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailurePhase {
    /// S20-210 type judgment.
    Type,
    /// S20-220 graph/CFG judgment.
    Cfg,
    /// S20-260 lowering judgment.
    Lowering,
    /// S20-250 value hashing.
    Fingerprint,
    /// S20-270 execution boundary.
    Execution,
}

impl FailurePhase {
    const fn tag(self) -> u32 {
        match self {
            Self::Type => 1,
            Self::Cfg => 2,
            Self::Lowering => 3,
            Self::Fingerprint => 4,
            Self::Execution => 5,
        }
    }
}

/// String-free stable failure projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureEvidence {
    /// Exact owning validation phase.
    pub phase: FailurePhase,
    /// Exact frozen numeric failure code.
    pub numeric_code: u32,
}

/// Ordered execution-input evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionInputEvidence {
    /// Every input was canonical, hashable, and epoch-bound.
    Validated(Vec<ValueHash>),
    /// Invalid/oversized inputs cannot receive invented hashes.
    UnavailableBeforeValidation {
        /// Submitted input count.
        submitted_count: u64,
    },
}

/// Hash-only observed S20-270 termination evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedTermination {
    /// Successful returned value hash.
    Success(ValueHash),
    /// Deterministic resource ceiling.
    ResourceLimit(ResourceKind),
    /// Deterministic cancellation point.
    Cancelled,
    /// Explicit trap and optional payload hash.
    Trap {
        /// Exact frozen trap tag.
        trap_tag: u32,
        /// Optional canonical payload hash.
        payload: Option<ValueHash>,
    },
    /// Impossible post-validation runtime state.
    InternalInvariant,
}

/// Observed or rejected execution report evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionReportResult {
    /// One verified S20-270 observation.
    Observed {
        /// Root/profile-bound cache key.
        cache_key: BytecodeCacheKey,
        /// Hash-only termination projection.
        termination: ObservedTermination,
        /// Executed Boolean instruction count.
        instruction_count: u64,
        /// Charged fuel.
        fuel_used: u64,
        /// Peak semantic value units.
        peak_value_units: u64,
        /// S20-270 evidence anchor.
        observation_id: ObservationId,
    },
    /// String-free pre-execution rejection.
    Rejected(FailureEvidence),
}

/// Complete derived restricted execution envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionReportEnvelope {
    /// Content-derived restricted report ID.
    report_id: ExecutionReportId,
    /// Exact schema epoch.
    schema_epoch: SchemaEpochId,
    /// Exact state root.
    state_root: StateRoot,
    /// Exact Function identity.
    function: EntityId,
    /// Ordered input evidence.
    inputs: ExecutionInputEvidence,
    /// Exact S20-270 limits.
    limits: ExecutionLimits,
    /// Observed or rejected evidence.
    result: ExecutionReportResult,
}

impl ExecutionReportEnvelope {
    /// Returns the content-derived restricted report ID.
    #[must_use]
    pub const fn report_id(&self) -> ExecutionReportId {
        self.report_id
    }

    /// Returns the exact schema epoch.
    #[must_use]
    pub const fn schema_epoch(&self) -> SchemaEpochId {
        self.schema_epoch
    }

    /// Returns the exact state root.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    /// Returns the executed Function identity.
    #[must_use]
    pub const fn function(&self) -> EntityId {
        self.function
    }

    /// Returns ordered input evidence.
    #[must_use]
    pub const fn inputs(&self) -> &ExecutionInputEvidence {
        &self.inputs
    }

    /// Returns the exact execution limits.
    #[must_use]
    pub const fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// Returns the observed or rejected evidence.
    #[must_use]
    pub const fn result(&self) -> &ExecutionReportResult {
        &self.result
    }
}

/// Builds and verifies one restricted execution report envelope.
///
/// # Errors
///
/// Preserves exact earlier failures or returns the first deterministic S20-290
/// context/cache/observation/resource failure.
pub fn build_execution_report(
    input: LoweringInput<'_>,
    request: &ExecutionRequest,
    execution: &core::result::Result<ExecutionOutcome, ExecutionError>,
) -> Result<ExecutionReportEnvelope> {
    if input.profile != CacheProfile::RESTRICTED_V1 {
        return report_fail(ReportErrorCode::ProfileUnsupported);
    }
    let (inputs, result) = match execution {
        Ok(outcome) => {
            let hashes = validated_execution_input_hashes(input, request)?;
            let expected_cache = derive_cache_key(
                input.schema_epoch,
                input.state_root,
                input.function.entity_id,
                input.profile,
            )?;
            if outcome.schema_epoch != input.schema_epoch
                || outcome.state_root != input.state_root
                || outcome.function != input.function.entity_id
            {
                return report_fail(ReportErrorCode::ContextMismatch);
            }
            if outcome.cache_key != expected_cache {
                return report_fail(ReportErrorCode::CacheKeyMismatch);
            }
            let termination =
                project_termination(input.types, input.schema_epoch, &outcome.termination)?;
            let expected_observation = derive_observation_id(
                input,
                request.limits,
                outcome.cache_key,
                &hashes,
                &outcome.termination,
                outcome.instruction_count,
                outcome.fuel_used,
                outcome.peak_value_units,
            )?;
            if expected_observation != outcome.observation_id {
                return report_fail(ReportErrorCode::ObservationMismatch);
            }
            (
                ExecutionInputEvidence::Validated(hashes),
                ExecutionReportResult::Observed {
                    cache_key: outcome.cache_key,
                    termination,
                    instruction_count: outcome.instruction_count,
                    fuel_used: outcome.fuel_used,
                    peak_value_units: outcome.peak_value_units,
                    observation_id: outcome.observation_id,
                },
            )
        }
        Err(error) => (
            optional_input_evidence(input, request),
            ExecutionReportResult::Rejected(project_failure(error)),
        ),
    };
    let mut report = ExecutionReportEnvelope {
        report_id: ExecutionReportId::from_bytes([0; 32]),
        schema_epoch: input.schema_epoch,
        state_root: input.state_root,
        function: input.function.entity_id,
        inputs,
        limits: request.limits,
        result,
    };
    report.report_id = ExecutionReportId::derive(execution_report_preimage(&report)?);
    Ok(report)
}

/// Reproduces the exact restricted execution-report preimage.
///
/// # Errors
///
/// Returns `REPORT_RESOURCE_LIMIT` when the frozen preimage cap is exceeded.
pub fn execution_report_preimage(
    report: &ExecutionReportEnvelope,
) -> core::result::Result<Vec<u8>, ReportError> {
    let mut encoder = Encoder::new(MAX_REPORT_PREIMAGE_BYTES);
    encoder.fixed(b"SLEYEXR1")?;
    encoder.u32(PROFILE_VERSION)?;
    encoder.fixed(report.schema_epoch.as_bytes())?;
    encoder.fixed(&SSMC1_FIELD_SCHEMA_HASH)?;
    encoder.fixed(&SSMC1_DECODER_LIMITS_HASH)?;
    encoder.fixed(report.state_root.as_bytes())?;
    encoder.fixed(report.function.as_bytes())?;
    for part in CacheProfile::RESTRICTED_V1.vm_version {
        encoder.u32(part)?;
    }
    encoder.u32(EXECUTION_PROFILE)?;
    encode_input_evidence(&mut encoder, &report.inputs)?;
    encode_limits(&mut encoder, report.limits)?;
    encode_execution_result(&mut encoder, &report.result)?;
    Ok(encoder.output)
}

/// Required restricted test-report non-finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TestReportFinality {
    /// Protected policy and several resource units remain unproven.
    PolicyAndResourceIncomplete,
}

impl TestReportFinality {
    const fn tag(self) -> u32 {
        match self {
            Self::PolicyAndResourceIncomplete => 1,
        }
    }
}

/// Hash-only expected `TestCase` outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedEvidence {
    /// Exact expected value hash.
    Value(ValueHash),
    /// Exact frozen trap code.
    FailureCode(u32),
}

/// Restricted comparison only; none of these arms means final test pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestrictedComparison {
    /// Expected and observed restricted projections match.
    Match,
    /// Expected and observed restricted projections differ.
    Mismatch,
    /// Execution was rejected before an observation existed.
    ExecutionRejected,
}

impl RestrictedComparison {
    const fn tag(self) -> u32 {
        match self {
            Self::Match => 1,
            Self::Mismatch => 2,
            Self::ExecutionRejected => 3,
        }
    }
}

/// One selected `TestCase` comparison entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedTestEntry {
    /// `TestCase` identity.
    pub test: EntityId,
    /// Verified execution report identity.
    pub execution_report: ExecutionReportId,
    /// Hash-only expected projection.
    pub expected: ExpectedEvidence,
    /// Restricted non-final comparison.
    pub comparison: RestrictedComparison,
}

/// Complete derived restricted test envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestReportEnvelope {
    /// Content-derived restricted report ID.
    report_id: TestReportId,
    /// Exact schema epoch.
    schema_epoch: SchemaEpochId,
    /// Exact state root.
    state_root: StateRoot,
    /// Required non-finality.
    finality: TestReportFinality,
    /// Raw-ID ordered validated Contract identities.
    contracts: Vec<EntityId>,
    /// Raw-ID ordered validated `TestCase` identities.
    tests: Vec<EntityId>,
    /// Raw-ID ordered selected `TestCase` identities.
    selected_tests: Vec<EntityId>,
    /// S20-240 typed contract assertion count.
    contract_assertions: u32,
    /// S20-240 charged work.
    plan_work: u64,
    /// Exact selected comparison entries.
    entries: Vec<RestrictedTestEntry>,
    /// Restricted expectation matches.
    match_count: u64,
    /// Restricted expectation mismatches.
    mismatch_count: u64,
    /// Pre-observation execution rejections.
    rejected_count: u64,
}

impl TestReportEnvelope {
    /// Returns the content-derived restricted report ID.
    #[must_use]
    pub const fn report_id(&self) -> TestReportId {
        self.report_id
    }

    /// Returns the exact schema epoch.
    #[must_use]
    pub const fn schema_epoch(&self) -> SchemaEpochId {
        self.schema_epoch
    }

    /// Returns the exact state root.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    /// Returns the required non-finality.
    #[must_use]
    pub const fn finality(&self) -> TestReportFinality {
        self.finality
    }

    /// Returns raw-ID ordered Contract identities.
    #[must_use]
    pub fn contracts(&self) -> &[EntityId] {
        &self.contracts
    }

    /// Returns raw-ID ordered validated `TestCase` identities.
    #[must_use]
    pub fn tests(&self) -> &[EntityId] {
        &self.tests
    }

    /// Returns raw-ID ordered selected `TestCase` identities.
    #[must_use]
    pub fn selected_tests(&self) -> &[EntityId] {
        &self.selected_tests
    }

    /// Returns selected comparison entries.
    #[must_use]
    pub fn entries(&self) -> &[RestrictedTestEntry] {
        &self.entries
    }

    /// Returns `(match, mismatch, rejected)` counts.
    #[must_use]
    pub const fn comparison_counts(&self) -> (u64, u64, u64) {
        (self.match_count, self.mismatch_count, self.rejected_count)
    }
}

/// Builds one restricted, policy/resource-incomplete test envelope.
///
/// # Errors
///
/// Preserves exact expected-value type/fingerprint failures or returns the
/// first deterministic plan/execution/resource mismatch.
pub fn build_test_report(
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    state_root: StateRoot,
    plan: &ContractTestReport,
    selected: &[TestCaseDefinition],
    executions: &[ExecutionReportEnvelope],
) -> Result<TestReportEnvelope> {
    validate_plan(plan, selected, executions)?;
    let mut entries = Vec::with_capacity(selected.len());
    let mut match_count = 0_u64;
    let mut mismatch_count = 0_u64;
    let mut rejected_count = 0_u64;
    for ((test, execution), selected_id) in
        selected.iter().zip(executions).zip(&plan.selected_tests)
    {
        verify_execution_report(execution)?;
        if test.entity_id != *selected_id
            || execution.schema_epoch != schema_epoch
            || execution.state_root != state_root
            || execution.function != test.target
        {
            return report_fail(ReportErrorCode::TestExecutionMismatch);
        }
        let expected_inputs = validated_hashes(types, schema_epoch, &test.inputs)?;
        if execution.inputs != ExecutionInputEvidence::Validated(expected_inputs) {
            return report_fail(ReportErrorCode::TestExecutionMismatch);
        }
        let expected = project_expected(types, schema_epoch, &test.expected)?;
        let comparison = compare_expected(expected, &execution.result);
        match comparison {
            RestrictedComparison::Match => increment(&mut match_count)?,
            RestrictedComparison::Mismatch => increment(&mut mismatch_count)?,
            RestrictedComparison::ExecutionRejected => increment(&mut rejected_count)?,
        }
        entries.push(RestrictedTestEntry {
            test: test.entity_id,
            execution_report: execution.report_id,
            expected,
            comparison,
        });
    }
    let mut report = TestReportEnvelope {
        report_id: TestReportId::from_bytes([0; 32]),
        schema_epoch,
        state_root,
        finality: TestReportFinality::PolicyAndResourceIncomplete,
        contracts: plan.contracts.clone(),
        tests: plan.tests.clone(),
        selected_tests: plan.selected_tests.clone(),
        contract_assertions: plan.contract_assertions,
        plan_work: plan.work,
        entries,
        match_count,
        mismatch_count,
        rejected_count,
    };
    report.report_id = TestReportId::derive(test_report_preimage(&report)?);
    Ok(report)
}

/// Reproduces the exact restricted test-report preimage.
///
/// # Errors
///
/// Returns `REPORT_RESOURCE_LIMIT` when the frozen preimage cap is exceeded.
pub fn test_report_preimage(
    report: &TestReportEnvelope,
) -> core::result::Result<Vec<u8>, ReportError> {
    let mut encoder = Encoder::new(MAX_REPORT_PREIMAGE_BYTES);
    encoder.fixed(b"SLEYTSR1")?;
    encoder.u32(PROFILE_VERSION)?;
    encoder.fixed(report.schema_epoch.as_bytes())?;
    encoder.fixed(&SSMC1_FIELD_SCHEMA_HASH)?;
    encoder.fixed(&SSMC1_DECODER_LIMITS_HASH)?;
    encoder.fixed(report.state_root.as_bytes())?;
    encoder.u32(report.finality.tag())?;
    encoder.id_list(&report.contracts)?;
    encoder.id_list(&report.tests)?;
    encoder.id_list(&report.selected_tests)?;
    encoder.u32(report.contract_assertions)?;
    encoder.u64(report.plan_work)?;
    encoder.u64(len_u64(report.entries.len())?)?;
    for entry in &report.entries {
        encoder.fixed(entry.test.as_bytes())?;
        encoder.fixed(entry.execution_report.as_bytes())?;
        match entry.expected {
            ExpectedEvidence::Value(hash) => {
                encoder.u32(1)?;
                encoder.fixed(hash.as_bytes())?;
            }
            ExpectedEvidence::FailureCode(code) => {
                encoder.u32(2)?;
                encoder.u32(code)?;
            }
        }
        encoder.u32(entry.comparison.tag())?;
    }
    encoder.u64(report.match_count)?;
    encoder.u64(report.mismatch_count)?;
    encoder.u64(report.rejected_count)?;
    Ok(encoder.output)
}

fn validated_hashes(
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    values: &[ConstValue],
) -> Result<Vec<ValueHash>> {
    if values.len() > MAX_EXECUTION_INPUTS {
        return report_fail(ReportErrorCode::ResourceLimit);
    }
    let mut hashes = Vec::with_capacity(values.len());
    let mut value_units = 0_u64;
    for value in values {
        types.check_constant(value)?;
        types.require_hashable(&value.value_type)?;
        value_units = value_units
            .checked_add(execution_value_units(value))
            .filter(|units| *units <= MAX_EXECUTION_INPUT_VALUE_UNITS)
            .ok_or_else(|| ReportError::new(ReportErrorCode::ResourceLimit))?;
        hashes.push(hash_validated_value(schema_epoch, value)?);
    }
    Ok(hashes)
}

fn optional_input_evidence(
    input: LoweringInput<'_>,
    request: &ExecutionRequest,
) -> ExecutionInputEvidence {
    let submitted_count = u64::try_from(request.inputs.len()).unwrap_or(u64::MAX);
    match validated_execution_input_hashes(input, request) {
        Ok(hashes) => ExecutionInputEvidence::Validated(hashes),
        Err(_) => ExecutionInputEvidence::UnavailableBeforeValidation { submitted_count },
    }
}

fn project_failure(error: &ExecutionError) -> FailureEvidence {
    match error {
        ExecutionError::Lowering(error) => project_lowering_failure(error),
        ExecutionError::Type(error) => FailureEvidence {
            phase: FailurePhase::Type,
            numeric_code: error.code().numeric(),
        },
        ExecutionError::Fingerprint(error) => FailureEvidence {
            phase: FailurePhase::Fingerprint,
            numeric_code: error.code().numeric(),
        },
        ExecutionError::Status(error) => FailureEvidence {
            phase: FailurePhase::Execution,
            numeric_code: error.numeric(),
        },
        ExecutionError::Exec(error) => FailureEvidence {
            phase: FailurePhase::Execution,
            numeric_code: error.numeric(),
        },
    }
}

fn project_lowering_failure(error: &LoweringError) -> FailureEvidence {
    match error {
        LoweringError::Cfg(error) => project_cfg_failure(error),
        LoweringError::Lower(error) => FailureEvidence {
            phase: FailurePhase::Lowering,
            numeric_code: error.code().numeric(),
        },
    }
}

fn project_cfg_failure(error: &CfgValidationError) -> FailureEvidence {
    match error {
        CfgValidationError::Type(error) => FailureEvidence {
            phase: FailurePhase::Type,
            numeric_code: error.code().numeric(),
        },
        CfgValidationError::Cfg(error) => FailureEvidence {
            phase: FailurePhase::Cfg,
            numeric_code: error.code().numeric(),
        },
    }
}

fn project_termination(
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    termination: &ExecutionTermination,
) -> Result<ObservedTermination> {
    Ok(match termination {
        ExecutionTermination::Success(value) => {
            ObservedTermination::Success(hash_value(types, schema_epoch, value)?)
        }
        ExecutionTermination::ResourceLimit(kind) => ObservedTermination::ResourceLimit(*kind),
        ExecutionTermination::Cancelled => ObservedTermination::Cancelled,
        ExecutionTermination::Trap { trap_tag, payload } => ObservedTermination::Trap {
            trap_tag: *trap_tag,
            payload: payload
                .as_ref()
                .map(|value| hash_value(types, schema_epoch, value))
                .transpose()?,
        },
        ExecutionTermination::InternalInvariant => ObservedTermination::InternalInvariant,
    })
}

fn hash_value(
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    value: &ConstValue,
) -> Result<ValueHash> {
    types.check_constant(value)?;
    types.require_hashable(&value.value_type)?;
    Ok(hash_validated_value(schema_epoch, value)?)
}

fn validate_plan(
    plan: &ContractTestReport,
    selected: &[TestCaseDefinition],
    executions: &[ExecutionReportEnvelope],
) -> Result<()> {
    if !matches!(plan.selection_finality, TestPlanFinality::PolicyIncomplete)
        || !strict_ids(&plan.contracts)
        || !strict_ids(&plan.tests)
        || !strict_ids(&plan.selected_tests)
        || plan.contracts.len() > MAX_REPORT_TEST_ENTRIES
        || plan.tests.len() > MAX_REPORT_TEST_ENTRIES
        || plan.selected_tests.len() > MAX_REPORT_TEST_ENTRIES
        || selected.len() != plan.selected_tests.len()
        || executions.len() != plan.selected_tests.len()
        || !plan
            .selected_tests
            .iter()
            .all(|test| plan.tests.binary_search(test).is_ok())
    {
        return report_fail(ReportErrorCode::TestPlanInvalid);
    }
    Ok(())
}

fn strict_ids(values: &[EntityId]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn verify_execution_report(report: &ExecutionReportEnvelope) -> Result<()> {
    let expected = ExecutionReportId::derive(execution_report_preimage(report)?);
    if expected == report.report_id {
        Ok(())
    } else {
        report_fail(ReportErrorCode::TestExecutionMismatch)
    }
}

fn project_expected(
    types: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    expected: &ExpectedOutcome,
) -> Result<ExpectedEvidence> {
    match expected {
        ExpectedOutcome::Value(value) => Ok(ExpectedEvidence::Value(hash_value(
            types,
            schema_epoch,
            value,
        )?)),
        ExpectedOutcome::FailureCode(code) if (1..=4).contains(code) => {
            Ok(ExpectedEvidence::FailureCode(*code))
        }
        ExpectedOutcome::FailureCode(_) => report_fail(ReportErrorCode::TestPlanInvalid),
    }
}

fn compare_expected(
    expected: ExpectedEvidence,
    observed: &ExecutionReportResult,
) -> RestrictedComparison {
    let ExecutionReportResult::Observed { termination, .. } = observed else {
        return RestrictedComparison::ExecutionRejected;
    };
    let matches = match (expected, termination) {
        (ExpectedEvidence::Value(expected), ObservedTermination::Success(actual)) => {
            expected == *actual
        }
        (
            ExpectedEvidence::FailureCode(expected),
            ObservedTermination::Trap {
                trap_tag: actual, ..
            },
        ) => expected == *actual,
        _ => false,
    };
    if matches {
        RestrictedComparison::Match
    } else {
        RestrictedComparison::Mismatch
    }
}

fn increment(value: &mut u64) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| ReportError::new(ReportErrorCode::ResourceLimit))?;
    Ok(())
}

fn encode_input_evidence(
    encoder: &mut Encoder,
    evidence: &ExecutionInputEvidence,
) -> core::result::Result<(), ReportError> {
    match evidence {
        ExecutionInputEvidence::Validated(hashes) => {
            encoder.u32(1)?;
            encoder.u64(len_u64(hashes.len())?)?;
            for hash in hashes {
                encoder.fixed(hash.as_bytes())?;
            }
        }
        ExecutionInputEvidence::UnavailableBeforeValidation { submitted_count } => {
            encoder.u32(2)?;
            encoder.u64(*submitted_count)?;
        }
    }
    Ok(())
}

fn encode_limits(
    encoder: &mut Encoder,
    limits: ExecutionLimits,
) -> core::result::Result<(), ReportError> {
    encoder.u64(limits.max_instructions)?;
    encoder.u64(limits.max_fuel)?;
    encoder.u64(limits.max_value_units)?;
    encoder.u64(limits.max_output_units)?;
    match limits.cancel_at_fuel {
        None => encoder.u32(1),
        Some(value) => {
            encoder.u32(2)?;
            encoder.u64(value)
        }
    }
}

fn encode_execution_result(
    encoder: &mut Encoder,
    result: &ExecutionReportResult,
) -> core::result::Result<(), ReportError> {
    match result {
        ExecutionReportResult::Observed {
            cache_key,
            termination,
            instruction_count,
            fuel_used,
            peak_value_units,
            observation_id,
        } => {
            encoder.u32(1)?;
            encoder.fixed(cache_key.as_bytes())?;
            encode_observed_termination(encoder, termination)?;
            encoder.u64(*instruction_count)?;
            encoder.u64(*fuel_used)?;
            encoder.u64(*peak_value_units)?;
            encoder.fixed(observation_id.as_bytes())
        }
        ExecutionReportResult::Rejected(failure) => {
            encoder.u32(2)?;
            encoder.u32(failure.phase.tag())?;
            encoder.u32(failure.numeric_code)
        }
    }
}

fn encode_observed_termination(
    encoder: &mut Encoder,
    termination: &ObservedTermination,
) -> core::result::Result<(), ReportError> {
    match termination {
        ObservedTermination::Success(hash) => {
            encoder.u32(1)?;
            encoder.fixed(hash.as_bytes())
        }
        ObservedTermination::ResourceLimit(kind) => {
            encoder.u32(2)?;
            encoder.u32(kind.tag())
        }
        ObservedTermination::Cancelled => encoder.u32(3),
        ObservedTermination::Trap { trap_tag, payload } => {
            encoder.u32(4)?;
            encoder.u32(*trap_tag)?;
            match payload {
                None => encoder.u32(1),
                Some(hash) => {
                    encoder.u32(2)?;
                    encoder.fixed(hash.as_bytes())
                }
            }
        }
        ObservedTermination::InternalInvariant => encoder.u32(5),
    }
}

fn len_u64(value: usize) -> core::result::Result<u64, ReportError> {
    u64::try_from(value).map_err(|_| ReportError::new(ReportErrorCode::ResourceLimit))
}

fn report_fail<T>(code: ReportErrorCode) -> Result<T> {
    Err(ReportError::new(code).into())
}

struct Encoder {
    output: Vec<u8>,
    max: u64,
}

impl Encoder {
    fn new(max: u64) -> Self {
        Self {
            output: Vec::new(),
            max,
        }
    }

    fn fixed(&mut self, bytes: &[u8]) -> core::result::Result<(), ReportError> {
        let next = len_u64(self.output.len())?
            .checked_add(len_u64(bytes.len())?)
            .filter(|value| *value <= self.max)
            .ok_or_else(|| ReportError::new(ReportErrorCode::ResourceLimit))?;
        let capacity =
            usize::try_from(next).map_err(|_| ReportError::new(ReportErrorCode::ResourceLimit))?;
        self.output
            .reserve(capacity.saturating_sub(self.output.len()));
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    fn u32(&mut self, value: u32) -> core::result::Result<(), ReportError> {
        self.fixed(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> core::result::Result<(), ReportError> {
        self.fixed(&value.to_be_bytes())
    }

    fn id_list(&mut self, values: &[EntityId]) -> core::result::Result<(), ReportError> {
        self.u64(len_u64(values.len())?)?;
        for value in values {
            self.fixed(value.as_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sley_check::{
        TypeErrorCode,
        cfg::{CfgError, CfgErrorCode},
    };
    use sley_ssmc::{
        Block, ConstData, EffectEnvironment, FunctionGraph, Immediate, Opcode, Operation,
        OperationResultRef, Parameter, ParameterRole, Reachability, ResourceLimits,
        ReturnTerminator, Terminator, TypeExpr, ValueRef, Visibility,
        fingerprint::{FingerprintError, FingerprintErrorCode},
    };
    use sley_vm::{ExecutionErrorCode, LowerErrorCode, execute_function};

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn epoch() -> SchemaEpochId {
        SchemaEpochId::from_bytes([8; 32])
    }

    fn root() -> StateRoot {
        StateRoot::from_bytes([9; 32])
    }

    fn bool_value(value: bool) -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(value),
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

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            inputs: vec![bool_value(true), bool_value(false)],
            limits: limits(),
        }
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
                schema_epoch: epoch(),
                state_root: root(),
                profile: CacheProfile::RESTRICTED_V1,
            }
        }
    }

    fn fixture() -> Fixture {
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
                opcode: Opcode::BoolAnd,
                operands: vec![ValueRef::Parameter(left), ValueRef::Parameter(right)],
                result_types: vec![TypeExpr::Bool],
                immediate: Immediate::None,
            }],
        }
    }

    fn observed_report(fixture: &Fixture, request: &ExecutionRequest) -> ExecutionReportEnvelope {
        let execution = execute_function(fixture.input(), request.clone());
        build_execution_report(fixture.input(), request, &execution).unwrap()
    }

    fn test_case(expected: ExpectedOutcome) -> TestCaseDefinition {
        TestCaseDefinition {
            entity_id: id(50),
            target: id(1),
            inputs: request().inputs,
            effect_environment: EffectEnvironment::Replay(Vec::new()),
            expected,
            observations: Vec::new(),
            resource_limits: ResourceLimits {
                fuel: 100,
                memory_bytes: 1_000,
                output_bytes: 100,
                effect_count: 0,
                call_depth: 1,
                wall_timeout_millis: 1_000,
            },
        }
    }

    fn plan() -> ContractTestReport {
        ContractTestReport {
            contracts: vec![id(40)],
            tests: vec![id(50)],
            selected_tests: vec![id(50)],
            selection_finality: TestPlanFinality::PolicyIncomplete,
            contract_assertions: 3,
            work: 17,
        }
    }

    fn report_code(error: ReportValidationError) -> ReportErrorCode {
        match error {
            ReportValidationError::Report(error) => error.code(),
            other => panic!("unexpected earlier error: {other}"),
        }
    }

    #[test]
    fn stable_report_codes_are_frozen() {
        let codes = [
            ReportErrorCode::ProfileUnsupported,
            ReportErrorCode::ContextMismatch,
            ReportErrorCode::CacheKeyMismatch,
            ReportErrorCode::ObservationMismatch,
            ReportErrorCode::TestPlanInvalid,
            ReportErrorCode::TestExecutionMismatch,
            ReportErrorCode::ResourceLimit,
            ReportErrorCode::InternalInvariant,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 29_000 + u32::try_from(offset).unwrap());
        }
    }

    #[test]
    fn observed_execution_vector_is_exact() {
        let fixture = fixture();
        let report = observed_report(&fixture, &request());
        let preimage = execution_report_preimage(&report).unwrap();
        assert_eq!(&preimage[..12], b"SLEYEXR1\0\0\0\x01");
        assert_eq!(preimage.len(), 428);
        assert_eq!(
            report.report_id.into_bytes(),
            decode_hex_32("6a492a48bf104044413eb48ba9752c3fb48536aee88228e0382b882558d4f926")
        );
    }

    #[test]
    fn rejected_vector_and_unavailable_input_are_exact() {
        let fixture = fixture();
        let malformed = ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Unit,
        };
        let request = ExecutionRequest {
            inputs: vec![malformed],
            limits: limits(),
        };
        let execution = Err(ExecutionError::Exec(ExecutionErrorCode::InputTypeMismatch));
        let report = build_execution_report(fixture.input(), &request, &execution).unwrap();
        assert_eq!(
            report.inputs,
            ExecutionInputEvidence::UnavailableBeforeValidation { submitted_count: 1 }
        );
        assert_eq!(execution_report_preimage(&report).unwrap().len(), 248);
        assert_eq!(
            report.report_id.into_bytes(),
            decode_hex_32("599ff358eb271964c8c4a5273dc07074aedf102cbc04da01542abb286d6133cc")
        );
    }

    #[test]
    fn failure_projection_preserves_all_phases_and_graph_codes() {
        let cases = [
            (
                ExecutionError::Type(TypeError::new(TypeErrorCode::ConstShape)),
                FailurePhase::Type,
                21_014,
            ),
            (
                ExecutionError::Lowering(LoweringError::Cfg(CfgValidationError::Cfg(
                    CfgError::new(CfgErrorCode::GraphUnresolvedReference),
                ))),
                FailurePhase::Cfg,
                22_004,
            ),
            (
                ExecutionError::Lowering(LoweringError::Lower(LowerError::new(
                    LowerErrorCode::OpcodeUnsupported,
                ))),
                FailurePhase::Lowering,
                26_001,
            ),
            (
                ExecutionError::Fingerprint(FingerprintError::new(
                    FingerprintErrorCode::ValueHashValueInvalid,
                )),
                FailurePhase::Fingerprint,
                25_007,
            ),
            (
                ExecutionError::Exec(ExecutionErrorCode::InputCountMismatch),
                FailurePhase::Execution,
                27_000,
            ),
        ];
        for (error, phase, numeric_code) in cases {
            assert_eq!(
                project_failure(&error),
                FailureEvidence {
                    phase,
                    numeric_code
                }
            );
        }
    }

    #[test]
    fn observed_context_cache_and_observation_tampering_fail_exactly() {
        let fixture = fixture();
        let request = request();
        let base = execute_function(fixture.input(), request.clone()).unwrap();

        let mut context = base.clone();
        context.state_root = StateRoot::from_bytes([1; 32]);
        assert_eq!(
            report_code(
                build_execution_report(fixture.input(), &request, &Ok(context)).unwrap_err()
            ),
            ReportErrorCode::ContextMismatch
        );

        let mut cache = base.clone();
        cache.cache_key = BytecodeCacheKey::from_bytes([2; 32]);
        assert_eq!(
            report_code(build_execution_report(fixture.input(), &request, &Ok(cache)).unwrap_err()),
            ReportErrorCode::CacheKeyMismatch
        );

        let mut observation = base;
        observation.observation_id = ObservationId::from_bytes([3; 32]);
        assert_eq!(
            report_code(
                build_execution_report(fixture.input(), &request, &Ok(observation)).unwrap_err()
            ),
            ReportErrorCode::ObservationMismatch
        );
    }

    #[test]
    fn malformed_observed_input_preserves_exact_type_failure() {
        let fixture = fixture();
        let good_request = request();
        let outcome = execute_function(fixture.input(), good_request).unwrap();
        let malformed = ExecutionRequest {
            inputs: vec![
                ConstValue {
                    value_type: TypeExpr::Bool,
                    data: ConstData::Unit,
                },
                bool_value(false),
            ],
            limits: limits(),
        };
        let error = build_execution_report(fixture.input(), &malformed, &Ok(outcome)).unwrap_err();
        let ReportValidationError::Type(error) = error else {
            panic!("exact type failure must be preserved");
        };
        assert_eq!(error.code(), TypeErrorCode::ConstShape);
    }

    #[test]
    fn test_match_vector_is_exact_and_nonfinal() {
        let fixture = fixture();
        let execution = observed_report(&fixture, &request());
        let test = test_case(ExpectedOutcome::Value(bool_value(false)));
        let report = build_test_report(
            &fixture.types,
            epoch(),
            root(),
            &plan(),
            &[test],
            &[execution],
        )
        .unwrap();
        assert_eq!(
            report.finality,
            TestReportFinality::PolicyAndResourceIncomplete
        );
        assert_eq!(report.comparison_counts(), (1, 0, 0));
        assert_eq!(report.entries[0].comparison, RestrictedComparison::Match);
        let preimage = test_report_preimage(&report).unwrap();
        assert_eq!(&preimage[..12], b"SLEYTSR1\0\0\0\x01");
        assert_eq!(preimage.len(), 412);
        assert_eq!(
            report.report_id.into_bytes(),
            decode_hex_32("84ec5b6b388266836beb6ead51d6cb8648fb0cee1fbf348c4b6c2bb011d62a2d")
        );
    }

    #[test]
    fn value_mismatch_and_execution_rejection_are_distinct() {
        let fixture = fixture();
        let execution = observed_report(&fixture, &request());
        let mismatch = build_test_report(
            &fixture.types,
            epoch(),
            root(),
            &plan(),
            &[test_case(ExpectedOutcome::Value(bool_value(true)))],
            &[execution],
        )
        .unwrap();
        assert_eq!(mismatch.comparison_counts(), (0, 1, 0));

        let rejected_result = Err(ExecutionError::Exec(ExecutionErrorCode::InputTypeMismatch));
        let rejected =
            build_execution_report(fixture.input(), &request(), &rejected_result).unwrap();
        let report = build_test_report(
            &fixture.types,
            epoch(),
            root(),
            &plan(),
            &[test_case(ExpectedOutcome::Value(bool_value(false)))],
            &[rejected],
        )
        .unwrap();
        assert_eq!(report.comparison_counts(), (0, 0, 1));
        assert_eq!(
            report.entries[0].comparison,
            RestrictedComparison::ExecutionRejected
        );
    }

    #[test]
    fn trap_code_comparison_matrix_is_exact() {
        let observed = |termination| ExecutionReportResult::Observed {
            cache_key: BytecodeCacheKey::from_bytes([1; 32]),
            termination,
            instruction_count: 0,
            fuel_used: 0,
            peak_value_units: 0,
            observation_id: ObservationId::from_bytes([2; 32]),
        };
        assert_eq!(
            compare_expected(
                ExpectedEvidence::FailureCode(2),
                &observed(ObservedTermination::Trap {
                    trap_tag: 2,
                    payload: None,
                })
            ),
            RestrictedComparison::Match
        );
        assert_eq!(
            compare_expected(
                ExpectedEvidence::FailureCode(2),
                &observed(ObservedTermination::Trap {
                    trap_tag: 3,
                    payload: None,
                })
            ),
            RestrictedComparison::Mismatch
        );
        assert_eq!(
            compare_expected(
                ExpectedEvidence::FailureCode(2),
                &observed(ObservedTermination::ResourceLimit(ResourceKind::Fuel))
            ),
            RestrictedComparison::Mismatch
        );
    }

    #[test]
    fn plan_order_and_execution_binding_fail_closed() {
        let fixture = fixture();
        let execution = observed_report(&fixture, &request());
        let test = test_case(ExpectedOutcome::Value(bool_value(false)));
        let mut unordered = plan();
        unordered.tests = vec![id(51), id(50)];
        assert_eq!(
            report_code(
                build_test_report(
                    &fixture.types,
                    epoch(),
                    root(),
                    &unordered,
                    core::slice::from_ref(&test),
                    core::slice::from_ref(&execution),
                )
                .unwrap_err()
            ),
            ReportErrorCode::TestPlanInvalid
        );

        let mut wrong_target = test;
        wrong_target.target = id(99);
        assert_eq!(
            report_code(
                build_test_report(
                    &fixture.types,
                    epoch(),
                    root(),
                    &plan(),
                    &[wrong_target],
                    &[execution],
                )
                .unwrap_err()
            ),
            ReportErrorCode::TestExecutionMismatch
        );
    }

    #[test]
    fn execution_report_id_tampering_is_rejected_by_test_aggregation() {
        let fixture = fixture();
        let mut execution = observed_report(&fixture, &request());
        execution.report_id = ExecutionReportId::from_bytes([7; 32]);
        let error = build_test_report(
            &fixture.types,
            epoch(),
            root(),
            &plan(),
            &[test_case(ExpectedOutcome::Value(bool_value(false)))],
            &[execution],
        )
        .unwrap_err();
        assert_eq!(report_code(error), ReportErrorCode::TestExecutionMismatch);
    }

    #[test]
    fn bounded_encoder_rejects_overflow() {
        let mut encoder = Encoder::new(3);
        assert_eq!(
            encoder.fixed(&[0; 4]).unwrap_err().code(),
            ReportErrorCode::ResourceLimit
        );
    }

    #[test]
    fn repeated_equivalent_reports_are_byte_identical() {
        let fixture = fixture();
        let request = request();
        let baseline = observed_report(&fixture, &request);
        let bytes = execution_report_preimage(&baseline).unwrap();
        for _ in 0..128 {
            let report = observed_report(&fixture, &request);
            assert_eq!(report, baseline);
            assert_eq!(execution_report_preimage(&report).unwrap(), bytes);
        }
    }

    fn decode_hex_32(hex: &str) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut output = [0; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            output[index] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        output
    }
}
