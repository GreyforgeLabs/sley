//! Pure ordered S20-360 candidate validation.
//!
//! The public entry point consumes exact candidate bytes and one explicitly
//! constructed trusted context. It builds validator-owned phase evidence and
//! never accepts caller-provided phase outcomes, roots, diagnostics, test
//! selections, or context digests. Validation performs no I/O and mutates no
//! accepted state, policy, repository, ref, transaction graph, or capability
//! ledger.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use sley_check::{
    TypeError,
    cfg::{CfgErrorCode, CfgValidationError, validate_function_graph},
    contracts::{
        ContractTestErrorCode, ContractTestReport, ContractTestValidationError,
        validate_contract_test_program,
    },
    effects::{
        EffectErrorCode, EffectReport, EffectValidationError, FunctionUnit, validate_effect_program,
    },
};
use sley_id::{
    CapabilitySummaryDigest, EntityId, PolicyRootId, PrincipalId, StateRoot, TransactionId,
    ValidationProfileId,
};
use sley_mutate::{
    CandidateApplyError, CandidateError, EntityObject, ImportedCandidate, MutationClass,
    PreconditionPayload, ProposedEntityState, apply_candidate_to_snapshot,
    full_validation_profile_id, full_validation_profile_record, import_candidate,
};
use sley_scb1::{
    MAX_STANDALONE_BYTES, ScbError, ScbErrorCode, encode_list, encode_record, encode_text,
    encode_union, encode_uvar,
};
use sley_ssmc::{
    EffectKind,
    fingerprint::{FingerprintError, hash_validated_value},
};
use sley_state_root::{
    AcceptedStateRoot, StateRootBuilder, StateRootError, conformance_registry, import_state_root,
};

use crate::{
    AcceptedPolicyRoot, CapabilityError, CapabilityErrorCode, CapabilityToken,
    CapabilityTrustedKey, CapabilityVerificationRequest, PolicyRootError, PolicyRootErrorCode,
    build_capability_summary_projection, finalize_mandatory_contract_tests,
    validate_ordinary_program_isolation, verify_capability_token,
};

use super::{
    CandidateDecision, CandidateDiagnostic, CandidatePhaseResult, CandidateResultError,
    CandidateResultRecord, DiagnosticRetryability, ImportedCandidateResult, PhaseEvidenceDigest,
    PhaseOutcome, ValidationContextDigest, candidate_attempt_digest,
    candidate_program::{CandidateProgram, CandidateProgramError, OwnedFunctionUnit},
    candidate_result::{build_candidate_result, encode_phase14_result_core},
    phase_evidence_digest, validation_context_digest,
};

const CONTEXT_FORMAT_VERSION: u32 = 1;
const RESULT_FORMAT_VERSION: u32 = 1;
const MAX_CONTEXT_ENTITIES: u32 = 65_535;
const MAX_LOCAL_TEST_LIMIT: u64 = 1_000_000_000_000_000;
const CONTEXT_INVENTORY_DOMAIN: &[u8] = b"sley2.validation-context-inventory.v1";
const CONTEXT_TOMBSTONES_DOMAIN: &[u8] = b"sley2.validation-context-tombstones.v1";

/// Explicit local S20-360 ceilings. Effective limits are the minimum of these,
/// the frozen validation profile, SCB1, and protected policy ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateValidationLimits {
    /// Maximum candidate operations accepted locally.
    pub max_operations: u32,
    /// Maximum candidate preconditions accepted locally.
    pub max_preconditions: u32,
    /// Maximum stored candidate bytes accepted locally.
    pub max_candidate_bytes: u64,
    /// Maximum deterministic decoded/change-byte charge.
    pub max_decoded_value_bytes: u64,
    /// Maximum aggregate graph/checker work.
    pub max_graph_work: u64,
    /// Maximum validator-selected tests.
    pub max_selected_tests: u32,
    /// Maximum live entity objects in the trusted base/proposed inventory.
    pub max_entities: u32,
    /// Maximum selected-test call-depth ceiling.
    pub max_test_call_depth: u64,
    /// Maximum selected-test wall-time ceiling in milliseconds.
    pub max_test_wall_timeout_millis: u64,
}

impl CandidateValidationLimits {
    /// Returns the widest local ceilings permitted by the frozen full-v1
    /// profile and current conformance implementation.
    #[must_use]
    pub fn full_v1() -> Self {
        let profile = full_validation_profile_record();
        Self {
            max_operations: profile.max_operations,
            max_preconditions: profile.max_preconditions,
            max_candidate_bytes: profile.max_candidate_bytes,
            max_decoded_value_bytes: profile.max_decoded_value_bytes,
            max_graph_work: profile.max_graph_work,
            max_selected_tests: profile.max_selected_tests,
            max_entities: MAX_CONTEXT_ENTITIES,
            max_test_call_depth: MAX_LOCAL_TEST_LIMIT,
            max_test_wall_timeout_millis: MAX_LOCAL_TEST_LIMIT,
        }
    }

    fn effective(self) -> Self {
        let profile = Self::full_v1();
        Self {
            max_operations: self.max_operations.min(profile.max_operations),
            max_preconditions: self.max_preconditions.min(profile.max_preconditions),
            max_candidate_bytes: self
                .max_candidate_bytes
                .min(profile.max_candidate_bytes)
                .min(MAX_STANDALONE_BYTES as u64),
            max_decoded_value_bytes: self
                .max_decoded_value_bytes
                .min(profile.max_decoded_value_bytes),
            max_graph_work: self.max_graph_work.min(profile.max_graph_work),
            max_selected_tests: self.max_selected_tests.min(profile.max_selected_tests),
            max_entities: self.max_entities.min(MAX_CONTEXT_ENTITIES),
            max_test_call_depth: self.max_test_call_depth.min(MAX_LOCAL_TEST_LIMIT),
            max_test_wall_timeout_millis: self
                .max_test_wall_timeout_millis
                .min(MAX_LOCAL_TEST_LIMIT),
        }
    }
}

impl Default for CandidateValidationLimits {
    fn default() -> Self {
        Self::full_v1()
    }
}

/// One capability token plus the exact host-trusted issuer/key/secret tuple
/// used to authenticate it. Secret bytes never enter result or context bytes.
#[derive(Clone, Copy, Debug)]
pub struct TrustedCandidateCapability<'a> {
    token: &'a CapabilityToken,
    trusted_key: &'a CapabilityTrustedKey,
}

impl<'a> TrustedCandidateCapability<'a> {
    /// Constructs one explicit trusted capability input.
    #[must_use]
    pub const fn new(token: &'a CapabilityToken, trusted_key: &'a CapabilityTrustedKey) -> Self {
        Self { token, trusted_key }
    }
}

/// Closed validator-owned context. The digest is computed internally from a
/// canonical public projection; callers cannot supply or replace it.
pub struct CandidateValidationContext<'a> {
    base_transaction_id: TransactionId,
    base_state: &'a AcceptedStateRoot,
    base_objects: &'a [EntityObject],
    tombstones: &'a [EntityId],
    policy: &'a AcceptedPolicyRoot,
    principal_id: PrincipalId,
    capabilities: &'a [TrustedCandidateCapability<'a>],
    capability_summary_digest: CapabilitySummaryDigest,
    now_unix_millis: u64,
    limits: CandidateValidationLimits,
    context_digest: ValidationContextDigest,
}

impl<'a> CandidateValidationContext<'a> {
    /// Constructs a closed trusted context and derives its public digest.
    ///
    /// Token bodies must already share the supplied outer principal,
    /// workspace, policy, and state-root bindings and may not duplicate a
    /// token digest. MAC/expiry/policy verification still runs in phase 9.
    /// Base inventory and tombstone completeness deliberately remain phase-2
    /// judgments so invalid candidate results preserve monotonic evidence.
    ///
    /// # Errors
    ///
    /// Returns a context-construction error for an unprojectable capability
    /// summary or canonical public projection.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_transaction_id: TransactionId,
        base_state: &'a AcceptedStateRoot,
        base_objects: &'a [EntityObject],
        tombstones: &'a [EntityId],
        policy: &'a AcceptedPolicyRoot,
        principal_id: PrincipalId,
        capabilities: &'a [TrustedCandidateCapability<'a>],
        now_unix_millis: u64,
        limits: CandidateValidationLimits,
    ) -> Result<Self, CandidateValidationError> {
        let limits = limits.effective();
        let tokens = capabilities
            .iter()
            .map(|capability| capability.token.clone())
            .collect::<Vec<_>>();
        let summary = build_capability_summary_projection(
            principal_id,
            base_state.record.workspace_id,
            policy.root(),
            base_state.root,
            &tokens,
        )?;
        let public_projection = encode_context_projection(
            base_transaction_id,
            base_state,
            base_objects,
            tombstones,
            policy.root(),
            principal_id,
            summary.digest(),
            now_unix_millis,
            limits,
        )?;
        let context_digest = validation_context_digest(&public_projection)?;
        Ok(Self {
            base_transaction_id,
            base_state,
            base_objects,
            tombstones,
            policy,
            principal_id,
            capabilities,
            capability_summary_digest: summary.digest(),
            now_unix_millis,
            limits,
            context_digest,
        })
    }

    /// Returns the validator-derived public context digest.
    #[must_use]
    pub const fn context_digest(&self) -> ValidationContextDigest {
        self.context_digest
    }

    /// Returns the independently projected capability-summary digest.
    #[must_use]
    pub const fn capability_summary_digest(&self) -> CapabilitySummaryDigest {
        self.capability_summary_digest
    }
}

/// In-process S20-360 decision output. Imported result bytes alone do not
/// construct this wrapper; only `validate_candidate_bytes` does.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateValidationOutput {
    result: ImportedCandidateResult,
}

impl CandidateValidationOutput {
    /// Returns the exact validator-owned result record and stored bytes.
    #[must_use]
    pub const fn result(&self) -> &ImportedCandidateResult {
        &self.result
    }

    /// Returns whether all fourteen validation phases passed.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.result.record.decision == CandidateDecision::Valid
    }
}

/// Context-construction or result-rendering failure. Candidate invalidity is
/// not an error here; it is returned as a canonical terminal result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateValidationError {
    /// Capability-summary public projection could not be constructed.
    Capability(CapabilityError),
    /// Candidate-result evidence could not be canonically encoded.
    Result(CandidateResultError),
    /// Context public projection could not be canonically encoded.
    Scb(ScbError),
}

impl fmt::Display for CandidateValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capability(error) => error.fmt(formatter),
            Self::Result(error) => error.fmt(formatter),
            Self::Scb(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CandidateValidationError {}

impl From<CapabilityError> for CandidateValidationError {
    fn from(value: CapabilityError) -> Self {
        Self::Capability(value)
    }
}

impl From<CandidateResultError> for CandidateValidationError {
    fn from(value: CandidateResultError) -> Self {
        Self::Result(value)
    }
}

impl From<ScbError> for CandidateValidationError {
    fn from(value: ScbError) -> Self {
        Self::Scb(value)
    }
}

#[derive(Clone, Copy)]
struct Failure {
    phase: u32,
    decision: CandidateDecision,
    source_symbol: &'static str,
    source_numeric_code: Option<u32>,
    retryability: DiagnosticRetryability,
}

impl Failure {
    const fn new(
        phase: u32,
        decision: CandidateDecision,
        source_symbol: &'static str,
        source_numeric_code: Option<u32>,
        retryability: DiagnosticRetryability,
    ) -> Self {
        Self {
            phase,
            decision,
            source_symbol,
            source_numeric_code,
            retryability,
        }
    }
}

struct ResultRenderer {
    attempt_digest: sley_id::CandidateAttemptDigest,
    context_digest: ValidationContextDigest,
    validation_profile_id: ValidationProfileId,
    candidate_id: Option<sley_id::CandidateId>,
    now_unix_millis: u64,
    passed: Vec<CandidatePhaseResult>,
    affected_closure: Vec<EntityId>,
    required_capabilities: Vec<EntityId>,
    selected_tests: Vec<EntityId>,
}

impl ResultRenderer {
    fn new(
        attempt_digest: sley_id::CandidateAttemptDigest,
        context_digest: ValidationContextDigest,
        validation_profile_id: ValidationProfileId,
        now_unix_millis: u64,
    ) -> Self {
        Self {
            attempt_digest,
            context_digest,
            validation_profile_id,
            candidate_id: None,
            now_unix_millis,
            passed: Vec::with_capacity(14),
            affected_closure: Vec::new(),
            required_capabilities: Vec::new(),
            selected_tests: Vec::new(),
        }
    }

    fn set_candidate(&mut self, candidate: &ImportedCandidate) {
        self.candidate_id = Some(candidate.candidate_id);
    }

    fn pass(&mut self, phase: u32, values: &[Vec<u8>]) -> Result<(), CandidateValidationError> {
        debug_assert_eq!(usize::try_from(phase).ok(), Some(self.passed.len() + 1));
        let payload = encode_list(values)?;
        let evidence = self.evidence(phase, &payload)?;
        self.passed.push(CandidatePhaseResult {
            phase_tag: phase,
            outcome: PhaseOutcome::Passed,
            evidence_digest: Some(evidence),
            terminal_decision: None,
        });
        Ok(())
    }

    fn finish_failure(
        self,
        failure: Failure,
    ) -> Result<CandidateValidationOutput, CandidateValidationError> {
        debug_assert_eq!(
            usize::try_from(failure.phase).ok(),
            Some(self.passed.len() + 1)
        );
        let failure_payload = encode_record(&[
            (1, encode_uvar(u64::from(failure.decision.tag()))),
            (2, encode_text(failure.source_symbol)?),
            (3, encode_option_u32(failure.source_numeric_code)?),
        ])?;
        let evidence = self.evidence(failure.phase, &failure_payload)?;
        let mut phases = self.passed;
        phases.push(CandidatePhaseResult {
            phase_tag: failure.phase,
            outcome: PhaseOutcome::Failed,
            evidence_digest: Some(evidence),
            terminal_decision: Some(failure.decision),
        });
        for phase_tag in (failure.phase + 1)..=14 {
            phases.push(CandidatePhaseResult {
                phase_tag,
                outcome: PhaseOutcome::NotRun,
                evidence_digest: None,
                terminal_decision: None,
            });
        }
        let result_code = failure
            .decision
            .numeric_code()
            .expect("non-valid terminal decision has one frozen code");
        let record = CandidateResultRecord {
            format_version: RESULT_FORMAT_VERSION,
            candidate_attempt_digest: self.attempt_digest,
            candidate_id: self.candidate_id,
            validation_profile_id: self.validation_profile_id,
            validation_context_digest: self.context_digest,
            decision: failure.decision,
            phase_results: phases,
            diagnostics: vec![CandidateDiagnostic {
                phase_tag: failure.phase,
                result_code,
                source_numeric_code: failure.source_numeric_code,
                source_symbol: failure.source_symbol.to_owned(),
                retryability: failure.retryability,
                causal_digest: None,
            }],
            affected_closure: self.affected_closure,
            required_capabilities: self.required_capabilities,
            selected_tests: self.selected_tests,
            candidate_root: None,
            validated_at_unix_millis: self.now_unix_millis,
        };
        Ok(CandidateValidationOutput {
            result: build_candidate_result(&record)?,
        })
    }

    fn finish_valid(
        self,
        candidate_root: StateRoot,
    ) -> Result<CandidateValidationOutput, CandidateValidationError> {
        debug_assert_eq!(self.passed.len(), 13);
        let mut phases = self.passed;
        phases.push(CandidatePhaseResult {
            phase_tag: 14,
            outcome: PhaseOutcome::Passed,
            evidence_digest: None,
            terminal_decision: None,
        });
        let mut record = CandidateResultRecord {
            format_version: RESULT_FORMAT_VERSION,
            candidate_attempt_digest: self.attempt_digest,
            candidate_id: self.candidate_id,
            validation_profile_id: self.validation_profile_id,
            validation_context_digest: self.context_digest,
            decision: CandidateDecision::Valid,
            phase_results: phases,
            diagnostics: Vec::new(),
            affected_closure: self.affected_closure,
            required_capabilities: self.required_capabilities,
            selected_tests: self.selected_tests,
            candidate_root: Some(candidate_root),
            validated_at_unix_millis: self.now_unix_millis,
        };
        let core = encode_phase14_result_core(&record)?;
        record.phase_results[13].evidence_digest = Some(phase_evidence_digest(14, &core)?);
        Ok(CandidateValidationOutput {
            result: build_candidate_result(&record)?,
        })
    }

    fn evidence(
        &self,
        phase: u32,
        phase_payload: &[u8],
    ) -> Result<PhaseEvidenceDigest, CandidateValidationError> {
        let projection = encode_record(&[
            (1, self.attempt_digest.as_bytes().to_vec()),
            (2, self.context_digest.as_bytes().to_vec()),
            (3, encode_option_candidate_id(self.candidate_id)?),
            (4, phase_payload.to_vec()),
        ])?;
        Ok(phase_evidence_digest(phase, &projection)?)
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_context_projection(
    base_transaction_id: TransactionId,
    base_state: &AcceptedStateRoot,
    base_objects: &[EntityObject],
    tombstones: &[EntityId],
    policy_root: PolicyRootId,
    principal_id: PrincipalId,
    capability_summary: CapabilitySummaryDigest,
    now_unix_millis: u64,
    limits: CandidateValidationLimits,
) -> Result<Vec<u8>, ScbError> {
    let mut inventory = base_objects
        .iter()
        .map(|object| {
            encode_record(&[
                (1, object.record().entity_id.as_bytes().to_vec()),
                (2, object.object_id().as_bytes().to_vec()),
            ])
        })
        .collect::<Result<Vec<_>, _>>()?;
    inventory.sort();
    let mut tombstones = tombstones.to_vec();
    tombstones.sort_unstable();
    let tombstones = tombstones
        .iter()
        .map(|entity| entity.as_bytes().to_vec())
        .collect::<Vec<_>>();
    let inventory_digest =
        context_component_digest(CONTEXT_INVENTORY_DOMAIN, &encode_list(&inventory)?)?;
    let tombstone_digest =
        context_component_digest(CONTEXT_TOMBSTONES_DOMAIN, &encode_list(&tombstones)?)?;
    encode_record(&[
        (1, encode_uvar(u64::from(CONTEXT_FORMAT_VERSION))),
        (2, base_transaction_id.as_bytes().to_vec()),
        (3, base_state.root.as_bytes().to_vec()),
        (4, base_state.record.schema_epoch_id.as_bytes().to_vec()),
        (5, policy_root.as_bytes().to_vec()),
        (6, principal_id.as_bytes().to_vec()),
        (7, capability_summary.as_bytes().to_vec()),
        (8, encode_uvar(now_unix_millis)),
        (9, inventory_digest.to_vec()),
        (10, tombstone_digest.to_vec()),
        (11, encode_limits(limits)?),
    ])
}

fn context_component_digest(domain: &[u8], payload: &[u8]) -> Result<[u8; 32], ScbError> {
    let payload_len =
        u64::try_from(payload.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&payload_len.to_be_bytes());
    hasher.update(payload);
    Ok(*hasher.finalize().as_bytes())
}

fn encode_limits(limits: CandidateValidationLimits) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(u64::from(limits.max_operations))),
        (2, encode_uvar(u64::from(limits.max_preconditions))),
        (3, encode_uvar(limits.max_candidate_bytes)),
        (4, encode_uvar(limits.max_decoded_value_bytes)),
        (5, encode_uvar(limits.max_graph_work)),
        (6, encode_uvar(u64::from(limits.max_selected_tests))),
        (7, encode_uvar(u64::from(limits.max_entities))),
        (8, encode_uvar(limits.max_test_call_depth)),
        (9, encode_uvar(limits.max_test_wall_timeout_millis)),
    ])
}

fn encode_option_candidate_id(
    candidate_id: Option<sley_id::CandidateId>,
) -> Result<Vec<u8>, ScbError> {
    match candidate_id {
        None => encode_union(0, &[]),
        Some(value) => encode_union(1, value.as_bytes()),
    }
}

fn encode_option_u32(value: Option<u32>) -> Result<Vec<u8>, ScbError> {
    match value {
        None => encode_union(0, &[]),
        Some(value) => encode_union(1, &encode_uvar(u64::from(value))),
    }
}

// The ordered pipeline implementation follows below. Keeping helpers in this
// module ensures no caller can invoke, skip, or reorder an individual phase.

/// Runs the exact ordered fourteen-phase S20-360 pipeline over candidate bytes.
///
/// Candidate invalidity is returned as a canonical successful output carrying
/// the terminal decision. The `Err` arm is reserved for inability to render
/// validator evidence itself.
///
/// # Errors
///
/// Returns only canonical context/result encoding failures. No candidate
/// failure mutates caller-owned state or enters this error channel.
#[allow(clippy::too_many_lines)]
pub fn validate_candidate_bytes(
    context: &CandidateValidationContext<'_>,
    stored_candidate_bytes: &[u8],
) -> Result<CandidateValidationOutput, CandidateValidationError> {
    let attempt = candidate_attempt_digest(stored_candidate_bytes)?;
    let profile_id = full_validation_profile_id().map_err(candidate_result_from_candidate)?;
    let mut renderer = ResultRenderer::new(
        attempt,
        context.context_digest,
        profile_id,
        context.now_unix_millis,
    );

    // Phase 1: canonical candidate frame, digest, record, and structural shape.
    let candidate = match import_candidate(stored_candidate_bytes) {
        Ok(candidate) => candidate,
        Err(error) => {
            let failure = candidate_import_failure(&error);
            return renderer.finish_failure(failure);
        }
    };
    renderer.set_candidate(&candidate);
    renderer.pass(
        1,
        &[
            candidate.candidate_id.as_bytes().to_vec(),
            encode_uvar(stored_candidate_bytes.len() as u64),
        ],
    )?;

    // Phase 2: profile, hard limits, and exact closed trusted inventory.
    if let Err(failure) = validate_phase_two(context, &candidate) {
        return renderer.finish_failure(failure);
    }
    renderer.pass(
        2,
        &[
            candidate.record.schema_epoch_id.as_bytes().to_vec(),
            encode_uvar(candidate.record.operations.len() as u64),
            encode_uvar(candidate.record.preconditions.len() as u64),
            encode_uvar(context.base_objects.len() as u64),
            encode_limits(context.limits.effective())?,
        ],
    )?;

    // Phase 3: exact accepted-base, epoch, policy, expiry, and preimage freshness.
    if let Err(failure) = validate_phase_three(context, &candidate) {
        return renderer.finish_failure(failure);
    }
    renderer.pass(
        3,
        &[
            context.base_transaction_id.as_bytes().to_vec(),
            context.base_state.root.as_bytes().to_vec(),
            context.policy.root().as_bytes().to_vec(),
            encode_uvar(context.now_unix_millis),
        ],
    )?;

    // Phase 4: deterministic creation identities and live/tombstone collision.
    if let Err(failure) = validate_phase_four(context, &candidate) {
        return renderer.finish_failure(failure);
    }
    renderer.pass(
        4,
        &[
            encode_uvar(
                candidate
                    .record
                    .operations
                    .iter()
                    .filter(|operation| operation.class == MutationClass::CreateEntity)
                    .count() as u64,
            ),
            encode_uvar(context.tombstones.len() as u64),
        ],
    )?;

    // Phase 5: pure apply, complete all-18-kind graph/reference projection,
    // dependency/root consistency, and conservative base+proposed closure.
    let proposed = match apply_candidate_to_snapshot(
        candidate.record.schema_epoch_id,
        &candidate.record,
        context.base_objects,
        &context.base_state.record.entry_points,
    ) {
        Ok(proposed) => proposed,
        Err(error) => return renderer.finish_failure(candidate_apply_failure(&error)),
    };
    let base_program = match CandidateProgram::project(context.base_objects) {
        Ok(program) => program,
        Err(error) => return renderer.finish_failure(program_failure(error)),
    };
    let program = match CandidateProgram::project(proposed.entities()) {
        Ok(program) => program,
        Err(error) => return renderer.finish_failure(program_failure(error)),
    };
    if let Err(failure) = validate_phase_five_context(context, &proposed, &base_program, &program) {
        return renderer.finish_failure(failure);
    }
    let mut seeds = candidate
        .record
        .operations
        .iter()
        .map(|operation| operation.target_entity)
        .collect::<Vec<_>>();
    seeds.sort_unstable();
    seeds.dedup();
    let base_closure = match base_program.affected_closure(&seeds) {
        Ok(closure) => closure,
        Err(error) => return renderer.finish_failure(program_failure(error)),
    };
    let proposed_closure = match program.affected_closure(&seeds) {
        Ok(closure) => closure,
        Err(error) => return renderer.finish_failure(program_failure(error)),
    };
    renderer.affected_closure = sorted_union(&base_closure, &proposed_closure);
    let base_requirements = base_program.required_capabilities(&renderer.affected_closure);
    let proposed_requirements = program.required_capabilities(&renderer.affected_closure);
    renderer.required_capabilities = sorted_union(&base_requirements, &proposed_requirements);
    let base_functions = base_program.affected_functions(&renderer.affected_closure);
    let proposed_functions = program.affected_functions(&renderer.affected_closure);
    let affected_functions = sorted_union(&base_functions, &proposed_functions);
    renderer.pass(
        5,
        &[
            encode_uvar(proposed.entities().len() as u64),
            encode_uvar(program.edge_count() as u64),
            encode_uvar(program.graph_work()),
            encode_entity_ids(&renderer.affected_closure)?,
            encode_entity_ids(&renderer.required_capabilities)?,
        ],
    )?;

    // Phase 6: complete type/constant projection through the S20-210 owner.
    let types = match program.validate_types() {
        Ok(types) => types,
        Err(error) => return renderer.finish_failure(type_failure(6, &error)),
    };
    if let Err(error) = program.validate_restricted_type_fingerprint_claims(
        candidate.record.schema_epoch_id,
        proposed.entities(),
    ) {
        return renderer.finish_failure(fingerprint_semantic_failure(
            6,
            CandidateDecision::TypeError,
            &error,
        ));
    }
    renderer.pass(
        6,
        &[
            encode_uvar(program.type_definitions.len() as u64),
            encode_uvar(program.constants.len() as u64),
            encode_uvar(program.functions.len() as u64),
        ],
    )?;

    // Phase 7: every complete function-owned CFG through S20-220.
    let owned_units = program.function_units();
    let mut cfg_edges = 0_u64;
    let mut cfg_work = 0_u64;
    for unit in &owned_units {
        let report = match validate_function_graph(
            &types,
            &unit.function,
            &unit.parameters,
            &unit.blocks,
            &unit.operations,
        ) {
            Ok(report) => report,
            Err(error) => return renderer.finish_failure(cfg_failure(&error)),
        };
        cfg_edges = match cfg_edges.checked_add(u64::from(report.edges)) {
            Some(value) => value,
            None => return renderer.finish_failure(resource_failure(7, "CFG_RESOURCE_LIMIT")),
        };
        cfg_work = match cfg_work.checked_add(report.dominator_word_operations) {
            Some(value) => value,
            None => return renderer.finish_failure(resource_failure(7, "CFG_RESOURCE_LIMIT")),
        };
    }
    renderer.pass(
        7,
        &[
            encode_uvar(owned_units.len() as u64),
            encode_uvar(cfg_edges),
            encode_uvar(cfg_work),
        ],
    )?;

    // Phase 8: exact static effect closure through S20-230.
    let borrowed_units = borrow_units(&owned_units);
    let contract_ids = program
        .contracts
        .iter()
        .map(|contract| contract.entity_id)
        .collect::<Vec<_>>();
    let effect_report = match validate_effect_program(
        &types,
        &borrowed_units,
        &program.effects,
        &program.requirements,
        &program.adapters,
        &contract_ids,
    ) {
        Ok(report) => report,
        Err(error) => return renderer.finish_failure(effect_failure(&error)),
    };
    if let Err(error) = program.validate_restricted_function_fingerprint_claims(
        candidate.record.schema_epoch_id,
        proposed.entities(),
    ) {
        return renderer.finish_failure(fingerprint_semantic_failure(
            8,
            CandidateDecision::EffectError,
            &error,
        ));
    }
    renderer.pass(
        8,
        &[
            encode_uvar(effect_report.functions.len() as u64),
            encode_uvar(u64::from(effect_report.call_edges)),
            encode_uvar(u64::from(effect_report.closure_rounds)),
            encode_uvar(effect_report.closure_work),
        ],
    )?;

    // Phase 9: proposal binding, authenticated tokens, policy grants and pure
    // protected-root isolation over an in-memory candidate root.
    let grant = match validate_phase_nine(
        context,
        &candidate,
        &program,
        &affected_functions,
        &renderer.required_capabilities,
    ) {
        Ok(grant) => grant,
        Err(failure) => return renderer.finish_failure(failure),
    };
    let provisional_root = match build_candidate_state_root(context.base_state, &proposed) {
        Ok(root) => root,
        Err(error) => return renderer.finish_failure(state_root_failure(9, &error)),
    };
    let isolation = match validate_ordinary_program_isolation(
        context.policy,
        context.base_state,
        &provisional_root,
    ) {
        Ok(report) => report,
        Err(error) => return renderer.finish_failure(policy_failure(9, &error)),
    };
    renderer.pass(
        9,
        &[
            context.principal_id.as_bytes().to_vec(),
            context.capability_summary_digest.as_bytes().to_vec(),
            encode_uvar(context.capabilities.len() as u64),
            encode_uvar(isolation.protected_entities_checked),
            provisional_root.root.as_bytes().to_vec(),
        ],
    )?;

    // Phase 10/11: the combined S20-240 checker has frozen first-failure
    // ordering. Test-plan-class failures therefore prove the contract prefix
    // passed and are rendered at phase 11; all other failures remain phase 10.
    let contract_report = match validate_contract_test_program(
        &types,
        &borrowed_units,
        &program.effects,
        &program.requirements,
        &program.adapters,
        &program.type_definitions,
        &program.constants,
        &program.globals,
        &program.contracts,
        &program.tests,
        &affected_functions,
        &context.policy.record().required_tests,
    ) {
        Ok(report) => report,
        Err(error) => {
            if let Some(failure) = contract_plan_failure(&error) {
                renderer.pass(
                    10,
                    &[
                        encode_uvar(program.contracts.len() as u64),
                        b"CONTRACT_PREFIX_PASSED".to_vec(),
                    ],
                )?;
                return renderer.finish_failure(failure);
            }
            return renderer.finish_failure(contract_failure(&error));
        }
    };
    renderer.pass(
        10,
        &[
            encode_uvar(contract_report.contracts.len() as u64),
            encode_uvar(u64::from(contract_report.contract_assertions)),
        ],
    )?;

    renderer
        .selected_tests
        .clone_from(&contract_report.selected_tests);
    if renderer.selected_tests.len() > context.limits.effective().max_selected_tests as usize {
        return renderer.finish_failure(resource_failure(11, "CONTRACT_TEST_PLAN_RESOURCE_LIMIT"));
    }
    let final_plan = match finalize_mandatory_contract_tests(context.policy, &contract_report) {
        Ok(plan) => plan,
        Err(error) => return renderer.finish_failure(test_plan_policy_failure(&error)),
    };
    renderer.pass(
        11,
        &[
            encode_entity_ids(&renderer.selected_tests)?,
            encode_entity_ids(&final_plan.required_tests)?,
            encode_entity_ids(&final_plan.required_contracts)?,
        ],
    )?;

    // Phase 12: deterministic supported-work and selected-test ceilings.
    let resource_report = match validate_phase_twelve(
        context,
        &candidate,
        &proposed,
        &program,
        &contract_report,
        &effect_report,
        cfg_work,
        &provisional_root,
        grant.resource_ceilings(),
        &renderer.selected_tests,
    ) {
        Ok(report) => report,
        Err(failure) => return renderer.finish_failure(failure),
    };
    renderer.pass(
        12,
        &[
            encode_uvar(resource_report.total_work),
            encode_uvar(resource_report.decoded_change_bytes),
            encode_uvar(resource_report.selected_tests),
        ],
    )?;

    // Phase 13: rebuild all proposed bindings/root canonically and prove exact
    // equality with the root used for phase-9 protected isolation.
    let candidate_root = match build_candidate_state_root(context.base_state, &proposed) {
        Ok(root) => root,
        Err(error) => return renderer.finish_failure(state_root_failure(13, &error)),
    };
    if candidate_root != provisional_root {
        return renderer.finish_failure(Failure::new(
            13,
            CandidateDecision::InternalError,
            "CANDIDATE_ROOT_REBUILD_MISMATCH",
            None,
            DiagnosticRetryability::InternalRepair,
        ));
    }
    renderer.pass(
        13,
        &[
            candidate_root.root.as_bytes().to_vec(),
            encode_uvar(candidate_root.record.entity_bindings.len() as u64),
            encode_uvar(candidate_root.stored_bytes.len() as u64),
        ],
    )?;

    // Phase 14 is rendered from the exact final-result core by finish_valid.
    renderer.finish_valid(candidate_root.root)
}

fn validate_phase_two(
    context: &CandidateValidationContext<'_>,
    candidate: &ImportedCandidate,
) -> Result<(), Failure> {
    let limits = context.limits.effective();
    if candidate.stored_bytes.len() as u64 > limits.max_candidate_bytes
        || candidate.record.operations.len() > limits.max_operations as usize
        || candidate.record.preconditions.len() > limits.max_preconditions as usize
        || context.base_objects.len() > limits.max_entities as usize
        || context.base_state.record.entity_bindings.len() > limits.max_entities as usize
    {
        return Err(resource_failure(2, "SCB_RESOURCE_LIMIT"));
    }
    let state_registry = conformance_registry().map_err(|_| {
        Failure::new(
            2,
            CandidateDecision::InternalError,
            "CANDIDATE_CONTEXT_STATE_REGISTRY_INVALID",
            None,
            DiagnosticRetryability::InternalRepair,
        )
    })?;
    let imported_state = import_state_root(&state_registry, &context.base_state.stored_bytes)
        .map_err(|error| {
            Failure::new(
                2,
                CandidateDecision::InvalidSchema,
                error.code_str(),
                None,
                DiagnosticRetryability::FreshAuthority,
            )
        })?;
    if imported_state != *context.base_state {
        return Err(Failure::new(
            2,
            CandidateDecision::InvalidSchema,
            "CANDIDATE_CONTEXT_STATE_ROOT_MISMATCH",
            None,
            DiagnosticRetryability::FreshAuthority,
        ));
    }
    if context.base_objects.len() != context.base_state.record.entity_bindings.len() {
        return Err(Failure::new(
            2,
            CandidateDecision::InvalidSchema,
            "CANDIDATE_CONTEXT_INVENTORY_MISMATCH",
            None,
            DiagnosticRetryability::Permanent,
        ));
    }
    let mut previous = None;
    for (object, (entity_id, object_id)) in context
        .base_objects
        .iter()
        .zip(&context.base_state.record.entity_bindings)
    {
        if previous.is_some_and(|prior| prior >= object.record().entity_id)
            || object.record().entity_id != *entity_id
            || object.object_id() != *object_id
            || object.schema_epoch_id() != context.base_state.record.schema_epoch_id
        {
            return Err(Failure::new(
                2,
                CandidateDecision::InvalidSchema,
                "CANDIDATE_CONTEXT_INVENTORY_MISMATCH",
                None,
                DiagnosticRetryability::Permanent,
            ));
        }
        previous = Some(object.record().entity_id);
    }
    if context.tombstones.windows(2).any(|pair| pair[0] >= pair[1])
        || context.tombstones.iter().any(|tombstone| {
            context
                .base_state
                .record
                .entity_bindings
                .binary_search_by_key(tombstone, |(entity, _)| *entity)
                .is_ok()
        })
    {
        return Err(Failure::new(
            2,
            CandidateDecision::InvalidSchema,
            "CANDIDATE_CONTEXT_TOMBSTONE_SET_INVALID",
            None,
            DiagnosticRetryability::Permanent,
        ));
    }
    if context.base_state.record.policy_root != context.policy.root()
        || context.base_state.record.workspace_id != context.policy.record().workspace_id
    {
        return Err(Failure::new(
            2,
            CandidateDecision::InvalidSchema,
            "CANDIDATE_CONTEXT_POLICY_BINDING_INVALID",
            None,
            DiagnosticRetryability::FreshAuthority,
        ));
    }
    Ok(())
}

fn validate_phase_three(
    context: &CandidateValidationContext<'_>,
    candidate: &ImportedCandidate,
) -> Result<(), Failure> {
    let record = &candidate.record;
    if record.base_transaction_id != context.base_transaction_id {
        return Err(stale_root_failure("CANDIDATE_BASE_TRANSACTION_MISMATCH"));
    }
    if record.base_root != context.base_state.root {
        return Err(stale_root_failure("CANDIDATE_BASE_ROOT_MISMATCH"));
    }
    if record.workspace_id != context.base_state.record.workspace_id {
        return Err(stale_root_failure("CANDIDATE_WORKSPACE_MISMATCH"));
    }
    if record.schema_epoch_id != context.base_state.record.schema_epoch_id {
        return Err(stale_root_failure("CANDIDATE_SCHEMA_EPOCH_MISMATCH"));
    }
    if record.policy_root_id != context.policy.root() {
        return Err(stale_root_failure("CANDIDATE_POLICY_ROOT_MISMATCH"));
    }
    if context.now_unix_millis >= record.expiry.not_after {
        return Err(Failure::new(
            3,
            CandidateDecision::StaleRoot,
            "CANDIDATE_EXPIRY_EXPIRED",
            None,
            DiagnosticRetryability::Permanent,
        ));
    }
    if context
        .policy
        .record()
        .expiry_unix_millis
        .is_some_and(|expiry| context.now_unix_millis >= expiry)
    {
        return Err(Failure::new(
            3,
            CandidateDecision::StaleRoot,
            "POLICY_ROOT_EXPIRED",
            None,
            DiagnosticRetryability::FreshAuthority,
        ));
    }
    for precondition in &record.preconditions {
        let expected = match &precondition.payload {
            PreconditionPayload::ExpectedIdentityAbsent(_) => continue,
            PreconditionPayload::ExactEntityVersion(value) => (value.entity_id, value.object_id),
            PreconditionPayload::ExactContainerVersion(value) => {
                (value.container_id, value.object_id)
            }
        };
        let actual = context
            .base_state
            .record
            .entity_bindings
            .binary_search_by_key(&expected.0, |(entity, _)| *entity)
            .ok()
            .map(|index| context.base_state.record.entity_bindings[index].1);
        if actual != Some(expected.1) {
            return Err(Failure::new(
                3,
                CandidateDecision::StaleEntity,
                "CANDIDATE_APPLY_EXACT_PREIMAGE_MISMATCH",
                None,
                DiagnosticRetryability::FreshBase,
            ));
        }
    }
    Ok(())
}

fn validate_phase_four(
    context: &CandidateValidationContext<'_>,
    candidate: &ImportedCandidate,
) -> Result<(), Failure> {
    let mut create_ordinal = 0_u64;
    for (operation, precondition) in candidate
        .record
        .operations
        .iter()
        .zip(&candidate.record.preconditions)
    {
        if operation.class != MutationClass::CreateEntity {
            continue;
        }
        let expected = EntityId::derive(
            candidate.record.workspace_id,
            candidate.record.candidate_nonce,
            u32::from(operation.target_kind),
            create_ordinal,
        );
        create_ordinal = create_ordinal.checked_add(1).ok_or_else(|| {
            Failure::new(
                4,
                CandidateDecision::ResourceLimit,
                "SSMC_RESOURCE_LIMIT",
                Some(20_014),
                DiagnosticRetryability::HigherCeilings,
            )
        })?;
        let PreconditionPayload::ExpectedIdentityAbsent(absent) = &precondition.payload else {
            return Err(Failure::new(
                4,
                CandidateDecision::InvalidIdentity,
                "MUTATION_CANDIDATE_PRECONDITION_MISMATCH",
                Some(35_006),
                DiagnosticRetryability::Permanent,
            ));
        };
        if operation.target_entity != expected || absent.entity_id != expected {
            return Err(Failure::new(
                4,
                CandidateDecision::InvalidIdentity,
                "MUTATION_CANDIDATE_TARGET_ENTITY",
                Some(35_009),
                DiagnosticRetryability::Permanent,
            ));
        }
        if context
            .base_state
            .record
            .entity_bindings
            .binary_search_by_key(&expected, |(entity, _)| *entity)
            .is_ok()
            || context.tombstones.binary_search(&expected).is_ok()
        {
            return Err(Failure::new(
                4,
                CandidateDecision::InvalidIdentity,
                "CANDIDATE_IDENTITY_COLLISION",
                None,
                DiagnosticRetryability::Permanent,
            ));
        }
    }
    Ok(())
}

fn validate_phase_five_context(
    context: &CandidateValidationContext<'_>,
    proposed: &ProposedEntityState,
    base_program: &CandidateProgram,
    program: &CandidateProgram,
) -> Result<(), Failure> {
    if proposed
        .entry_points()
        .iter()
        .any(|entry| program.kinds.get(entry) != Some(&16))
    {
        return Err(Failure::new(
            5,
            CandidateDecision::InvalidGraph,
            "STATE_ROOT_ENTRY_POINT_KIND_INVALID",
            None,
            DiagnosticRetryability::Permanent,
        ));
    }
    if base_program.dependency_roots() != context.base_state.record.dependency_roots
        || program.dependency_roots() != context.base_state.record.dependency_roots
    {
        return Err(Failure::new(
            5,
            CandidateDecision::InvalidGraph,
            "CANDIDATE_DEPENDENCY_ROOT_CHANGE_UNSUPPORTED",
            None,
            DiagnosticRetryability::Permanent,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_phase_nine<'a>(
    context: &'a CandidateValidationContext<'_>,
    candidate: &ImportedCandidate,
    program: &CandidateProgram,
    affected_functions: &[EntityId],
    required_capabilities: &[EntityId],
) -> Result<&'a crate::PrincipalGrant, Failure> {
    if candidate.record.principal_id != context.principal_id {
        return Err(Failure::new(
            9,
            CandidateDecision::CapabilityDenied,
            "CAP_PRINCIPAL_MISMATCH",
            Some(CapabilityErrorCode::PrincipalMismatch.numeric()),
            DiagnosticRetryability::FreshAuthority,
        ));
    }
    if candidate.record.capability_summary_digest != context.capability_summary_digest {
        return Err(Failure::new(
            9,
            CandidateDecision::CapabilityDenied,
            "CAPABILITY_SUMMARY_MISMATCH",
            None,
            DiagnosticRetryability::FreshAuthority,
        ));
    }
    let grant = context
        .policy
        .principal_grant(context.principal_id)
        .map_err(|error| policy_failure(9, &error))?;
    for operation in &candidate.record.operations {
        let tag = u32::from(operation.class.tag());
        if grant
            .allowed_mutation_class_tags()
            .binary_search(&tag)
            .is_err()
        {
            return Err(Failure::new(
                9,
                CandidateDecision::CapabilityDenied,
                "POLICY_GRANT_DENIED",
                Some(PolicyRootErrorCode::GrantDenied.numeric()),
                DiagnosticRetryability::FreshAuthority,
            ));
        }
    }
    if candidate.record.operations.len() as u64 > grant.resource_ceilings().max_mutation_count {
        return Err(Failure::new(
            9,
            CandidateDecision::CapabilityDenied,
            "CAP_BUDGET_EXCEEDED",
            Some(CapabilityErrorCode::BudgetExceeded.numeric()),
            DiagnosticRetryability::FreshAuthority,
        ));
    }

    for capability in context.capabilities {
        let body = capability.token.body();
        let Some(effect_kind) = EffectKind::from_tag(body.effect_kind_tag) else {
            return Err(Failure::new(
                9,
                CandidateDecision::CapabilityDenied,
                "CAP_EFFECT_MISMATCH",
                Some(CapabilityErrorCode::EffectMismatch.numeric()),
                DiagnosticRetryability::FreshAuthority,
            ));
        };
        let request = CapabilityVerificationRequest {
            principal_id: context.principal_id,
            workspace_id: context.base_state.record.workspace_id,
            state_root: context.base_state.root,
            effect_id: body.effect_id,
            effect_kind,
            scope_hash: body.scope_hash,
            adapter_id: body.adapter_id,
            now_unix_millis: context.now_unix_millis,
            required_budget: body.budget,
        };
        if let Err(error) = verify_capability_token(
            context.policy,
            capability.token,
            capability.trusted_key,
            &request,
        ) {
            return Err(capability_failure(9, &error));
        }
    }

    let requirements = program
        .requirements
        .iter()
        .map(|requirement| (requirement.entity_id, requirement))
        .collect::<BTreeMap<_, _>>();
    let effects = program
        .effects
        .iter()
        .map(|effect| (effect.entity_id, effect))
        .collect::<BTreeMap<_, _>>();
    for required in required_capabilities {
        let Some(requirement) = requirements.get(required) else {
            return Err(Failure::new(
                9,
                CandidateDecision::CapabilityDenied,
                "CAPABILITY_REQUIREMENT_UNRESOLVED",
                None,
                DiagnosticRetryability::Permanent,
            ));
        };
        let Some(effect) = effects.get(&requirement.effect) else {
            return Err(Failure::new(
                9,
                CandidateDecision::CapabilityDenied,
                "CAP_EFFECT_MISMATCH",
                Some(CapabilityErrorCode::EffectMismatch.numeric()),
                DiagnosticRetryability::Permanent,
            ));
        };
        if grant
            .allowed_effect_kind_tags()
            .binary_search(&effect.effect_kind.tag())
            .is_err()
        {
            return Err(Failure::new(
                9,
                CandidateDecision::CapabilityDenied,
                "POLICY_GRANT_DENIED",
                Some(PolicyRootErrorCode::GrantDenied.numeric()),
                DiagnosticRetryability::FreshAuthority,
            ));
        }
        let mut scope_hashes = BTreeSet::new();
        for scope in &requirement.allowed_scopes {
            let hash = hash_validated_value(candidate.record.schema_epoch_id, scope)
                .map_err(|error| fingerprint_capability_failure(&error))?;
            scope_hashes.insert(hash);
        }
        let satisfied = context.capabilities.iter().any(|capability| {
            let body = capability.token.body();
            body.effect_id == requirement.effect
                && body.effect_kind_tag == effect.effect_kind.tag()
                && scope_hashes.contains(&body.scope_hash)
        });
        if !satisfied {
            return Err(Failure::new(
                9,
                CandidateDecision::CapabilityDenied,
                "CAP_SCOPE_MISMATCH",
                Some(CapabilityErrorCode::ScopeMismatch.numeric()),
                DiagnosticRetryability::FreshAuthority,
            ));
        }
    }

    for function_id in affected_functions {
        let Some(function) = program
            .functions
            .iter()
            .find(|function| function.entity_id == *function_id)
        else {
            continue;
        };
        for effect_id in &function.effects {
            if !required_capabilities.iter().any(|required| {
                requirements
                    .get(required)
                    .is_some_and(|requirement| requirement.effect == *effect_id)
            }) {
                return Err(Failure::new(
                    9,
                    CandidateDecision::CapabilityDenied,
                    "CAPABILITY_REQUIREMENT_MISSING",
                    None,
                    DiagnosticRetryability::FreshAuthority,
                ));
            }
        }
    }
    Ok(grant)
}

#[derive(Clone, Copy)]
struct ResourceAnalysisReport {
    total_work: u64,
    decoded_change_bytes: u64,
    selected_tests: u64,
}

#[allow(clippy::too_many_arguments)]
fn validate_phase_twelve(
    context: &CandidateValidationContext<'_>,
    candidate: &ImportedCandidate,
    proposed: &ProposedEntityState,
    program: &CandidateProgram,
    contract_report: &ContractTestReport,
    effect_report: &EffectReport,
    cfg_work: u64,
    provisional_root: &AcceptedStateRoot,
    policy_ceilings: crate::PolicyResourceCeilings,
    selected_tests: &[EntityId],
) -> Result<ResourceAnalysisReport, Failure> {
    if !program.operation_analysis_supported() {
        return Err(Failure::new(
            12,
            CandidateDecision::ResourceLimit,
            "CANDIDATE_OPERATION_ANALYSIS_UNSUPPORTED",
            None,
            DiagnosticRetryability::InternalRepair,
        ));
    }
    let limits = context.limits.effective();
    let mutation_work = (candidate.record.operations.len() as u64)
        .checked_add(candidate.record.preconditions.len() as u64)
        .and_then(|work| work.checked_add(proposed.affected_entities().len() as u64))
        .and_then(|work| work.checked_add(proposed.entities().len() as u64))
        .and_then(|work| work.checked_add(provisional_root.record.entity_bindings.len() as u64))
        .and_then(|work| work.checked_add(provisional_root.record.entry_points.len() as u64))
        .and_then(|work| work.checked_add(provisional_root.record.dependency_roots.len() as u64))
        .and_then(|work| work.checked_add(selected_tests.len() as u64))
        .ok_or_else(|| resource_failure(12, "CANDIDATE_GRAPH_WORK_LIMIT"))?;
    let total_work = program
        .graph_work()
        .checked_add(mutation_work)
        .and_then(|work| work.checked_add(cfg_work))
        .and_then(|work| work.checked_add(effect_report.closure_work))
        .and_then(|work| work.checked_add(contract_report.work))
        .ok_or_else(|| resource_failure(12, "CANDIDATE_GRAPH_WORK_LIMIT"))?;
    if total_work > limits.max_graph_work {
        return Err(resource_failure(12, "CANDIDATE_GRAPH_WORK_LIMIT"));
    }
    let mut decoded_change_bytes = candidate.stored_bytes.len() as u64;
    for entity in proposed.affected_entities() {
        if let Some(object) = proposed.entity(*entity) {
            decoded_change_bytes = decoded_change_bytes
                .checked_add(object.stored_bytes().len() as u64)
                .ok_or_else(|| resource_failure(12, "SCB_RESOURCE_LIMIT"))?;
        }
    }
    decoded_change_bytes = decoded_change_bytes
        .checked_add(provisional_root.stored_bytes.len() as u64)
        .ok_or_else(|| resource_failure(12, "SCB_RESOURCE_LIMIT"))?;
    if decoded_change_bytes > limits.max_decoded_value_bytes {
        return Err(resource_failure(12, "SCB_RESOURCE_LIMIT"));
    }
    let tests = program
        .tests
        .iter()
        .map(|test| (test.entity_id, test))
        .collect::<BTreeMap<_, _>>();
    for selected in selected_tests {
        let Some(test) = tests.get(selected) else {
            return Err(Failure::new(
                12,
                CandidateDecision::InternalError,
                "CANDIDATE_SELECTED_TEST_UNRESOLVED",
                None,
                DiagnosticRetryability::InternalRepair,
            ));
        };
        let resource = test.resource_limits;
        if resource.fuel > policy_ceilings.max_fuel
            || resource.memory_bytes > policy_ceilings.max_memory_bytes
            || resource.output_bytes > policy_ceilings.max_output_bytes
            || resource.effect_count > policy_ceilings.max_effect_count
            || resource.call_depth > limits.max_test_call_depth
            || resource.wall_timeout_millis > limits.max_test_wall_timeout_millis
        {
            return Err(resource_failure(12, "CANDIDATE_TEST_RESOURCE_LIMIT"));
        }
    }
    Ok(ResourceAnalysisReport {
        total_work,
        decoded_change_bytes,
        selected_tests: selected_tests.len() as u64,
    })
}

fn build_candidate_state_root(
    base: &AcceptedStateRoot,
    proposed: &ProposedEntityState,
) -> Result<AcceptedStateRoot, StateRootError> {
    let mut builder = StateRootBuilder::new(
        base.record.workspace_id,
        base.record.contract_root,
        base.record.test_root,
        base.record.policy_root,
    );
    for object in proposed.entities() {
        builder = builder.entity_binding(object.record().entity_id, object.object_id());
    }
    for entry_point in proposed.entry_points() {
        builder = builder.entry_point(*entry_point);
    }
    for dependency_root in &base.record.dependency_roots {
        builder = builder.dependency_root(*dependency_root);
    }
    for flag in &base.record.interpretation_flags {
        builder = builder.interpretation_flag(*flag);
    }
    builder.build(&conformance_registry()?)
}

fn borrow_units(units: &[OwnedFunctionUnit]) -> Vec<FunctionUnit<'_>> {
    units
        .iter()
        .map(|unit| FunctionUnit {
            function: &unit.function,
            parameters: &unit.parameters,
            blocks: &unit.blocks,
            operations: &unit.operations,
        })
        .collect()
}

fn sorted_union(left: &[EntityId], right: &[EntityId]) -> Vec<EntityId> {
    left.iter()
        .chain(right)
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn encode_entity_ids(values: &[EntityId]) -> Result<Vec<u8>, ScbError> {
    encode_list(
        &values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
}

fn candidate_import_failure(error: &CandidateError) -> Failure {
    let source_numeric_code = error.numeric_code();
    Failure::new(
        1,
        CandidateDecision::InvalidEncoding,
        error.code(),
        source_numeric_code,
        DiagnosticRetryability::Permanent,
    )
}

fn candidate_apply_failure(error: &CandidateApplyError) -> Failure {
    match error {
        CandidateApplyError::Object(error) if error.code() == ScbErrorCode::ResourceLimit => {
            resource_failure(5, error.code().as_str())
        }
        CandidateApplyError::ExactPreimageMismatch => Failure::new(
            5,
            CandidateDecision::ResourceLimit,
            error.code(),
            None,
            DiagnosticRetryability::InternalRepair,
        ),
        _ => Failure::new(
            5,
            CandidateDecision::InvalidGraph,
            error.code(),
            None,
            DiagnosticRetryability::Permanent,
        ),
    }
}

fn program_failure(error: CandidateProgramError) -> Failure {
    match error {
        CandidateProgramError::UnresolvedReference => Failure::new(
            5,
            CandidateDecision::UnresolvedReference,
            error.source_symbol(),
            Some(error.source_numeric_code()),
            DiagnosticRetryability::Permanent,
        ),
        CandidateProgramError::ResourceLimit => resource_failure(5, error.source_symbol()),
        _ => Failure::new(
            5,
            CandidateDecision::InvalidGraph,
            error.source_symbol(),
            Some(error.source_numeric_code()),
            DiagnosticRetryability::Permanent,
        ),
    }
}

fn type_failure(phase: u32, error: &TypeError) -> Failure {
    if error.code() == sley_check::TypeErrorCode::ResourceLimit {
        resource_failure(phase, error.code().as_str())
    } else {
        Failure::new(
            phase,
            CandidateDecision::TypeError,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::Permanent,
        )
    }
}

fn cfg_failure(error: &CfgValidationError) -> Failure {
    match error {
        CfgValidationError::Cfg(error) if error.code() == CfgErrorCode::ResourceLimit => {
            resource_failure(7, error.code().as_str())
        }
        CfgValidationError::Cfg(error) => Failure::new(
            7,
            CandidateDecision::ControlFlowError,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::Permanent,
        ),
        CfgValidationError::Type(error) => Failure::new(
            7,
            CandidateDecision::InternalError,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::InternalRepair,
        ),
    }
}

fn effect_failure(error: &EffectValidationError) -> Failure {
    match error {
        EffectValidationError::Effect(error) if error.code() == EffectErrorCode::ResourceLimit => {
            resource_failure(8, error.code().as_str())
        }
        EffectValidationError::Effect(error) => Failure::new(
            8,
            CandidateDecision::EffectError,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::Permanent,
        ),
        EffectValidationError::Cfg(error) => {
            let (symbol, numeric) = cfg_source(error);
            Failure::new(
                8,
                CandidateDecision::InternalError,
                symbol,
                Some(numeric),
                DiagnosticRetryability::InternalRepair,
            )
        }
        EffectValidationError::Type(error) => Failure::new(
            8,
            CandidateDecision::InternalError,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::InternalRepair,
        ),
    }
}

fn contract_failure(error: &ContractTestValidationError) -> Failure {
    match error {
        ContractTestValidationError::ContractTest(error)
            if error.code() == ContractTestErrorCode::ResourceLimit =>
        {
            resource_failure(10, error.code().as_str())
        }
        ContractTestValidationError::ContractTest(error) => Failure::new(
            10,
            CandidateDecision::ContractError,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::Permanent,
        ),
        ContractTestValidationError::Type(error) => Failure::new(
            10,
            CandidateDecision::InternalError,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::InternalRepair,
        ),
        ContractTestValidationError::Effect(error) => {
            let (symbol, numeric) = effect_source(error);
            Failure::new(
                10,
                CandidateDecision::InternalError,
                symbol,
                Some(numeric),
                DiagnosticRetryability::InternalRepair,
            )
        }
    }
}

fn contract_plan_failure(error: &ContractTestValidationError) -> Option<Failure> {
    let ContractTestValidationError::ContractTest(error) = error else {
        return None;
    };
    let code = error.code();
    if matches!(
        code,
        ContractTestErrorCode::TestTargetInvalid
            | ContractTestErrorCode::TestInputType
            | ContractTestErrorCode::TestEffectEnvironmentUnsupported
            | ContractTestErrorCode::TestExpectedType
            | ContractTestErrorCode::TestFailureCodeInvalid
            | ContractTestErrorCode::TestObservationUnsupported
            | ContractTestErrorCode::TestSelectionInvalid
    ) {
        Some(Failure::new(
            11,
            CandidateDecision::TestPlanError,
            code.as_str(),
            Some(code.numeric()),
            DiagnosticRetryability::Permanent,
        ))
    } else if code == ContractTestErrorCode::ResourceLimit {
        Some(resource_failure(11, code.as_str()))
    } else {
        None
    }
}

fn test_plan_policy_failure(error: &PolicyRootError) -> Failure {
    Failure::new(
        11,
        CandidateDecision::TestPlanError,
        error.code_str(),
        policy_numeric(error),
        DiagnosticRetryability::FreshAuthority,
    )
}

fn policy_failure(phase: u32, error: &PolicyRootError) -> Failure {
    Failure::new(
        phase,
        CandidateDecision::CapabilityDenied,
        error.code_str(),
        policy_numeric(error),
        DiagnosticRetryability::FreshAuthority,
    )
}

fn policy_numeric(error: &PolicyRootError) -> Option<u32> {
    match error {
        PolicyRootError::PolicyRoot(code) => Some(code.numeric()),
        PolicyRootError::Schema(_) | PolicyRootError::Scb(_) => None,
    }
}

fn capability_failure(phase: u32, error: &CapabilityError) -> Failure {
    let numeric = match error {
        CapabilityError::Capability(code) => Some(code.numeric()),
        CapabilityError::Scb(_) => None,
    };
    Failure::new(
        phase,
        CandidateDecision::CapabilityDenied,
        error.code_str(),
        numeric,
        DiagnosticRetryability::FreshAuthority,
    )
}

fn fingerprint_capability_failure(error: &FingerprintError) -> Failure {
    if error.code() == sley_ssmc::fingerprint::FingerprintErrorCode::ResourceLimit {
        resource_failure(9, error.code().as_str())
    } else {
        Failure::new(
            9,
            CandidateDecision::CapabilityDenied,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::Permanent,
        )
    }
}

fn fingerprint_semantic_failure(
    phase: u32,
    decision: CandidateDecision,
    error: &FingerprintError,
) -> Failure {
    if error.code() == sley_ssmc::fingerprint::FingerprintErrorCode::ResourceLimit {
        resource_failure(phase, error.code().as_str())
    } else {
        Failure::new(
            phase,
            decision,
            error.code().as_str(),
            Some(error.code().numeric()),
            DiagnosticRetryability::Permanent,
        )
    }
}

fn state_root_failure(phase: u32, error: &StateRootError) -> Failure {
    let is_resource = matches!(
        error,
        StateRootError::Scb(error) if error.code() == ScbErrorCode::ResourceLimit
    );
    if is_resource {
        resource_failure(phase, error.code_str())
    } else {
        Failure::new(
            phase,
            CandidateDecision::InternalError,
            error.code_str(),
            None,
            DiagnosticRetryability::InternalRepair,
        )
    }
}

fn cfg_source(error: &CfgValidationError) -> (&'static str, u32) {
    match error {
        CfgValidationError::Cfg(error) => (error.code().as_str(), error.code().numeric()),
        CfgValidationError::Type(error) => (error.code().as_str(), error.code().numeric()),
    }
}

fn effect_source(error: &EffectValidationError) -> (&'static str, u32) {
    match error {
        EffectValidationError::Effect(error) => (error.code().as_str(), error.code().numeric()),
        EffectValidationError::Cfg(error) => cfg_source(error),
        EffectValidationError::Type(error) => (error.code().as_str(), error.code().numeric()),
    }
}

fn stale_root_failure(symbol: &'static str) -> Failure {
    Failure::new(
        3,
        CandidateDecision::StaleRoot,
        symbol,
        None,
        DiagnosticRetryability::FreshBase,
    )
}

fn resource_failure(phase: u32, symbol: &'static str) -> Failure {
    Failure::new(
        phase,
        CandidateDecision::ResourceLimit,
        symbol,
        None,
        DiagnosticRetryability::HigherCeilings,
    )
}

fn candidate_result_from_candidate(error: CandidateError) -> CandidateValidationError {
    let result = match error {
        CandidateError::Scb(error) => CandidateResultError::Scb(error),
        _ => CandidateResultError::Scb(ScbError::new(ScbErrorCode::UnionInvalid)),
    };
    CandidateValidationError::Result(result)
}

#[cfg(test)]
mod tests {
    use sley_id::{
        CandidateNonce, ObjectId, PrincipalId, ReferenceAdapterId, TransactionId, ValueHash,
        WorkspaceId,
    };
    use sley_mutate::{
        BoundPrecondition, CandidateExpiry, CandidateRecord, EntityObjectRecord,
        ExactEntityVersion, ExpectedIdentityAbsent, ImportedCandidate, MutationOperation,
        MutationPayload, PreconditionPayload, PreimageRequirement, build_candidate,
        build_entity_object,
        value::{
            BlockBody, ConstantBody, ContractBody, DependencyBindingBody, EffectDefBody,
            EntityBodyValue, EntityIdSet, FunctionBody, NamespaceBody, OperationBody,
            ParameterBody, TestCaseBody, TypeDefBody,
        },
    };
    use sley_ssmc::{
        ConstData, ConstValue, ContractBinding, ContractKind, ContractSource, EffectEnvironment,
        ExpectedOutcome, Immediate, Opcode, OperationResultRef, ParameterRole, Reachability,
        ResourceLimits, ReturnTerminator, Terminator, TypeDefForm, TypeDefinition, TypeExpr,
        TypeParameterDef, ValueRef, Visibility,
    };
    use sley_state_root::{
        StateRootBuilder, conformance_epoch_id as state_epoch_id,
        conformance_registry as state_registry,
    };

    use crate::{
        CapabilityIssuerId, CapabilityKeyId, CapabilityResourceBudget, CapabilitySecret,
        CapabilityTokenNonce, CapabilityTokenRequest, PolicyResourceCeilings, PolicyRootBuilder,
        PrincipalGrantBuilder, conformance_registry as policy_registry, import_capability_token,
        issue_capability_token,
    };

    use super::*;

    const NOW: u64 = 1_000;

    fn fixed<T>(byte: u8, constructor: impl FnOnce([u8; 32]) -> T) -> T {
        constructor([byte; 32])
    }

    struct Fixture {
        workspace_id: WorkspaceId,
        transaction_id: TransactionId,
        principal_id: PrincipalId,
        base_objects: Vec<EntityObject>,
        base_state: AcceptedStateRoot,
        policy: AcceptedPolicyRoot,
        candidate: ImportedCandidate,
    }

    impl Fixture {
        fn valid() -> Self {
            Self::with_policy_options(true, false, None)
        }

        fn with_policy_options(
            allow_create: bool,
            protect_base: bool,
            required_contract: Option<EntityId>,
        ) -> Self {
            let workspace_id = fixed(1, WorkspaceId::from_bytes);
            let principal_id = fixed(2, PrincipalId::from_bytes);
            let transaction_id = fixed(3, TransactionId::from_bytes);
            let base_entity = fixed(10, EntityId::from_bytes);
            let mut grant = PrincipalGrantBuilder::new(PolicyResourceCeilings::new(
                1_000, 1_000, 1_000, 100, 100, 100,
            ))
            .mutation_class(MutationClass::ReplaceEntityVersion);
            if allow_create {
                grant = grant.mutation_class(MutationClass::CreateEntity);
            }
            let grant = grant.build().unwrap();
            let mut policy =
                PolicyRootBuilder::new(workspace_id).principal_grant(principal_id, grant);
            if protect_base {
                policy = policy.protected_entity(base_entity);
            }
            if let Some(required_contract) = required_contract {
                policy = policy.required_contract(required_contract);
            }
            let policy = policy.build(&policy_registry().unwrap()).unwrap();

            let schema_epoch_id = state_epoch_id().unwrap();
            let base_object = build_entity_object(
                schema_epoch_id,
                &EntityObjectRecord {
                    entity_id: base_entity,
                    body: EntityBodyValue::Namespace(NamespaceBody {
                        parent: None,
                        members: EntityIdSet::from_unsorted(vec![]).unwrap(),
                    }),
                    label: None,
                    semantic_fingerprint: None,
                },
            )
            .unwrap();
            let base_state = StateRootBuilder::new(
                workspace_id,
                fixed(20, ObjectId::from_bytes),
                fixed(21, ObjectId::from_bytes),
                policy.root(),
            )
            .entity_binding(base_entity, base_object.object_id())
            .build(&state_registry().unwrap())
            .unwrap();

            let nonce = fixed(30, CandidateNonce::from_bytes);
            let target = EntityId::derive(workspace_id, nonce, 3, 0);
            let summary = build_capability_summary_projection(
                principal_id,
                workspace_id,
                policy.root(),
                base_state.root,
                &[],
            )
            .unwrap();
            let candidate = build_candidate(&CandidateRecord {
                format_version: 1,
                workspace_id,
                base_transaction_id: transaction_id,
                base_root: base_state.root,
                schema_epoch_id,
                policy_root_id: policy.root(),
                principal_id,
                capability_summary_digest: summary.digest(),
                operations: vec![MutationOperation {
                    ordinal: 0,
                    class: MutationClass::CreateEntity,
                    target_kind: 3,
                    target_entity: target,
                    field_tag: None,
                    payload: MutationPayload::CreateEntity(EntityBodyValue::Namespace(
                        NamespaceBody {
                            parent: None,
                            members: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        },
                    )),
                    precondition_ordinal: 0,
                }],
                preconditions: vec![BoundPrecondition {
                    operation_ordinal: 0,
                    requirement: PreimageRequirement::ExpectedIdentityAbsent,
                    payload: PreconditionPayload::ExpectedIdentityAbsent(ExpectedIdentityAbsent {
                        entity_id: target,
                    }),
                }],
                validation_profile_id: full_validation_profile_id().unwrap(),
                candidate_nonce: nonce,
                expiry: CandidateExpiry::unix_millis(NOW + 1_000),
            })
            .unwrap();
            Self {
                workspace_id,
                transaction_id,
                principal_id,
                base_objects: vec![base_object],
                base_state,
                policy,
                candidate,
            }
        }

        fn context(&self) -> CandidateValidationContext<'_> {
            CandidateValidationContext::new(
                self.transaction_id,
                &self.base_state,
                &self.base_objects,
                &[],
                &self.policy,
                self.principal_id,
                &[],
                NOW,
                CandidateValidationLimits::full_v1(),
            )
            .unwrap()
        }

        fn create_candidate(
            &self,
            nonce_byte: u8,
            bodies: Vec<(u16, EntityBodyValue)>,
        ) -> ImportedCandidate {
            let nonce = fixed(nonce_byte, CandidateNonce::from_bytes);
            let mut operations = Vec::with_capacity(bodies.len());
            let mut preconditions = Vec::with_capacity(bodies.len());
            for (ordinal, (kind, body)) in bodies.into_iter().enumerate() {
                let ordinal = u32::try_from(ordinal).unwrap();
                let target = EntityId::derive(
                    self.workspace_id,
                    nonce,
                    u32::from(kind),
                    u64::from(ordinal),
                );
                operations.push(MutationOperation {
                    ordinal,
                    class: MutationClass::CreateEntity,
                    target_kind: kind,
                    target_entity: target,
                    field_tag: None,
                    payload: MutationPayload::CreateEntity(body),
                    precondition_ordinal: ordinal,
                });
                preconditions.push(BoundPrecondition {
                    operation_ordinal: ordinal,
                    requirement: PreimageRequirement::ExpectedIdentityAbsent,
                    payload: PreconditionPayload::ExpectedIdentityAbsent(ExpectedIdentityAbsent {
                        entity_id: target,
                    }),
                });
            }
            let mut record = self.candidate.record.clone();
            record.candidate_nonce = nonce;
            record.operations = operations;
            record.preconditions = preconditions;
            build_candidate(&record).unwrap()
        }

        fn created_id(&self, nonce_byte: u8, kind: u16, ordinal: u64) -> EntityId {
            EntityId::derive(
                self.workspace_id,
                fixed(nonce_byte, CandidateNonce::from_bytes),
                u32::from(kind),
                ordinal,
            )
        }

        fn context_with<'a>(
            &'a self,
            base_objects: &'a [EntityObject],
            tombstones: &'a [EntityId],
            limits: CandidateValidationLimits,
        ) -> CandidateValidationContext<'a> {
            CandidateValidationContext::new(
                self.transaction_id,
                &self.base_state,
                base_objects,
                tombstones,
                &self.policy,
                self.principal_id,
                &[],
                NOW,
                limits,
            )
            .unwrap()
        }
    }

    fn unit() -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Unit,
            data: ConstData::Unit,
        }
    }

    const fn zero_resources() -> ResourceLimits {
        ResourceLimits {
            fuel: 0,
            memory_bytes: 0,
            output_bytes: 0,
            effect_count: 0,
            call_depth: 0,
            wall_timeout_millis: 0,
        }
    }

    fn assert_terminal(
        output: &CandidateValidationOutput,
        decision: CandidateDecision,
        phase: u32,
        source_symbol: &str,
    ) {
        let record = &output.result().record;
        assert_eq!(record.decision, decision);
        assert_eq!(record.candidate_root, None);
        assert_eq!(record.diagnostics.len(), 1);
        assert_eq!(record.diagnostics[0].phase_tag, phase);
        assert_eq!(record.diagnostics[0].source_symbol, source_symbol);
        for prior in &record.phase_results[..usize::try_from(phase - 1).unwrap()] {
            assert_eq!(prior.outcome, PhaseOutcome::Passed);
            assert!(prior.evidence_digest.is_some());
        }
        let failed = &record.phase_results[usize::try_from(phase - 1).unwrap()];
        assert_eq!(failed.outcome, PhaseOutcome::Failed);
        assert_eq!(failed.terminal_decision, Some(decision));
        assert!(failed.evidence_digest.is_some());
        for later in &record.phase_results[usize::try_from(phase).unwrap()..] {
            assert_eq!(later.outcome, PhaseOutcome::NotRun);
            assert_eq!(later.evidence_digest, None);
            assert_eq!(later.terminal_decision, None);
        }
    }

    #[test]
    fn valid_candidate_runs_all_phases_deterministically_without_mutating_base() {
        let fixture = Fixture::valid();
        let state_before = fixture.base_state.clone();
        let objects_before = fixture.base_objects.clone();
        let candidate_before = fixture.candidate.clone();

        let first =
            validate_candidate_bytes(&fixture.context(), &fixture.candidate.stored_bytes).unwrap();
        let second =
            validate_candidate_bytes(&fixture.context(), &fixture.candidate.stored_bytes).unwrap();

        assert!(first.is_valid());
        assert_eq!(first, second);
        assert_eq!(first.result().record.decision, CandidateDecision::Valid);
        assert_eq!(
            first.result().record.candidate_id,
            Some(fixture.candidate.candidate_id)
        );
        assert!(first.result().record.candidate_root.is_some());
        assert_eq!(
            hex(first.result().candidate_result_id.as_bytes()),
            "16ad5d91483c8aae6439ca6bcb5c638d49bf8b82ba41cc0ab4f59783a05e08ec"
        );
        assert_eq!(first.result().record.phase_results.len(), 14);
        assert!(
            first
                .result()
                .record
                .phase_results
                .iter()
                .all(|phase| phase.outcome == PhaseOutcome::Passed
                    && phase.evidence_digest.is_some()
                    && phase.terminal_decision.is_none())
        );
        assert_eq!(fixture.base_state, state_before);
        assert_eq!(fixture.base_objects, objects_before);
        assert_eq!(fixture.candidate, candidate_before);
    }

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn canonical_frame_and_context_inventory_fail_monotonically() {
        let fixture = Fixture::valid();
        let malformed = validate_candidate_bytes(&fixture.context(), b"not-a-candidate").unwrap();
        assert_terminal(
            &malformed,
            CandidateDecision::InvalidEncoding,
            1,
            "SCB_LENGTH_OVERFLOW",
        );
        assert_eq!(malformed.result().record.candidate_id, None);
        assert!(malformed.result().record.affected_closure.is_empty());

        let empty_inventory = fixture.context_with(&[], &[], CandidateValidationLimits::full_v1());
        let incomplete =
            validate_candidate_bytes(&empty_inventory, &fixture.candidate.stored_bytes).unwrap();
        assert_terminal(
            &incomplete,
            CandidateDecision::InvalidSchema,
            2,
            "CANDIDATE_CONTEXT_INVENTORY_MISMATCH",
        );

        let mut corrupted_state = fixture.base_state.clone();
        corrupted_state.root = fixed(89, StateRoot::from_bytes);
        let corrupted_context = CandidateValidationContext::new(
            fixture.transaction_id,
            &corrupted_state,
            &fixture.base_objects,
            &[],
            &fixture.policy,
            fixture.principal_id,
            &[],
            NOW,
            CandidateValidationLimits::full_v1(),
        )
        .unwrap();
        let corrupted =
            validate_candidate_bytes(&corrupted_context, &fixture.candidate.stored_bytes).unwrap();
        assert_terminal(
            &corrupted,
            CandidateDecision::InvalidSchema,
            2,
            "CANDIDATE_CONTEXT_STATE_ROOT_MISMATCH",
        );
    }

    #[test]
    fn context_digest_binds_effective_not_requested_ceilings() {
        let fixture = Fixture::valid();
        let full = fixture.context();
        let wider = CandidateValidationLimits {
            max_operations: u32::MAX,
            max_preconditions: u32::MAX,
            max_candidate_bytes: u64::MAX,
            max_decoded_value_bytes: u64::MAX,
            max_graph_work: u64::MAX,
            max_selected_tests: u32::MAX,
            max_entities: u32::MAX,
            max_test_call_depth: u64::MAX,
            max_test_wall_timeout_millis: u64::MAX,
        };
        let clamped = fixture.context_with(&fixture.base_objects, &[], wider);
        assert_eq!(full.context_digest(), clamped.context_digest());
    }

    #[test]
    fn stale_root_and_exact_entity_preimage_are_distinct() {
        let fixture = Fixture::valid();

        let mut stale_root_record = fixture.candidate.record.clone();
        stale_root_record.base_root = fixed(90, StateRoot::from_bytes);
        let stale_root = build_candidate(&stale_root_record).unwrap();
        let output =
            validate_candidate_bytes(&fixture.context(), &stale_root.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::StaleRoot,
            3,
            "CANDIDATE_BASE_ROOT_MISMATCH",
        );

        let base = &fixture.base_objects[0];
        let mut stale_entity_record = fixture.candidate.record.clone();
        stale_entity_record.operations = vec![MutationOperation {
            ordinal: 0,
            class: MutationClass::ReplaceEntityVersion,
            target_kind: 3,
            target_entity: base.record().entity_id,
            field_tag: None,
            payload: MutationPayload::ReplaceEntityVersion(EntityBodyValue::Namespace(
                NamespaceBody {
                    parent: None,
                    members: EntityIdSet::from_unsorted(vec![]).unwrap(),
                },
            )),
            precondition_ordinal: 0,
        }];
        stale_entity_record.preconditions = vec![BoundPrecondition {
            operation_ordinal: 0,
            requirement: PreimageRequirement::ExactEntityVersion,
            payload: PreconditionPayload::ExactEntityVersion(ExactEntityVersion {
                entity_id: base.record().entity_id,
                object_id: fixed(91, ObjectId::from_bytes),
            }),
        }];
        let stale_entity = build_candidate(&stale_entity_record).unwrap();
        let output =
            validate_candidate_bytes(&fixture.context(), &stale_entity.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::StaleEntity,
            3,
            "CANDIDATE_APPLY_EXACT_PREIMAGE_MISMATCH",
        );
    }

    #[test]
    fn tombstones_graph_errors_and_missing_references_are_distinct() {
        let fixture = Fixture::valid();
        let target = fixture.candidate.record.operations[0].target_entity;
        let tombstones = [target];
        let collision_context = fixture.context_with(
            &fixture.base_objects,
            &tombstones,
            CandidateValidationLimits::full_v1(),
        );
        let collision =
            validate_candidate_bytes(&collision_context, &fixture.candidate.stored_bytes).unwrap();
        assert_terminal(
            &collision,
            CandidateDecision::InvalidIdentity,
            4,
            "CANDIDATE_IDENTITY_COLLISION",
        );

        let unresolved = fixture.create_candidate(
            40,
            vec![(
                3,
                EntityBodyValue::Namespace(NamespaceBody {
                    parent: Some(fixed(92, EntityId::from_bytes)),
                    members: EntityIdSet::from_unsorted(vec![]).unwrap(),
                }),
            )],
        );
        let output =
            validate_candidate_bytes(&fixture.context(), &unresolved.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::UnresolvedReference,
            5,
            "GRAPH_UNRESOLVED_REFERENCE",
        );

        let dependency = fixture.create_candidate(
            41,
            vec![(
                18,
                EntityBodyValue::DependencyBinding(DependencyBindingBody {
                    dependency_root: fixed(93, StateRoot::from_bytes),
                    external_package: fixed(94, EntityId::from_bytes),
                    local_namespace: fixture.base_objects[0].record().entity_id,
                }),
            )],
        );
        let output =
            validate_candidate_bytes(&fixture.context(), &dependency.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::InvalidGraph,
            5,
            "CANDIDATE_DEPENDENCY_ROOT_CHANGE_UNSUPPORTED",
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn type_cfg_and_effect_checkers_preserve_exact_source_codes() {
        let fixture = Fixture::valid();

        let type_error = fixture.create_candidate(
            50,
            vec![(
                4,
                EntityBodyValue::TypeDef(TypeDefBody {
                    type_parameters: vec![TypeParameterDef { ordinal: 1 }],
                    form: TypeDefForm::Record(vec![]),
                    invariants: EntityIdSet::from_unsorted(vec![]).unwrap(),
                    visibility: Visibility::Private,
                }),
            )],
        );
        let output =
            validate_candidate_bytes(&fixture.context(), &type_error.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::TypeError,
            6,
            "TYPE_PARAMETER_OUT_OF_SCOPE",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(21_002)
        );

        let function = fixture.created_id(51, 5, 0);
        let parameter = fixture.created_id(51, 6, 1);
        let block = fixture.created_id(51, 7, 2);
        let cfg_error = fixture.create_candidate(
            51,
            vec![
                (
                    5,
                    EntityBodyValue::Function(FunctionBody {
                        type_parameters: vec![],
                        parameters: vec![parameter],
                        result_type: TypeExpr::Bool,
                        effects: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        entry_block: block,
                        blocks: vec![block],
                        contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        visibility: Visibility::Private,
                    }),
                ),
                (
                    6,
                    EntityBodyValue::Parameter(ParameterBody {
                        owner: function,
                        role: ParameterRole::Function,
                        ordinal: 0,
                        value_type: TypeExpr::Unit,
                    }),
                ),
                (
                    7,
                    EntityBodyValue::Block(BlockBody {
                        function,
                        parameters: vec![],
                        operations: vec![],
                        terminator: Terminator::Return(ReturnTerminator {
                            value: ValueRef::Parameter(parameter),
                        }),
                        reachability: Reachability::Required,
                    }),
                ),
            ],
        );
        let output = validate_candidate_bytes(&fixture.context(), &cfg_error.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::ControlFlowError,
            7,
            "CFG_RETURN_TYPE",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(22_008)
        );

        let function = fixture.created_id(52, 5, 0);
        let parameter = fixture.created_id(52, 6, 1);
        let block = fixture.created_id(52, 7, 2);
        let effect = fixture.created_id(52, 11, 3);
        let effect_error = fixture.create_candidate(
            52,
            vec![
                (
                    5,
                    EntityBodyValue::Function(FunctionBody {
                        type_parameters: vec![],
                        parameters: vec![parameter],
                        result_type: TypeExpr::Unit,
                        effects: EntityIdSet::from_unsorted(vec![effect]).unwrap(),
                        entry_block: block,
                        blocks: vec![block],
                        contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        visibility: Visibility::Private,
                    }),
                ),
                (
                    6,
                    EntityBodyValue::Parameter(ParameterBody {
                        owner: function,
                        role: ParameterRole::Function,
                        ordinal: 0,
                        value_type: TypeExpr::Unit,
                    }),
                ),
                (
                    7,
                    EntityBodyValue::Block(BlockBody {
                        function,
                        parameters: vec![],
                        operations: vec![],
                        terminator: Terminator::Return(ReturnTerminator {
                            value: ValueRef::Parameter(parameter),
                        }),
                        reachability: Reachability::Required,
                    }),
                ),
                (
                    11,
                    EntityBodyValue::EffectDef(EffectDefBody {
                        effect_kind: EffectKind::StdoutWrite,
                        scope_type: TypeExpr::Unit,
                        request_type: TypeExpr::Unit,
                        response_type: TypeExpr::Unit,
                        failure_type: TypeExpr::Unit,
                        visibility: Visibility::Private,
                    }),
                ),
            ],
        );
        let output =
            validate_candidate_bytes(&fixture.context(), &effect_error.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::EffectError,
            8,
            "EFFECT_CLOSURE_MISMATCH",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(23_003)
        );
    }

    #[test]
    fn stale_semantic_fingerprint_claim_is_recomputed_and_rejected() {
        let fixture = Fixture::valid();
        let entity_id = fixed(10, EntityId::from_bytes);
        let schema_epoch_id = fixture.base_state.record.schema_epoch_id;
        let type_parameters = vec![];
        let form = TypeDefForm::Record(vec![]);
        let invariants = EntityIdSet::from_unsorted(vec![]).unwrap();
        let computed = sley_ssmc::fingerprint::fingerprint_type_definition(
            schema_epoch_id,
            &TypeDefinition {
                entity_id,
                type_parameters: type_parameters.clone(),
                form: form.clone(),
                invariants: invariants.as_slice().to_vec(),
                visibility: Visibility::Private,
            },
        )
        .unwrap();
        let base_object = build_entity_object(
            schema_epoch_id,
            &EntityObjectRecord {
                entity_id,
                body: EntityBodyValue::TypeDef(TypeDefBody {
                    type_parameters,
                    form,
                    invariants,
                    visibility: Visibility::Private,
                }),
                label: None,
                semantic_fingerprint: Some(computed),
            },
        )
        .unwrap();
        let base_state = StateRootBuilder::new(
            fixture.workspace_id,
            fixture.base_state.record.contract_root,
            fixture.base_state.record.test_root,
            fixture.policy.root(),
        )
        .entity_binding(entity_id, base_object.object_id())
        .build(&state_registry().unwrap())
        .unwrap();
        let summary = build_capability_summary_projection(
            fixture.principal_id,
            fixture.workspace_id,
            fixture.policy.root(),
            base_state.root,
            &[],
        )
        .unwrap();
        let mut record = fixture.candidate.record.clone();
        record.base_root = base_state.root;
        record.capability_summary_digest = summary.digest();
        record.operations = vec![MutationOperation {
            ordinal: 0,
            class: MutationClass::ReplaceEntityVersion,
            target_kind: 4,
            target_entity: entity_id,
            field_tag: None,
            payload: MutationPayload::ReplaceEntityVersion(EntityBodyValue::TypeDef(TypeDefBody {
                type_parameters: vec![],
                form: TypeDefForm::Record(vec![]),
                invariants: EntityIdSet::from_unsorted(vec![]).unwrap(),
                visibility: Visibility::Exported,
            })),
            precondition_ordinal: 0,
        }];
        record.preconditions = vec![BoundPrecondition {
            operation_ordinal: 0,
            requirement: PreimageRequirement::ExactEntityVersion,
            payload: PreconditionPayload::ExactEntityVersion(ExactEntityVersion {
                entity_id,
                object_id: base_object.object_id(),
            }),
        }];
        let candidate = build_candidate(&record).unwrap();
        let base_objects = [base_object];
        let context = CandidateValidationContext::new(
            fixture.transaction_id,
            &base_state,
            &base_objects,
            &[],
            &fixture.policy,
            fixture.principal_id,
            &[],
            NOW,
            CandidateValidationLimits::full_v1(),
        )
        .unwrap();

        let output = validate_candidate_bytes(&context, &candidate.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::TypeError,
            6,
            "FINGERPRINT_MISMATCH",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(25_004)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn policy_contract_and_test_plan_fail_at_their_owned_phases() {
        let fixture = Fixture::valid();

        let mut denied_record = fixture.candidate.record.clone();
        denied_record.principal_id = fixed(95, PrincipalId::from_bytes);
        let denied = build_candidate(&denied_record).unwrap();
        let output = validate_candidate_bytes(&fixture.context(), &denied.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::CapabilityDenied,
            9,
            "CAP_PRINCIPAL_MISMATCH",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(CapabilityErrorCode::PrincipalMismatch.numeric())
        );

        let function = fixture.created_id(60, 5, 0);
        let parameter = fixture.created_id(60, 6, 1);
        let block = fixture.created_id(60, 7, 2);
        let contract = fixture.created_id(60, 13, 3);
        let contract_error = fixture.create_candidate(
            60,
            vec![
                (
                    5,
                    EntityBodyValue::Function(FunctionBody {
                        type_parameters: vec![],
                        parameters: vec![parameter],
                        result_type: TypeExpr::Unit,
                        effects: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        entry_block: block,
                        blocks: vec![block],
                        contracts: EntityIdSet::from_unsorted(vec![contract]).unwrap(),
                        visibility: Visibility::Private,
                    }),
                ),
                (
                    6,
                    EntityBodyValue::Parameter(ParameterBody {
                        owner: function,
                        role: ParameterRole::Function,
                        ordinal: 0,
                        value_type: TypeExpr::Unit,
                    }),
                ),
                (
                    7,
                    EntityBodyValue::Block(BlockBody {
                        function,
                        parameters: vec![],
                        operations: vec![],
                        terminator: Terminator::Return(ReturnTerminator {
                            value: ValueRef::Parameter(parameter),
                        }),
                        reachability: Reachability::Required,
                    }),
                ),
                (
                    13,
                    EntityBodyValue::Contract(ContractBody {
                        target: function,
                        contract_kind: ContractKind::Precondition,
                        predicate: function,
                        bindings: vec![ContractBinding {
                            predicate_parameter: 0,
                            source: ContractSource::Parameter(parameter),
                        }],
                        resource_limits: None,
                    }),
                ),
            ],
        );
        let output =
            validate_candidate_bytes(&fixture.context(), &contract_error.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::ContractError,
            10,
            "CONTRACT_TARGET_INVALID",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(24_005)
        );

        let function = fixture.created_id(61, 5, 0);
        let parameter = fixture.created_id(61, 6, 1);
        let block = fixture.created_id(61, 7, 2);
        let test = fixture.create_candidate(
            61,
            vec![
                (
                    5,
                    EntityBodyValue::Function(FunctionBody {
                        type_parameters: vec![],
                        parameters: vec![parameter],
                        result_type: TypeExpr::Unit,
                        effects: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        entry_block: block,
                        blocks: vec![block],
                        contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        visibility: Visibility::Private,
                    }),
                ),
                (
                    6,
                    EntityBodyValue::Parameter(ParameterBody {
                        owner: function,
                        role: ParameterRole::Function,
                        ordinal: 0,
                        value_type: TypeExpr::Unit,
                    }),
                ),
                (
                    7,
                    EntityBodyValue::Block(BlockBody {
                        function,
                        parameters: vec![],
                        operations: vec![],
                        terminator: Terminator::Return(ReturnTerminator {
                            value: ValueRef::Parameter(parameter),
                        }),
                        reachability: Reachability::Required,
                    }),
                ),
                (
                    14,
                    EntityBodyValue::TestCase(TestCaseBody {
                        target: function,
                        inputs: vec![ConstValue {
                            value_type: TypeExpr::Bool,
                            data: ConstData::Bool(false),
                        }],
                        effect_environment: EffectEnvironment::Replay(vec![]),
                        expected: ExpectedOutcome::Value(unit()),
                        observations: vec![],
                        resource_limits: zero_resources(),
                    }),
                ),
            ],
        );
        let output = validate_candidate_bytes(&fixture.context(), &test.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::TestPlanError,
            11,
            "TEST_PLAN_INPUT_TYPE",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(24_011)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn expiry_summary_grants_isolation_and_mandatory_policy_are_enforced() {
        let fixture = Fixture::valid();

        let mut expired_record = fixture.candidate.record.clone();
        expired_record.expiry = CandidateExpiry::unix_millis(NOW);
        let expired = build_candidate(&expired_record).unwrap();
        let output = validate_candidate_bytes(&fixture.context(), &expired.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::StaleRoot,
            3,
            "CANDIDATE_EXPIRY_EXPIRED",
        );

        let mut summary_record = fixture.candidate.record.clone();
        summary_record.capability_summary_digest = fixed(96, CapabilitySummaryDigest::from_bytes);
        let summary_mismatch = build_candidate(&summary_record).unwrap();
        let output =
            validate_candidate_bytes(&fixture.context(), &summary_mismatch.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::CapabilityDenied,
            9,
            "CAPABILITY_SUMMARY_MISMATCH",
        );

        let denied_fixture = Fixture::with_policy_options(false, false, None);
        let output = validate_candidate_bytes(
            &denied_fixture.context(),
            &denied_fixture.candidate.stored_bytes,
        )
        .unwrap();
        assert_terminal(
            &output,
            CandidateDecision::CapabilityDenied,
            9,
            "POLICY_GRANT_DENIED",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(PolicyRootErrorCode::GrantDenied.numeric())
        );

        let protected_fixture = Fixture::with_policy_options(true, true, None);
        let base = &protected_fixture.base_objects[0];
        let mut replacement_record = protected_fixture.candidate.record.clone();
        replacement_record.operations = vec![MutationOperation {
            ordinal: 0,
            class: MutationClass::ReplaceEntityVersion,
            target_kind: 3,
            target_entity: base.record().entity_id,
            field_tag: None,
            payload: MutationPayload::ReplaceEntityVersion(EntityBodyValue::Namespace(
                NamespaceBody {
                    parent: Some(base.record().entity_id),
                    members: EntityIdSet::from_unsorted(vec![]).unwrap(),
                },
            )),
            precondition_ordinal: 0,
        }];
        replacement_record.preconditions = vec![BoundPrecondition {
            operation_ordinal: 0,
            requirement: PreimageRequirement::ExactEntityVersion,
            payload: PreconditionPayload::ExactEntityVersion(ExactEntityVersion {
                entity_id: base.record().entity_id,
                object_id: base.object_id(),
            }),
        }];
        let replacement = build_candidate(&replacement_record).unwrap();
        let output =
            validate_candidate_bytes(&protected_fixture.context(), &replacement.stored_bytes)
                .unwrap();
        assert_terminal(
            &output,
            CandidateDecision::CapabilityDenied,
            9,
            "POLICY_ISOLATION_PROTECTED_ENTITY_CHANGED",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(PolicyRootErrorCode::ProtectedEntityChanged.numeric())
        );

        let required_contract = fixed(97, EntityId::from_bytes);
        let mandatory_fixture = Fixture::with_policy_options(true, false, Some(required_contract));
        let output = validate_candidate_bytes(
            &mandatory_fixture.context(),
            &mandatory_fixture.candidate.stored_bytes,
        )
        .unwrap();
        assert_terminal(
            &output,
            CandidateDecision::TestPlanError,
            11,
            "POLICY_FINAL_REQUIRED_CONTRACT_MISSING",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(PolicyRootErrorCode::RequiredContractMissing.numeric())
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authenticated_capabilities_are_verified_without_ledger_mutation() {
        let fixture = Fixture::valid();
        let adapter_id = fixed(70, ReferenceAdapterId::from_bytes);
        let grant = PrincipalGrantBuilder::new(PolicyResourceCeilings::new(
            1_000, 1_000, 1_000, 100, 100, 100,
        ))
        .mutation_class(MutationClass::CreateEntity)
        .effect_kind(EffectKind::FileRead)
        .adapter_id(adapter_id)
        .build()
        .unwrap();
        let policy = PolicyRootBuilder::new(fixture.workspace_id)
            .principal_grant(fixture.principal_id, grant)
            .build(&policy_registry().unwrap())
            .unwrap();
        let base_state = StateRootBuilder::new(
            fixture.workspace_id,
            fixture.base_state.record.contract_root,
            fixture.base_state.record.test_root,
            policy.root(),
        )
        .entity_binding(
            fixture.base_objects[0].record().entity_id,
            fixture.base_objects[0].object_id(),
        )
        .build(&state_registry().unwrap())
        .unwrap();
        let trusted_key = CapabilityTrustedKey::new(
            fixed(71, CapabilityIssuerId::from_bytes),
            fixed(72, CapabilityKeyId::from_bytes),
            fixed(73, CapabilitySecret::from_bytes),
        );
        let token = issue_capability_token(
            &policy,
            &trusted_key,
            &CapabilityTokenRequest {
                principal_id: fixture.principal_id,
                workspace_id: fixture.workspace_id,
                state_root: base_state.root,
                effect_id: fixed(74, EntityId::from_bytes),
                effect_kind: EffectKind::FileRead,
                scope_hash: fixed(75, ValueHash::from_bytes),
                adapter_id,
                budget: CapabilityResourceBudget::new(1, 1, 1, 1, 1, 1),
                now_unix_millis: NOW - 1,
                expiry_unix_millis: NOW + 1_000,
                token_nonce: fixed(76, CapabilityTokenNonce::from_bytes),
            },
        )
        .unwrap();
        let summary = build_capability_summary_projection(
            fixture.principal_id,
            fixture.workspace_id,
            policy.root(),
            base_state.root,
            core::slice::from_ref(&token),
        )
        .unwrap();
        let mut record = fixture.candidate.record.clone();
        record.base_root = base_state.root;
        record.policy_root_id = policy.root();
        record.capability_summary_digest = summary.digest();
        let candidate = build_candidate(&record).unwrap();
        let capability = [TrustedCandidateCapability::new(&token, &trusted_key)];
        let context = CandidateValidationContext::new(
            fixture.transaction_id,
            &base_state,
            &fixture.base_objects,
            &[],
            &policy,
            fixture.principal_id,
            &capability,
            NOW,
            CandidateValidationLimits::full_v1(),
        )
        .unwrap();
        let key_before = trusted_key.clone();
        let token_before = token.clone();
        let output = validate_candidate_bytes(&context, &candidate.stored_bytes).unwrap();
        assert!(output.is_valid());
        assert_eq!(trusted_key, key_before);
        assert_eq!(token, token_before);

        let mut tampered_bytes = token.stored_bytes().to_vec();
        let last = tampered_bytes.last_mut().unwrap();
        *last ^= 1;
        let tampered = import_capability_token(&tampered_bytes).unwrap();
        assert_eq!(tampered.digest(), token.digest());
        let tampered_capability = [TrustedCandidateCapability::new(&tampered, &trusted_key)];
        let tampered_context = CandidateValidationContext::new(
            fixture.transaction_id,
            &base_state,
            &fixture.base_objects,
            &[],
            &policy,
            fixture.principal_id,
            &tampered_capability,
            NOW,
            CandidateValidationLimits::full_v1(),
        )
        .unwrap();
        assert_eq!(context.context_digest(), tampered_context.context_digest());
        let output = validate_candidate_bytes(&tampered_context, &candidate.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::CapabilityDenied,
            9,
            "CAP_AUTHENTICATOR_INVALID",
        );
        assert_eq!(
            output.result().record.diagnostics[0].source_numeric_code,
            Some(CapabilityErrorCode::AuthenticatorInvalid.numeric())
        );
    }

    #[test]
    fn resource_and_unsupported_operation_analysis_fail_closed() {
        let fixture = Fixture::valid();
        let mut limits = CandidateValidationLimits::full_v1();
        limits.max_decoded_value_bytes = 0;
        let context = fixture.context_with(&fixture.base_objects, &[], limits);
        let output = validate_candidate_bytes(&context, &fixture.candidate.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::ResourceLimit,
            12,
            "SCB_RESOURCE_LIMIT",
        );

        let function = fixture.created_id(62, 5, 0);
        let block = fixture.created_id(62, 7, 1);
        let constant = fixture.created_id(62, 9, 2);
        let operation = fixture.created_id(62, 8, 3);
        let unsupported = fixture.create_candidate(
            62,
            vec![
                (
                    5,
                    EntityBodyValue::Function(FunctionBody {
                        type_parameters: vec![],
                        parameters: vec![],
                        result_type: TypeExpr::Unit,
                        effects: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        entry_block: block,
                        blocks: vec![block],
                        contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
                        visibility: Visibility::Private,
                    }),
                ),
                (
                    7,
                    EntityBodyValue::Block(BlockBody {
                        function,
                        parameters: vec![],
                        operations: vec![operation],
                        terminator: Terminator::Return(ReturnTerminator {
                            value: ValueRef::OperationResult(OperationResultRef {
                                operation,
                                result_index: 0,
                            }),
                        }),
                        reachability: Reachability::Required,
                    }),
                ),
                (9, EntityBodyValue::Constant(ConstantBody { value: unit() })),
                (
                    8,
                    EntityBodyValue::Operation(OperationBody {
                        block,
                        ordinal: 0,
                        opcode: Opcode::ConstantRef.tag(),
                        operands: vec![],
                        result_types: vec![TypeExpr::Unit],
                        immediate: Immediate::Entity(constant),
                    }),
                ),
            ],
        );
        let output =
            validate_candidate_bytes(&fixture.context(), &unsupported.stored_bytes).unwrap();
        assert_terminal(
            &output,
            CandidateDecision::ResourceLimit,
            12,
            "CANDIDATE_OPERATION_ANALYSIS_UNSUPPORTED",
        );
    }
}
