//! Canonical S20-360 candidate-result bytes and monotonic shape validation.
//!
//! Import proves only canonical bytes, the result digest, and internal record
//! shape. It does not rerun a validation phase, authenticate a context, grant
//! commit authority, or make imported evidence authoritative.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "crate-private encoder is reserved for validator-owned result construction"
    )
)]

use core::fmt;

use sley_id::{
    CandidateAttemptDigest, CandidateId, CandidateResultId, EntityId, StateRoot,
    ValidationProfileId,
};
use sley_mutate::full_validation_profile_id;
use sley_scb1::{
    MAX_STANDALONE_BYTES, ScbError, ScbErrorCode, ScbValueCursor, encode_list, encode_record,
    encode_text, encode_union, encode_uvar,
};

const RESULT_MAGIC: &[u8; 8] = b"SLEYCRS1";
const ATTEMPT_MAGIC: &[u8; 8] = b"SLEYATT1";
const RESULT_FORMAT_VERSION: u32 = 1;
const RESULT_ENVELOPE_VERSION: u64 = 1;
const RESULT_FIELD_COUNT: u64 = 13;
const PHASE_FIELD_COUNT: u64 = 4;
const DIAGNOSTIC_FIELD_COUNT: u64 = 6;
const PHASE_COUNT: usize = 14;
const MAX_DIAGNOSTICS: usize = 1_024;
const MAX_DIAGNOSTIC_SYMBOL_BYTES: usize = 96;
const MAX_RESULT_ENTITY_SET: usize = 65_535;
const PHASE_EVIDENCE_DOMAIN: &[u8] = b"sley2.candidate-phase-evidence.v1";
const VALIDATION_CONTEXT_DOMAIN: &[u8] = b"sley2.validation-context.v1";

macro_rules! evidence_digest_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs the digest wrapper from exact raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the exact raw digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

evidence_digest_type!(
    /// Digest of the validator-owned public context projection.
    ValidationContextDigest
);
evidence_digest_type!(
    /// Digest of one canonical validation-phase input/output projection.
    PhaseEvidenceDigest
);
evidence_digest_type!(
    /// Optional scrubbed causal digest carried by a diagnostic.
    DiagnosticCausalDigest
);

/// Closed candidate-result decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CandidateDecision {
    /// All fourteen phases passed.
    Valid,
    /// Candidate framing, canonical bytes, digest, or structural import failed.
    InvalidEncoding,
    /// Schema/profile/context-limit admission failed.
    InvalidSchema,
    /// Accepted transaction or root binding was stale.
    StaleRoot,
    /// An exact entity/container preimage was stale.
    StaleEntity,
    /// Deterministic identity or collision judgment failed.
    InvalidIdentity,
    /// Proposed graph structure was invalid.
    InvalidGraph,
    /// A semantic entity reference did not resolve.
    UnresolvedReference,
    /// Static type validation failed.
    TypeError,
    /// Control-flow validation failed.
    ControlFlowError,
    /// Static effect validation failed.
    EffectError,
    /// Protected capability or policy validation denied the candidate.
    CapabilityDenied,
    /// Contract validation failed.
    ContractError,
    /// A deterministic validation work ceiling was exhausted.
    ResourceLimit,
    /// Mandatory test planning failed.
    TestPlanError,
    /// A validator invariant failed closed.
    InternalError,
}

impl CandidateDecision {
    /// Returns the exact closed wire tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Valid => 1,
            Self::InvalidEncoding => 2,
            Self::InvalidSchema => 3,
            Self::StaleRoot => 4,
            Self::StaleEntity => 5,
            Self::InvalidIdentity => 6,
            Self::InvalidGraph => 7,
            Self::UnresolvedReference => 8,
            Self::TypeError => 9,
            Self::ControlFlowError => 10,
            Self::EffectError => 11,
            Self::CapabilityDenied => 12,
            Self::ContractError => 13,
            Self::ResourceLimit => 14,
            Self::TestPlanError => 15,
            Self::InternalError => 16,
        }
    }

    /// Returns a decision for one exact closed wire tag.
    #[must_use]
    pub const fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Valid),
            2 => Some(Self::InvalidEncoding),
            3 => Some(Self::InvalidSchema),
            4 => Some(Self::StaleRoot),
            5 => Some(Self::StaleEntity),
            6 => Some(Self::InvalidIdentity),
            7 => Some(Self::InvalidGraph),
            8 => Some(Self::UnresolvedReference),
            9 => Some(Self::TypeError),
            10 => Some(Self::ControlFlowError),
            11 => Some(Self::EffectError),
            12 => Some(Self::CapabilityDenied),
            13 => Some(Self::ContractError),
            14 => Some(Self::ResourceLimit),
            15 => Some(Self::TestPlanError),
            16 => Some(Self::InternalError),
            _ => None,
        }
    }

    /// Returns the frozen S20-360 outer diagnostic code.
    #[must_use]
    pub const fn numeric_code(self) -> Option<u32> {
        match self {
            Self::Valid => None,
            Self::InvalidEncoding => Some(36_000),
            Self::InvalidSchema => Some(36_001),
            Self::StaleRoot => Some(36_002),
            Self::StaleEntity => Some(36_003),
            Self::InvalidIdentity => Some(36_004),
            Self::InvalidGraph => Some(36_005),
            Self::UnresolvedReference => Some(36_006),
            Self::TypeError => Some(36_007),
            Self::ControlFlowError => Some(36_008),
            Self::EffectError => Some(36_009),
            Self::CapabilityDenied => Some(36_010),
            Self::ContractError => Some(36_011),
            Self::ResourceLimit => Some(36_012),
            Self::TestPlanError => Some(36_013),
            Self::InternalError => Some(36_014),
        }
    }

    /// Returns the exact stable result symbol.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Valid => "CANDIDATE_VALIDATION_VALID",
            Self::InvalidEncoding => "CANDIDATE_VALIDATION_INVALID_ENCODING",
            Self::InvalidSchema => "CANDIDATE_VALIDATION_INVALID_SCHEMA",
            Self::StaleRoot => "CANDIDATE_VALIDATION_STALE_ROOT",
            Self::StaleEntity => "CANDIDATE_VALIDATION_STALE_ENTITY",
            Self::InvalidIdentity => "CANDIDATE_VALIDATION_INVALID_IDENTITY",
            Self::InvalidGraph => "CANDIDATE_VALIDATION_INVALID_GRAPH",
            Self::UnresolvedReference => "CANDIDATE_VALIDATION_UNRESOLVED_REFERENCE",
            Self::TypeError => "CANDIDATE_VALIDATION_TYPE_ERROR",
            Self::ControlFlowError => "CANDIDATE_VALIDATION_CONTROL_FLOW_ERROR",
            Self::EffectError => "CANDIDATE_VALIDATION_EFFECT_ERROR",
            Self::CapabilityDenied => "CANDIDATE_VALIDATION_CAPABILITY_DENIED",
            Self::ContractError => "CANDIDATE_VALIDATION_CONTRACT_ERROR",
            Self::ResourceLimit => "CANDIDATE_VALIDATION_RESOURCE_LIMIT",
            Self::TestPlanError => "CANDIDATE_VALIDATION_TEST_PLAN_ERROR",
            Self::InternalError => "CANDIDATE_VALIDATION_INTERNAL_ERROR",
        }
    }

    const fn fixed_failed_phase(self) -> Option<u32> {
        match self {
            Self::Valid | Self::ResourceLimit | Self::InternalError => None,
            Self::InvalidEncoding => Some(1),
            Self::InvalidSchema => Some(2),
            Self::StaleRoot | Self::StaleEntity => Some(3),
            Self::InvalidIdentity => Some(4),
            Self::InvalidGraph | Self::UnresolvedReference => Some(5),
            Self::TypeError => Some(6),
            Self::ControlFlowError => Some(7),
            Self::EffectError => Some(8),
            Self::CapabilityDenied => Some(9),
            Self::ContractError => Some(10),
            Self::TestPlanError => Some(11),
        }
    }
}

/// Closed validation-phase outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PhaseOutcome {
    /// The phase ran and passed.
    Passed,
    /// The phase ran and terminally failed.
    Failed,
    /// The phase did not run after an earlier terminal failure.
    NotRun,
}

impl PhaseOutcome {
    const fn tag(self) -> u32 {
        match self {
            Self::Passed => 1,
            Self::Failed => 2,
            Self::NotRun => 3,
        }
    }

    const fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Passed),
            2 => Some(Self::Failed),
            3 => Some(Self::NotRun),
            _ => None,
        }
    }
}

/// One exact phase result in the mandatory fourteen-phase sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePhaseResult {
    /// Exact phase tag `1..=14`.
    pub phase_tag: u32,
    /// Closed phase outcome.
    pub outcome: PhaseOutcome,
    /// Validator-derived evidence; absent only for `NotRun`.
    pub evidence_digest: Option<PhaseEvidenceDigest>,
    /// Outer terminal decision; present only for the one failed phase.
    pub terminal_decision: Option<CandidateDecision>,
}

/// Closed diagnostic retry classification.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DiagnosticRetryability {
    /// Repeating unchanged inputs cannot succeed.
    Permanent,
    /// A freshly accepted base/root may resolve the failure.
    FreshBase,
    /// Fresh policy, capability, or principal authority may resolve the failure.
    FreshAuthority,
    /// Narrowly higher allowed validation ceilings may resolve the failure.
    HigherCeilings,
    /// Validator repair/restart is required before retry.
    InternalRepair,
}

impl DiagnosticRetryability {
    const fn tag(self) -> u32 {
        match self {
            Self::Permanent => 1,
            Self::FreshBase => 2,
            Self::FreshAuthority => 3,
            Self::HigherCeilings => 4,
            Self::InternalRepair => 5,
        }
    }

    const fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Permanent),
            2 => Some(Self::FreshBase),
            3 => Some(Self::FreshAuthority),
            4 => Some(Self::HigherCeilings),
            5 => Some(Self::InternalRepair),
            _ => None,
        }
    }
}

/// One bounded machine diagnostic for the terminal validation phase.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CandidateDiagnostic {
    /// Terminal phase tag.
    pub phase_tag: u32,
    /// Frozen S20-360 outer result code.
    pub result_code: u32,
    /// Optional preserved numeric code from the owning lower-layer checker.
    pub source_numeric_code: Option<u32>,
    /// Exact bounded ASCII source symbol, never free-form host text.
    pub source_symbol: String,
    /// Closed retry classification.
    pub retryability: DiagnosticRetryability,
    /// Optional scrubbed causal digest.
    pub causal_digest: Option<DiagnosticCausalDigest>,
}

/// Exact thirteen-field candidate-result record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateResultRecord {
    /// Must be exactly one.
    pub format_version: u32,
    /// Causal identity of the raw candidate-byte attempt.
    pub candidate_attempt_digest: CandidateAttemptDigest,
    /// Verified candidate identity, absent only for invalid encoding.
    pub candidate_id: Option<CandidateId>,
    /// Exact full-v1 validation profile.
    pub validation_profile_id: ValidationProfileId,
    /// Validator-owned public context projection digest.
    pub validation_context_digest: ValidationContextDigest,
    /// Closed outer decision.
    pub decision: CandidateDecision,
    /// Exact fourteen monotonic phase records.
    pub phase_results: Vec<CandidatePhaseResult>,
    /// Bounded deterministic terminal diagnostics.
    /// Element zero is the canonical primary diagnostic when nonempty.
    pub diagnostics: Vec<CandidateDiagnostic>,
    /// Raw-ID-sorted affected semantic closure.
    pub affected_closure: Vec<EntityId>,
    /// Raw-ID-sorted required capability-requirement identities.
    pub required_capabilities: Vec<EntityId>,
    /// Raw-ID-sorted validator-selected test identities.
    pub selected_tests: Vec<EntityId>,
    /// Candidate semantic root, present exactly for `Valid`.
    pub candidate_root: Option<StateRoot>,
    /// Explicit trusted validation time in Unix milliseconds.
    pub validated_at_unix_millis: u64,
}

/// Canonical imported result bytes with a verified trailer.
///
/// This type is intentionally not proof that validation ran. Commit logic must
/// consume a validator-owned result and independently perform S20-390 rechecks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedCandidateResult {
    /// Strictly decoded shape-checked record.
    pub record: CandidateResultRecord,
    /// Exact digest of the result preimage.
    pub candidate_result_id: CandidateResultId,
    /// Exact result preimage without its digest trailer.
    pub preimage: Vec<u8>,
    /// Exact canonical stored bytes including the trailer.
    pub stored_bytes: Vec<u8>,
}

/// Stable semantic result-codec failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateResultErrorCode {
    /// `CANDIDATE_RESULT_FORMAT_VERSION`
    FormatVersion,
    /// `CANDIDATE_RESULT_PROFILE_INVALID`
    ProfileInvalid,
    /// `CANDIDATE_RESULT_PHASE_SHAPE`
    PhaseShape,
    /// `CANDIDATE_RESULT_DECISION_PHASE_MISMATCH`
    DecisionPhaseMismatch,
    /// `CANDIDATE_RESULT_DIAGNOSTIC_INVALID`
    DiagnosticInvalid,
    /// `CANDIDATE_RESULT_SET_INVALID`
    SetInvalid,
    /// `CANDIDATE_RESULT_CANDIDATE_ID_SHAPE`
    CandidateIdShape,
    /// `CANDIDATE_RESULT_ROOT_SHAPE`
    RootShape,
}

impl CandidateResultErrorCode {
    /// Returns the exact stable symbol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FormatVersion => "CANDIDATE_RESULT_FORMAT_VERSION",
            Self::ProfileInvalid => "CANDIDATE_RESULT_PROFILE_INVALID",
            Self::PhaseShape => "CANDIDATE_RESULT_PHASE_SHAPE",
            Self::DecisionPhaseMismatch => "CANDIDATE_RESULT_DECISION_PHASE_MISMATCH",
            Self::DiagnosticInvalid => "CANDIDATE_RESULT_DIAGNOSTIC_INVALID",
            Self::SetInvalid => "CANDIDATE_RESULT_SET_INVALID",
            Self::CandidateIdShape => "CANDIDATE_RESULT_CANDIDATE_ID_SHAPE",
            Self::RootShape => "CANDIDATE_RESULT_ROOT_SHAPE",
        }
    }

    /// Returns the frozen result-integrity numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::FormatVersion => 36_100,
            Self::ProfileInvalid => 36_101,
            Self::PhaseShape => 36_102,
            Self::DecisionPhaseMismatch => 36_103,
            Self::DiagnosticInvalid => 36_104,
            Self::SetInvalid => 36_105,
            Self::CandidateIdShape => 36_106,
            Self::RootShape => 36_107,
        }
    }
}

/// Exact canonical or semantic candidate-result failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateResultError {
    /// Strict SCB1 syntax, canonicality, digest, or resource failure.
    Scb(ScbError),
    /// Result record shape violated the frozen S20-360 contract.
    Result(CandidateResultErrorCode),
}

impl CandidateResultError {
    /// Returns the exact stable source symbol.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Scb(error) => error.code().as_str(),
            Self::Result(code) => code.as_str(),
        }
    }

    /// Returns a result-integrity numeric code while preserving SCB1's
    /// independent namespace.
    #[must_use]
    pub const fn numeric_code(&self) -> Option<u32> {
        match self {
            Self::Scb(_) => None,
            Self::Result(code) => Some(code.numeric()),
        }
    }
}

impl fmt::Display for CandidateResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CandidateResultError {}

impl From<ScbError> for CandidateResultError {
    fn from(value: ScbError) -> Self {
        Self::Scb(value)
    }
}

/// Derives the causal digest for one raw candidate-byte validation attempt.
///
/// # Errors
///
/// Returns `SCB_RESOURCE_LIMIT` only when the host cannot represent the slice
/// length as the frozen unsigned 64-bit length field.
pub fn candidate_attempt_digest(
    stored_candidate_bytes: &[u8],
) -> Result<CandidateAttemptDigest, CandidateResultError> {
    let mut preimage = Vec::with_capacity(ATTEMPT_MAGIC.len() + 8 + stored_candidate_bytes.len());
    preimage.extend_from_slice(ATTEMPT_MAGIC);
    let length = u64::try_from(stored_candidate_bytes.len())
        .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    preimage.extend_from_slice(&length.to_be_bytes());
    preimage.extend_from_slice(stored_candidate_bytes);
    Ok(CandidateAttemptDigest::derive(&preimage))
}

/// Derives one phase-evidence digest from exact canonical input/output bytes.
///
/// # Errors
///
/// Returns `SCB_RESOURCE_LIMIT` when the evidence projection exceeds the
/// frozen standalone byte ceiling.
pub fn phase_evidence_digest(
    phase_tag: u32,
    canonical_phase_input_output: &[u8],
) -> Result<PhaseEvidenceDigest, CandidateResultError> {
    if canonical_phase_input_output.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit).into());
    }
    let length = u64::try_from(canonical_phase_input_output.len())
        .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PHASE_EVIDENCE_DOMAIN);
    hasher.update(&phase_tag.to_be_bytes());
    hasher.update(&encode_uvar(length));
    hasher.update(canonical_phase_input_output);
    Ok(PhaseEvidenceDigest::from_bytes(
        *hasher.finalize().as_bytes(),
    ))
}

/// Derives the validation-context digest from its canonical public projection.
///
/// Secrets, authenticators, handles, paths, and raw capability-token bytes are
/// forbidden from the caller-owned canonical projection.
///
/// # Errors
///
/// Returns `SCB_RESOURCE_LIMIT` when the projection exceeds the frozen byte
/// ceiling.
pub fn validation_context_digest(
    canonical_public_projection: &[u8],
) -> Result<ValidationContextDigest, CandidateResultError> {
    if canonical_public_projection.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit).into());
    }
    let length = u64::try_from(canonical_public_projection.len())
        .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(VALIDATION_CONTEXT_DOMAIN);
    hasher.update(&length.to_be_bytes());
    hasher.update(canonical_public_projection);
    Ok(ValidationContextDigest::from_bytes(
        *hasher.finalize().as_bytes(),
    ))
}

/// Imports canonical candidate-result bytes and validates monotonic shape.
///
/// Import is intentionally non-authoritative and never reruns validation.
///
/// # Errors
///
/// Returns the first strict envelope, digest, record, or semantic-shape error.
pub fn import_candidate_result(
    input: &[u8],
) -> Result<ImportedCandidateResult, CandidateResultError> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit).into());
    }
    if input.len() < 32 {
        return Err(ScbError::new(ScbErrorCode::LengthOverflow).into());
    }
    let (preimage, trailer) = input.split_at(input.len() - 32);
    let mut cursor = ScbValueCursor::new(preimage)?;
    if cursor.read_exact_bytes(RESULT_MAGIC.len())? != RESULT_MAGIC {
        return Err(ScbError::new(ScbErrorCode::MagicInvalid).into());
    }
    if cursor.read_uvar(64)? != RESULT_ENVELOPE_VERSION {
        return Err(ScbError::new(ScbErrorCode::VersionUnsupported).into());
    }
    let payload = cursor.read_sized_payload()?;
    cursor.check_finished()?;
    let candidate_result_id = CandidateResultId::derive(preimage);
    if trailer != candidate_result_id.as_bytes() {
        return Err(ScbError::new(ScbErrorCode::DigestMismatch).into());
    }
    let record = decode_result_record(payload)?;
    validate_result_record(&record)?;
    Ok(ImportedCandidateResult {
        record,
        candidate_result_id,
        preimage: preimage.to_vec(),
        stored_bytes: input.to_vec(),
    })
}

pub(crate) fn build_candidate_result(
    record: &CandidateResultRecord,
) -> Result<ImportedCandidateResult, CandidateResultError> {
    validate_result_record(record)?;
    let payload = encode_result_record(record)?;
    let mut preimage = Vec::with_capacity(RESULT_MAGIC.len() + 12 + payload.len());
    preimage.extend_from_slice(RESULT_MAGIC);
    preimage.extend_from_slice(&encode_uvar(RESULT_ENVELOPE_VERSION));
    preimage.extend_from_slice(&encode_uvar(
        u64::try_from(payload.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?,
    ));
    preimage.extend_from_slice(&payload);
    let candidate_result_id = CandidateResultId::derive(&preimage);
    let mut stored_bytes = preimage.clone();
    stored_bytes.extend_from_slice(candidate_result_id.as_bytes());
    if stored_bytes.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit).into());
    }
    Ok(ImportedCandidateResult {
        record: record.clone(),
        candidate_result_id,
        preimage,
        stored_bytes,
    })
}

/// Encodes the validator-owned phase-14 final-result core without creating a
/// self-hash cycle.
///
/// The caller supplies a draft valid record whose first thirteen phases are
/// complete and whose phase-14 record is `Passed` with no evidence or terminal
/// decision. This helper encodes result fields 1 through 6 and 8 through 13,
/// plus full phase records 1 through 13 and the phase-14 tag/outcome only.
pub(crate) fn encode_phase14_result_core(
    record: &CandidateResultRecord,
) -> Result<Vec<u8>, CandidateResultError> {
    if record.decision != CandidateDecision::Valid
        || record.phase_results.len() != PHASE_COUNT
        || record.phase_results[..13].iter().any(|phase| {
            phase.outcome != PhaseOutcome::Passed
                || phase.evidence_digest.is_none()
                || phase.terminal_decision.is_some()
        })
        || record.phase_results[13].phase_tag != 14
        || record.phase_results[13].outcome != PhaseOutcome::Passed
        || record.phase_results[13].evidence_digest.is_some()
        || record.phase_results[13].terminal_decision.is_some()
    {
        return Err(result_error(CandidateResultErrorCode::PhaseShape));
    }

    let mut phase_results = record.phase_results[..13]
        .iter()
        .map(encode_phase_result)
        .collect::<Result<Vec<_>, _>>()?;
    phase_results.push(encode_record(&[
        (1, encode_uvar(14)),
        (2, encode_uvar(u64::from(PhaseOutcome::Passed.tag()))),
    ])?);
    let diagnostics = record
        .diagnostics
        .iter()
        .map(encode_diagnostic)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(encode_record(&[
        (1, encode_uvar(u64::from(record.format_version))),
        (2, record.candidate_attempt_digest.as_bytes().to_vec()),
        (
            3,
            encode_option_fixed(record.candidate_id.as_ref().map(CandidateId::as_bytes))?,
        ),
        (4, record.validation_profile_id.as_bytes().to_vec()),
        (5, record.validation_context_digest.as_bytes().to_vec()),
        (6, encode_uvar(u64::from(record.decision.tag()))),
        (7, encode_list(&phase_results)?),
        (8, encode_list(&diagnostics)?),
        (9, encode_entity_set(&record.affected_closure)?),
        (10, encode_entity_set(&record.required_capabilities)?),
        (11, encode_entity_set(&record.selected_tests)?),
        (
            12,
            encode_option_fixed(record.candidate_root.as_ref().map(StateRoot::as_bytes))?,
        ),
        (13, encode_uvar(record.validated_at_unix_millis)),
    ])?)
}

fn encode_result_record(record: &CandidateResultRecord) -> Result<Vec<u8>, ScbError> {
    let phase_results = record
        .phase_results
        .iter()
        .map(encode_phase_result)
        .collect::<Result<Vec<_>, _>>()?;
    let diagnostics = record
        .diagnostics
        .iter()
        .map(encode_diagnostic)
        .collect::<Result<Vec<_>, _>>()?;
    encode_record(&[
        (1, encode_uvar(u64::from(record.format_version))),
        (2, record.candidate_attempt_digest.as_bytes().to_vec()),
        (
            3,
            encode_option_fixed(record.candidate_id.as_ref().map(CandidateId::as_bytes))?,
        ),
        (4, record.validation_profile_id.as_bytes().to_vec()),
        (5, record.validation_context_digest.as_bytes().to_vec()),
        (6, encode_uvar(u64::from(record.decision.tag()))),
        (7, encode_list(&phase_results)?),
        (8, encode_list(&diagnostics)?),
        (9, encode_entity_set(&record.affected_closure)?),
        (10, encode_entity_set(&record.required_capabilities)?),
        (11, encode_entity_set(&record.selected_tests)?),
        (
            12,
            encode_option_fixed(record.candidate_root.as_ref().map(StateRoot::as_bytes))?,
        ),
        (13, encode_uvar(record.validated_at_unix_millis)),
    ])
}

fn encode_phase_result(phase: &CandidatePhaseResult) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(u64::from(phase.phase_tag))),
        (2, encode_uvar(u64::from(phase.outcome.tag()))),
        (
            3,
            encode_option_fixed(
                phase
                    .evidence_digest
                    .as_ref()
                    .map(PhaseEvidenceDigest::as_bytes),
            )?,
        ),
        (
            4,
            encode_option_u32(phase.terminal_decision.map(CandidateDecision::tag))?,
        ),
    ])
}

fn encode_diagnostic(diagnostic: &CandidateDiagnostic) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(u64::from(diagnostic.phase_tag))),
        (2, encode_uvar(u64::from(diagnostic.result_code))),
        (3, encode_option_u32(diagnostic.source_numeric_code)?),
        (4, encode_text(&diagnostic.source_symbol)?),
        (5, encode_uvar(u64::from(diagnostic.retryability.tag()))),
        (
            6,
            encode_option_fixed(
                diagnostic
                    .causal_digest
                    .as_ref()
                    .map(DiagnosticCausalDigest::as_bytes),
            )?,
        ),
    ])
}

fn encode_entity_set(values: &[EntityId]) -> Result<Vec<u8>, ScbError> {
    encode_list(
        &values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
}

fn encode_option_fixed(value: Option<&[u8; 32]>) -> Result<Vec<u8>, ScbError> {
    match value {
        None => encode_union(0, &[]),
        Some(bytes) => encode_union(1, bytes),
    }
}

fn encode_option_u32(value: Option<u32>) -> Result<Vec<u8>, ScbError> {
    match value {
        None => encode_union(0, &[]),
        Some(value) => encode_union(1, &encode_uvar(u64::from(value))),
    }
}

fn decode_result_record(input: &[u8]) -> Result<CandidateResultRecord, CandidateResultError> {
    let fields = decode_required_record(input, RESULT_FIELD_COUNT)?;
    Ok(CandidateResultRecord {
        format_version: read_complete_u32(fields[0])?,
        candidate_attempt_digest: CandidateAttemptDigest::from_bytes(read_fixed(fields[1])?),
        candidate_id: decode_option_fixed(fields[2])?.map(CandidateId::from_bytes),
        validation_profile_id: ValidationProfileId::from_bytes(read_fixed(fields[3])?),
        validation_context_digest: ValidationContextDigest::from_bytes(read_fixed(fields[4])?),
        decision: CandidateDecision::from_tag(read_complete_u32(fields[5])?)
            .ok_or_else(union_invalid)?,
        phase_results: decode_phase_results(fields[6])?,
        diagnostics: decode_diagnostics(fields[7])?,
        affected_closure: decode_entity_set(fields[8])?,
        required_capabilities: decode_entity_set(fields[9])?,
        selected_tests: decode_entity_set(fields[10])?,
        candidate_root: decode_option_fixed(fields[11])?.map(StateRoot::from_bytes),
        validated_at_unix_millis: read_complete_u64(fields[12])?,
    })
}

fn decode_phase_results(input: &[u8]) -> Result<Vec<CandidatePhaseResult>, CandidateResultError> {
    let elements = decode_list_payloads(input, PHASE_COUNT)?;
    elements
        .into_iter()
        .map(|element| {
            let fields = decode_required_record(element, PHASE_FIELD_COUNT)?;
            Ok(CandidatePhaseResult {
                phase_tag: read_complete_u32(fields[0])?,
                outcome: PhaseOutcome::from_tag(read_complete_u32(fields[1])?)
                    .ok_or_else(union_invalid)?,
                evidence_digest: decode_option_fixed(fields[2])?
                    .map(PhaseEvidenceDigest::from_bytes),
                terminal_decision: decode_option_u32(fields[3])?
                    .map(|tag| CandidateDecision::from_tag(tag).ok_or_else(union_invalid))
                    .transpose()?,
            })
        })
        .collect()
}

fn decode_diagnostics(input: &[u8]) -> Result<Vec<CandidateDiagnostic>, CandidateResultError> {
    let elements = decode_list_payloads(input, MAX_DIAGNOSTICS)?;
    elements
        .into_iter()
        .map(|element| {
            let fields = decode_required_record(element, DIAGNOSTIC_FIELD_COUNT)?;
            Ok(CandidateDiagnostic {
                phase_tag: read_complete_u32(fields[0])?,
                result_code: read_complete_u32(fields[1])?,
                source_numeric_code: decode_option_u32(fields[2])?,
                source_symbol: read_complete_text(fields[3])?,
                retryability: DiagnosticRetryability::from_tag(read_complete_u32(fields[4])?)
                    .ok_or_else(union_invalid)?,
                causal_digest: decode_option_fixed(fields[5])?
                    .map(DiagnosticCausalDigest::from_bytes),
            })
        })
        .collect()
}

fn decode_entity_set(input: &[u8]) -> Result<Vec<EntityId>, CandidateResultError> {
    let values = decode_list_payloads(input, MAX_RESULT_ENTITY_SET)?;
    values
        .into_iter()
        .map(|value| read_fixed(value).map(EntityId::from_bytes))
        .collect()
}

fn decode_required_record(
    input: &[u8],
    expected_count: u64,
) -> Result<Vec<&[u8]>, CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let count = cursor.read_record_field_count()?;
    if count != expected_count {
        return Err(ScbError::new(if count < expected_count {
            ScbErrorCode::FieldMissing
        } else {
            ScbErrorCode::FieldUnknown
        })
        .into());
    }
    let mut fields = Vec::with_capacity(
        usize::try_from(expected_count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?,
    );
    for expected_tag in 1..=expected_count {
        let tag = cursor.read_uvar(32)?;
        if tag != expected_tag {
            return Err(ScbError::new(if tag < expected_tag {
                ScbErrorCode::FieldDuplicate
            } else {
                ScbErrorCode::FieldMissing
            })
            .into());
        }
        fields.push(cursor.read_sized_payload()?);
    }
    cursor.check_finished()?;
    Ok(fields)
}

fn decode_list_payloads(
    input: &[u8],
    max_count: usize,
) -> Result<Vec<&[u8]>, CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let count = usize::try_from(cursor.read_list_count()?)
        .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > max_count {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit).into());
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(cursor.read_sized_payload()?);
    }
    cursor.check_finished()?;
    Ok(values)
}

fn read_fixed(input: &[u8]) -> Result<[u8; 32], CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let bytes = cursor.read_fixed_bytes()?;
    cursor.check_finished()?;
    Ok(bytes)
}

fn read_complete_u32(input: &[u8]) -> Result<u32, CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = u32::try_from(cursor.read_uvar(32)?)
        .map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))?;
    cursor.check_finished()?;
    Ok(value)
}

fn read_complete_u64(input: &[u8]) -> Result<u64, CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = cursor.read_uvar(64)?;
    cursor.check_finished()?;
    Ok(value)
}

fn read_complete_text(input: &[u8]) -> Result<String, CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = cursor.read_text()?.to_owned();
    cursor.check_finished()?;
    Ok(value)
}

fn decode_option_fixed(input: &[u8]) -> Result<Option<[u8; 32]>, CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let (tag, payload) = cursor.read_union()?;
    cursor.check_finished()?;
    match tag {
        0 if payload.is_empty() => Ok(None),
        1 => read_fixed(payload).map(Some),
        _ => Err(union_invalid()),
    }
}

fn decode_option_u32(input: &[u8]) -> Result<Option<u32>, CandidateResultError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let (tag, payload) = cursor.read_union()?;
    cursor.check_finished()?;
    match tag {
        0 if payload.is_empty() => Ok(None),
        1 => read_complete_u32(payload).map(Some),
        _ => Err(union_invalid()),
    }
}

fn union_invalid() -> CandidateResultError {
    ScbError::new(ScbErrorCode::UnionInvalid).into()
}

fn result_error(code: CandidateResultErrorCode) -> CandidateResultError {
    CandidateResultError::Result(code)
}

fn validate_result_record(record: &CandidateResultRecord) -> Result<(), CandidateResultError> {
    if record.format_version != RESULT_FORMAT_VERSION {
        return Err(result_error(CandidateResultErrorCode::FormatVersion));
    }
    let expected_profile = full_validation_profile_id()
        .map_err(|_| result_error(CandidateResultErrorCode::ProfileInvalid))?;
    if record.validation_profile_id != expected_profile {
        return Err(result_error(CandidateResultErrorCode::ProfileInvalid));
    }
    validate_set(&record.affected_closure)?;
    validate_set(&record.required_capabilities)?;
    validate_set(&record.selected_tests)?;

    let failed_phase = validate_phases(record)?;
    validate_decision_phase(record.decision, failed_phase)?;

    if (record.candidate_id.is_none()) != (record.decision == CandidateDecision::InvalidEncoding) {
        return Err(result_error(CandidateResultErrorCode::CandidateIdShape));
    }
    if (record.candidate_root.is_some()) != (record.decision == CandidateDecision::Valid) {
        return Err(result_error(CandidateResultErrorCode::RootShape));
    }
    if record.decision == CandidateDecision::InvalidEncoding
        && (!record.affected_closure.is_empty()
            || !record.required_capabilities.is_empty()
            || !record.selected_tests.is_empty())
    {
        return Err(result_error(CandidateResultErrorCode::SetInvalid));
    }
    validate_diagnostics(record, failed_phase)
}

fn validate_set(values: &[EntityId]) -> Result<(), CandidateResultError> {
    if values.len() > MAX_RESULT_ENTITY_SET || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(result_error(CandidateResultErrorCode::SetInvalid))
    } else {
        Ok(())
    }
}

fn validate_phases(record: &CandidateResultRecord) -> Result<Option<u32>, CandidateResultError> {
    if record.phase_results.len() != PHASE_COUNT {
        return Err(result_error(CandidateResultErrorCode::PhaseShape));
    }
    let mut failed_phase = None;
    for (index, phase) in record.phase_results.iter().enumerate() {
        let expected_tag = u32::try_from(index + 1)
            .map_err(|_| result_error(CandidateResultErrorCode::PhaseShape))?;
        if phase.phase_tag != expected_tag {
            return Err(result_error(CandidateResultErrorCode::PhaseShape));
        }
        match phase.outcome {
            PhaseOutcome::Passed
                if failed_phase.is_none()
                    && phase.evidence_digest.is_some()
                    && phase.terminal_decision.is_none() => {}
            PhaseOutcome::Failed
                if failed_phase.is_none()
                    && phase.evidence_digest.is_some()
                    && phase.terminal_decision == Some(record.decision)
                    && record.decision != CandidateDecision::Valid =>
            {
                failed_phase = Some(phase.phase_tag);
            }
            PhaseOutcome::NotRun
                if failed_phase.is_some()
                    && phase.evidence_digest.is_none()
                    && phase.terminal_decision.is_none() => {}
            _ => return Err(result_error(CandidateResultErrorCode::PhaseShape)),
        }
    }
    if record.decision == CandidateDecision::Valid {
        if failed_phase.is_some() {
            return Err(result_error(CandidateResultErrorCode::PhaseShape));
        }
    } else if failed_phase.is_none() {
        return Err(result_error(CandidateResultErrorCode::PhaseShape));
    }
    Ok(failed_phase)
}

fn validate_decision_phase(
    decision: CandidateDecision,
    failed_phase: Option<u32>,
) -> Result<(), CandidateResultError> {
    if let Some(expected) = decision.fixed_failed_phase()
        && failed_phase != Some(expected)
    {
        return Err(result_error(
            CandidateResultErrorCode::DecisionPhaseMismatch,
        ));
    }
    if matches!(
        decision,
        CandidateDecision::ResourceLimit | CandidateDecision::InternalError
    ) && !matches!(failed_phase, Some(2..=14))
    {
        return Err(result_error(
            CandidateResultErrorCode::DecisionPhaseMismatch,
        ));
    }
    Ok(())
}

fn validate_diagnostics(
    record: &CandidateResultRecord,
    failed_phase: Option<u32>,
) -> Result<(), CandidateResultError> {
    if record.decision == CandidateDecision::Valid {
        return if record.diagnostics.is_empty() {
            Ok(())
        } else {
            Err(result_error(CandidateResultErrorCode::DiagnosticInvalid))
        };
    }
    if record.diagnostics.len() > MAX_DIAGNOSTICS
        || record.diagnostics.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(result_error(CandidateResultErrorCode::DiagnosticInvalid));
    }
    let expected_code = record
        .decision
        .numeric_code()
        .ok_or_else(|| result_error(CandidateResultErrorCode::DiagnosticInvalid))?;
    let primary = record
        .diagnostics
        .first()
        .ok_or_else(|| result_error(CandidateResultErrorCode::DiagnosticInvalid))?;
    validate_diagnostic(primary, failed_phase, expected_code)?;
    for diagnostic in &record.diagnostics[1..] {
        validate_diagnostic(diagnostic, failed_phase, expected_code)?;
    }
    Ok(())
}

fn validate_diagnostic(
    diagnostic: &CandidateDiagnostic,
    failed_phase: Option<u32>,
    expected_code: u32,
) -> Result<(), CandidateResultError> {
    if Some(diagnostic.phase_tag) != failed_phase
        || diagnostic.result_code != expected_code
        || !valid_source_symbol(&diagnostic.source_symbol)
    {
        return Err(result_error(CandidateResultErrorCode::DiagnosticInvalid));
    }
    Ok(())
}

fn valid_source_symbol(symbol: &str) -> bool {
    !symbol.is_empty()
        && symbol.len() <= MAX_DIAGNOSTIC_SYMBOL_BYTES
        && symbol.as_bytes()[0].is_ascii_uppercase()
        && symbol
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(phase: u32) -> PhaseEvidenceDigest {
        phase_evidence_digest(phase, &[u8::try_from(phase).unwrap()]).unwrap()
    }

    fn valid_record() -> CandidateResultRecord {
        CandidateResultRecord {
            format_version: 1,
            candidate_attempt_digest: candidate_attempt_digest(b"candidate").unwrap(),
            candidate_id: Some(CandidateId::from_bytes([2; 32])),
            validation_profile_id: full_validation_profile_id().unwrap(),
            validation_context_digest: validation_context_digest(b"context").unwrap(),
            decision: CandidateDecision::Valid,
            phase_results: (1..=14)
                .map(|phase_tag| CandidatePhaseResult {
                    phase_tag,
                    outcome: PhaseOutcome::Passed,
                    evidence_digest: Some(evidence(phase_tag)),
                    terminal_decision: None,
                })
                .collect(),
            diagnostics: vec![],
            affected_closure: vec![EntityId::from_bytes([1; 32])],
            required_capabilities: vec![EntityId::from_bytes([3; 32])],
            selected_tests: vec![EntityId::from_bytes([4; 32])],
            candidate_root: Some(StateRoot::from_bytes([5; 32])),
            validated_at_unix_millis: 99,
        }
    }

    fn invalid_record(decision: CandidateDecision, failed_phase: u32) -> CandidateResultRecord {
        let mut record = valid_record();
        record.decision = decision;
        record.candidate_root = None;
        if decision == CandidateDecision::InvalidEncoding {
            record.candidate_id = None;
            record.affected_closure.clear();
            record.required_capabilities.clear();
            record.selected_tests.clear();
        }
        record.phase_results = (1..=14)
            .map(|phase_tag| match phase_tag.cmp(&failed_phase) {
                core::cmp::Ordering::Less => CandidatePhaseResult {
                    phase_tag,
                    outcome: PhaseOutcome::Passed,
                    evidence_digest: Some(evidence(phase_tag)),
                    terminal_decision: None,
                },
                core::cmp::Ordering::Equal => CandidatePhaseResult {
                    phase_tag,
                    outcome: PhaseOutcome::Failed,
                    evidence_digest: Some(evidence(phase_tag)),
                    terminal_decision: Some(decision),
                },
                core::cmp::Ordering::Greater => CandidatePhaseResult {
                    phase_tag,
                    outcome: PhaseOutcome::NotRun,
                    evidence_digest: None,
                    terminal_decision: None,
                },
            })
            .collect();
        record.diagnostics = vec![CandidateDiagnostic {
            phase_tag: failed_phase,
            result_code: decision.numeric_code().unwrap(),
            source_numeric_code: None,
            source_symbol: decision.symbol().to_owned(),
            retryability: DiagnosticRetryability::Permanent,
            causal_digest: None,
        }];
        record
    }

    #[test]
    fn valid_result_round_trip_is_byte_identical_and_digest_bound() {
        let built = build_candidate_result(&valid_record()).unwrap();
        let imported = import_candidate_result(&built.stored_bytes).unwrap();
        assert_eq!(imported, built);
        assert_eq!(
            built.candidate_result_id,
            CandidateResultId::derive(&built.preimage)
        );
        assert!(built.stored_bytes.starts_with(RESULT_MAGIC));
    }

    #[test]
    fn every_terminal_decision_has_the_exact_first_failed_phase() {
        let decisions = [
            (CandidateDecision::InvalidEncoding, 1),
            (CandidateDecision::InvalidSchema, 2),
            (CandidateDecision::StaleRoot, 3),
            (CandidateDecision::StaleEntity, 3),
            (CandidateDecision::InvalidIdentity, 4),
            (CandidateDecision::InvalidGraph, 5),
            (CandidateDecision::UnresolvedReference, 5),
            (CandidateDecision::TypeError, 6),
            (CandidateDecision::ControlFlowError, 7),
            (CandidateDecision::EffectError, 8),
            (CandidateDecision::CapabilityDenied, 9),
            (CandidateDecision::ContractError, 10),
            (CandidateDecision::ResourceLimit, 12),
            (CandidateDecision::TestPlanError, 11),
            (CandidateDecision::InternalError, 14),
        ];
        for (decision, phase) in decisions {
            let built = build_candidate_result(&invalid_record(decision, phase)).unwrap();
            assert_eq!(import_candidate_result(&built.stored_bytes).unwrap(), built);
        }
    }

    #[test]
    #[ignore = "explicit conformance fixture refresh helper"]
    fn emit_candidate_result_vectors_for_fixture_refresh() {
        use core::fmt::Write as _;

        let decisions = [
            (CandidateDecision::InvalidEncoding, 1),
            (CandidateDecision::InvalidSchema, 2),
            (CandidateDecision::StaleRoot, 3),
            (CandidateDecision::StaleEntity, 3),
            (CandidateDecision::InvalidIdentity, 4),
            (CandidateDecision::InvalidGraph, 5),
            (CandidateDecision::UnresolvedReference, 5),
            (CandidateDecision::TypeError, 6),
            (CandidateDecision::ControlFlowError, 7),
            (CandidateDecision::EffectError, 8),
            (CandidateDecision::CapabilityDenied, 9),
            (CandidateDecision::ContractError, 10),
            (CandidateDecision::ResourceLimit, 12),
            (CandidateDecision::TestPlanError, 11),
            (CandidateDecision::InternalError, 14),
        ];
        let mut records = vec![("VALID", 0, build_candidate_result(&valid_record()).unwrap())];
        records.extend(decisions.into_iter().map(|(decision, phase)| {
            (
                decision.symbol(),
                phase,
                build_candidate_result(&invalid_record(decision, phase)).unwrap(),
            )
        }));
        for (decision, phase, result) in records {
            let mut stored = String::with_capacity(result.stored_bytes.len() * 2);
            for byte in &result.stored_bytes {
                write!(&mut stored, "{byte:02x}").expect("writing to String cannot fail");
            }
            let mut id = String::with_capacity(result.candidate_result_id.as_bytes().len() * 2);
            for byte in result.candidate_result_id.as_bytes() {
                write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
            }
            println!("VECTOR|{decision}|{phase}|{id}|{stored}");
        }
    }

    #[test]
    fn monotonicity_identity_root_diagnostic_and_sets_fail_closed() {
        let mut record = invalid_record(CandidateDecision::TypeError, 6);
        record.phase_results[7].outcome = PhaseOutcome::Passed;
        record.phase_results[7].evidence_digest = Some(evidence(8));
        assert_eq!(
            build_candidate_result(&record).unwrap_err(),
            result_error(CandidateResultErrorCode::PhaseShape)
        );

        let mut record = invalid_record(CandidateDecision::TypeError, 6);
        record.candidate_id = None;
        assert_eq!(
            build_candidate_result(&record).unwrap_err(),
            result_error(CandidateResultErrorCode::CandidateIdShape)
        );

        let mut record = invalid_record(CandidateDecision::TypeError, 6);
        record.candidate_root = Some(StateRoot::from_bytes([9; 32]));
        assert_eq!(
            build_candidate_result(&record).unwrap_err(),
            result_error(CandidateResultErrorCode::RootShape)
        );

        let mut record = invalid_record(CandidateDecision::TypeError, 6);
        record.diagnostics[0].source_symbol = "free form".to_owned();
        assert_eq!(
            build_candidate_result(&record).unwrap_err(),
            result_error(CandidateResultErrorCode::DiagnosticInvalid)
        );

        let mut record = valid_record();
        record.affected_closure = vec![EntityId::from_bytes([7; 32]); 2];
        assert_eq!(
            build_candidate_result(&record).unwrap_err(),
            result_error(CandidateResultErrorCode::SetInvalid)
        );
    }

    #[test]
    fn envelope_rejects_digest_trailing_and_unknown_nested_tags() {
        let built = build_candidate_result(&valid_record()).unwrap();
        let mut digest_tamper = built.stored_bytes.clone();
        *digest_tamper.last_mut().unwrap() ^= 1;
        assert_eq!(
            import_candidate_result(&digest_tamper).unwrap_err().code(),
            ScbErrorCode::DigestMismatch.as_str()
        );

        let mut trailing = built.stored_bytes.clone();
        trailing.push(0);
        assert_ne!(import_candidate_result(&trailing), Ok(built.clone()));

        let mut record = valid_record();
        record.phase_results[0].terminal_decision = Some(CandidateDecision::Valid);
        assert_eq!(
            build_candidate_result(&record).unwrap_err(),
            result_error(CandidateResultErrorCode::PhaseShape)
        );
    }

    #[test]
    fn evidence_derivations_bind_full_bytes_and_lengths() {
        assert_eq!(
            candidate_attempt_digest(b"candidate").unwrap().as_bytes(),
            &[
                0xb9, 0xdb, 0x84, 0x12, 0x04, 0x04, 0x3e, 0x7e, 0xc2, 0x4f, 0x39, 0xc6, 0x07, 0xbf,
                0x10, 0x93, 0xb0, 0x76, 0xf2, 0x82, 0x04, 0xa0, 0x31, 0x64, 0x62, 0xc4, 0xea, 0x86,
                0xb4, 0x77, 0xc5, 0x65,
            ]
        );
        assert_eq!(
            evidence(1).as_bytes(),
            &[
                0x26, 0xdc, 0xa4, 0x42, 0x2c, 0x00, 0xc3, 0x02, 0xc3, 0xd4, 0x34, 0x7a, 0x86, 0xd6,
                0xc8, 0xbe, 0x07, 0x1b, 0x84, 0x29, 0x7c, 0xc3, 0xdd, 0xc2, 0x4e, 0xaf, 0x47, 0x74,
                0xd9, 0x03, 0x14, 0xd3,
            ]
        );
        assert_eq!(
            validation_context_digest(b"context").unwrap().as_bytes(),
            &[
                0xbe, 0x32, 0xf6, 0xb9, 0xce, 0x86, 0x4b, 0xc9, 0x5d, 0xd1, 0x2a, 0xcd, 0x7a, 0xad,
                0x49, 0xaa, 0x83, 0xa0, 0x33, 0x10, 0xda, 0x20, 0x66, 0xa3, 0xb2, 0x97, 0x68, 0x27,
                0xad, 0x5b, 0x07, 0x6a,
            ]
        );
        assert_ne!(
            candidate_attempt_digest(b"a").unwrap(),
            candidate_attempt_digest(b"a\0").unwrap()
        );
        assert_ne!(
            phase_evidence_digest(1, b"a").unwrap(),
            phase_evidence_digest(1, b"b").unwrap()
        );
        assert_ne!(
            validation_context_digest(b"a").unwrap(),
            validation_context_digest(b"a\0").unwrap()
        );
    }

    #[test]
    fn result_integrity_codes_are_exact_and_scb_stays_separate() {
        let codes = [
            CandidateResultErrorCode::FormatVersion,
            CandidateResultErrorCode::ProfileInvalid,
            CandidateResultErrorCode::PhaseShape,
            CandidateResultErrorCode::DecisionPhaseMismatch,
            CandidateResultErrorCode::DiagnosticInvalid,
            CandidateResultErrorCode::SetInvalid,
            CandidateResultErrorCode::CandidateIdShape,
            CandidateResultErrorCode::RootShape,
        ];
        for (code, numeric) in codes.into_iter().zip(36_100..=36_107) {
            assert_eq!(code.numeric(), numeric);
            assert_eq!(
                CandidateResultError::Result(code).numeric_code(),
                Some(numeric)
            );
        }
        assert_eq!(
            CandidateResultError::Scb(ScbError::new(ScbErrorCode::DigestMismatch)).numeric_code(),
            None
        );
    }
}
