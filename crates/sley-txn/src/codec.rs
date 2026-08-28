//! Canonical non-cyclic S20-390 transaction and complete-receipt records.

use core::fmt;
use std::collections::BTreeSet;

use sley_id::{
    CandidateId, CandidateResultId, CapabilitySummaryDigest, EntityId, ObjectId, PolicyRootId,
    PrincipalId, ReceiptId, SchemaEpochId, StateRoot, TestReportId, TransactionId,
    ValidationProfileId, WorkspaceId,
};
use sley_mutate::{CandidateError, ImportedCandidate, import_candidate};
use sley_policy::{
    AcceptedPolicyRoot, CandidateDecision, CandidateResultError, ImportedCandidateResult,
    PolicyRootError, ValidationContextDigest, import_candidate_result,
};
use sley_scb1::{
    MAX_COLLECTION_ELEMENTS, MAX_STANDALONE_BYTES, ScbError, ScbErrorCode, ScbValueCursor,
    encode_bytes, encode_list, encode_record, encode_union, encode_uvar,
};
use sley_state_root::{AcceptedStateRoot, StateRootError, import_state_root};

/// Exact transaction-core envelope magic.
pub const TRANSACTION_MAGIC: [u8; 8] = *b"SLEYTXN1";
/// Exact complete-receipt envelope magic.
pub const RECEIPT_MAGIC: [u8; 8] = *b"SLEYRCP1";
/// Exact envelope and record format version.
pub const TRANSACTION_FORMAT_VERSION: u32 = 1;
/// Exact restricted commit profile tag.
pub const COMMIT_PROFILE_RESTRICTED_V1: u32 = 1;
/// Exact restricted semantic profile tag.
pub const SEMANTIC_PROFILE_OPERATION_FREE_V1: u32 = 1;
/// Exact receipt-before-head durability profile tag.
pub const DURABILITY_PROFILE_RECEIPT_BEFORE_HEAD_V1: u32 = 1;

const ENVELOPE_VERSION: u64 = 1;
const TRANSACTION_FIELD_COUNT: u64 = 19;
const CHANGED_BINDING_FIELD_COUNT: u64 = 4;
const COMMIT_METADATA_FIELD_COUNT: u64 = 3;
const RECEIPT_FIELD_COUNT: u64 = 9;
const MANIFEST_FIELD_COUNT: u64 = 2;
const MAX_TRANSACTION_ITEMS: usize = 65_535;

/// Closed transaction kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionKind {
    /// Explicit higher-authority repository genesis.
    TrustedGenesis,
    /// Ordinary freshly validated candidate commit.
    OrdinaryCandidate,
}

impl TransactionKind {
    /// Returns the exact closed wire tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::TrustedGenesis => 1,
            Self::OrdinaryCandidate => 2,
        }
    }

    /// Resolves one exact closed wire tag.
    #[must_use]
    pub const fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::TrustedGenesis),
            2 => Some(Self::OrdinaryCandidate),
            _ => None,
        }
    }
}

/// Deterministic transaction profile metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitMetadata {
    /// Exact transaction commit profile.
    pub commit_profile: u32,
    /// Exact semantic validation subset.
    pub semantic_profile: u32,
    /// Exact durability ordering profile.
    pub durability_profile: u32,
}

impl CommitMetadata {
    /// Returns the only S20-390 restricted metadata value.
    #[must_use]
    pub const fn restricted_v1() -> Self {
        Self {
            commit_profile: COMMIT_PROFILE_RESTRICTED_V1,
            semantic_profile: SEMANTIC_PROFILE_OPERATION_FREE_V1,
            durability_profile: DURABILITY_PROFILE_RECEIPT_BEFORE_HEAD_V1,
        }
    }
}

/// One exact parent-to-committed entity-binding change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedBinding {
    /// Stable logical entity identity.
    pub entity_id: EntityId,
    /// Exact parent object, absent for creation.
    pub preimage: Option<ObjectId>,
    /// Exact committed object, absent for deletion.
    pub postimage: Option<ObjectId>,
    /// Candidate operation ordinals that produced this binding.
    pub mutation_ordinals: Vec<u32>,
}

/// Canonical parent-bound transaction core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionRecord {
    /// Exact record format version.
    pub format_version: u32,
    /// Closed transaction kind.
    pub transaction_kind: TransactionKind,
    /// Exact workspace.
    pub workspace_id: WorkspaceId,
    /// Ordered transaction parents.
    pub parent_transaction_ids: Vec<TransactionId>,
    /// Ordered semantic roots aligned with the transaction parents.
    pub parent_roots: Vec<StateRoot>,
    /// Exact semantic schema epoch.
    pub schema_epoch_id: SchemaEpochId,
    /// Exact protected policy root.
    pub policy_root_id: PolicyRootId,
    /// Authenticated principal for ordinary commits.
    pub principal_id: Option<PrincipalId>,
    /// Exact candidate identity for ordinary commits.
    pub candidate_id: Option<CandidateId>,
    /// Exact fresh commit-time result identity for ordinary commits.
    pub candidate_result_id: Option<CandidateResultId>,
    /// Exact fresh trusted validation-context digest.
    pub validation_context_digest: Option<ValidationContextDigest>,
    /// Exact validation profile.
    pub validation_profile_id: Option<ValidationProfileId>,
    /// Ancestry-independent committed semantic root.
    pub committed_root: StateRoot,
    /// Exact sorted binding diff.
    pub changed_entity_bindings: Vec<ChangedBinding>,
    /// Authenticated capability projection for ordinary commits.
    pub capability_summary_digest: Option<CapabilitySummaryDigest>,
    /// Validator-selected tests.
    pub selected_tests: Vec<EntityId>,
    /// Exact test report references.
    pub test_result_refs: Vec<TestReportId>,
    /// Complete non-reusable identity ledger after this transaction.
    pub tombstoned_entities: Vec<EntityId>,
    /// Deterministic profile metadata.
    pub commit_metadata: CommitMetadata,
}

/// Canonical transaction bytes and derived identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedTransaction {
    /// Strictly decoded record.
    pub record: TransactionRecord,
    /// Derived parent-bound revision identity.
    pub transaction_id: TransactionId,
    /// Exact digest preimage.
    pub preimage: Vec<u8>,
    /// Exact bytes including the transaction trailer.
    pub stored_bytes: Vec<u8>,
}

/// One exact object needed by changed-binding postimages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectManifestEntry {
    /// Immutable object identity.
    pub object_id: ObjectId,
    /// Exact standalone stored byte length.
    pub stored_length: u64,
}

/// Complete persisted receipt evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionReceiptRecord {
    /// Exact record format version.
    pub format_version: u32,
    /// Transaction lookup and revision identity.
    pub transaction_id: TransactionId,
    /// Exact canonical transaction bytes including trailer.
    pub stored_transaction: Vec<u8>,
    /// Exact candidate bytes for ordinary commits.
    pub stored_candidate: Option<Vec<u8>>,
    /// Exact fresh commit-time result bytes for ordinary commits.
    pub stored_candidate_result: Option<Vec<u8>>,
    /// Exact registry-authorized committed root bytes.
    pub stored_state_root: Vec<u8>,
    /// Exact registry-authorized protected policy bytes.
    pub stored_policy_root: Vec<u8>,
    /// Exact sorted changed-postimage object manifest.
    pub object_manifest: Vec<ObjectManifestEntry>,
    /// Exact receipt-before-head durability profile.
    pub durability_profile: u32,
}

/// Strictly verified complete persisted receipt and all nested records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedTransactionReceipt {
    /// Strictly decoded outer record.
    pub record: TransactionReceiptRecord,
    /// Independently authenticated receipt identity.
    pub receipt_id: ReceiptId,
    /// Exact outer receipt digest preimage.
    pub preimage: Vec<u8>,
    /// Exact outer bytes including receipt trailer.
    pub stored_bytes: Vec<u8>,
    /// Strictly imported nested transaction.
    pub transaction: ImportedTransaction,
    /// Strictly imported candidate for ordinary transactions.
    pub candidate: Option<ImportedCandidate>,
    /// Shape-verified, non-authoritative nested candidate result.
    pub candidate_result: Option<ImportedCandidateResult>,
    /// Registry-authorized committed semantic root.
    pub state_root: AcceptedStateRoot,
    /// Registry-authorized protected policy root.
    pub policy_root: AcceptedPolicyRoot,
}

/// Stable S20-390 transaction-owned failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionErrorCode {
    /// `TXN_FORMAT_VERSION`
    FormatVersion,
    /// `TXN_KIND_INVALID`
    KindInvalid,
    /// `TXN_PARENT_SHAPE`
    ParentShape,
    /// `TXN_FIELD_SHAPE`
    FieldShape,
    /// `TXN_CHANGED_BINDING_INVALID`
    ChangedBindingInvalid,
    /// `TXN_TOMBSTONE_INVALID`
    TombstoneInvalid,
    /// `TXN_RESULT_NOT_VALID`
    ResultNotValid,
    /// `TXN_RESULT_BINDING_MISMATCH`
    ResultBindingMismatch,
    /// `TXN_TEST_EVIDENCE_UNSUPPORTED`
    TestEvidenceUnsupported,
    /// `TXN_OBJECT_INVENTORY_MISMATCH`
    ObjectInventoryMismatch,
    /// `TXN_RECEIPT_BINDING_MISMATCH`
    ReceiptBindingMismatch,
    /// `TXN_RECEIPT_CONFLICT`
    ReceiptConflict,
    /// `TXN_GENESIS_INVALID`
    GenesisInvalid,
    /// `TXN_ALREADY_INITIALIZED`
    AlreadyInitialized,
    /// `REF_HEAD_MISSING`
    HeadMissing,
    /// `REF_HEAD_CORRUPT`
    HeadCorrupt,
    /// `REF_CAS_STALE`
    RefCasStale,
    /// `RECOVERY_RECEIPT_INCOMPLETE`
    RecoveryReceiptIncomplete,
    /// `RECOVERY_REF_CAS_INCOMPLETE`
    RecoveryRefCasIncomplete,
    /// `TXN_IO`
    Io,
    /// `TXN_INTERNAL_INVARIANT`
    InternalInvariant,
    /// `TXN_RESOURCE_LIMIT`
    ResourceLimit,
}

impl TransactionErrorCode {
    /// Returns the exact stable symbolic code.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::FormatVersion => "TXN_FORMAT_VERSION",
            Self::KindInvalid => "TXN_KIND_INVALID",
            Self::ParentShape => "TXN_PARENT_SHAPE",
            Self::FieldShape => "TXN_FIELD_SHAPE",
            Self::ChangedBindingInvalid => "TXN_CHANGED_BINDING_INVALID",
            Self::TombstoneInvalid => "TXN_TOMBSTONE_INVALID",
            Self::ResultNotValid => "TXN_RESULT_NOT_VALID",
            Self::ResultBindingMismatch => "TXN_RESULT_BINDING_MISMATCH",
            Self::TestEvidenceUnsupported => "TXN_TEST_EVIDENCE_UNSUPPORTED",
            Self::ObjectInventoryMismatch => "TXN_OBJECT_INVENTORY_MISMATCH",
            Self::ReceiptBindingMismatch => "TXN_RECEIPT_BINDING_MISMATCH",
            Self::ReceiptConflict => "TXN_RECEIPT_CONFLICT",
            Self::GenesisInvalid => "TXN_GENESIS_INVALID",
            Self::AlreadyInitialized => "TXN_ALREADY_INITIALIZED",
            Self::HeadMissing => "REF_HEAD_MISSING",
            Self::HeadCorrupt => "REF_HEAD_CORRUPT",
            Self::RefCasStale => "REF_CAS_STALE",
            Self::RecoveryReceiptIncomplete => "RECOVERY_RECEIPT_INCOMPLETE",
            Self::RecoveryRefCasIncomplete => "RECOVERY_REF_CAS_INCOMPLETE",
            Self::Io => "TXN_IO",
            Self::InternalInvariant => "TXN_INTERNAL_INVARIANT",
            Self::ResourceLimit => "TXN_RESOURCE_LIMIT",
        }
    }

    /// Returns the frozen S20-390 numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::FormatVersion => 39_000,
            Self::KindInvalid => 39_001,
            Self::ParentShape => 39_002,
            Self::FieldShape => 39_003,
            Self::ChangedBindingInvalid => 39_004,
            Self::TombstoneInvalid => 39_005,
            Self::ResultNotValid => 39_006,
            Self::ResultBindingMismatch => 39_007,
            Self::TestEvidenceUnsupported => 39_008,
            Self::ObjectInventoryMismatch => 39_009,
            Self::ReceiptBindingMismatch => 39_010,
            Self::ReceiptConflict => 39_011,
            Self::GenesisInvalid => 39_012,
            Self::AlreadyInitialized => 39_013,
            Self::HeadMissing => 39_014,
            Self::HeadCorrupt => 39_015,
            Self::RefCasStale => 39_016,
            Self::RecoveryReceiptIncomplete => 39_017,
            Self::RecoveryRefCasIncomplete => 39_018,
            Self::Io => 39_019,
            Self::InternalInvariant => 39_020,
            Self::ResourceLimit => 39_021,
        }
    }
}

/// Exact canonical or nested transaction-codec failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionCodecError {
    /// Strict SCB1 failure.
    Scb(ScbError),
    /// Transaction-owned semantic failure.
    Transaction(TransactionErrorCode),
    /// Nested candidate failure.
    Candidate(CandidateError),
    /// Nested candidate-result failure.
    CandidateResult(CandidateResultError),
    /// Nested state-root failure.
    StateRoot(StateRootError),
    /// Nested policy-root failure.
    PolicyRoot(PolicyRootError),
}

impl TransactionCodecError {
    /// Returns the exact stable source symbol without collapsing namespaces.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Scb(error) => error.code().as_str(),
            Self::Transaction(code) => code.symbol(),
            Self::Candidate(error) => error.code(),
            Self::CandidateResult(error) => error.code(),
            Self::StateRoot(error) => error.code_str(),
            Self::PolicyRoot(error) => error.code_str(),
        }
    }

    /// Returns a transaction-owned numeric code when this namespace owns the
    /// failure.
    #[must_use]
    pub const fn numeric_code(&self) -> Option<u32> {
        match self {
            Self::Transaction(code) => Some(code.numeric()),
            Self::Candidate(error) => error.numeric_code(),
            Self::CandidateResult(error) => error.numeric_code(),
            Self::Scb(_) | Self::StateRoot(_) | Self::PolicyRoot(_) => None,
        }
    }
}

impl fmt::Display for TransactionCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for TransactionCodecError {}

impl From<ScbError> for TransactionCodecError {
    fn from(value: ScbError) -> Self {
        Self::Scb(value)
    }
}

impl From<CandidateError> for TransactionCodecError {
    fn from(value: CandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl From<CandidateResultError> for TransactionCodecError {
    fn from(value: CandidateResultError) -> Self {
        Self::CandidateResult(value)
    }
}

impl From<StateRootError> for TransactionCodecError {
    fn from(value: StateRootError) -> Self {
        Self::StateRoot(value)
    }
}

impl From<PolicyRootError> for TransactionCodecError {
    fn from(value: PolicyRootError) -> Self {
        Self::PolicyRoot(value)
    }
}

/// Builds canonical transaction bytes without committing them.
///
/// # Errors
///
/// Returns the first record-shape or canonical encoding failure.
pub fn build_transaction(
    record: &TransactionRecord,
) -> Result<ImportedTransaction, TransactionCodecError> {
    validate_transaction_record(record)?;
    let payload = encode_transaction_record(record)?;
    let preimage = encode_envelope(TRANSACTION_MAGIC, &payload)?;
    let transaction_id = TransactionId::derive(&preimage);
    let stored_bytes = append_digest(&preimage, transaction_id.as_bytes())?;
    Ok(ImportedTransaction {
        record: record.clone(),
        transaction_id,
        preimage,
        stored_bytes,
    })
}

/// Imports and strictly validates canonical transaction bytes.
///
/// # Errors
///
/// Returns the first envelope, digest, record, or semantic-shape failure.
pub fn import_transaction(input: &[u8]) -> Result<ImportedTransaction, TransactionCodecError> {
    let DecodedEnvelope {
        preimage,
        trailer,
        payload,
    } = decode_envelope(input, TRANSACTION_MAGIC)?;
    let transaction_id = TransactionId::derive(preimage);
    if trailer != transaction_id.as_bytes() {
        return Err(ScbError::new(ScbErrorCode::DigestMismatch).into());
    }
    let record = decode_transaction_record(payload)?;
    validate_transaction_record(&record)?;
    Ok(ImportedTransaction {
        record,
        transaction_id,
        preimage: preimage.to_vec(),
        stored_bytes: input.to_vec(),
    })
}

/// Builds and cross-verifies a complete persisted transaction receipt.
///
/// # Errors
///
/// Returns the first outer, nested, or cross-binding failure.
pub fn build_transaction_receipt(
    record: &TransactionReceiptRecord,
) -> Result<ImportedTransactionReceipt, TransactionCodecError> {
    let nested = validate_receipt_record(record)?;
    let payload = encode_receipt_record(record)?;
    let preimage = encode_envelope(RECEIPT_MAGIC, &payload)?;
    let receipt_id = ReceiptId::derive(&preimage);
    let stored_bytes = append_digest(&preimage, receipt_id.as_bytes())?;
    Ok(ImportedTransactionReceipt {
        record: record.clone(),
        receipt_id,
        preimage,
        stored_bytes,
        transaction: nested.transaction,
        candidate: nested.candidate,
        candidate_result: nested.candidate_result,
        state_root: nested.state_root,
        policy_root: nested.policy_root,
    })
}

/// Imports and cross-verifies a complete persisted transaction receipt.
///
/// # Errors
///
/// Returns the first outer, nested, digest, or cross-binding failure.
pub fn import_transaction_receipt(
    input: &[u8],
) -> Result<ImportedTransactionReceipt, TransactionCodecError> {
    let DecodedEnvelope {
        preimage,
        trailer,
        payload,
    } = decode_envelope(input, RECEIPT_MAGIC)?;
    let receipt_id = ReceiptId::derive(preimage);
    if trailer != receipt_id.as_bytes() {
        return Err(ScbError::new(ScbErrorCode::DigestMismatch).into());
    }
    let record = decode_receipt_record(payload)?;
    let nested = validate_receipt_record(&record)?;
    Ok(ImportedTransactionReceipt {
        record,
        receipt_id,
        preimage: preimage.to_vec(),
        stored_bytes: input.to_vec(),
        transaction: nested.transaction,
        candidate: nested.candidate,
        candidate_result: nested.candidate_result,
        state_root: nested.state_root,
        policy_root: nested.policy_root,
    })
}

struct NestedReceipt {
    transaction: ImportedTransaction,
    candidate: Option<ImportedCandidate>,
    candidate_result: Option<ImportedCandidateResult>,
    state_root: AcceptedStateRoot,
    policy_root: AcceptedPolicyRoot,
}

fn validate_receipt_record(
    record: &TransactionReceiptRecord,
) -> Result<NestedReceipt, TransactionCodecError> {
    if record.format_version != TRANSACTION_FORMAT_VERSION {
        return Err(txn_error(TransactionErrorCode::FormatVersion));
    }
    if record.durability_profile != DURABILITY_PROFILE_RECEIPT_BEFORE_HEAD_V1 {
        return Err(txn_error(TransactionErrorCode::FieldShape));
    }
    validate_manifest(&record.object_manifest)?;

    let transaction = import_transaction(&record.stored_transaction)?;
    if transaction.transaction_id != record.transaction_id {
        return Err(txn_error(TransactionErrorCode::ReceiptBindingMismatch));
    }
    let state_registry = sley_state_root::conformance_registry()
        .map_err(StateRootError::from)
        .map_err(TransactionCodecError::StateRoot)?;
    let state_root = import_state_root(&state_registry, &record.stored_state_root)?;
    let policy_registry = sley_policy::conformance_registry()
        .map_err(PolicyRootError::from)
        .map_err(TransactionCodecError::PolicyRoot)?;
    let policy_root =
        sley_policy::import_policy_root(&policy_registry, &record.stored_policy_root)?;

    if transaction.record.committed_root != state_root.root
        || transaction.record.workspace_id != state_root.record.workspace_id
        || transaction.record.schema_epoch_id != state_root.record.schema_epoch_id
        || transaction.record.policy_root_id != state_root.record.policy_root
        || transaction.record.policy_root_id != policy_root.root()
        || transaction.record.workspace_id != policy_root.record().workspace_id
        || transaction.record.commit_metadata.durability_profile != record.durability_profile
    {
        return Err(txn_error(TransactionErrorCode::ReceiptBindingMismatch));
    }

    let candidate = record
        .stored_candidate
        .as_deref()
        .map(import_candidate)
        .transpose()?;
    let candidate_result = record
        .stored_candidate_result
        .as_deref()
        .map(import_candidate_result)
        .transpose()?;
    match transaction.record.transaction_kind {
        TransactionKind::TrustedGenesis => {
            if candidate.is_some() || candidate_result.is_some() {
                return Err(txn_error(TransactionErrorCode::GenesisInvalid));
            }
        }
        TransactionKind::OrdinaryCandidate => {
            let candidate = candidate
                .as_ref()
                .ok_or_else(|| txn_error(TransactionErrorCode::ReceiptBindingMismatch))?;
            let result = candidate_result
                .as_ref()
                .ok_or_else(|| txn_error(TransactionErrorCode::ReceiptBindingMismatch))?;
            validate_ordinary_nested(&transaction.record, candidate, result)?;
        }
    }
    validate_manifest_binding(&transaction.record, &record.object_manifest)?;
    Ok(NestedReceipt {
        transaction,
        candidate,
        candidate_result,
        state_root,
        policy_root,
    })
}

fn validate_ordinary_nested(
    transaction: &TransactionRecord,
    candidate: &ImportedCandidate,
    result: &ImportedCandidateResult,
) -> Result<(), TransactionCodecError> {
    if result.record.decision != CandidateDecision::Valid {
        return Err(txn_error(TransactionErrorCode::ResultNotValid));
    }
    let Some(parent_transaction_id) = transaction.parent_transaction_ids.first() else {
        return Err(txn_error(TransactionErrorCode::ParentShape));
    };
    let Some(parent_root) = transaction.parent_roots.first() else {
        return Err(txn_error(TransactionErrorCode::ParentShape));
    };
    if transaction.candidate_id != Some(candidate.candidate_id)
        || transaction.candidate_result_id != Some(result.candidate_result_id)
        || transaction.validation_context_digest != Some(result.record.validation_context_digest)
        || transaction.validation_profile_id != Some(result.record.validation_profile_id)
        || transaction.committed_root
            != result
                .record
                .candidate_root
                .ok_or_else(|| txn_error(TransactionErrorCode::ResultBindingMismatch))?
        || transaction.selected_tests != result.record.selected_tests
        || result.record.candidate_id != Some(candidate.candidate_id)
        || candidate.record.base_transaction_id != *parent_transaction_id
        || candidate.record.base_root != *parent_root
        || candidate.record.workspace_id != transaction.workspace_id
        || candidate.record.schema_epoch_id != transaction.schema_epoch_id
        || candidate.record.policy_root_id != transaction.policy_root_id
        || transaction.principal_id != Some(candidate.record.principal_id)
        || transaction.capability_summary_digest != Some(candidate.record.capability_summary_digest)
        || transaction.validation_profile_id != Some(candidate.record.validation_profile_id)
    {
        return Err(txn_error(TransactionErrorCode::ResultBindingMismatch));
    }
    Ok(())
}

fn validate_manifest_binding(
    transaction: &TransactionRecord,
    manifest: &[ObjectManifestEntry],
) -> Result<(), TransactionCodecError> {
    let expected = transaction
        .changed_entity_bindings
        .iter()
        .filter_map(|binding| binding.postimage)
        .collect::<BTreeSet<_>>();
    let actual = manifest
        .iter()
        .map(|entry| entry.object_id)
        .collect::<BTreeSet<_>>();
    if expected == actual {
        Ok(())
    } else {
        Err(txn_error(TransactionErrorCode::ObjectInventoryMismatch))
    }
}

fn validate_transaction_record(record: &TransactionRecord) -> Result<(), TransactionCodecError> {
    if record.format_version != TRANSACTION_FORMAT_VERSION {
        return Err(txn_error(TransactionErrorCode::FormatVersion));
    }
    if record.parent_transaction_ids.len() != record.parent_roots.len() {
        return Err(txn_error(TransactionErrorCode::ParentShape));
    }
    validate_sorted_ids(&record.selected_tests, TransactionErrorCode::FieldShape)?;
    validate_sorted_ids(
        &record.tombstoned_entities,
        TransactionErrorCode::TombstoneInvalid,
    )?;
    validate_sorted_ids(&record.test_result_refs, TransactionErrorCode::FieldShape)?;
    validate_changed_bindings(&record.changed_entity_bindings, record.transaction_kind)?;
    if record.commit_metadata != CommitMetadata::restricted_v1() {
        return Err(txn_error(TransactionErrorCode::FieldShape));
    }
    if !record.selected_tests.is_empty() || !record.test_result_refs.is_empty() {
        return Err(txn_error(TransactionErrorCode::TestEvidenceUnsupported));
    }
    let ordinary_fields = [
        record.principal_id.is_some(),
        record.candidate_id.is_some(),
        record.candidate_result_id.is_some(),
        record.validation_context_digest.is_some(),
        record.validation_profile_id.is_some(),
        record.capability_summary_digest.is_some(),
    ];
    match record.transaction_kind {
        TransactionKind::TrustedGenesis => {
            if !record.parent_transaction_ids.is_empty()
                || ordinary_fields.into_iter().any(|present| present)
                || record
                    .changed_entity_bindings
                    .iter()
                    .any(|binding| !binding.mutation_ordinals.is_empty())
            {
                return Err(txn_error(TransactionErrorCode::GenesisInvalid));
            }
        }
        TransactionKind::OrdinaryCandidate => {
            if record.parent_transaction_ids.len() != 1
                || ordinary_fields.into_iter().any(|present| !present)
            {
                return Err(txn_error(TransactionErrorCode::ParentShape));
            }
        }
    }
    Ok(())
}

fn validate_changed_bindings(
    bindings: &[ChangedBinding],
    kind: TransactionKind,
) -> Result<(), TransactionCodecError> {
    if bindings.len() > MAX_TRANSACTION_ITEMS
        || bindings
            .windows(2)
            .any(|pair| pair[0].entity_id >= pair[1].entity_id)
    {
        return Err(txn_error(TransactionErrorCode::ChangedBindingInvalid));
    }
    let mut ordinals = BTreeSet::new();
    for binding in bindings {
        if (binding.preimage.is_none() && binding.postimage.is_none())
            || binding.preimage == binding.postimage
            || binding
                .mutation_ordinals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || (kind == TransactionKind::OrdinaryCandidate && binding.mutation_ordinals.is_empty())
            || binding
                .mutation_ordinals
                .iter()
                .any(|ordinal| !ordinals.insert(*ordinal))
        {
            return Err(txn_error(TransactionErrorCode::ChangedBindingInvalid));
        }
    }
    Ok(())
}

fn validate_manifest(entries: &[ObjectManifestEntry]) -> Result<(), TransactionCodecError> {
    if entries.len() > MAX_TRANSACTION_ITEMS
        || entries
            .windows(2)
            .any(|pair| pair[0].object_id >= pair[1].object_id)
        || entries.iter().any(|entry| {
            entry.stored_length < 32 || entry.stored_length > MAX_STANDALONE_BYTES as u64
        })
    {
        Err(txn_error(TransactionErrorCode::ObjectInventoryMismatch))
    } else {
        Ok(())
    }
}

fn validate_sorted_ids<T: Ord>(
    values: &[T],
    code: TransactionErrorCode,
) -> Result<(), TransactionCodecError> {
    if values.len() > MAX_TRANSACTION_ITEMS || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(txn_error(code))
    } else {
        Ok(())
    }
}

fn encode_transaction_record(record: &TransactionRecord) -> Result<Vec<u8>, ScbError> {
    let parents = encode_fixed_list(
        record
            .parent_transaction_ids
            .iter()
            .map(TransactionId::as_bytes),
    )?;
    let parent_roots = encode_fixed_list(record.parent_roots.iter().map(StateRoot::as_bytes))?;
    let changed = record
        .changed_entity_bindings
        .iter()
        .map(encode_changed_binding)
        .collect::<Result<Vec<_>, _>>()?;
    let selected = encode_fixed_list(record.selected_tests.iter().map(EntityId::as_bytes))?;
    let reports = encode_fixed_list(record.test_result_refs.iter().map(TestReportId::as_bytes))?;
    let tombstones = encode_fixed_list(record.tombstoned_entities.iter().map(EntityId::as_bytes))?;
    encode_record(&[
        (1, encode_uvar(u64::from(record.format_version))),
        (2, encode_uvar(u64::from(record.transaction_kind.tag()))),
        (3, record.workspace_id.as_bytes().to_vec()),
        (4, parents),
        (5, parent_roots),
        (6, record.schema_epoch_id.as_bytes().to_vec()),
        (7, record.policy_root_id.as_bytes().to_vec()),
        (
            8,
            encode_option_fixed(record.principal_id.as_ref().map(PrincipalId::as_bytes))?,
        ),
        (
            9,
            encode_option_fixed(record.candidate_id.as_ref().map(CandidateId::as_bytes))?,
        ),
        (
            10,
            encode_option_fixed(
                record
                    .candidate_result_id
                    .as_ref()
                    .map(CandidateResultId::as_bytes),
            )?,
        ),
        (
            11,
            encode_option_fixed(
                record
                    .validation_context_digest
                    .as_ref()
                    .map(ValidationContextDigest::as_bytes),
            )?,
        ),
        (
            12,
            encode_option_fixed(
                record
                    .validation_profile_id
                    .as_ref()
                    .map(ValidationProfileId::as_bytes),
            )?,
        ),
        (13, record.committed_root.as_bytes().to_vec()),
        (14, encode_list(&changed)?),
        (
            15,
            encode_option_fixed(
                record
                    .capability_summary_digest
                    .as_ref()
                    .map(CapabilitySummaryDigest::as_bytes),
            )?,
        ),
        (16, selected),
        (17, reports),
        (18, tombstones),
        (19, encode_commit_metadata(record.commit_metadata)?),
    ])
}

fn encode_changed_binding(binding: &ChangedBinding) -> Result<Vec<u8>, ScbError> {
    let ordinals = binding
        .mutation_ordinals
        .iter()
        .map(|value| encode_uvar(u64::from(*value)))
        .collect::<Vec<_>>();
    encode_record(&[
        (1, binding.entity_id.as_bytes().to_vec()),
        (
            2,
            encode_option_fixed(binding.preimage.as_ref().map(ObjectId::as_bytes))?,
        ),
        (
            3,
            encode_option_fixed(binding.postimage.as_ref().map(ObjectId::as_bytes))?,
        ),
        (4, encode_list(&ordinals)?),
    ])
}

fn encode_commit_metadata(metadata: CommitMetadata) -> Result<Vec<u8>, ScbError> {
    encode_record(&[
        (1, encode_uvar(u64::from(metadata.commit_profile))),
        (2, encode_uvar(u64::from(metadata.semantic_profile))),
        (3, encode_uvar(u64::from(metadata.durability_profile))),
    ])
}

fn encode_receipt_record(record: &TransactionReceiptRecord) -> Result<Vec<u8>, ScbError> {
    let manifest = record
        .object_manifest
        .iter()
        .map(|entry| {
            encode_record(&[
                (1, entry.object_id.as_bytes().to_vec()),
                (2, encode_uvar(entry.stored_length)),
            ])
        })
        .collect::<Result<Vec<_>, _>>()?;
    encode_record(&[
        (1, encode_uvar(u64::from(record.format_version))),
        (2, record.transaction_id.as_bytes().to_vec()),
        (3, encode_bytes(&record.stored_transaction)?),
        (4, encode_option_bytes(record.stored_candidate.as_deref())?),
        (
            5,
            encode_option_bytes(record.stored_candidate_result.as_deref())?,
        ),
        (6, encode_bytes(&record.stored_state_root)?),
        (7, encode_bytes(&record.stored_policy_root)?),
        (8, encode_list(&manifest)?),
        (9, encode_uvar(u64::from(record.durability_profile))),
    ])
}

fn decode_transaction_record(input: &[u8]) -> Result<TransactionRecord, TransactionCodecError> {
    let fields = decode_required_record(input, TRANSACTION_FIELD_COUNT)?;
    Ok(TransactionRecord {
        format_version: read_u32(fields[0])?,
        transaction_kind: TransactionKind::from_tag(read_u32(fields[1])?)
            .ok_or_else(|| txn_error(TransactionErrorCode::KindInvalid))?,
        workspace_id: WorkspaceId::from_bytes(read_fixed(fields[2])?),
        parent_transaction_ids: decode_fixed_list(fields[3])?
            .into_iter()
            .map(TransactionId::from_bytes)
            .collect(),
        parent_roots: decode_fixed_list(fields[4])?
            .into_iter()
            .map(StateRoot::from_bytes)
            .collect(),
        schema_epoch_id: SchemaEpochId::from_bytes(read_fixed(fields[5])?),
        policy_root_id: PolicyRootId::from_bytes(read_fixed(fields[6])?),
        principal_id: decode_option_fixed(fields[7])?.map(PrincipalId::from_bytes),
        candidate_id: decode_option_fixed(fields[8])?.map(CandidateId::from_bytes),
        candidate_result_id: decode_option_fixed(fields[9])?.map(CandidateResultId::from_bytes),
        validation_context_digest: decode_option_fixed(fields[10])?
            .map(ValidationContextDigest::from_bytes),
        validation_profile_id: decode_option_fixed(fields[11])?
            .map(ValidationProfileId::from_bytes),
        committed_root: StateRoot::from_bytes(read_fixed(fields[12])?),
        changed_entity_bindings: decode_changed_bindings(fields[13])?,
        capability_summary_digest: decode_option_fixed(fields[14])?
            .map(CapabilitySummaryDigest::from_bytes),
        selected_tests: decode_fixed_list(fields[15])?
            .into_iter()
            .map(EntityId::from_bytes)
            .collect(),
        test_result_refs: decode_fixed_list(fields[16])?
            .into_iter()
            .map(TestReportId::from_bytes)
            .collect(),
        tombstoned_entities: decode_fixed_list(fields[17])?
            .into_iter()
            .map(EntityId::from_bytes)
            .collect(),
        commit_metadata: decode_commit_metadata(fields[18])?,
    })
}

fn decode_changed_bindings(input: &[u8]) -> Result<Vec<ChangedBinding>, TransactionCodecError> {
    decode_list_payloads(input)?
        .into_iter()
        .map(|payload| {
            let fields = decode_required_record(payload, CHANGED_BINDING_FIELD_COUNT)?;
            Ok(ChangedBinding {
                entity_id: EntityId::from_bytes(read_fixed(fields[0])?),
                preimage: decode_option_fixed(fields[1])?.map(ObjectId::from_bytes),
                postimage: decode_option_fixed(fields[2])?.map(ObjectId::from_bytes),
                mutation_ordinals: decode_list_payloads(fields[3])?
                    .into_iter()
                    .map(read_u32)
                    .collect::<Result<Vec<_>, _>>()?,
            })
        })
        .collect()
}

fn decode_commit_metadata(input: &[u8]) -> Result<CommitMetadata, TransactionCodecError> {
    let fields = decode_required_record(input, COMMIT_METADATA_FIELD_COUNT)?;
    Ok(CommitMetadata {
        commit_profile: read_u32(fields[0])?,
        semantic_profile: read_u32(fields[1])?,
        durability_profile: read_u32(fields[2])?,
    })
}

fn decode_receipt_record(input: &[u8]) -> Result<TransactionReceiptRecord, TransactionCodecError> {
    let fields = decode_required_record(input, RECEIPT_FIELD_COUNT)?;
    let object_manifest = decode_list_payloads(fields[7])?
        .into_iter()
        .map(|payload| {
            let fields = decode_required_record(payload, MANIFEST_FIELD_COUNT)?;
            Ok(ObjectManifestEntry {
                object_id: ObjectId::from_bytes(read_fixed(fields[0])?),
                stored_length: read_u64(fields[1])?,
            })
        })
        .collect::<Result<Vec<_>, TransactionCodecError>>()?;
    Ok(TransactionReceiptRecord {
        format_version: read_u32(fields[0])?,
        transaction_id: TransactionId::from_bytes(read_fixed(fields[1])?),
        stored_transaction: read_bytes(fields[2])?,
        stored_candidate: decode_option_bytes(fields[3])?,
        stored_candidate_result: decode_option_bytes(fields[4])?,
        stored_state_root: read_bytes(fields[5])?,
        stored_policy_root: read_bytes(fields[6])?,
        object_manifest,
        durability_profile: read_u32(fields[8])?,
    })
}

fn encode_envelope(magic: [u8; 8], payload: &[u8]) -> Result<Vec<u8>, ScbError> {
    let payload_len =
        u64::try_from(payload.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    let mut preimage = Vec::with_capacity(magic.len() + 12 + payload.len());
    preimage.extend_from_slice(&magic);
    preimage.extend_from_slice(&encode_uvar(ENVELOPE_VERSION));
    preimage.extend_from_slice(&encode_uvar(payload_len));
    preimage.extend_from_slice(payload);
    if preimage.len() + 32 > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    Ok(preimage)
}

fn append_digest(preimage: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, ScbError> {
    if preimage.len() + digest.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut stored = Vec::with_capacity(preimage.len() + digest.len());
    stored.extend_from_slice(preimage);
    stored.extend_from_slice(digest);
    Ok(stored)
}

struct DecodedEnvelope<'a> {
    preimage: &'a [u8],
    trailer: &'a [u8],
    payload: &'a [u8],
}

fn decode_envelope(
    input: &[u8],
    expected_magic: [u8; 8],
) -> Result<DecodedEnvelope<'_>, TransactionCodecError> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit).into());
    }
    if input.len() < 32 {
        return Err(ScbError::new(ScbErrorCode::LengthOverflow).into());
    }
    let (preimage, trailer) = input.split_at(input.len() - 32);
    let mut cursor = ScbValueCursor::new(preimage)?;
    if cursor.read_exact_bytes(expected_magic.len())? != expected_magic {
        return Err(ScbError::new(ScbErrorCode::MagicInvalid).into());
    }
    if cursor.read_uvar(64)? != ENVELOPE_VERSION {
        return Err(ScbError::new(ScbErrorCode::VersionUnsupported).into());
    }
    let payload = cursor.read_sized_payload()?;
    cursor.check_finished()?;
    Ok(DecodedEnvelope {
        preimage,
        trailer,
        payload,
    })
}

fn encode_fixed_list<'a, I>(values: I) -> Result<Vec<u8>, ScbError>
where
    I: IntoIterator<Item = &'a [u8; 32]>,
{
    encode_list(
        &values
            .into_iter()
            .map(|value| value.to_vec())
            .collect::<Vec<_>>(),
    )
}

fn encode_option_fixed(value: Option<&[u8; 32]>) -> Result<Vec<u8>, ScbError> {
    match value {
        None => encode_union(0, &[]),
        Some(value) => encode_union(1, value),
    }
}

fn encode_option_bytes(value: Option<&[u8]>) -> Result<Vec<u8>, ScbError> {
    match value {
        None => encode_union(0, &[]),
        Some(value) => encode_union(1, &encode_bytes(value)?),
    }
}

fn decode_required_record(
    input: &[u8],
    expected_count: u64,
) -> Result<Vec<&[u8]>, TransactionCodecError> {
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
    let capacity =
        usize::try_from(expected_count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    let mut fields = Vec::with_capacity(capacity);
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

fn decode_list_payloads(input: &[u8]) -> Result<Vec<&[u8]>, TransactionCodecError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let count = usize::try_from(cursor.read_list_count()?)
        .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > MAX_TRANSACTION_ITEMS || count as u64 > MAX_COLLECTION_ELEMENTS {
        return Err(txn_error(TransactionErrorCode::ResourceLimit));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(cursor.read_sized_payload()?);
    }
    cursor.check_finished()?;
    Ok(values)
}

fn decode_fixed_list(input: &[u8]) -> Result<Vec<[u8; 32]>, TransactionCodecError> {
    decode_list_payloads(input)?
        .into_iter()
        .map(read_fixed)
        .collect()
}

fn read_fixed(input: &[u8]) -> Result<[u8; 32], TransactionCodecError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = cursor.read_fixed_bytes()?;
    cursor.check_finished()?;
    Ok(value)
}

fn read_u32(input: &[u8]) -> Result<u32, TransactionCodecError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = u32::try_from(cursor.read_uvar(32)?)
        .map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))?;
    cursor.check_finished()?;
    Ok(value)
}

fn read_u64(input: &[u8]) -> Result<u64, TransactionCodecError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = cursor.read_uvar(64)?;
    cursor.check_finished()?;
    Ok(value)
}

fn read_bytes(input: &[u8]) -> Result<Vec<u8>, TransactionCodecError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = cursor.read_bytes()?.to_vec();
    cursor.check_finished()?;
    Ok(value)
}

fn decode_option_fixed(input: &[u8]) -> Result<Option<[u8; 32]>, TransactionCodecError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let (tag, payload) = cursor.read_union()?;
    cursor.check_finished()?;
    match tag {
        0 if payload.is_empty() => Ok(None),
        1 => read_fixed(payload).map(Some),
        _ => Err(ScbError::new(ScbErrorCode::UnionInvalid).into()),
    }
}

fn decode_option_bytes(input: &[u8]) -> Result<Option<Vec<u8>>, TransactionCodecError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let (tag, payload) = cursor.read_union()?;
    cursor.check_finished()?;
    match tag {
        0 if payload.is_empty() => Ok(None),
        1 => read_bytes(payload).map(Some),
        _ => Err(ScbError::new(ScbErrorCode::UnionInvalid).into()),
    }
}

fn txn_error(code: TransactionErrorCode) -> TransactionCodecError {
    TransactionCodecError::Transaction(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id<T>(byte: u8, constructor: impl FnOnce([u8; 32]) -> T) -> T {
        constructor([byte; 32])
    }

    fn genesis_record() -> TransactionRecord {
        TransactionRecord {
            format_version: 1,
            transaction_kind: TransactionKind::TrustedGenesis,
            workspace_id: id(1, WorkspaceId::from_bytes),
            parent_transaction_ids: Vec::new(),
            parent_roots: Vec::new(),
            schema_epoch_id: id(2, SchemaEpochId::from_bytes),
            policy_root_id: id(3, PolicyRootId::from_bytes),
            principal_id: None,
            candidate_id: None,
            candidate_result_id: None,
            validation_context_digest: None,
            validation_profile_id: None,
            committed_root: id(4, StateRoot::from_bytes),
            changed_entity_bindings: vec![ChangedBinding {
                entity_id: id(5, EntityId::from_bytes),
                preimage: None,
                postimage: Some(id(6, ObjectId::from_bytes)),
                mutation_ordinals: Vec::new(),
            }],
            capability_summary_digest: None,
            selected_tests: Vec::new(),
            test_result_refs: Vec::new(),
            tombstoned_entities: Vec::new(),
            commit_metadata: CommitMetadata::restricted_v1(),
        }
    }

    #[test]
    fn transaction_round_trip_is_non_cyclic_and_parent_bound() {
        let built = build_transaction(&genesis_record()).unwrap();
        assert_eq!(import_transaction(&built.stored_bytes).unwrap(), built);
        assert_eq!(built.transaction_id, TransactionId::derive(&built.preimage));
        assert!(
            !built
                .preimage
                .windows(32)
                .any(|window| { window == built.transaction_id.as_bytes() })
        );

        let mut ordinary = genesis_record();
        ordinary.transaction_kind = TransactionKind::OrdinaryCandidate;
        ordinary.parent_transaction_ids = vec![id(7, TransactionId::from_bytes)];
        ordinary.parent_roots = vec![id(8, StateRoot::from_bytes)];
        ordinary.principal_id = Some(id(9, PrincipalId::from_bytes));
        ordinary.candidate_id = Some(id(10, CandidateId::from_bytes));
        ordinary.candidate_result_id = Some(id(11, CandidateResultId::from_bytes));
        ordinary.validation_context_digest = Some(id(12, ValidationContextDigest::from_bytes));
        ordinary.validation_profile_id = Some(id(13, ValidationProfileId::from_bytes));
        ordinary.capability_summary_digest = Some(id(14, CapabilitySummaryDigest::from_bytes));
        ordinary.changed_entity_bindings[0].mutation_ordinals = vec![0];
        let first = build_transaction(&ordinary).unwrap();
        ordinary.parent_transaction_ids[0] = id(15, TransactionId::from_bytes);
        let second = build_transaction(&ordinary).unwrap();
        assert_ne!(first.transaction_id, second.transaction_id);
    }

    #[test]
    fn transaction_shape_rejects_self_equal_binding_and_test_claims() {
        let mut record = genesis_record();
        record.changed_entity_bindings[0].preimage = record.changed_entity_bindings[0].postimage;
        assert_eq!(
            build_transaction(&record).unwrap_err().code(),
            "TXN_CHANGED_BINDING_INVALID"
        );

        let mut record = genesis_record();
        record.selected_tests = vec![id(9, EntityId::from_bytes)];
        assert_eq!(
            build_transaction(&record).unwrap_err().code(),
            "TXN_TEST_EVIDENCE_UNSUPPORTED"
        );
    }

    #[test]
    fn transaction_import_rejects_digest_and_trailing_corruption() {
        let built = build_transaction(&genesis_record()).unwrap();
        let mut digest = built.stored_bytes.clone();
        *digest.last_mut().unwrap() ^= 1;
        assert_eq!(
            import_transaction(&digest).unwrap_err().code(),
            "SCB_DIGEST_MISMATCH"
        );
        let mut trailing = built.stored_bytes.clone();
        trailing.push(0);
        assert_ne!(import_transaction(&trailing).unwrap_err().code(), "");
    }

    #[test]
    fn transaction_error_codes_are_closed_and_contiguous() {
        let codes = [
            TransactionErrorCode::FormatVersion,
            TransactionErrorCode::KindInvalid,
            TransactionErrorCode::ParentShape,
            TransactionErrorCode::FieldShape,
            TransactionErrorCode::ChangedBindingInvalid,
            TransactionErrorCode::TombstoneInvalid,
            TransactionErrorCode::ResultNotValid,
            TransactionErrorCode::ResultBindingMismatch,
            TransactionErrorCode::TestEvidenceUnsupported,
            TransactionErrorCode::ObjectInventoryMismatch,
            TransactionErrorCode::ReceiptBindingMismatch,
            TransactionErrorCode::ReceiptConflict,
            TransactionErrorCode::GenesisInvalid,
            TransactionErrorCode::AlreadyInitialized,
            TransactionErrorCode::HeadMissing,
            TransactionErrorCode::HeadCorrupt,
            TransactionErrorCode::RefCasStale,
            TransactionErrorCode::RecoveryReceiptIncomplete,
            TransactionErrorCode::RecoveryRefCasIncomplete,
            TransactionErrorCode::Io,
            TransactionErrorCode::InternalInvariant,
            TransactionErrorCode::ResourceLimit,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 39_000 + u32::try_from(offset).unwrap());
            assert!(!code.symbol().is_empty());
        }
    }
}
