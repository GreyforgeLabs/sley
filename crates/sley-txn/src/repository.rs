//! Durable S20-390 transaction repository and fixed accepted-head CAS.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sley_id::{EntityId, ObjectId, PrincipalId, ReceiptId, TransactionId};
use sley_mutate::{EntityObject, import_entity_object};
use sley_policy::{
    AcceptedPolicyRoot, CandidateDecision, CandidateValidationContext, CandidateValidationError,
    CandidateValidationLimits, CandidateValidationOutput, ImportedCandidateResult,
    TrustedCandidateCapability, validate_candidate_bytes,
};
use sley_scb1::{MAX_STANDALONE_BYTES, ScbError, encode_uvar};
use sley_state_root::AcceptedStateRoot;
use sley_store::{ObjectStore, StoreError};

use crate::codec::{
    ChangedBinding, CommitMetadata, ImportedTransactionReceipt, ObjectManifestEntry,
    TransactionCodecError, TransactionErrorCode, TransactionKind, TransactionReceiptRecord,
    TransactionRecord, build_transaction, build_transaction_receipt, import_transaction_receipt,
};
use crate::maintenance::{
    RepositoryMaintenanceGuard, acquire_shared_repository_maintenance,
    initialize_repository_maintenance,
};

const HEAD_MAGIC: &[u8; 8] = b"SLEYHD01";
const HEAD_VERSION: u64 = 1;
const HEAD_CHECKSUM_DOMAIN: &[u8] = b"sley2.accepted-head.v1";
const HEAD_LEN: usize = 8 + 1 + 32 + 32;
const RECEIPT_STAGE_PREFIX: &str = ".sley-txn-stage-";
const HEAD_STAGE_PREFIX: &str = ".sley-head-stage-";
const STAGE_SUFFIX: &str = ".tmp";
const MAX_STAGE_ATTEMPTS: u64 = 1_024;

static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Complete verified transaction state loaded from durable bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRevision {
    transaction_id: TransactionId,
    receipt: ImportedTransactionReceipt,
    objects: Vec<EntityObject>,
}

impl VerifiedRevision {
    /// Returns the exact verified revision identity.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the independently authenticated complete receipt.
    #[must_use]
    pub const fn receipt(&self) -> &ImportedTransactionReceipt {
        &self.receipt
    }

    /// Returns the registry-authorized accepted semantic root.
    #[must_use]
    pub const fn state_root(&self) -> &AcceptedStateRoot {
        &self.receipt.state_root
    }

    /// Returns the registry-authorized protected policy root.
    #[must_use]
    pub const fn policy_root(&self) -> &AcceptedPolicyRoot {
        &self.receipt.policy_root
    }

    /// Returns every exact live entity object in state-root binding order.
    #[must_use]
    pub fn objects(&self) -> &[EntityObject] {
        &self.objects
    }

    /// Returns the complete sorted non-reusable identity ledger.
    #[must_use]
    pub fn tombstoned_entities(&self) -> &[EntityId] {
        &self.receipt.transaction.record.tombstoned_entities
    }
}

/// Complete verified fixed-head state loaded from durable bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedHead {
    revision: VerifiedRevision,
}

impl AcceptedHead {
    /// Returns the exact accepted revision identity.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.revision.transaction_id()
    }

    /// Returns the independently authenticated complete receipt.
    #[must_use]
    pub const fn receipt(&self) -> &ImportedTransactionReceipt {
        self.revision.receipt()
    }

    /// Returns the registry-authorized accepted semantic root.
    #[must_use]
    pub const fn state_root(&self) -> &AcceptedStateRoot {
        self.revision.state_root()
    }

    /// Returns the registry-authorized protected policy root.
    #[must_use]
    pub const fn policy_root(&self) -> &AcceptedPolicyRoot {
        self.revision.policy_root()
    }

    /// Returns every exact live entity object in state-root binding order.
    #[must_use]
    pub fn objects(&self) -> &[EntityObject] {
        self.revision.objects()
    }

    /// Returns the complete sorted non-reusable identity ledger.
    #[must_use]
    pub fn tombstoned_entities(&self) -> &[EntityId] {
        self.revision.tombstoned_entities()
    }

    /// Returns the verified revision backing this accepted-head claim.
    #[must_use]
    pub const fn verified_revision(&self) -> &VerifiedRevision {
        &self.revision
    }
}

/// Explicit higher-authority genesis material.
#[derive(Clone, Copy)]
pub struct TrustedGenesisInput<'a> {
    state_root: &'a AcceptedStateRoot,
    policy_root: &'a AcceptedPolicyRoot,
    objects: &'a [EntityObject],
    tombstoned_entities: &'a [EntityId],
}

impl<'a> TrustedGenesisInput<'a> {
    /// Constructs an explicit root-of-trust initialization input.
    #[must_use]
    pub const fn new(
        state_root: &'a AcceptedStateRoot,
        policy_root: &'a AcceptedPolicyRoot,
        objects: &'a [EntityObject],
        tombstoned_entities: &'a [EntityId],
    ) -> Self {
        Self {
            state_root,
            policy_root,
            objects,
            tombstoned_entities,
        }
    }
}

/// Fresh ordinary-candidate commit inputs not recoverable from accepted state.
#[derive(Clone, Copy)]
pub struct CommitInput<'a> {
    expected_parent: TransactionId,
    stored_candidate: &'a [u8],
    principal_id: PrincipalId,
    capabilities: &'a [TrustedCandidateCapability<'a>],
    now_unix_millis: u64,
    limits: CandidateValidationLimits,
}

impl<'a> CommitInput<'a> {
    /// Constructs a request. The engine still loads and verifies every
    /// accepted-state fact itself.
    #[must_use]
    pub const fn new(
        expected_parent: TransactionId,
        stored_candidate: &'a [u8],
        principal_id: PrincipalId,
        capabilities: &'a [TrustedCandidateCapability<'a>],
        now_unix_millis: u64,
        limits: CandidateValidationLimits,
    ) -> Self {
        Self {
            expected_parent,
            stored_candidate,
            principal_id,
            capabilities,
            now_unix_millis,
            limits,
        }
    }
}

/// Successful durable ordinary commit result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitOutput {
    transaction_id: TransactionId,
    receipt_id: ReceiptId,
    state_root: AcceptedStateRoot,
    candidate_result: ImportedCandidateResult,
}

impl CommitOutput {
    /// Returns the new durable accepted revision identity.
    #[must_use]
    pub const fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the complete persisted receipt identity.
    #[must_use]
    pub const fn receipt_id(&self) -> ReceiptId {
        self.receipt_id
    }

    /// Returns the committed ancestry-independent semantic root.
    #[must_use]
    pub const fn state_root(&self) -> &AcceptedStateRoot {
        &self.state_root
    }

    /// Returns the fresh commit-time validation result.
    #[must_use]
    pub const fn candidate_result(&self) -> &ImportedCandidateResult {
        &self.candidate_result
    }
}

/// Idempotent recovery summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Removed immutable-object staging remnants.
    pub removed_object_stages: u64,
    /// Removed receipt staging remnants.
    pub removed_receipt_stages: u64,
    /// Removed accepted-head staging remnants.
    pub removed_head_stages: u64,
    /// Verified accepted transaction after cleanup, when initialized.
    pub accepted_transaction_id: Option<TransactionId>,
}

/// Commit, persistence, or fresh-validation failure.
#[derive(Debug)]
pub enum CommitError {
    /// Canonical transaction or nested receipt failure.
    Codec(TransactionCodecError),
    /// Immutable object-store failure.
    Store(StoreError),
    /// Fresh validator could not render canonical evidence.
    Validation(CandidateValidationError),
    /// Fresh validation returned a non-`VALID` monotonic result.
    CandidateRejected(Box<CandidateValidationOutput>),
    /// Live accepted head did not equal the expected parent.
    StaleRoot {
        /// Caller-expected parent.
        expected: TransactionId,
        /// Current accepted parent.
        actual: TransactionId,
    },
    /// S20-390-owned semantic or durability failure.
    Transaction(TransactionErrorCode),
    /// Local host I/O failure.
    Io(io::Error),
}

impl CommitError {
    /// Returns the exact stable source symbol without collapsing namespaces.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Codec(error) => error.code(),
            Self::Store(error) => error.symbol(),
            Self::Validation(_) => TransactionErrorCode::InternalInvariant.symbol(),
            Self::CandidateRejected(output) => output.result().record.decision.symbol(),
            Self::StaleRoot { .. } => "STALE_ROOT",
            Self::Transaction(code) => code.symbol(),
            Self::Io(_) => TransactionErrorCode::Io.symbol(),
        }
    }

    /// Returns the owning numeric code when frozen by S20-360 or S20-390.
    #[must_use]
    pub fn numeric_code(&self) -> Option<u32> {
        match self {
            Self::Codec(error) => error.numeric_code(),
            Self::CandidateRejected(output) => output.result().record.decision.numeric_code(),
            Self::StaleRoot { .. } => CandidateDecision::StaleRoot.numeric_code(),
            Self::Transaction(code) => Some(code.numeric()),
            Self::Store(_) | Self::Validation(_) | Self::Io(_) => None,
        }
    }
}

impl fmt::Display for CommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Validation(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::CandidateRejected(_) | Self::StaleRoot { .. } | Self::Transaction(_) => None,
        }
    }
}

impl From<TransactionCodecError> for CommitError {
    fn from(value: TransactionCodecError) -> Self {
        Self::Codec(value)
    }
}

impl From<StoreError> for CommitError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<CandidateValidationError> for CommitError {
    fn from(value: CandidateValidationError) -> Self {
        Self::Validation(value)
    }
}

impl From<io::Error> for CommitError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Repository-rooted S20-390 transaction and fixed-head owner.
#[derive(Clone, Debug)]
pub struct TransactionRepository {
    root: PathBuf,
    object_store: ObjectStore,
}

impl TransactionRepository {
    /// Creates a repository handle. The explicit root must already exist.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            object_store: ObjectStore::new(root.clone()),
            root,
        }
    }

    /// Returns the configured repository root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Acquires shared repository-maintenance ownership for one composite
    /// transaction/ref operation.
    ///
    /// The guard must remain held until every object, transaction, head, and
    /// ref read or mutation in that operation is complete.
    ///
    /// # Errors
    ///
    /// Returns `TXN_IO` when the repository maintenance boundary cannot be
    /// created, verified, or locked.
    pub fn acquire_shared_maintenance(&self) -> Result<RepositoryMaintenanceGuard, CommitError> {
        initialize_repository_maintenance(&self.root)?;
        Ok(acquire_shared_repository_maintenance(&self.root)?)
    }

    /// Installs one explicit trusted genesis and makes it durably accepted.
    ///
    /// # Errors
    ///
    /// Fails if already initialized, supplied facts disagree, persistence
    /// fails, or the head cannot become durable.
    pub fn initialize_trusted_genesis(
        &self,
        input: TrustedGenesisInput<'_>,
    ) -> Result<AcceptedHead, CommitError> {
        self.initialize_trusted_genesis_inner(input, Fault::None)
    }

    /// Freshly validates and atomically commits one ordinary candidate.
    ///
    /// # Errors
    ///
    /// Returns a typed stale or validation result before any write, or the
    /// first exact object, receipt, CAS, recovery, or I/O failure.
    pub fn commit(&self, input: CommitInput<'_>) -> Result<CommitOutput, CommitError> {
        self.commit_inner(input, Fault::None)
    }

    /// Loads and verifies the complete currently accepted state.
    ///
    /// # Errors
    ///
    /// Returns `REF_HEAD_MISSING` when uninitialized or the first exact
    /// head, receipt, root, policy, object, or ancestry failure.
    pub fn accepted_head(&self) -> Result<AcceptedHead, CommitError> {
        self.ensure_read_layout()?;
        let maintenance = acquire_shared_repository_maintenance(&self.root)?;
        self.accepted_head_with_maintenance(&maintenance)
    }

    /// Loads and verifies the accepted head while a composite caller holds
    /// repository-maintenance ownership.
    ///
    /// # Errors
    ///
    /// Returns `TXN_IO` for a mismatched guard or invalid layout, or the first
    /// exact accepted-head verification failure.
    pub fn accepted_head_with_maintenance(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
    ) -> Result<AcceptedHead, CommitError> {
        self.validate_maintenance(maintenance)?;
        self.ensure_read_layout()?;
        let _lock = self.acquire_existing_lock()?;
        let transaction_id = self
            .read_head()?
            .ok_or_else(|| txn_commit_error(TransactionErrorCode::HeadMissing))?;
        self.load_accepted(transaction_id)
    }

    /// Loads and verifies an arbitrary durable transaction revision without
    /// consulting the accepted-head pointer.
    ///
    /// # Errors
    ///
    /// Returns the first exact receipt, root, policy, object, or ancestry
    /// failure for the requested transaction.
    pub fn verified_revision(
        &self,
        transaction_id: TransactionId,
    ) -> Result<VerifiedRevision, CommitError> {
        self.ensure_read_layout()?;
        let maintenance = acquire_shared_repository_maintenance(&self.root)?;
        self.verified_revision_with_maintenance(&maintenance, transaction_id)
    }

    /// Loads an arbitrary verified revision while a composite caller holds
    /// repository-maintenance ownership.
    ///
    /// # Errors
    ///
    /// Returns `TXN_IO` for a mismatched guard or invalid layout, or the first
    /// exact revision verification failure.
    pub fn verified_revision_with_maintenance(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
        transaction_id: TransactionId,
    ) -> Result<VerifiedRevision, CommitError> {
        self.validate_maintenance(maintenance)?;
        self.ensure_read_layout()?;
        let _lock = self.acquire_existing_lock()?;
        self.load_verified_revision(transaction_id)
    }

    /// Removes owned staging remnants and verifies the surviving accepted
    /// state without guessing or rolling back a corrupt head.
    ///
    /// # Errors
    ///
    /// Returns the first cleanup or accepted-state verification failure.
    pub fn recover(&self) -> Result<RecoveryReport, CommitError> {
        let _maintenance = self.acquire_shared_maintenance()?;
        self.ensure_layout_under_maintenance()?;
        let _lock = self.acquire_lock()?;
        let object_events = self.object_store.recover_staged()?;
        let removed_receipt_stages = self.remove_receipt_stages()?;
        let removed_head_stages = self.remove_head_stages()?;
        let accepted_transaction_id = self.read_head()?;
        if let Some(transaction_id) = accepted_transaction_id {
            self.load_accepted(transaction_id)?;
        }
        Ok(RecoveryReport {
            removed_object_stages: usize_to_u64(object_events.len())?,
            removed_receipt_stages,
            removed_head_stages,
            accepted_transaction_id,
        })
    }

    fn initialize_trusted_genesis_inner(
        &self,
        input: TrustedGenesisInput<'_>,
        fault: Fault,
    ) -> Result<AcceptedHead, CommitError> {
        let _maintenance = self.acquire_shared_maintenance()?;
        self.ensure_layout_under_maintenance()?;
        let _lock = self.acquire_lock()?;
        if self.read_head()?.is_some() {
            return Err(txn_commit_error(TransactionErrorCode::AlreadyInitialized));
        }
        validate_inventory(
            input.state_root,
            input.policy_root,
            input.objects,
            input.tombstoned_entities,
        )?;
        let changed_entity_bindings =
            derive_binding_diff(&[], &input.state_root.record.entity_bindings, None)?;
        let manifest = manifest_for_changed(&changed_entity_bindings, input.objects)?;
        self.persist_objects(&manifest, input.objects)?;
        fault.fail_if(Fault::AfterObjectsBeforeReceipt)?;

        let transaction = build_transaction(&TransactionRecord {
            format_version: 1,
            transaction_kind: TransactionKind::TrustedGenesis,
            workspace_id: input.state_root.record.workspace_id,
            parent_transaction_ids: Vec::new(),
            parent_roots: Vec::new(),
            schema_epoch_id: input.state_root.record.schema_epoch_id,
            policy_root_id: input.policy_root.root(),
            principal_id: None,
            candidate_id: None,
            candidate_result_id: None,
            validation_context_digest: None,
            validation_profile_id: None,
            committed_root: input.state_root.root,
            changed_entity_bindings,
            capability_summary_digest: None,
            selected_tests: Vec::new(),
            test_result_refs: Vec::new(),
            tombstoned_entities: input.tombstoned_entities.to_vec(),
            commit_metadata: CommitMetadata::restricted_v1(),
        })?;
        let receipt = build_transaction_receipt(&TransactionReceiptRecord {
            format_version: 1,
            transaction_id: transaction.transaction_id,
            stored_transaction: transaction.stored_bytes,
            stored_candidate: None,
            stored_candidate_result: None,
            stored_state_root: input.state_root.stored_bytes.clone(),
            stored_policy_root: input.policy_root.stored_bytes().to_vec(),
            object_manifest: manifest,
            durability_profile: CommitMetadata::restricted_v1().durability_profile,
        })?;
        self.persist_receipt(&receipt, fault)?;
        fault.fail_if(Fault::AfterReceiptBeforeHead)?;
        self.cas_head(None, receipt.transaction.transaction_id, fault)?;
        self.load_accepted(receipt.transaction.transaction_id)
    }

    fn commit_inner(
        &self,
        input: CommitInput<'_>,
        fault: Fault,
    ) -> Result<CommitOutput, CommitError> {
        let _maintenance = self.acquire_shared_maintenance()?;
        self.ensure_layout_under_maintenance()?;
        let _lock = self.acquire_lock()?;
        let actual = self
            .read_head()?
            .ok_or_else(|| txn_commit_error(TransactionErrorCode::HeadMissing))?;
        if actual != input.expected_parent {
            return Err(CommitError::StaleRoot {
                expected: input.expected_parent,
                actual,
            });
        }
        let base = self.load_accepted(actual)?;
        let context = CandidateValidationContext::new(
            actual,
            base.state_root(),
            base.objects(),
            base.tombstoned_entities(),
            base.policy_root(),
            input.principal_id,
            input.capabilities,
            input.now_unix_millis,
            input.limits,
        )?;
        let validation = validate_candidate_bytes(&context, input.stored_candidate)?;
        if !validation.is_valid() {
            return Err(CommitError::CandidateRejected(Box::new(validation)));
        }
        let plan = validation
            .validated_plan()
            .ok_or_else(|| txn_commit_error(TransactionErrorCode::InternalInvariant))?;
        if !validation.result().record.selected_tests.is_empty() {
            return Err(txn_commit_error(
                TransactionErrorCode::TestEvidenceUnsupported,
            ));
        }
        let changed_entity_bindings = derive_binding_diff(
            &base.state_root().record.entity_bindings,
            &plan.candidate_root().record.entity_bindings,
            Some(&plan.candidate().record.operations),
        )?;
        let manifest =
            manifest_for_changed(&changed_entity_bindings, plan.proposed_state().entities())?;
        let tombstones = next_tombstones(
            base.tombstoned_entities(),
            &changed_entity_bindings,
            plan.proposed_state().entities(),
        )?;
        self.persist_objects(&manifest, plan.proposed_state().entities())?;
        fault.fail_if(Fault::AfterObjectsBeforeReceipt)?;

        let result = validation.result().clone();
        let candidate = plan.candidate();
        let transaction = build_transaction(&TransactionRecord {
            format_version: 1,
            transaction_kind: TransactionKind::OrdinaryCandidate,
            workspace_id: plan.candidate_root().record.workspace_id,
            parent_transaction_ids: vec![actual],
            parent_roots: vec![base.state_root().root],
            schema_epoch_id: plan.candidate_root().record.schema_epoch_id,
            policy_root_id: base.policy_root().root(),
            principal_id: Some(input.principal_id),
            candidate_id: Some(candidate.candidate_id),
            candidate_result_id: Some(result.candidate_result_id),
            validation_context_digest: Some(result.record.validation_context_digest),
            validation_profile_id: Some(result.record.validation_profile_id),
            committed_root: plan.candidate_root().root,
            changed_entity_bindings,
            capability_summary_digest: Some(candidate.record.capability_summary_digest),
            selected_tests: result.record.selected_tests.clone(),
            test_result_refs: Vec::new(),
            tombstoned_entities: tombstones,
            commit_metadata: CommitMetadata::restricted_v1(),
        })?;
        let receipt = build_transaction_receipt(&TransactionReceiptRecord {
            format_version: 1,
            transaction_id: transaction.transaction_id,
            stored_transaction: transaction.stored_bytes,
            stored_candidate: Some(candidate.stored_bytes.clone()),
            stored_candidate_result: Some(result.stored_bytes.clone()),
            stored_state_root: plan.candidate_root().stored_bytes.clone(),
            stored_policy_root: base.policy_root().stored_bytes().to_vec(),
            object_manifest: manifest,
            durability_profile: CommitMetadata::restricted_v1().durability_profile,
        })?;
        self.persist_receipt(&receipt, fault)?;
        fault.fail_if(Fault::AfterReceiptBeforeHead)?;
        self.cas_head(Some(actual), receipt.transaction.transaction_id, fault)?;
        Ok(CommitOutput {
            transaction_id: receipt.transaction.transaction_id,
            receipt_id: receipt.receipt_id,
            state_root: receipt.state_root,
            candidate_result: result,
        })
    }

    fn load_accepted(&self, transaction_id: TransactionId) -> Result<AcceptedHead, CommitError> {
        let revision = self.load_verified_revision(transaction_id)?;
        Ok(AcceptedHead { revision })
    }

    fn load_verified_revision(
        &self,
        transaction_id: TransactionId,
    ) -> Result<VerifiedRevision, CommitError> {
        let receipt = self.read_receipt_readonly(transaction_id)?;
        self.verify_transaction_relationship(&receipt)?;
        let objects = self.load_objects(&receipt.state_root)?;
        verify_manifest_lengths(&receipt.record.object_manifest, &objects)?;
        validate_inventory(
            &receipt.state_root,
            &receipt.policy_root,
            &objects,
            &receipt.transaction.record.tombstoned_entities,
        )?;
        Ok(VerifiedRevision {
            transaction_id,
            receipt,
            objects,
        })
    }

    fn verify_transaction_relationship(
        &self,
        receipt: &ImportedTransactionReceipt,
    ) -> Result<(), CommitError> {
        let record = &receipt.transaction.record;
        match record.transaction_kind {
            TransactionKind::TrustedGenesis => {
                let expected =
                    derive_binding_diff(&[], &receipt.state_root.record.entity_bindings, None)?;
                if expected != record.changed_entity_bindings {
                    return Err(txn_commit_error(TransactionErrorCode::GenesisInvalid));
                }
            }
            TransactionKind::OrdinaryCandidate => {
                let parent_id = record.parent_transaction_ids[0];
                let parent = self.read_receipt_readonly(parent_id)?;
                if parent.transaction.transaction_id != parent_id
                    || parent.state_root.root != record.parent_roots[0]
                    || parent.state_root.record.workspace_id != record.workspace_id
                    || parent.state_root.record.schema_epoch_id != record.schema_epoch_id
                    || parent.policy_root.root() != record.policy_root_id
                {
                    return Err(txn_commit_error(TransactionErrorCode::ParentShape));
                }
                let candidate = receipt.candidate.as_ref().ok_or_else(|| {
                    txn_commit_error(TransactionErrorCode::ReceiptBindingMismatch)
                })?;
                let expected = derive_binding_diff(
                    &parent.state_root.record.entity_bindings,
                    &receipt.state_root.record.entity_bindings,
                    Some(&candidate.record.operations),
                )?;
                if expected != record.changed_entity_bindings {
                    return Err(txn_commit_error(
                        TransactionErrorCode::ChangedBindingInvalid,
                    ));
                }
                let expected_tombstones = next_tombstones_from_records(
                    &parent.transaction.record.tombstoned_entities,
                    &record.changed_entity_bindings,
                    &receipt.state_root.record.entity_bindings,
                )?;
                if expected_tombstones != record.tombstoned_entities {
                    return Err(txn_commit_error(TransactionErrorCode::TombstoneInvalid));
                }
            }
        }
        Ok(())
    }

    fn load_objects(&self, root: &AcceptedStateRoot) -> Result<Vec<EntityObject>, CommitError> {
        let verifier = entity_verifier(root.record.schema_epoch_id);
        root.record
            .entity_bindings
            .iter()
            .map(|(entity_id, object_id)| {
                let bytes = self.object_store.read(*object_id, &verifier)?;
                let object = import_entity_object(root.record.schema_epoch_id, &bytes)
                    .map_err(TransactionCodecError::Scb)?;
                if object.record().entity_id != *entity_id || object.object_id() != *object_id {
                    return Err(txn_commit_error(
                        TransactionErrorCode::ObjectInventoryMismatch,
                    ));
                }
                Ok(object)
            })
            .collect()
    }

    fn persist_objects(
        &self,
        manifest: &[ObjectManifestEntry],
        objects: &[EntityObject],
    ) -> Result<(), CommitError> {
        let by_id = objects
            .iter()
            .map(|object| (object.object_id(), object))
            .collect::<BTreeMap<_, _>>();
        for entry in manifest {
            let object = by_id
                .get(&entry.object_id)
                .ok_or_else(|| txn_commit_error(TransactionErrorCode::ObjectInventoryMismatch))?;
            if usize_to_u64(object.stored_bytes().len())? != entry.stored_length {
                return Err(txn_commit_error(
                    TransactionErrorCode::ObjectInventoryMismatch,
                ));
            }
            let verifier = entity_verifier(object.schema_epoch_id());
            self.object_store
                .put(entry.object_id, object.stored_bytes(), &verifier)?;
        }
        Ok(())
    }

    fn persist_receipt(
        &self,
        receipt: &ImportedTransactionReceipt,
        fault: Fault,
    ) -> Result<(), CommitError> {
        let final_path = self.receipt_path(receipt.transaction.transaction_id)?;
        let final_dir = final_path
            .parent()
            .ok_or_else(|| txn_commit_error(TransactionErrorCode::Io))?;
        if path_exists(&final_path)? {
            return Self::verify_existing_receipt(&final_path, receipt);
        }
        let (stage_path, mut stage) = reserve_stage(final_dir, RECEIPT_STAGE_PREFIX)?;
        if fault == Fault::DuringReceiptWrite {
            let split = receipt.stored_bytes.len() / 2;
            stage.write_all(&receipt.stored_bytes[..split])?;
            stage.flush()?;
            stage.sync_all()?;
            return Err(txn_commit_error(
                TransactionErrorCode::RecoveryReceiptIncomplete,
            ));
        }
        stage.write_all(&receipt.stored_bytes)?;
        stage.flush()?;
        stage.sync_all()?;
        drop(stage);
        let staged = bounded_read(&stage_path, MAX_STANDALONE_BYTES)?;
        let imported = import_transaction_receipt(&staged)?;
        if imported != *receipt {
            return Err(txn_commit_error(
                TransactionErrorCode::ReceiptBindingMismatch,
            ));
        }
        match fs::hard_link(&stage_path, &final_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Self::verify_existing_receipt(&final_path, receipt)?;
                remove_file_if_exists(&stage_path)?;
                sync_dir(final_dir)?;
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        sync_dir(final_dir)?;
        remove_file_if_exists(&stage_path)?;
        sync_dir(final_dir)?;
        let final_bytes = bounded_read(&final_path, MAX_STANDALONE_BYTES)?;
        if import_transaction_receipt(&final_bytes)? != *receipt {
            return Err(txn_commit_error(
                TransactionErrorCode::ReceiptBindingMismatch,
            ));
        }
        Ok(())
    }

    fn verify_existing_receipt(
        path: &Path,
        expected: &ImportedTransactionReceipt,
    ) -> Result<(), CommitError> {
        let bytes = bounded_read(path, MAX_STANDALONE_BYTES)?;
        let existing = import_transaction_receipt(&bytes)?;
        if existing == *expected {
            File::open(path)?.sync_all()?;
            let parent = path
                .parent()
                .ok_or_else(|| txn_commit_error(TransactionErrorCode::Io))?;
            sync_dir(parent)?;
            Ok(())
        } else {
            Err(txn_commit_error(TransactionErrorCode::ReceiptConflict))
        }
    }

    fn read_receipt_readonly(
        &self,
        transaction_id: TransactionId,
    ) -> Result<ImportedTransactionReceipt, CommitError> {
        let path = self.receipt_path_readonly(transaction_id)?;
        Self::read_receipt_at(transaction_id, &path)
    }

    fn read_receipt_at(
        transaction_id: TransactionId,
        path: &Path,
    ) -> Result<ImportedTransactionReceipt, CommitError> {
        if !path_exists(path)? {
            return Err(txn_commit_error(
                TransactionErrorCode::RecoveryReceiptIncomplete,
            ));
        }
        let bytes = bounded_read(path, MAX_STANDALONE_BYTES)?;
        let receipt = import_transaction_receipt(&bytes)?;
        if receipt.transaction.transaction_id == transaction_id {
            Ok(receipt)
        } else {
            Err(txn_commit_error(
                TransactionErrorCode::ReceiptBindingMismatch,
            ))
        }
    }

    fn cas_head(
        &self,
        expected: Option<TransactionId>,
        new: TransactionId,
        fault: Fault,
    ) -> Result<(), CommitError> {
        if self.read_head()? != expected {
            return Err(txn_commit_error(TransactionErrorCode::RefCasStale));
        }
        fault.fail_if(Fault::BeforeHeadRename)?;
        let head_dir = self.head_dir();
        let head_path = self.head_path();
        let bytes = encode_head(new);
        let (stage_path, mut stage) = reserve_stage(&head_dir, HEAD_STAGE_PREFIX)?;
        stage.write_all(&bytes)?;
        stage.flush()?;
        stage.sync_all()?;
        drop(stage);
        if decode_head(&bounded_read(&stage_path, HEAD_LEN)?)? != new {
            return Err(txn_commit_error(TransactionErrorCode::HeadCorrupt));
        }
        reject_symlink_if_present(&head_path)?;
        fs::rename(&stage_path, &head_path)?;
        fault.fail_if(Fault::AfterHeadRenameBeforeSync)?;
        sync_dir(&head_dir)?;
        if self.read_head()? == Some(new) {
            Ok(())
        } else {
            Err(txn_commit_error(TransactionErrorCode::HeadCorrupt))
        }
    }

    fn read_head(&self) -> Result<Option<TransactionId>, CommitError> {
        let path = self.head_path();
        if !path_exists(&path)? {
            return Ok(None);
        }
        let bytes = bounded_read(&path, HEAD_LEN)?;
        decode_head(&bytes).map(Some)
    }

    fn receipt_path(&self, transaction_id: TransactionId) -> Result<PathBuf, CommitError> {
        let hex = hex_id(transaction_id.as_bytes());
        let mut current = self.transactions_dir();
        for component in [&hex[0..2], &hex[2..4]] {
            current = create_dir_component(&current, component)?;
        }
        Ok(current.join(format!("{hex}.receipt.scb1")))
    }

    fn receipt_path_readonly(&self, transaction_id: TransactionId) -> Result<PathBuf, CommitError> {
        let hex = hex_id(transaction_id.as_bytes());
        let final_path = self
            .transactions_dir()
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{hex}.receipt.scb1"));
        let mut current = self.transactions_dir();
        ensure_existing_directory(&current)?;
        for component in [&hex[0..2], &hex[2..4]] {
            let next = current.join(component);
            match fs::symlink_metadata(&next) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(txn_commit_error(TransactionErrorCode::Io));
                }
                Ok(_) => current = next,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(final_path)
    }

    #[cfg(test)]
    fn ensure_layout(&self) -> Result<(), CommitError> {
        initialize_repository_maintenance(&self.root)?;
        self.ensure_layout_under_maintenance()
    }

    fn ensure_layout_under_maintenance(&self) -> Result<(), CommitError> {
        ensure_existing_directory(&self.root)?;
        let transactions = create_dir_component(&self.root, "transactions")?;
        create_dir_component(&transactions, "v1")?;
        create_dir_component(&self.root, "heads")?;
        create_dir_component(&self.root, "locks")?;
        Ok(())
    }

    fn ensure_read_layout(&self) -> Result<(), CommitError> {
        ensure_existing_directory(&self.root)?;
        ensure_existing_directory(&self.transactions_dir())?;
        ensure_existing_directory(&self.head_dir())?;
        ensure_existing_directory(&self.root.join("locks"))?;
        Ok(())
    }

    fn validate_maintenance(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
    ) -> Result<(), CommitError> {
        if !maintenance.covers(&self.root) {
            return Err(txn_commit_error(TransactionErrorCode::Io));
        }
        Ok(())
    }

    fn acquire_lock(&self) -> Result<File, CommitError> {
        self.acquire_lock_inner(false)
    }

    fn acquire_lock_inner(&self, fail_after_create_before_sync: bool) -> Result<File, CommitError> {
        let path = self.root.join("locks").join("accepted.lock");
        reject_symlink_if_present(&path)?;
        let (file, created) = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                reject_symlink_if_present(&path)?;
                (
                    OpenOptions::new().read(true).write(true).open(&path)?,
                    false,
                )
            }
            Err(error) => return Err(error.into()),
        };
        if created && fail_after_create_before_sync {
            return Err(
                io::Error::other("injected accepted-lock create-before-sync failure").into(),
            );
        }
        if !file.metadata()?.is_file() {
            return Err(txn_commit_error(TransactionErrorCode::Io));
        }
        file.sync_all()?;
        sync_dir(
            path.parent()
                .ok_or_else(|| txn_commit_error(TransactionErrorCode::Io))?,
        )?;
        file.lock()?;
        Ok(file)
    }

    fn acquire_existing_lock(&self) -> Result<File, CommitError> {
        let path = self.root.join("locks").join("accepted.lock");
        reject_symlink_if_present(&path)?;
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        if !file.metadata()?.is_file() {
            return Err(txn_commit_error(TransactionErrorCode::Io));
        }
        file.lock()?;
        Ok(file)
    }

    fn transactions_dir(&self) -> PathBuf {
        self.root.join("transactions").join("v1")
    }

    fn head_dir(&self) -> PathBuf {
        self.root.join("heads")
    }

    fn head_path(&self) -> PathBuf {
        self.head_dir().join("accepted")
    }

    fn remove_receipt_stages(&self) -> Result<u64, CommitError> {
        remove_stages_recursive(&self.transactions_dir(), RECEIPT_STAGE_PREFIX, 2)
    }

    fn remove_head_stages(&self) -> Result<u64, CommitError> {
        remove_stages_recursive(&self.head_dir(), HEAD_STAGE_PREFIX, 0)
    }

    #[cfg(test)]
    fn commit_with_fault(
        &self,
        input: CommitInput<'_>,
        fault: Fault,
    ) -> Result<CommitOutput, CommitError> {
        self.commit_inner(input, fault)
    }
}

fn validate_inventory(
    state_root: &AcceptedStateRoot,
    policy_root: &AcceptedPolicyRoot,
    objects: &[EntityObject],
    tombstones: &[EntityId],
) -> Result<(), CommitError> {
    if state_root.record.policy_root != policy_root.root()
        || state_root.record.workspace_id != policy_root.record().workspace_id
        || objects.len() != state_root.record.entity_bindings.len()
        || tombstones.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(txn_commit_error(
            TransactionErrorCode::ObjectInventoryMismatch,
        ));
    }
    for (object, (entity_id, object_id)) in objects.iter().zip(&state_root.record.entity_bindings) {
        let imported =
            import_entity_object(state_root.record.schema_epoch_id, object.stored_bytes())
                .map_err(TransactionCodecError::Scb)?;
        if imported != *object
            || object.schema_epoch_id() != state_root.record.schema_epoch_id
            || object.record().entity_id != *entity_id
            || object.object_id() != *object_id
        {
            return Err(txn_commit_error(
                TransactionErrorCode::ObjectInventoryMismatch,
            ));
        }
    }
    if tombstones.iter().any(|entity_id| {
        state_root
            .record
            .entity_bindings
            .binary_search_by_key(entity_id, |(candidate, _)| *candidate)
            .is_ok()
    }) {
        return Err(txn_commit_error(TransactionErrorCode::TombstoneInvalid));
    }
    Ok(())
}

fn verify_manifest_lengths(
    manifest: &[ObjectManifestEntry],
    objects: &[EntityObject],
) -> Result<(), CommitError> {
    let by_id = objects
        .iter()
        .map(|object| (object.object_id(), object.stored_bytes().len()))
        .collect::<BTreeMap<_, _>>();
    for entry in manifest {
        let Some(actual_length) = by_id.get(&entry.object_id) else {
            return Err(txn_commit_error(
                TransactionErrorCode::ObjectInventoryMismatch,
            ));
        };
        if usize_to_u64(*actual_length)? != entry.stored_length {
            return Err(txn_commit_error(
                TransactionErrorCode::ObjectInventoryMismatch,
            ));
        }
    }
    Ok(())
}

fn derive_binding_diff(
    base: &[(EntityId, ObjectId)],
    committed: &[(EntityId, ObjectId)],
    operations: Option<&[sley_mutate::MutationOperation]>,
) -> Result<Vec<ChangedBinding>, CommitError> {
    let base = base.iter().copied().collect::<BTreeMap<_, _>>();
    let committed = committed.iter().copied().collect::<BTreeMap<_, _>>();
    let identities = base
        .keys()
        .chain(committed.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut out = Vec::new();
    for entity_id in identities {
        let preimage = base.get(&entity_id).copied();
        let postimage = committed.get(&entity_id).copied();
        if preimage == postimage {
            continue;
        }
        let mutation_ordinals = operations.map_or_else(Vec::new, |operations| {
            operations
                .iter()
                .filter(|operation| operation.target_entity == entity_id)
                .map(|operation| operation.ordinal)
                .collect()
        });
        if operations.is_some() && mutation_ordinals.is_empty() {
            return Err(txn_commit_error(
                TransactionErrorCode::ChangedBindingInvalid,
            ));
        }
        out.push(ChangedBinding {
            entity_id,
            preimage,
            postimage,
            mutation_ordinals,
        });
    }
    Ok(out)
}

fn manifest_for_changed(
    changed: &[ChangedBinding],
    objects: &[EntityObject],
) -> Result<Vec<ObjectManifestEntry>, CommitError> {
    let by_id = objects
        .iter()
        .map(|object| (object.object_id(), object))
        .collect::<BTreeMap<_, _>>();
    let mut manifest = changed
        .iter()
        .filter_map(|binding| binding.postimage)
        .map(|object_id| {
            let object = by_id
                .get(&object_id)
                .ok_or_else(|| txn_commit_error(TransactionErrorCode::ObjectInventoryMismatch))?;
            Ok(ObjectManifestEntry {
                object_id,
                stored_length: usize_to_u64(object.stored_bytes().len())?,
            })
        })
        .collect::<Result<Vec<_>, CommitError>>()?;
    manifest.sort_by_key(|entry| entry.object_id);
    manifest.dedup_by_key(|entry| entry.object_id);
    Ok(manifest)
}

fn next_tombstones(
    previous: &[EntityId],
    changed: &[ChangedBinding],
    proposed_objects: &[EntityObject],
) -> Result<Vec<EntityId>, CommitError> {
    let bindings = proposed_objects
        .iter()
        .map(|object| (object.record().entity_id, object.object_id()))
        .collect::<Vec<_>>();
    next_tombstones_from_records(previous, changed, &bindings)
}

fn next_tombstones_from_records(
    previous: &[EntityId],
    changed: &[ChangedBinding],
    committed: &[(EntityId, ObjectId)],
) -> Result<Vec<EntityId>, CommitError> {
    let mut tombstones = previous.iter().copied().collect::<BTreeSet<_>>();
    for binding in changed {
        if binding.preimage.is_some() && binding.postimage.is_none() {
            tombstones.insert(binding.entity_id);
        }
        if binding.postimage.is_some() && tombstones.contains(&binding.entity_id) {
            return Err(txn_commit_error(TransactionErrorCode::TombstoneInvalid));
        }
    }
    if committed
        .iter()
        .any(|(entity_id, _)| tombstones.contains(entity_id))
    {
        return Err(txn_commit_error(TransactionErrorCode::TombstoneInvalid));
    }
    Ok(tombstones.into_iter().collect())
}

fn entity_verifier(epoch: sley_id::SchemaEpochId) -> impl Fn(&[u8]) -> Result<ObjectId, ScbError> {
    move |bytes| import_entity_object(epoch, bytes).map(|object| object.object_id())
}

fn encode_head(transaction_id: TransactionId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(HEAD_LEN - 32);
    prefix.extend_from_slice(HEAD_MAGIC);
    prefix.extend_from_slice(&encode_uvar(HEAD_VERSION));
    prefix.extend_from_slice(transaction_id.as_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(HEAD_CHECKSUM_DOMAIN);
    hasher.update(&prefix);
    let mut out = prefix;
    out.extend_from_slice(hasher.finalize().as_bytes());
    out
}

fn decode_head(bytes: &[u8]) -> Result<TransactionId, CommitError> {
    if bytes.len() != HEAD_LEN
        || &bytes[..HEAD_MAGIC.len()] != HEAD_MAGIC
        || bytes[HEAD_MAGIC.len()] != 1
    {
        return Err(txn_commit_error(TransactionErrorCode::HeadCorrupt));
    }
    let prefix_len = HEAD_LEN - 32;
    let mut hasher = blake3::Hasher::new();
    hasher.update(HEAD_CHECKSUM_DOMAIN);
    hasher.update(&bytes[..prefix_len]);
    if &bytes[prefix_len..] != hasher.finalize().as_bytes() {
        return Err(txn_commit_error(TransactionErrorCode::HeadCorrupt));
    }
    let mut id = [0_u8; 32];
    id.copy_from_slice(&bytes[HEAD_MAGIC.len() + 1..prefix_len]);
    Ok(TransactionId::from_bytes(id))
}

fn ensure_existing_directory(path: &Path) -> Result<(), CommitError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(txn_commit_error(TransactionErrorCode::Io));
    }
    Ok(())
}

fn create_dir_component(parent: &Path, component: &str) -> Result<PathBuf, CommitError> {
    ensure_existing_directory(parent)?;
    let path = parent.join(component);
    match fs::create_dir(&path) {
        Ok(()) => sync_dir(parent)?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure_existing_directory(&path)?;
    Ok(path)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), CommitError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(txn_commit_error(TransactionErrorCode::Io))
        }
        Ok(metadata) if !metadata.is_file() => Err(txn_commit_error(TransactionErrorCode::Io)),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn path_exists(path: &Path) -> Result<bool, CommitError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(txn_commit_error(TransactionErrorCode::Io))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn reserve_stage(dir: &Path, prefix: &str) -> Result<(PathBuf, File), CommitError> {
    ensure_existing_directory(dir)?;
    for _ in 0..MAX_STAGE_ATTEMPTS {
        let token = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("{prefix}{}-{token:016x}{STAGE_SUFFIX}", std::process::id());
        let path = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(txn_commit_error(TransactionErrorCode::Io))
}

fn bounded_read(path: &Path, maximum: usize) -> Result<Vec<u8>, CommitError> {
    reject_symlink_if_present(path)?;
    let file = File::open(path)?;
    let length = usize::try_from(file.metadata()?.len())
        .map_err(|_| txn_commit_error(TransactionErrorCode::ResourceLimit))?;
    if length > maximum {
        return Err(txn_commit_error(TransactionErrorCode::ResourceLimit));
    }
    let mut bytes = Vec::with_capacity(length);
    file.take(u64::try_from(maximum + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(txn_commit_error(TransactionErrorCode::ResourceLimit));
    }
    Ok(bytes)
}

fn sync_dir(path: &Path) -> Result<(), CommitError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), CommitError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_stages_recursive(
    root: &Path,
    prefix: &str,
    remaining_depth: usize,
) -> Result<u64, CommitError> {
    ensure_existing_directory(root)?;
    let mut removed = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() && remaining_depth > 0 {
            removed = removed
                .checked_add(remove_stages_recursive(&path, prefix, remaining_depth - 1)?)
                .ok_or_else(|| txn_commit_error(TransactionErrorCode::ResourceLimit))?;
        } else if file_type.is_file() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(prefix) && name.ends_with(STAGE_SUFFIX) {
                fs::remove_file(&path)?;
                removed = removed
                    .checked_add(1)
                    .ok_or_else(|| txn_commit_error(TransactionErrorCode::ResourceLimit))?;
            }
        }
    }
    if removed > 0 {
        sync_dir(root)?;
    }
    Ok(removed)
}

fn hex_id(bytes: &[u8; 32]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn usize_to_u64(value: usize) -> Result<u64, CommitError> {
    u64::try_from(value).map_err(|_| txn_commit_error(TransactionErrorCode::ResourceLimit))
}

fn txn_commit_error(code: TransactionErrorCode) -> CommitError {
    CommitError::Transaction(code)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    AfterObjectsBeforeReceipt,
    DuringReceiptWrite,
    AfterReceiptBeforeHead,
    BeforeHeadRename,
    AfterHeadRenameBeforeSync,
}

impl Fault {
    fn fail_if(self, boundary: Self) -> Result<(), CommitError> {
        if self == boundary {
            let code = match boundary {
                Self::DuringReceiptWrite => TransactionErrorCode::RecoveryReceiptIncomplete,
                Self::BeforeHeadRename | Self::AfterHeadRenameBeforeSync => {
                    TransactionErrorCode::RecoveryRefCasIncomplete
                }
                Self::None | Self::AfterObjectsBeforeReceipt | Self::AfterReceiptBeforeHead => {
                    TransactionErrorCode::Io
                }
            };
            Err(txn_commit_error(code))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use sley_id::{CandidateNonce, ObjectId, WorkspaceId};
    use sley_mutate::{
        BoundPrecondition, CandidateExpiry, CandidateRecord, EntityObjectRecord,
        ExpectedIdentityAbsent, ImportedCandidate, MutationClass, MutationOperation,
        MutationPayload, PreconditionPayload, PreimageRequirement, build_candidate,
        build_entity_object, full_validation_profile_id,
        value::{EntityBodyValue, EntityIdSet, NamespaceBody},
    };
    use sley_policy::{
        PolicyResourceCeilings, PolicyRootBuilder, PrincipalGrantBuilder,
        build_capability_summary_projection, conformance_registry as policy_registry,
    };
    use sley_state_root::{
        StateRootBuilder, conformance_epoch_id as state_epoch_id,
        conformance_registry as state_registry,
    };

    use super::*;

    const NOW: u64 = 1_000;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let sequence = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sley-txn-{label}-{}-{sequence:016x}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    struct Fixture {
        temp: TempDir,
        repository: TransactionRepository,
        principal_id: PrincipalId,
        genesis_transaction_id: TransactionId,
        candidate: ImportedCandidate,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let temp = TempDir::new(label);
            let repository = TransactionRepository::new(&temp.path);
            let workspace_id = fixed(1, WorkspaceId::from_bytes);
            let principal_id = fixed(2, PrincipalId::from_bytes);
            let base_entity = fixed(10, EntityId::from_bytes);
            let grant = PrincipalGrantBuilder::new(PolicyResourceCeilings::new(
                1_000, 1_000, 1_000, 100, 100, 100,
            ))
            .mutation_class(MutationClass::CreateEntity)
            .build()
            .unwrap();
            let policy = PolicyRootBuilder::new(workspace_id)
                .principal_grant(principal_id, grant)
                .build(&policy_registry().unwrap())
                .unwrap();
            let schema_epoch_id = state_epoch_id().unwrap();
            let base_object = build_entity_object(
                schema_epoch_id,
                &EntityObjectRecord {
                    entity_id: base_entity,
                    body: namespace_body(),
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
            let genesis = repository
                .initialize_trusted_genesis(TrustedGenesisInput::new(
                    &base_state,
                    &policy,
                    core::slice::from_ref(&base_object),
                    &[],
                ))
                .unwrap();
            let genesis_transaction_id = genesis.transaction_id();
            let candidate = candidate_for(
                workspace_id,
                principal_id,
                genesis_transaction_id,
                &base_state,
                &policy,
                30,
            );
            Self {
                temp,
                repository,
                principal_id,
                genesis_transaction_id,
                candidate,
            }
        }

        fn input(&self) -> CommitInput<'_> {
            CommitInput::new(
                self.genesis_transaction_id,
                &self.candidate.stored_bytes,
                self.principal_id,
                &[],
                NOW,
                CandidateValidationLimits::full_v1(),
            )
        }

        fn alternate_candidate(&self, nonce_byte: u8) -> ImportedCandidate {
            let head = self.repository.accepted_head().unwrap();
            candidate_for(
                head.state_root().record.workspace_id,
                self.principal_id,
                self.genesis_transaction_id,
                head.state_root(),
                head.policy_root(),
                nonce_byte,
            )
        }
    }

    fn fixed<T>(byte: u8, constructor: impl FnOnce([u8; 32]) -> T) -> T {
        constructor([byte; 32])
    }

    fn namespace_body() -> EntityBodyValue {
        EntityBodyValue::Namespace(NamespaceBody {
            parent: None,
            members: EntityIdSet::from_unsorted(vec![]).unwrap(),
        })
    }

    fn candidate_for(
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        base_transaction_id: TransactionId,
        base_state: &AcceptedStateRoot,
        policy: &AcceptedPolicyRoot,
        nonce_byte: u8,
    ) -> ImportedCandidate {
        let nonce = fixed(nonce_byte, CandidateNonce::from_bytes);
        let target = EntityId::derive(workspace_id, nonce, 3, 0);
        let summary = build_capability_summary_projection(
            principal_id,
            workspace_id,
            policy.root(),
            base_state.root,
            &[],
        )
        .unwrap();
        build_candidate(&CandidateRecord {
            format_version: 1,
            workspace_id,
            base_transaction_id,
            base_root: base_state.root,
            schema_epoch_id: base_state.record.schema_epoch_id,
            policy_root_id: policy.root(),
            principal_id,
            capability_summary_digest: summary.digest(),
            operations: vec![MutationOperation {
                ordinal: 0,
                class: MutationClass::CreateEntity,
                target_kind: 3,
                target_entity: target,
                field_tag: None,
                payload: MutationPayload::CreateEntity(namespace_body()),
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
        .unwrap()
    }

    #[test]
    fn head_codec_detects_corruption() {
        let transaction_id = TransactionId::from_bytes([7; 32]);
        let bytes = encode_head(transaction_id);
        assert_eq!(decode_head(&bytes).unwrap(), transaction_id);
        let mut corrupted = bytes;
        *corrupted.last_mut().unwrap() ^= 1;
        assert_eq!(
            decode_head(&corrupted).unwrap_err().code(),
            "REF_HEAD_CORRUPT"
        );
    }

    #[test]
    fn interrupted_accepted_lock_creation_is_redurabilized_on_retry() {
        let temp = TempDir::new("accepted-lock-retry");
        let repository = TransactionRepository::new(&temp.path);
        let _maintenance = repository.acquire_shared_maintenance().unwrap();
        repository.ensure_layout_under_maintenance().unwrap();

        assert_eq!(
            repository.acquire_lock_inner(true).unwrap_err().code(),
            "TXN_IO"
        );
        assert!(temp.path.join("locks/accepted.lock").is_file());
        drop(repository.acquire_lock().unwrap());
        drop(repository.acquire_existing_lock().unwrap());
    }

    #[test]
    fn valid_commit_advances_only_to_a_complete_verified_receipt() {
        let fixture = Fixture::new("valid");
        let output = fixture.repository.commit(fixture.input()).unwrap();
        assert_eq!(
            output.candidate_result().record.decision,
            CandidateDecision::Valid
        );
        assert_ne!(output.transaction_id(), fixture.genesis_transaction_id);
        assert_ne!(output.state_root().root, fixture.candidate.record.base_root);

        let accepted = fixture.repository.accepted_head().unwrap();
        assert_eq!(accepted.transaction_id(), output.transaction_id());
        assert_eq!(accepted.receipt().receipt_id, output.receipt_id());
        assert_eq!(accepted.state_root(), output.state_root());
        assert_eq!(accepted.objects().len(), 2);
        assert_eq!(
            accepted.receipt().candidate_result.as_ref().unwrap(),
            output.candidate_result()
        );

        let recovery = fixture.repository.recover().unwrap();
        assert_eq!(
            recovery.accepted_transaction_id,
            Some(output.transaction_id())
        );
        assert_eq!(recovery.removed_object_stages, 0);
        assert_eq!(recovery.removed_receipt_stages, 0);
        assert_eq!(recovery.removed_head_stages, 0);
    }

    #[test]
    fn verified_revision_loads_non_head_transaction_without_acceptance_claim() {
        let fixture = Fixture::new("verified-non-head");
        let output = fixture.repository.commit(fixture.input()).unwrap();

        let genesis = fixture
            .repository
            .verified_revision(fixture.genesis_transaction_id)
            .unwrap();
        assert_eq!(genesis.transaction_id(), fixture.genesis_transaction_id);
        assert_eq!(
            fixture.repository.accepted_head().unwrap().transaction_id(),
            output.transaction_id()
        );
        assert_ne!(genesis.transaction_id(), output.transaction_id());
        assert!(genesis.receipt().candidate_result.is_none());
    }

    #[test]
    fn verified_revision_does_not_consult_corrupt_accepted_head() {
        let fixture = Fixture::new("verified-corrupt-head");
        let output = fixture.repository.commit(fixture.input()).unwrap();
        fs::write(fixture.repository.head_path(), b"not-a-valid-head").unwrap();

        let revision = fixture
            .repository
            .verified_revision(output.transaction_id())
            .unwrap();
        assert_eq!(revision.transaction_id(), output.transaction_id());
        assert_eq!(
            fixture.repository.accepted_head().unwrap_err().code(),
            "REF_HEAD_CORRUPT"
        );
    }

    #[cfg(unix)]
    #[test]
    fn verified_revision_rejects_symlinked_receipt_fanout() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new("verified-symlink-fanout");
        let outside = TempDir::new("verified-symlink-outside");
        let repository = TransactionRepository::new(&temp.path);
        repository.ensure_layout().unwrap();
        symlink(
            &outside.path,
            temp.path.join("transactions").join("v1").join("ab"),
        )
        .unwrap();
        let transaction_id = TransactionId::from_bytes([0xab; 32]);
        assert_eq!(
            repository
                .verified_revision(transaction_id)
                .unwrap_err()
                .code(),
            "TXN_IO"
        );
    }

    #[test]
    fn stale_concurrent_commit_never_last_write_wins() {
        let fixture = Fixture::new("stale");
        let first = fixture.repository.commit(fixture.input()).unwrap();
        let second = fixture.repository.commit(fixture.input()).unwrap_err();
        assert_eq!(second.code(), "STALE_ROOT");
        assert_eq!(second.numeric_code(), Some(36_002));
        assert_eq!(
            fixture.repository.accepted_head().unwrap().transaction_id(),
            first.transaction_id()
        );
    }

    #[test]
    fn invalid_candidate_returns_monotonic_result_without_state_change() {
        let fixture = Fixture::new("invalid");
        let before = fixture.repository.accepted_head().unwrap();
        let mut candidate = fixture.candidate.stored_bytes.clone();
        *candidate.last_mut().unwrap() ^= 1;
        let error = fixture
            .repository
            .commit(CommitInput::new(
                fixture.genesis_transaction_id,
                &candidate,
                fixture.principal_id,
                &[],
                NOW,
                CandidateValidationLimits::full_v1(),
            ))
            .unwrap_err();
        assert_eq!(error.code(), "CANDIDATE_VALIDATION_INVALID_ENCODING");
        assert_eq!(error.numeric_code(), Some(36_000));
        assert_eq!(
            fixture.repository.accepted_head().unwrap().transaction_id(),
            before.transaction_id()
        );
    }

    #[test]
    fn independent_threads_serialize_and_one_observes_stale_head() {
        let fixture = Fixture::new("threads");
        let second_candidate = fixture.alternate_candidate(31);
        let repository = Arc::new(fixture.repository.clone());
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for candidate in [fixture.candidate.clone(), second_candidate] {
            let repository = Arc::clone(&repository);
            let barrier = Arc::clone(&barrier);
            let principal_id = fixture.principal_id;
            let parent = fixture.genesis_transaction_id;
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                repository.commit(CommitInput::new(
                    parent,
                    &candidate.stored_bytes,
                    principal_id,
                    &[],
                    NOW,
                    CandidateValidationLimits::full_v1(),
                ))
            }));
        }
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter_map(|outcome| outcome.as_ref().err())
                .filter(|error| error.code() == "STALE_ROOT")
                .count(),
            1
        );
        repository.accepted_head().unwrap();
    }

    #[test]
    fn interruption_matrix_accepts_only_old_or_complete_new_state() {
        let cases = [
            (Fault::AfterObjectsBeforeReceipt, false, 0_u64),
            (Fault::DuringReceiptWrite, false, 1_u64),
            (Fault::AfterReceiptBeforeHead, false, 0_u64),
            (Fault::BeforeHeadRename, false, 0_u64),
            (Fault::AfterHeadRenameBeforeSync, true, 0_u64),
        ];
        for (index, (fault, new_visible, expected_receipt_stages)) in cases.into_iter().enumerate()
        {
            let fixture = Fixture::new(&format!("fault-{index}"));
            let error = fixture
                .repository
                .commit_with_fault(fixture.input(), fault)
                .unwrap_err();
            assert!(matches!(
                error.code(),
                "TXN_IO" | "RECOVERY_RECEIPT_INCOMPLETE" | "RECOVERY_REF_CAS_INCOMPLETE"
            ));
            let recovered = fixture.repository.recover().unwrap();
            assert_eq!(recovered.removed_receipt_stages, expected_receipt_stages);
            let accepted = fixture.repository.accepted_head().unwrap();
            if new_visible {
                assert_ne!(accepted.transaction_id(), fixture.genesis_transaction_id);
                assert_eq!(
                    accepted.receipt().transaction.record.transaction_kind,
                    TransactionKind::OrdinaryCandidate
                );
                assert_eq!(accepted.objects().len(), 2);
            } else {
                assert_eq!(accepted.transaction_id(), fixture.genesis_transaction_id);
                assert_eq!(
                    accepted.receipt().transaction.record.transaction_kind,
                    TransactionKind::TrustedGenesis
                );
                assert_eq!(accepted.objects().len(), 1);
            }
        }
    }

    #[test]
    fn corrupted_head_and_symlinked_owned_directory_fail_closed() {
        let fixture = Fixture::new("head-corrupt");
        let head_path = fixture.repository.head_path();
        let mut bytes = fs::read(&head_path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&head_path, bytes).unwrap();
        assert_eq!(
            fixture.repository.accepted_head().unwrap_err().code(),
            "REF_HEAD_CORRUPT"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let temp = TempDir::new("symlink");
            let outside = TempDir::new("symlink-outside");
            symlink(&outside.path, temp.path.join("transactions")).unwrap();
            let repository = TransactionRepository::new(&temp.path);
            assert_eq!(repository.accepted_head().unwrap_err().code(), "TXN_IO");
        }
    }

    #[test]
    fn accepted_head_rejects_manifest_length_mismatch() {
        let fixture = Fixture::new("manifest-length");
        let output = fixture.repository.commit(fixture.input()).unwrap();
        let accepted = fixture.repository.accepted_head().unwrap();
        let mut record = accepted.receipt().record.clone();
        record.object_manifest[0].stored_length = record.object_manifest[0]
            .stored_length
            .checked_add(1)
            .unwrap();
        let forged = build_transaction_receipt(&record).unwrap();
        let path = fixture
            .repository
            .receipt_path(output.transaction_id())
            .unwrap();
        fs::write(path, forged.stored_bytes).unwrap();
        assert_eq!(
            fixture.repository.accepted_head().unwrap_err().code(),
            "TXN_OBJECT_INVENTORY_MISMATCH"
        );
    }

    #[test]
    fn verified_revision_rejects_manifest_length_mismatch() {
        let fixture = Fixture::new("verified-manifest-length");
        let output = fixture.repository.commit(fixture.input()).unwrap();
        let revision = fixture
            .repository
            .verified_revision(output.transaction_id())
            .unwrap();
        let mut record = revision.receipt().record.clone();
        record.object_manifest[0].stored_length = record.object_manifest[0]
            .stored_length
            .checked_add(1)
            .unwrap();
        let forged = build_transaction_receipt(&record).unwrap();
        let path = fixture
            .repository
            .receipt_path(output.transaction_id())
            .unwrap();
        fs::write(path, forged.stored_bytes).unwrap();
        assert_eq!(
            fixture
                .repository
                .verified_revision(output.transaction_id())
                .unwrap_err()
                .code(),
            "TXN_OBJECT_INVENTORY_MISMATCH"
        );
    }

    #[test]
    fn verified_revision_missing_parent_creates_no_fanout_or_lock_state() {
        let fixture = Fixture::new("verified-missing-parent-readonly");
        let output = fixture.repository.commit(fixture.input()).unwrap();
        let parent_path = fixture
            .repository
            .receipt_path(fixture.genesis_transaction_id)
            .unwrap();
        let parent_leaf = parent_path.parent().unwrap().to_path_buf();
        fs::remove_file(&parent_path).unwrap();
        fs::remove_dir(&parent_leaf).unwrap();
        let before = snapshot_tree(&fixture.temp.path);

        assert_eq!(
            fixture
                .repository
                .verified_revision(output.transaction_id())
                .unwrap_err()
                .code(),
            "RECOVERY_RECEIPT_INCOMPLETE"
        );
        assert_eq!(snapshot_tree(&fixture.temp.path), before);
        assert!(!parent_leaf.exists());
    }

    #[test]
    #[ignore = "explicit S20-390 conformance fixture refresh helper"]
    fn emit_transaction_receipt_vectors_for_fixture_refresh() {
        let fixture = Fixture::new("emit");
        let genesis = fixture.repository.accepted_head().unwrap();
        emit_vector("GENESIS", genesis.receipt());
        fixture.repository.commit(fixture.input()).unwrap();
        let ordinary = fixture.repository.accepted_head().unwrap();
        emit_vector("ORDINARY", ordinary.receipt());
    }

    fn emit_vector(kind: &str, receipt: &ImportedTransactionReceipt) {
        println!(
            "TXN_VECTOR|{kind}|{}|{}|{}|{}|{}",
            hex(receipt.transaction.transaction_id.as_bytes()),
            hex(receipt.receipt_id.as_bytes()),
            hex(&receipt.transaction.stored_bytes),
            hex(&receipt.stored_bytes),
            manifest_descriptor(&receipt.record.object_manifest),
        );
        if kind == "ORDINARY" {
            let mut record = receipt.record.clone();
            record.object_manifest[0].stored_length = record.object_manifest[0]
                .stored_length
                .checked_add(1)
                .unwrap();
            let bad = build_transaction_receipt(&record).unwrap();
            println!(
                "TXN_REJECT|manifest-stored-length|TXN_OBJECT_INVENTORY_MISMATCH|{}|{}",
                hex(&bad.stored_bytes),
                manifest_descriptor(&receipt.record.object_manifest),
            );
        }
    }

    fn manifest_descriptor(manifest: &[ObjectManifestEntry]) -> String {
        manifest
            .iter()
            .map(|entry| {
                format!(
                    "{}:{}",
                    hex(entry.object_id.as_bytes()),
                    entry.stored_length
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn snapshot_tree(root: &Path) -> Vec<PathBuf> {
        fn visit(root: &Path, current: &Path, output: &mut Vec<PathBuf>) {
            let mut entries = fs::read_dir(current)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                let path = entry.path();
                output.push(path.strip_prefix(root).unwrap().to_path_buf());
                if entry.file_type().unwrap().is_dir() {
                    visit(root, &path, output);
                }
            }
        }

        let mut output = Vec::new();
        visit(root, root, &mut output);
        output
    }

    fn hex(bytes: &[u8]) -> String {
        use fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
