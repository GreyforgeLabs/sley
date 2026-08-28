use core::fmt;

use sley_id::{
    CandidateId, CandidateNonce, CapabilitySummaryDigest, EntityId, ObjectId, PolicyRootId,
    PrincipalId, SchemaEpochId, StateRoot, TransactionId, ValidationProfileId, WorkspaceId,
};
use sley_scb1::{ScbError, ScbErrorCode};

use crate::value::{
    ContractBody, DependencyBindingBody, EntityBodyValue, EntryPointBody, FieldValue, TestCaseBody,
};
use crate::{MutationClass, PreimageRequirement, mutation_operation_descriptor};

/// Exact S20-345/S20-350 candidate-record format version.
pub const CANDIDATE_FORMAT_VERSION: u32 = 1;

/// Exact S20-345 validation-profile format version.
pub const VALIDATION_PROFILE_FORMAT_VERSION: u32 = 1;

/// Candidate-envelope magic bytes.
pub const CANDIDATE_MAGIC: &[u8; 8] = b"SLEYCAN1";

/// Candidate-envelope version.
pub const CANDIDATE_ENVELOPE_VERSION: u64 = 1;

/// S20-345 full-v1 validation phase tags.
pub const FULL_VALIDATION_PHASE_TAGS: [u32; 14] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];

/// Proposal-only candidate encoding or structural construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateError {
    /// Strict SCB1 syntax, canonicality, digest, or resource failure.
    Scb(ScbError),
    /// Candidate record format version was not exactly v1.
    FormatVersionUnsupported,
    /// Candidate expiry was not epoch-1 Unix-millis with a nonzero deadline.
    ExpiryInvalid,
    /// Operation list was empty.
    EmptyOperations,
    /// Operation ordinals were not contiguous from zero.
    OperationOrdinalMismatch,
    /// Operation precondition ordinal did not match the operation ordinal.
    OperationPreconditionOrdinalMismatch,
    /// Candidate did not carry exactly one precondition per operation.
    PreconditionCountMismatch,
    /// Precondition ordinal, requirement, target identity, or field binding mismatched.
    PreconditionMismatch,
    /// No immutable S20-340 descriptor exists for the operation key.
    DescriptorUnknown,
    /// Operation payload did not match its class, target kind, or descriptor field.
    PayloadKindMismatch,
    /// Create-entity operation did not target the deterministic S20-110 identity.
    TargetEntityMismatch,
    /// Validation profile record was not the exact full-v1 profile.
    ValidationProfileInvalid,
}

impl CandidateError {
    /// Returns a stable failure code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Scb(error) => error.code().as_str(),
            Self::FormatVersionUnsupported => "MUTATION_CANDIDATE_FORMAT_VERSION",
            Self::ExpiryInvalid => "MUTATION_CANDIDATE_EXPIRY_INVALID",
            Self::EmptyOperations => "MUTATION_CANDIDATE_EMPTY_OPERATIONS",
            Self::OperationOrdinalMismatch => "MUTATION_CANDIDATE_OPERATION_ORDINAL",
            Self::OperationPreconditionOrdinalMismatch => {
                "MUTATION_CANDIDATE_OPERATION_PRECONDITION_ORDINAL"
            }
            Self::PreconditionCountMismatch => "MUTATION_CANDIDATE_PRECONDITION_COUNT",
            Self::PreconditionMismatch => "MUTATION_CANDIDATE_PRECONDITION_MISMATCH",
            Self::DescriptorUnknown => "MUTATION_CANDIDATE_DESCRIPTOR_UNKNOWN",
            Self::PayloadKindMismatch => "MUTATION_CANDIDATE_PAYLOAD_KIND",
            Self::TargetEntityMismatch => "MUTATION_CANDIDATE_TARGET_ENTITY",
            Self::ValidationProfileInvalid => "MUTATION_CANDIDATE_VALIDATION_PROFILE",
        }
    }

    /// Returns the frozen S20-350 numeric code for candidate-specific errors.
    ///
    /// SCB1 failures retain the separate `SCB_*` namespace and therefore do
    /// not acquire a candidate numeric code.
    #[must_use]
    pub const fn numeric_code(&self) -> Option<u32> {
        match self {
            Self::Scb(_) => None,
            Self::FormatVersionUnsupported => Some(35_000),
            Self::ExpiryInvalid => Some(35_001),
            Self::EmptyOperations => Some(35_002),
            Self::OperationOrdinalMismatch => Some(35_003),
            Self::OperationPreconditionOrdinalMismatch => Some(35_004),
            Self::PreconditionCountMismatch => Some(35_005),
            Self::PreconditionMismatch => Some(35_006),
            Self::DescriptorUnknown => Some(35_007),
            Self::PayloadKindMismatch => Some(35_008),
            Self::TargetEntityMismatch => Some(35_009),
            Self::ValidationProfileInvalid => Some(35_010),
        }
    }
}

impl fmt::Display for CandidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for CandidateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scb(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ScbError> for CandidateError {
    fn from(value: ScbError) -> Self {
        Self::Scb(value)
    }
}

/// Epoch-1 candidate expiry proposal data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateExpiry {
    /// Clock tag. Epoch 1 permits only tag 1, Unix time in milliseconds.
    pub clock: u16,
    /// Half-open deadline; zero is invalid.
    pub not_after: u64,
}

impl CandidateExpiry {
    /// Constructs a Unix-millis candidate expiry without reading a clock.
    #[must_use]
    pub const fn unix_millis(not_after: u64) -> Self {
        Self {
            clock: 1,
            not_after,
        }
    }

    pub(crate) fn validate(self) -> Result<(), CandidateError> {
        if self.clock == 1 && self.not_after != 0 {
            Ok(())
        } else {
            Err(CandidateError::ExpiryInvalid)
        }
    }
}

/// Class-6 reference payload selected by the exact field descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReferenceTarget {
    /// Exact `EntityId` replacement.
    Entity(EntityId),
    /// Exact `Option<EntityId>` replacement using SCB1 generic Option tags.
    Optional(Option<EntityId>),
}

/// Class-7 ordered-child insertion payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedInsert {
    /// Zero-based insertion index.
    pub index: u32,
    /// Child entity expected to be inserted.
    pub child: EntityId,
}

/// Class-8 ordered-child removal payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedRemove {
    /// Zero-based removal index.
    pub index: u32,
    /// Child entity expected at the removed position.
    pub expected_child: EntityId,
}

/// Class-9 ordered-child movement payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedMove {
    /// Zero-based source index.
    pub from: u32,
    /// Zero-based target index.
    pub to: u32,
    /// Child entity expected at the source position.
    pub expected_child: EntityId,
}

/// Closed candidate mutation payload keyed by the operation class tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationPayload {
    /// Class 1: create a new typed entity body.
    CreateEntity(EntityBodyValue),
    /// Class 2: replace one typed entity body version.
    ReplaceEntityVersion(EntityBodyValue),
    /// Class 3: delete a live entity binding; payload is `Unit`.
    DeleteEntityBinding,
    /// Class 4: set one scalar field.
    SetScalarField(FieldValue),
    /// Class 5: replace one complete typed field.
    ReplaceTypedField(FieldValue),
    /// Class 6: retarget one direct or optional entity reference.
    RetargetReference(ReferenceTarget),
    /// Class 7: insert into one ordered child list.
    InsertOrderedChild(OrderedInsert),
    /// Class 8: remove from one ordered child list.
    RemoveOrderedChild(OrderedRemove),
    /// Class 9: move within one ordered child list.
    MoveOrderedChild(OrderedMove),
    /// Class 10: add an entry-point binding.
    AddEntryPoint(EntryPointBody),
    /// Class 11: remove an entry-point binding; payload is `Unit`.
    RemoveEntryPoint,
    /// Class 12: add a test-case binding.
    AddTest(TestCaseBody),
    /// Class 13: replace a test-case version.
    ReplaceTest(TestCaseBody),
    /// Class 14: add a contract binding.
    AddContract(ContractBody),
    /// Class 15: replace a contract version.
    ReplaceContract(ContractBody),
    /// Class 16: update a dependency binding.
    UpdateDependencyBinding(DependencyBindingBody),
}

impl MutationPayload {
    /// Returns the exact mutation class selected by this payload.
    #[must_use]
    pub const fn class(&self) -> MutationClass {
        match self {
            Self::CreateEntity(_) => MutationClass::CreateEntity,
            Self::ReplaceEntityVersion(_) => MutationClass::ReplaceEntityVersion,
            Self::DeleteEntityBinding => MutationClass::DeleteEntityBinding,
            Self::SetScalarField(_) => MutationClass::SetScalarField,
            Self::ReplaceTypedField(_) => MutationClass::ReplaceTypedField,
            Self::RetargetReference(_) => MutationClass::RetargetReference,
            Self::InsertOrderedChild(_) => MutationClass::InsertOrderedChild,
            Self::RemoveOrderedChild(_) => MutationClass::RemoveOrderedChild,
            Self::MoveOrderedChild(_) => MutationClass::MoveOrderedChild,
            Self::AddEntryPoint(_) => MutationClass::AddEntryPoint,
            Self::RemoveEntryPoint => MutationClass::RemoveEntryPoint,
            Self::AddTest(_) => MutationClass::AddTest,
            Self::ReplaceTest(_) => MutationClass::ReplaceTest,
            Self::AddContract(_) => MutationClass::AddContract,
            Self::ReplaceContract(_) => MutationClass::ReplaceContract,
            Self::UpdateDependencyBinding(_) => MutationClass::UpdateDependencyBinding,
        }
    }

    pub(crate) fn matches_descriptor(
        &self,
        class: MutationClass,
        target_kind: u16,
        field_tag: Option<u16>,
        value_type: &str,
    ) -> bool {
        if self.class() != class {
            return false;
        }
        match self {
            Self::CreateEntity(value) | Self::ReplaceEntityVersion(value) => {
                field_tag.is_none()
                    && value.kind_tag() == target_kind
                    && value_type == body_type_name(target_kind)
            }
            Self::DeleteEntityBinding | Self::RemoveEntryPoint => {
                field_tag.is_none() && value_type == "Unit"
            }
            Self::SetScalarField(value) | Self::ReplaceTypedField(value) => {
                let (kind, field) = value.field_key();
                Some(field) == field_tag && kind == target_kind
            }
            Self::RetargetReference(ReferenceTarget::Entity(_)) => {
                field_tag.is_some() && value_type == "EntityId"
            }
            Self::RetargetReference(ReferenceTarget::Optional(_)) => {
                field_tag.is_some() && value_type == "Option<EntityId>"
            }
            Self::InsertOrderedChild(_)
            | Self::RemoveOrderedChild(_)
            | Self::MoveOrderedChild(_) => field_tag.is_some() && value_type == "List<EntityId>",
            Self::AddEntryPoint(_) => target_kind == 16 && field_tag.is_none(),
            Self::AddTest(_) | Self::ReplaceTest(_) => target_kind == 14 && field_tag.is_none(),
            Self::AddContract(_) | Self::ReplaceContract(_) => {
                target_kind == 13 && field_tag.is_none()
            }
            Self::UpdateDependencyBinding(_) => target_kind == 18 && field_tag.is_none(),
        }
    }
}

/// One canonical candidate operation record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationOperation {
    /// Contiguous candidate operation ordinal.
    pub ordinal: u32,
    /// Closed mutation class.
    pub class: MutationClass,
    /// Exact entity kind tag.
    pub target_kind: u16,
    /// Exact target entity identity.
    pub target_entity: EntityId,
    /// Exact field tag when the class is field-scoped.
    pub field_tag: Option<u32>,
    /// Descriptor-selected payload.
    pub payload: MutationPayload,
    /// Ordinal of the bound precondition record.
    pub precondition_ordinal: u32,
}

/// Expected-identity-absence precondition payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedIdentityAbsent {
    /// Derived entity identity that must not be live or tombstoned.
    pub entity_id: EntityId,
}

/// Exact entity-version precondition payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactEntityVersion {
    /// Target entity identity.
    pub entity_id: EntityId,
    /// Exact current immutable object identity.
    pub object_id: ObjectId,
}

/// Exact container-version precondition payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactContainerVersion {
    /// Target container entity identity.
    pub container_id: EntityId,
    /// Exact current immutable container object identity.
    pub object_id: ObjectId,
    /// Exact ordered-child field tag.
    pub field_tag: u32,
}

/// Closed precondition payload selected by the requirement tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreconditionPayload {
    /// Requirement 1.
    ExpectedIdentityAbsent(ExpectedIdentityAbsent),
    /// Requirement 2.
    ExactEntityVersion(ExactEntityVersion),
    /// Requirement 3.
    ExactContainerVersion(ExactContainerVersion),
}

impl PreconditionPayload {
    /// Returns the exact closed preimage requirement selected by this payload.
    #[must_use]
    pub const fn requirement(&self) -> PreimageRequirement {
        match self {
            Self::ExpectedIdentityAbsent(_) => PreimageRequirement::ExpectedIdentityAbsent,
            Self::ExactEntityVersion(_) => PreimageRequirement::ExactEntityVersion,
            Self::ExactContainerVersion(_) => PreimageRequirement::ExactContainerVersion,
        }
    }
}

/// One same-ordinal bound precondition for a candidate operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundPrecondition {
    /// Operation ordinal this precondition binds.
    pub operation_ordinal: u32,
    /// Closed descriptor-selected requirement.
    pub requirement: PreimageRequirement,
    /// Requirement-selected payload.
    pub payload: PreconditionPayload,
}

/// Exact S20-345 full-v1 validation profile record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationProfileRecord {
    /// Must be exactly 1.
    pub format_version: u32,
    /// Ordered phase tags. The full v1 profile is exactly 1 through 14.
    pub phase_tags: Vec<u32>,
    /// Maximum candidate operations.
    pub max_operations: u32,
    /// Maximum candidate preconditions.
    pub max_preconditions: u32,
    /// Maximum stored candidate bytes.
    pub max_candidate_bytes: u64,
    /// Maximum decoded mutation-value allocation.
    pub max_decoded_value_bytes: u64,
    /// Maximum graph validation work.
    pub max_graph_work: u64,
    /// Maximum selected tests.
    pub max_selected_tests: u32,
}

impl ValidationProfileRecord {
    /// Returns the exact frozen full-v1 validation profile.
    #[must_use]
    pub fn full_v1() -> Self {
        Self {
            format_version: VALIDATION_PROFILE_FORMAT_VERSION,
            phase_tags: FULL_VALIDATION_PHASE_TAGS.to_vec(),
            max_operations: 65_535,
            max_preconditions: 65_535,
            max_candidate_bytes: 67_108_864,
            max_decoded_value_bytes: 67_108_864,
            max_graph_work: 10_000_000,
            max_selected_tests: 65_535,
        }
    }

    pub(crate) fn validate_full_v1(&self) -> Result<(), CandidateError> {
        if self == &Self::full_v1() {
            Ok(())
        } else {
            Err(CandidateError::ValidationProfileInvalid)
        }
    }
}

/// Exact 13-field canonical candidate record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRecord {
    /// Must be exactly 1.
    pub format_version: u32,
    /// Exact target workspace.
    pub workspace_id: WorkspaceId,
    /// Exact accepted parent transaction.
    pub base_transaction_id: TransactionId,
    /// Exact accepted semantic root.
    pub base_root: StateRoot,
    /// Exact schema epoch.
    pub schema_epoch_id: SchemaEpochId,
    /// Protected policy root that must later judge this proposal.
    pub policy_root_id: PolicyRootId,
    /// Opaque principal identity reference.
    pub principal_id: PrincipalId,
    /// Proposal binding to the authenticated capability summary.
    pub capability_summary_digest: CapabilitySummaryDigest,
    /// Nonempty contiguous candidate operations.
    pub operations: Vec<MutationOperation>,
    /// One same-ordinal precondition per operation.
    pub preconditions: Vec<BoundPrecondition>,
    /// Exact validation profile identity.
    pub validation_profile_id: ValidationProfileId,
    /// Exact replay and identity nonce.
    pub candidate_nonce: CandidateNonce,
    /// Exact proposal expiry.
    pub expiry: CandidateExpiry,
}

impl CandidateRecord {
    /// Validates proposal-only structural bindings without judging state.
    ///
    /// # Errors
    ///
    /// Returns a stable [`CandidateError`] when the record is not structurally
    /// canonical for S20-350.
    pub fn validate(&self) -> Result<(), CandidateError> {
        if self.format_version != CANDIDATE_FORMAT_VERSION {
            return Err(CandidateError::FormatVersionUnsupported);
        }
        self.expiry.validate()?;
        if self.validation_profile_id != crate::codec::full_validation_profile_id()? {
            return Err(CandidateError::ValidationProfileInvalid);
        }
        if self.operations.is_empty() {
            return Err(CandidateError::EmptyOperations);
        }
        let profile = ValidationProfileRecord::full_v1();
        if self.operations.len() > profile.max_operations as usize
            || self.preconditions.len() > profile.max_preconditions as usize
        {
            return Err(CandidateError::Scb(ScbError::new(
                ScbErrorCode::ResourceLimit,
            )));
        }
        if self.operations.len() != self.preconditions.len() {
            return Err(CandidateError::PreconditionCountMismatch);
        }

        let mut create_ordinal = 0_u64;
        for (index, (operation, precondition)) in
            self.operations.iter().zip(&self.preconditions).enumerate()
        {
            let expected_ordinal =
                u32::try_from(index).map_err(|_| CandidateError::OperationOrdinalMismatch)?;
            if operation.ordinal != expected_ordinal {
                return Err(CandidateError::OperationOrdinalMismatch);
            }
            if operation.precondition_ordinal != operation.ordinal {
                return Err(CandidateError::OperationPreconditionOrdinalMismatch);
            }
            let field_tag = descriptor_field_tag(operation.field_tag)?;
            let descriptor =
                mutation_operation_descriptor(operation.class, operation.target_kind, field_tag)
                    .ok_or(CandidateError::DescriptorUnknown)?;
            if !operation.payload.matches_descriptor(
                operation.class,
                operation.target_kind,
                field_tag,
                descriptor.value_type,
            ) {
                return Err(CandidateError::PayloadKindMismatch);
            }
            if operation.class == MutationClass::CreateEntity {
                let expected = EntityId::derive(
                    self.workspace_id,
                    self.candidate_nonce,
                    u32::from(operation.target_kind),
                    create_ordinal,
                );
                if operation.target_entity != expected {
                    return Err(CandidateError::TargetEntityMismatch);
                }
                create_ordinal = create_ordinal
                    .checked_add(1)
                    .ok_or(CandidateError::OperationOrdinalMismatch)?;
            }
            validate_precondition(operation, precondition, descriptor.preimage)?;
        }
        Ok(())
    }
}

/// Imported canonical candidate bytes with verified digest trailer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedCandidate {
    /// Decoded candidate record.
    pub record: CandidateRecord,
    /// Derived candidate identity.
    pub candidate_id: CandidateId,
    /// Exact candidate preimage bytes.
    pub preimage: Vec<u8>,
    /// Exact stored bytes, including the digest trailer.
    pub stored_bytes: Vec<u8>,
}

/// Encodes one canonical candidate record.
///
/// # Errors
///
/// Returns a stable error when the record violates S20-350 structural rules or
/// when strict SCB1 encoding fails.
pub fn encode_candidate_record(record: &CandidateRecord) -> Result<Vec<u8>, CandidateError> {
    crate::codec::encode_candidate_record(record)
}

/// Decodes one canonical candidate record, without an envelope digest trailer.
///
/// # Errors
///
/// Returns a stable error when the bytes are not strict SCB1 or violate
/// S20-350 structural rules.
pub fn decode_candidate_record(input: &[u8]) -> Result<CandidateRecord, CandidateError> {
    crate::codec::decode_candidate_record(input)
}

/// Builds stored candidate bytes and derives the candidate identity.
///
/// # Errors
///
/// Returns a stable error when the record is not a structurally valid
/// proposal-only S20-350 candidate.
pub fn build_candidate(record: &CandidateRecord) -> Result<ImportedCandidate, CandidateError> {
    crate::codec::build_candidate(record)
}

/// Imports stored candidate bytes and verifies the digest trailer.
///
/// # Errors
///
/// Returns a stable error when the envelope, digest, record bytes, or
/// candidate structure are invalid.
pub fn import_candidate(input: &[u8]) -> Result<ImportedCandidate, CandidateError> {
    crate::codec::import_candidate(input)
}

/// Returns the exact frozen full-v1 validation profile record.
#[must_use]
pub fn full_validation_profile_record() -> ValidationProfileRecord {
    ValidationProfileRecord::full_v1()
}

/// Returns the exact frozen full-v1 validation profile identity.
///
/// # Errors
///
/// Returns a stable error only if strict SCB1 profile encoding fails.
pub fn full_validation_profile_id() -> Result<ValidationProfileId, CandidateError> {
    crate::codec::full_validation_profile_id()
}

pub(crate) fn descriptor_field_tag(field_tag: Option<u32>) -> Result<Option<u16>, CandidateError> {
    field_tag
        .map(|tag| u16::try_from(tag).map_err(|_| CandidateError::DescriptorUnknown))
        .transpose()
}

pub(crate) fn scb_invalid() -> ScbError {
    ScbError::new(ScbErrorCode::UnionInvalid)
}

fn validate_precondition(
    operation: &MutationOperation,
    precondition: &BoundPrecondition,
    expected_requirement: PreimageRequirement,
) -> Result<(), CandidateError> {
    if precondition.operation_ordinal != operation.ordinal
        || precondition.requirement != expected_requirement
        || precondition.payload.requirement() != precondition.requirement
    {
        return Err(CandidateError::PreconditionMismatch);
    }
    match (&precondition.requirement, &precondition.payload) {
        (
            PreimageRequirement::ExpectedIdentityAbsent,
            PreconditionPayload::ExpectedIdentityAbsent(payload),
        ) if payload.entity_id == operation.target_entity => Ok(()),
        (
            PreimageRequirement::ExactEntityVersion,
            PreconditionPayload::ExactEntityVersion(payload),
        ) if payload.entity_id == operation.target_entity => Ok(()),
        (
            PreimageRequirement::ExactContainerVersion,
            PreconditionPayload::ExactContainerVersion(payload),
        ) if payload.container_id == operation.target_entity
            && operation.field_tag == Some(payload.field_tag) =>
        {
            Ok(())
        }
        _ => Err(CandidateError::PreconditionMismatch),
    }
}

fn body_type_name(target_kind: u16) -> &'static str {
    match target_kind {
        1 => "WorkspaceBody",
        2 => "PackageBody",
        3 => "NamespaceBody",
        4 => "TypeDefBody",
        5 => "FunctionBody",
        6 => "ParameterBody",
        7 => "BlockBody",
        8 => "OperationBody",
        9 => "ConstantBody",
        10 => "GlobalValueBody",
        11 => "EffectDefBody",
        12 => "CapabilityRequirementBody",
        13 => "ContractBody",
        14 => "TestCaseBody",
        15 => "AdapterImportBody",
        16 => "EntryPointBody",
        17 => "PolicyBindingBody",
        18 => "DependencyBindingBody",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_error_registry_is_exact_and_scb_stays_separate() {
        let errors = [
            CandidateError::FormatVersionUnsupported,
            CandidateError::ExpiryInvalid,
            CandidateError::EmptyOperations,
            CandidateError::OperationOrdinalMismatch,
            CandidateError::OperationPreconditionOrdinalMismatch,
            CandidateError::PreconditionCountMismatch,
            CandidateError::PreconditionMismatch,
            CandidateError::DescriptorUnknown,
            CandidateError::PayloadKindMismatch,
            CandidateError::TargetEntityMismatch,
            CandidateError::ValidationProfileInvalid,
        ];
        let expected_symbols = [
            "MUTATION_CANDIDATE_FORMAT_VERSION",
            "MUTATION_CANDIDATE_EXPIRY_INVALID",
            "MUTATION_CANDIDATE_EMPTY_OPERATIONS",
            "MUTATION_CANDIDATE_OPERATION_ORDINAL",
            "MUTATION_CANDIDATE_OPERATION_PRECONDITION_ORDINAL",
            "MUTATION_CANDIDATE_PRECONDITION_COUNT",
            "MUTATION_CANDIDATE_PRECONDITION_MISMATCH",
            "MUTATION_CANDIDATE_DESCRIPTOR_UNKNOWN",
            "MUTATION_CANDIDATE_PAYLOAD_KIND",
            "MUTATION_CANDIDATE_TARGET_ENTITY",
            "MUTATION_CANDIDATE_VALIDATION_PROFILE",
        ];
        for ((error, symbol), numeric) in
            errors.iter().zip(expected_symbols).zip(35_000_u32..=35_010)
        {
            assert_eq!(error.code(), symbol);
            assert_eq!(error.numeric_code(), Some(numeric));
        }
        assert_eq!(
            CandidateError::Scb(ScbError::new(ScbErrorCode::UnionInvalid)).numeric_code(),
            None
        );
    }
}
