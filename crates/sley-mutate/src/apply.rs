//! Pure S20-360 candidate application over an immutable entity snapshot.
//!
//! This module checks candidate preimages against one exact base snapshot and
//! then evaluates operations in candidate order on an in-memory clone. It
//! performs no store I/O, accepted-root mutation, policy judgment, tombstone
//! lookup, semantic validation, commit, receipt creation, or capability use.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use sley_id::{EntityId, SchemaEpochId};
use sley_scb1::ScbError;

use crate::candidate::{
    BoundPrecondition, CandidateError, CandidateRecord, MutationOperation, MutationPayload,
    PreconditionPayload, ReferenceTarget,
};
use crate::object::{EntityObject, EntityObjectRecord, build_entity_object};
use crate::value::EntityBodyValue;

/// Pure candidate-application failure with a stable machine symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CandidateApplyError {
    /// Candidate structure no longer satisfies its frozen S20-350 contract.
    Candidate(CandidateError),
    /// Canonical construction of a proposed immutable object failed.
    Object(ScbError),
    /// The supplied base inventory contains the same logical identity twice.
    SnapshotDuplicateEntity,
    /// A supplied base object belongs to a different schema epoch.
    SnapshotEpochMismatch,
    /// The supplied root entry-point list contains a duplicate identity.
    SnapshotDuplicateEntryPoint,
    /// The supplied root entry-point list names no live base binding.
    SnapshotEntryPointUnbound,
    /// A creation identity is already live in the exact base snapshot.
    IdentityAlreadyLive,
    /// An exact entity/container preimage is absent or has a different object ID.
    ExactPreimageMismatch,
    /// An operation requires a live proposed entity that is absent.
    TargetMissing,
    /// Creation tried to bind an identity already present in the proposed state.
    TargetAlreadyExists,
    /// An operation's declared kind differs from the live proposed entity body.
    TargetKindMismatch,
    /// A field/reference/list payload did not match the exact live body field.
    FieldMismatch,
    /// An ordered-list index is outside the deterministic operation boundary.
    OrderedIndexInvalid,
    /// An ordered remove/move expected a different child at the bound index.
    OrderedExpectedChildMismatch,
    /// Add-entry-point targeted an identity already present in the root list.
    EntryPointAlreadyPresent,
    /// Remove-entry-point targeted an identity absent from the root list.
    EntryPointMissing,
    /// Delete-entity targeted an identity still present in the root entry-point list.
    EntryPointStillBound,
}

impl CandidateApplyError {
    /// Returns the stable S20-360 application symbol.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Candidate(error) => error.code(),
            Self::Object(error) => error.code().as_str(),
            Self::SnapshotDuplicateEntity => "CANDIDATE_APPLY_SNAPSHOT_DUPLICATE_ENTITY",
            Self::SnapshotEpochMismatch => "CANDIDATE_APPLY_SNAPSHOT_EPOCH_MISMATCH",
            Self::SnapshotDuplicateEntryPoint => "CANDIDATE_APPLY_SNAPSHOT_DUPLICATE_ENTRY_POINT",
            Self::SnapshotEntryPointUnbound => "CANDIDATE_APPLY_SNAPSHOT_ENTRY_POINT_UNBOUND",
            Self::IdentityAlreadyLive => "CANDIDATE_APPLY_IDENTITY_ALREADY_LIVE",
            Self::ExactPreimageMismatch => "CANDIDATE_APPLY_EXACT_PREIMAGE_MISMATCH",
            Self::TargetMissing => "CANDIDATE_APPLY_TARGET_MISSING",
            Self::TargetAlreadyExists => "CANDIDATE_APPLY_TARGET_ALREADY_EXISTS",
            Self::TargetKindMismatch => "CANDIDATE_APPLY_TARGET_KIND_MISMATCH",
            Self::FieldMismatch => "CANDIDATE_APPLY_FIELD_MISMATCH",
            Self::OrderedIndexInvalid => "CANDIDATE_APPLY_ORDERED_INDEX_INVALID",
            Self::OrderedExpectedChildMismatch => "CANDIDATE_APPLY_ORDERED_EXPECTED_CHILD_MISMATCH",
            Self::EntryPointAlreadyPresent => "CANDIDATE_APPLY_ENTRY_POINT_ALREADY_PRESENT",
            Self::EntryPointMissing => "CANDIDATE_APPLY_ENTRY_POINT_MISSING",
            Self::EntryPointStillBound => "CANDIDATE_APPLY_ENTRY_POINT_STILL_BOUND",
        }
    }
}

impl fmt::Display for CandidateApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CandidateApplyError {}

impl From<CandidateError> for CandidateApplyError {
    fn from(value: CandidateError) -> Self {
        Self::Candidate(value)
    }
}

impl From<ScbError> for CandidateApplyError {
    fn from(value: ScbError) -> Self {
        Self::Object(value)
    }
}

/// Immutable result of pure ordered operation evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedEntityState {
    schema_epoch_id: SchemaEpochId,
    entities: Vec<EntityObject>,
    entry_points: Vec<EntityId>,
    affected_entities: Vec<EntityId>,
    deleted_entities: Vec<EntityId>,
}

impl ProposedEntityState {
    /// Returns the exact object schema epoch used for every proposed object.
    #[must_use]
    pub const fn schema_epoch_id(&self) -> SchemaEpochId {
        self.schema_epoch_id
    }

    /// Returns all live proposed objects sorted by embedded `EntityId`.
    #[must_use]
    pub fn entities(&self) -> &[EntityObject] {
        &self.entities
    }

    /// Returns the candidate root's proposed sorted entry-point identities.
    #[must_use]
    pub fn entry_points(&self) -> &[EntityId] {
        &self.entry_points
    }

    /// Returns every operation target once in raw-ID order.
    #[must_use]
    pub fn affected_entities(&self) -> &[EntityId] {
        &self.affected_entities
    }

    /// Returns identities removed from the proposed live binding map.
    #[must_use]
    pub fn deleted_entities(&self) -> &[EntityId] {
        &self.deleted_entities
    }

    /// Returns one proposed object by its exact logical identity.
    #[must_use]
    pub fn entity(&self, entity_id: EntityId) -> Option<&EntityObject> {
        self.entities
            .binary_search_by_key(&entity_id, |object| object.record().entity_id)
            .ok()
            .map(|index| &self.entities[index])
    }
}

/// Applies one structurally valid candidate to an exact immutable base snapshot.
///
/// All bound preconditions are checked against the original base map before
/// any operation runs. Operations then execute in their canonical ordinal
/// order against a private clone. An error drops that clone and cannot mutate
/// any caller-owned object or root.
///
/// Tombstone collision, complete base-root inventory, semantic graph,
/// capability, policy, and candidate-root judgments remain owning S20-360
/// phase obligations outside this narrow evaluator.
///
/// # Errors
///
/// Returns the first deterministic snapshot, preimage, operation-local, or
/// object-construction failure.
pub fn apply_candidate_to_snapshot(
    schema_epoch_id: SchemaEpochId,
    candidate: &CandidateRecord,
    base_objects: &[EntityObject],
    base_entry_points: &[EntityId],
) -> Result<ProposedEntityState, CandidateApplyError> {
    candidate.validate()?;
    if candidate.schema_epoch_id != schema_epoch_id {
        return Err(CandidateApplyError::SnapshotEpochMismatch);
    }

    let mut base = BTreeMap::new();
    for object in base_objects {
        if object.schema_epoch_id() != schema_epoch_id {
            return Err(CandidateApplyError::SnapshotEpochMismatch);
        }
        let entity_id = object.record().entity_id;
        if base.insert(entity_id, object.clone()).is_some() {
            return Err(CandidateApplyError::SnapshotDuplicateEntity);
        }
    }

    let mut entry_points = BTreeSet::new();
    for entry_point in base_entry_points {
        if !entry_points.insert(*entry_point) {
            return Err(CandidateApplyError::SnapshotDuplicateEntryPoint);
        }
        if !base.contains_key(entry_point) {
            return Err(CandidateApplyError::SnapshotEntryPointUnbound);
        }
    }

    check_base_preconditions(&base, &candidate.preconditions)?;

    let mut proposed = base;
    let mut affected = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    for operation in &candidate.operations {
        apply_operation(
            schema_epoch_id,
            &mut proposed,
            &mut entry_points,
            &mut affected,
            &mut deleted,
            operation,
        )?;
    }

    Ok(ProposedEntityState {
        schema_epoch_id,
        entities: proposed.into_values().collect(),
        entry_points: entry_points.into_iter().collect(),
        affected_entities: affected.into_iter().collect(),
        deleted_entities: deleted.into_iter().collect(),
    })
}

fn check_base_preconditions(
    base: &BTreeMap<EntityId, EntityObject>,
    preconditions: &[BoundPrecondition],
) -> Result<(), CandidateApplyError> {
    for precondition in preconditions {
        match &precondition.payload {
            PreconditionPayload::ExpectedIdentityAbsent(payload) => {
                if base.contains_key(&payload.entity_id) {
                    return Err(CandidateApplyError::IdentityAlreadyLive);
                }
            }
            PreconditionPayload::ExactEntityVersion(payload) => {
                if base.get(&payload.entity_id).map(EntityObject::object_id)
                    != Some(payload.object_id)
                {
                    return Err(CandidateApplyError::ExactPreimageMismatch);
                }
            }
            PreconditionPayload::ExactContainerVersion(payload) => {
                if base.get(&payload.container_id).map(EntityObject::object_id)
                    != Some(payload.object_id)
                {
                    return Err(CandidateApplyError::ExactPreimageMismatch);
                }
            }
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "closed 16-class dispatcher keeps operation ordering auditable"
)]
fn apply_operation(
    schema_epoch_id: SchemaEpochId,
    proposed: &mut BTreeMap<EntityId, EntityObject>,
    entry_points: &mut BTreeSet<EntityId>,
    affected: &mut BTreeSet<EntityId>,
    deleted: &mut BTreeSet<EntityId>,
    operation: &MutationOperation,
) -> Result<(), CandidateApplyError> {
    affected.insert(operation.target_entity);
    match &operation.payload {
        MutationPayload::CreateEntity(body) => {
            if proposed.contains_key(&operation.target_entity) {
                return Err(CandidateApplyError::TargetAlreadyExists);
            }
            ensure_body_kind(operation, body)?;
            let object = build_entity_object(
                schema_epoch_id,
                &EntityObjectRecord {
                    entity_id: operation.target_entity,
                    body: body.clone(),
                    label: None,
                    semantic_fingerprint: None,
                },
            )?;
            proposed.insert(operation.target_entity, object);
        }
        MutationPayload::ReplaceEntityVersion(body) => {
            replace_body(schema_epoch_id, proposed, operation, body.clone())?;
        }
        MutationPayload::DeleteEntityBinding => {
            ensure_live_kind(proposed, operation)?;
            if entry_points.contains(&operation.target_entity) {
                return Err(CandidateApplyError::EntryPointStillBound);
            }
            proposed.remove(&operation.target_entity);
            deleted.insert(operation.target_entity);
        }
        MutationPayload::SetScalarField(value) | MutationPayload::ReplaceTypedField(value) => {
            mutate_body(schema_epoch_id, proposed, operation, |body| {
                body.replace_field(value.clone())
            })?;
        }
        MutationPayload::RetargetReference(target) => {
            let field_tag = operation_field_tag(operation)?;
            mutate_body(schema_epoch_id, proposed, operation, |body| match target {
                ReferenceTarget::Entity(entity_id) => {
                    body.replace_direct_reference(field_tag, *entity_id)
                }
                ReferenceTarget::Optional(entity_id) => {
                    body.replace_optional_reference(field_tag, *entity_id)
                }
            })?;
        }
        MutationPayload::InsertOrderedChild(payload) => {
            let field_tag = operation_field_tag(operation)?;
            mutate_body_result(schema_epoch_id, proposed, operation, |body| {
                let children = body
                    .ordered_entity_children_mut(field_tag)
                    .ok_or(CandidateApplyError::FieldMismatch)?;
                let index = usize::try_from(payload.index)
                    .map_err(|_| CandidateApplyError::OrderedIndexInvalid)?;
                if index > children.len() {
                    return Err(CandidateApplyError::OrderedIndexInvalid);
                }
                children.insert(index, payload.child);
                Ok(())
            })?;
        }
        MutationPayload::RemoveOrderedChild(payload) => {
            let field_tag = operation_field_tag(operation)?;
            mutate_body_result(schema_epoch_id, proposed, operation, |body| {
                let children = body
                    .ordered_entity_children_mut(field_tag)
                    .ok_or(CandidateApplyError::FieldMismatch)?;
                let index = usize::try_from(payload.index)
                    .map_err(|_| CandidateApplyError::OrderedIndexInvalid)?;
                let child = children
                    .get(index)
                    .ok_or(CandidateApplyError::OrderedIndexInvalid)?;
                if *child != payload.expected_child {
                    return Err(CandidateApplyError::OrderedExpectedChildMismatch);
                }
                children.remove(index);
                Ok(())
            })?;
        }
        MutationPayload::MoveOrderedChild(payload) => {
            let field_tag = operation_field_tag(operation)?;
            mutate_body_result(schema_epoch_id, proposed, operation, |body| {
                let children = body
                    .ordered_entity_children_mut(field_tag)
                    .ok_or(CandidateApplyError::FieldMismatch)?;
                let from = usize::try_from(payload.from)
                    .map_err(|_| CandidateApplyError::OrderedIndexInvalid)?;
                let to = usize::try_from(payload.to)
                    .map_err(|_| CandidateApplyError::OrderedIndexInvalid)?;
                if from >= children.len() || to >= children.len() {
                    return Err(CandidateApplyError::OrderedIndexInvalid);
                }
                if children[from] != payload.expected_child {
                    return Err(CandidateApplyError::OrderedExpectedChildMismatch);
                }
                let child = children.remove(from);
                children.insert(to, child);
                Ok(())
            })?;
        }
        MutationPayload::AddEntryPoint(body) => {
            replace_body(
                schema_epoch_id,
                proposed,
                operation,
                EntityBodyValue::EntryPoint(body.clone()),
            )?;
            if !entry_points.insert(operation.target_entity) {
                return Err(CandidateApplyError::EntryPointAlreadyPresent);
            }
        }
        MutationPayload::RemoveEntryPoint => {
            ensure_live_kind(proposed, operation)?;
            if !entry_points.remove(&operation.target_entity) {
                return Err(CandidateApplyError::EntryPointMissing);
            }
        }
        MutationPayload::AddTest(body) | MutationPayload::ReplaceTest(body) => {
            replace_body(
                schema_epoch_id,
                proposed,
                operation,
                EntityBodyValue::TestCase(body.clone()),
            )?;
        }
        MutationPayload::AddContract(body) | MutationPayload::ReplaceContract(body) => {
            replace_body(
                schema_epoch_id,
                proposed,
                operation,
                EntityBodyValue::Contract(body.clone()),
            )?;
        }
        MutationPayload::UpdateDependencyBinding(body) => {
            replace_body(
                schema_epoch_id,
                proposed,
                operation,
                EntityBodyValue::DependencyBinding(body.clone()),
            )?;
        }
    }
    Ok(())
}

fn operation_field_tag(operation: &MutationOperation) -> Result<u16, CandidateApplyError> {
    operation
        .field_tag
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(CandidateApplyError::FieldMismatch)
}

fn ensure_body_kind(
    operation: &MutationOperation,
    body: &EntityBodyValue,
) -> Result<(), CandidateApplyError> {
    if body.kind_tag() == operation.target_kind {
        Ok(())
    } else {
        Err(CandidateApplyError::TargetKindMismatch)
    }
}

fn ensure_live_kind(
    proposed: &BTreeMap<EntityId, EntityObject>,
    operation: &MutationOperation,
) -> Result<(), CandidateApplyError> {
    let object = proposed
        .get(&operation.target_entity)
        .ok_or(CandidateApplyError::TargetMissing)?;
    ensure_body_kind(operation, &object.record().body)
}

fn replace_body(
    schema_epoch_id: SchemaEpochId,
    proposed: &mut BTreeMap<EntityId, EntityObject>,
    operation: &MutationOperation,
    body: EntityBodyValue,
) -> Result<(), CandidateApplyError> {
    ensure_body_kind(operation, &body)?;
    let current = proposed
        .get(&operation.target_entity)
        .ok_or(CandidateApplyError::TargetMissing)?;
    ensure_body_kind(operation, &current.record().body)?;
    let record = EntityObjectRecord {
        entity_id: operation.target_entity,
        body,
        label: current.record().label.clone(),
        semantic_fingerprint: current.record().semantic_fingerprint,
    };
    let replacement = build_entity_object(schema_epoch_id, &record)?;
    proposed.insert(operation.target_entity, replacement);
    Ok(())
}

fn mutate_body<F>(
    schema_epoch_id: SchemaEpochId,
    proposed: &mut BTreeMap<EntityId, EntityObject>,
    operation: &MutationOperation,
    mutation: F,
) -> Result<(), CandidateApplyError>
where
    F: FnOnce(&mut EntityBodyValue) -> bool,
{
    mutate_body_result(schema_epoch_id, proposed, operation, |body| {
        if mutation(body) {
            Ok(())
        } else {
            Err(CandidateApplyError::FieldMismatch)
        }
    })
}

fn mutate_body_result<F>(
    schema_epoch_id: SchemaEpochId,
    proposed: &mut BTreeMap<EntityId, EntityObject>,
    operation: &MutationOperation,
    mutation: F,
) -> Result<(), CandidateApplyError>
where
    F: FnOnce(&mut EntityBodyValue) -> Result<(), CandidateApplyError>,
{
    let current = proposed
        .get(&operation.target_entity)
        .ok_or(CandidateApplyError::TargetMissing)?;
    ensure_body_kind(operation, &current.record().body)?;
    let mut record = current.record().clone();
    mutation(&mut record.body)?;
    let replacement = build_entity_object(schema_epoch_id, &record)?;
    proposed.insert(operation.target_entity, replacement);
    Ok(())
}

#[cfg(test)]
mod tests {
    use sley_id::{
        CandidateNonce, CapabilitySummaryDigest, ObjectId, PolicyRootId, PrincipalId, StateRoot,
        TransactionId, WorkspaceId,
    };

    use super::*;
    use crate::candidate::{
        CandidateExpiry, ExactContainerVersion, ExactEntityVersion, ExpectedIdentityAbsent,
        OrderedInsert, OrderedMove,
    };
    use crate::value::{
        EntityIdSet, EntryExposure, EntryPointBody, FieldValue, FunctionBody, TestCaseBody,
        WorkspaceBody,
    };
    use crate::{MutationClass, PreimageRequirement, full_validation_profile_id};

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn workspace_body(root_namespace: EntityId) -> EntityBodyValue {
        EntityBodyValue::Workspace(WorkspaceBody {
            packages: EntityIdSet::from_unsorted(vec![]).unwrap(),
            root_namespace,
            capability_requirements: EntityIdSet::from_unsorted(vec![]).unwrap(),
            contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
            tests: EntityIdSet::from_unsorted(vec![]).unwrap(),
        })
    }

    fn object(epoch: SchemaEpochId, entity_id: EntityId, body: EntityBodyValue) -> EntityObject {
        build_entity_object(
            epoch,
            &EntityObjectRecord {
                entity_id,
                body,
                label: Some("kept".to_owned()),
                semantic_fingerprint: None,
            },
        )
        .unwrap()
    }

    fn exact_precondition(
        ordinal: u32,
        entity_id: EntityId,
        object_id: ObjectId,
    ) -> BoundPrecondition {
        BoundPrecondition {
            operation_ordinal: ordinal,
            requirement: PreimageRequirement::ExactEntityVersion,
            payload: PreconditionPayload::ExactEntityVersion(ExactEntityVersion {
                entity_id,
                object_id,
            }),
        }
    }

    fn candidate(
        epoch: SchemaEpochId,
        workspace_id: WorkspaceId,
        nonce: CandidateNonce,
        operations: Vec<MutationOperation>,
        preconditions: Vec<BoundPrecondition>,
    ) -> CandidateRecord {
        CandidateRecord {
            format_version: 1,
            workspace_id,
            base_transaction_id: TransactionId::from_bytes([2; 32]),
            base_root: StateRoot::from_bytes([3; 32]),
            schema_epoch_id: epoch,
            policy_root_id: PolicyRootId::from_bytes([4; 32]),
            principal_id: PrincipalId::from_bytes([5; 32]),
            capability_summary_digest: CapabilitySummaryDigest::from_bytes([6; 32]),
            operations,
            preconditions,
            validation_profile_id: full_validation_profile_id().unwrap(),
            candidate_nonce: nonce,
            expiry: CandidateExpiry::unix_millis(10),
        }
    }

    #[test]
    fn sequential_field_edits_bind_once_to_the_exact_base_object() {
        let epoch = SchemaEpochId::from_bytes([1; 32]);
        let target = id(10);
        let base = object(epoch, target, workspace_body(id(11)));
        let operations = vec![
            MutationOperation {
                ordinal: 0,
                class: MutationClass::RetargetReference,
                target_kind: 1,
                target_entity: target,
                field_tag: Some(2),
                payload: MutationPayload::RetargetReference(ReferenceTarget::Entity(id(12))),
                precondition_ordinal: 0,
            },
            MutationOperation {
                ordinal: 1,
                class: MutationClass::ReplaceTypedField,
                target_kind: 1,
                target_entity: target,
                field_tag: Some(4),
                payload: MutationPayload::ReplaceTypedField(FieldValue::WorkspaceContracts(
                    EntityIdSet::from_unsorted(vec![id(13)]).unwrap(),
                )),
                precondition_ordinal: 1,
            },
        ];
        let preconditions = vec![
            exact_precondition(0, target, base.object_id()),
            exact_precondition(1, target, base.object_id()),
        ];
        let record = candidate(
            epoch,
            WorkspaceId::from_bytes([9; 32]),
            CandidateNonce::from_bytes([8; 32]),
            operations,
            preconditions,
        );

        let proposed = apply_candidate_to_snapshot(epoch, &record, &[base], &[]).unwrap();
        let result = proposed.entity(target).unwrap();
        let EntityBodyValue::Workspace(body) = &result.record().body else {
            panic!("expected workspace body");
        };
        assert_eq!(body.root_namespace, id(12));
        assert_eq!(body.contracts.as_slice(), &[id(13)]);
        assert_eq!(result.record().label.as_deref(), Some("kept"));
        assert_eq!(proposed.affected_entities(), &[target]);
    }

    #[test]
    fn creation_checks_base_absence_and_builds_an_unlabelled_object() {
        let epoch = SchemaEpochId::from_bytes([1; 32]);
        let workspace_id = WorkspaceId::from_bytes([9; 32]);
        let nonce = CandidateNonce::from_bytes([8; 32]);
        let target = EntityId::derive(workspace_id, nonce, 1, 0);
        let operation = MutationOperation {
            ordinal: 0,
            class: MutationClass::CreateEntity,
            target_kind: 1,
            target_entity: target,
            field_tag: None,
            payload: MutationPayload::CreateEntity(workspace_body(id(11))),
            precondition_ordinal: 0,
        };
        let precondition = BoundPrecondition {
            operation_ordinal: 0,
            requirement: PreimageRequirement::ExpectedIdentityAbsent,
            payload: PreconditionPayload::ExpectedIdentityAbsent(ExpectedIdentityAbsent {
                entity_id: target,
            }),
        };
        let record = candidate(
            epoch,
            workspace_id,
            nonce,
            vec![operation],
            vec![precondition],
        );

        let proposed = apply_candidate_to_snapshot(epoch, &record, &[], &[]).unwrap();
        let created = proposed.entity(target).unwrap();
        assert_eq!(created.record().label, None);
        assert_eq!(created.record().semantic_fingerprint, None);

        assert_eq!(
            apply_candidate_to_snapshot(epoch, &record, core::slice::from_ref(created), &[])
                .unwrap_err(),
            CandidateApplyError::IdentityAlreadyLive
        );
    }

    #[test]
    fn ordered_operations_use_final_index_and_expected_child() {
        let epoch = SchemaEpochId::from_bytes([1; 32]);
        let target = id(20);
        let base = object(
            epoch,
            target,
            EntityBodyValue::Function(FunctionBody {
                type_parameters: vec![],
                parameters: vec![id(1), id(2), id(3)],
                result_type: sley_ssmc::TypeExpr::Unit,
                effects: EntityIdSet::from_unsorted(vec![]).unwrap(),
                entry_block: id(21),
                blocks: vec![],
                contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
                visibility: sley_ssmc::Visibility::Private,
            }),
        );
        let operations = vec![
            MutationOperation {
                ordinal: 0,
                class: MutationClass::MoveOrderedChild,
                target_kind: 5,
                target_entity: target,
                field_tag: Some(2),
                payload: MutationPayload::MoveOrderedChild(OrderedMove {
                    from: 0,
                    to: 2,
                    expected_child: id(1),
                }),
                precondition_ordinal: 0,
            },
            MutationOperation {
                ordinal: 1,
                class: MutationClass::InsertOrderedChild,
                target_kind: 5,
                target_entity: target,
                field_tag: Some(2),
                payload: MutationPayload::InsertOrderedChild(OrderedInsert {
                    index: 1,
                    child: id(4),
                }),
                precondition_ordinal: 1,
            },
        ];
        let preconditions = (0..2)
            .map(|ordinal| BoundPrecondition {
                operation_ordinal: ordinal,
                requirement: PreimageRequirement::ExactContainerVersion,
                payload: PreconditionPayload::ExactContainerVersion(ExactContainerVersion {
                    container_id: target,
                    object_id: base.object_id(),
                    field_tag: 2,
                }),
            })
            .collect();
        let record = candidate(
            epoch,
            WorkspaceId::from_bytes([9; 32]),
            CandidateNonce::from_bytes([8; 32]),
            operations,
            preconditions,
        );

        let proposed = apply_candidate_to_snapshot(epoch, &record, &[base], &[]).unwrap();
        let EntityBodyValue::Function(body) = &proposed.entity(target).unwrap().record().body
        else {
            panic!("expected function body");
        };
        assert_eq!(body.parameters, vec![id(2), id(4), id(3), id(1)]);
    }

    #[test]
    fn stale_preimage_and_entry_point_duplicates_fail_without_input_mutation() {
        let epoch = SchemaEpochId::from_bytes([1; 32]);
        let target = id(30);
        let base = object(
            epoch,
            target,
            EntityBodyValue::TestCase(TestCaseBody {
                target: id(31),
                inputs: vec![],
                effect_environment: sley_ssmc::EffectEnvironment::Replay(vec![]),
                expected: sley_ssmc::ExpectedOutcome::Value(sley_ssmc::ConstValue {
                    value_type: sley_ssmc::TypeExpr::Unit,
                    data: sley_ssmc::ConstData::Unit,
                }),
                observations: vec![],
                resource_limits: sley_ssmc::ResourceLimits {
                    fuel: 1,
                    memory_bytes: 1,
                    output_bytes: 1,
                    effect_count: 1,
                    call_depth: 1,
                    wall_timeout_millis: 1,
                },
            }),
        );
        let operation = MutationOperation {
            ordinal: 0,
            class: MutationClass::ReplaceTest,
            target_kind: 14,
            target_entity: target,
            field_tag: None,
            payload: MutationPayload::ReplaceTest(match base.record().body.clone() {
                EntityBodyValue::TestCase(body) => body,
                _ => unreachable!(),
            }),
            precondition_ordinal: 0,
        };
        let record = candidate(
            epoch,
            WorkspaceId::from_bytes([9; 32]),
            CandidateNonce::from_bytes([8; 32]),
            vec![operation],
            vec![exact_precondition(
                0,
                target,
                ObjectId::from_bytes([99; 32]),
            )],
        );
        let before = base.clone();
        assert_eq!(
            apply_candidate_to_snapshot(epoch, &record, core::slice::from_ref(&base), &[])
                .unwrap_err(),
            CandidateApplyError::ExactPreimageMismatch
        );
        assert_eq!(base, before);

        assert_eq!(
            apply_candidate_to_snapshot(epoch, &record, &[base], &[target, target]).unwrap_err(),
            CandidateApplyError::SnapshotDuplicateEntryPoint
        );
    }

    #[test]
    fn entry_points_must_be_live_and_explicitly_removed_before_delete() {
        let epoch = SchemaEpochId::from_bytes([1; 32]);
        let target = id(40);
        let base = object(
            epoch,
            target,
            EntityBodyValue::EntryPoint(EntryPointBody {
                function: id(41),
                exposure: EntryExposure::Protocol,
            }),
        );
        let operation = MutationOperation {
            ordinal: 0,
            class: MutationClass::DeleteEntityBinding,
            target_kind: 16,
            target_entity: target,
            field_tag: None,
            payload: MutationPayload::DeleteEntityBinding,
            precondition_ordinal: 0,
        };
        let record = candidate(
            epoch,
            WorkspaceId::from_bytes([9; 32]),
            CandidateNonce::from_bytes([8; 32]),
            vec![operation],
            vec![exact_precondition(0, target, base.object_id())],
        );

        assert_eq!(
            apply_candidate_to_snapshot(epoch, &record, core::slice::from_ref(&base), &[target])
                .unwrap_err(),
            CandidateApplyError::EntryPointStillBound
        );
        assert_eq!(
            apply_candidate_to_snapshot(epoch, &record, core::slice::from_ref(&base), &[id(99)])
                .unwrap_err(),
            CandidateApplyError::SnapshotEntryPointUnbound
        );
    }
}
