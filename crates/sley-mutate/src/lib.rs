#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

/// Closed S20-340 primitive mutation class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MutationClass {
    /// Create a new logical entity and require its identity to be absent.
    CreateEntity,
    /// Replace one immutable entity version.
    ReplaceEntityVersion,
    /// Delete one live entity binding without permitting identity reuse.
    DeleteEntityBinding,
    /// Replace a scalar field.
    SetScalarField,
    /// Replace any complete typed field.
    ReplaceTypedField,
    /// Replace a direct entity reference.
    RetargetReference,
    /// Insert into a `List<EntityId>` field.
    InsertOrderedChild,
    /// Remove from a `List<EntityId>` field.
    RemoveOrderedChild,
    /// Move within a `List<EntityId>` field.
    MoveOrderedChild,
    /// Add an entry-point entity binding.
    AddEntryPoint,
    /// Remove an entry-point entity binding.
    RemoveEntryPoint,
    /// Add a test entity binding.
    AddTest,
    /// Replace a test entity version.
    ReplaceTest,
    /// Add a contract entity binding.
    AddContract,
    /// Replace a contract entity version.
    ReplaceContract,
    /// Replace a dependency-binding entity version.
    UpdateDependencyBinding,
}

impl MutationClass {
    /// Returns the closed generated mutation-class tag.
    #[must_use]
    pub const fn tag(self) -> u16 {
        match self {
            Self::CreateEntity => 1,
            Self::ReplaceEntityVersion => 2,
            Self::DeleteEntityBinding => 3,
            Self::SetScalarField => 4,
            Self::ReplaceTypedField => 5,
            Self::RetargetReference => 6,
            Self::InsertOrderedChild => 7,
            Self::RemoveOrderedChild => 8,
            Self::MoveOrderedChild => 9,
            Self::AddEntryPoint => 10,
            Self::RemoveEntryPoint => 11,
            Self::AddTest => 12,
            Self::ReplaceTest => 13,
            Self::AddContract => 14,
            Self::ReplaceContract => 15,
            Self::UpdateDependencyBinding => 16,
        }
    }

    /// Returns the closed mutation class for an exact generated tag.
    #[must_use]
    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::CreateEntity),
            2 => Some(Self::ReplaceEntityVersion),
            3 => Some(Self::DeleteEntityBinding),
            4 => Some(Self::SetScalarField),
            5 => Some(Self::ReplaceTypedField),
            6 => Some(Self::RetargetReference),
            7 => Some(Self::InsertOrderedChild),
            8 => Some(Self::RemoveOrderedChild),
            9 => Some(Self::MoveOrderedChild),
            10 => Some(Self::AddEntryPoint),
            11 => Some(Self::RemoveEntryPoint),
            12 => Some(Self::AddTest),
            13 => Some(Self::ReplaceTest),
            14 => Some(Self::AddContract),
            15 => Some(Self::ReplaceContract),
            16 => Some(Self::UpdateDependencyBinding),
            _ => None,
        }
    }
}

/// Closed preimage shape required before a later candidate may carry an operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PreimageRequirement {
    /// Entity creation must prove that the derived logical identity is absent.
    ExpectedIdentityAbsent,
    /// Mutation must bind the exact current immutable entity version.
    ExactEntityVersion,
    /// Collection mutation must bind the exact current containing entity version.
    ExactContainerVersion,
}

impl PreimageRequirement {
    /// Returns the closed precondition-requirement tag.
    #[must_use]
    pub const fn tag(self) -> u16 {
        match self {
            Self::ExpectedIdentityAbsent => 1,
            Self::ExactEntityVersion => 2,
            Self::ExactContainerVersion => 3,
        }
    }

    /// Returns the closed precondition requirement for an exact tag.
    #[must_use]
    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::ExpectedIdentityAbsent),
            2 => Some(Self::ExactEntityVersion),
            3 => Some(Self::ExactContainerVersion),
            _ => None,
        }
    }
}

/// Closed additional field-operation shape inferred from the exact manifest type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FieldMutationShape {
    /// Only complete typed-field replacement is generated.
    TypedOnly,
    /// Scalar replacement is also generated.
    Scalar,
    /// Direct entity-reference retargeting is also generated.
    DirectEntityReference,
    /// Ordered-child insertion, removal, and movement are also generated.
    OrderedEntityChildren,
}

/// One frozen SSMC1 field usable by generated mutation descriptors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldSchemaDescriptor {
    /// Field tag within its entity body record.
    pub tag: u16,
    /// Canonical field name.
    pub name: &'static str,
    /// Exact type expression from the canonical manifest.
    pub value_type: &'static str,
    /// Whether the field is required in SSMC1.
    pub required: bool,
    /// Additional operation family generated from the exact field type shape.
    pub mutation_shape: FieldMutationShape,
}

/// One frozen SSMC1 entity-body descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntitySchemaDescriptor {
    /// Closed entity-kind tag.
    pub kind_tag: u16,
    /// Canonical entity-kind name.
    pub kind_name: &'static str,
    /// Canonical body-record name.
    pub body_name: &'static str,
    /// Ordered body fields.
    pub fields: &'static [FieldSchemaDescriptor],
}

/// One concrete schema-generated operation affordance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationOperationDescriptor {
    /// Closed primitive class.
    pub class: MutationClass,
    /// Eligible SSMC1 entity kind.
    pub target_kind: u16,
    /// Eligible body field, or `None` for entity-scoped operations.
    pub field_tag: Option<u16>,
    /// Exact value type supplied by the canonical manifest.
    pub value_type: &'static str,
    /// Preimage evidence later candidate construction must bind.
    pub preimage: PreimageRequirement,
}

include!("generated.rs");

mod candidate;
mod codec;
mod object;

pub use candidate::{
    BoundPrecondition, CandidateError, CandidateExpiry, CandidateRecord, ExactContainerVersion,
    ExactEntityVersion, ExpectedIdentityAbsent, ImportedCandidate, MutationOperation,
    MutationPayload, OrderedInsert, OrderedMove, OrderedRemove, PreconditionPayload,
    ReferenceTarget, ValidationProfileRecord, build_candidate, decode_candidate_record,
    encode_candidate_record, full_validation_profile_id, full_validation_profile_record,
    import_candidate,
};
pub use object::{
    ENTITY_OBJECT_CONTRACT_TAG, ENTITY_OBJECT_FORMAT_VERSION, ENTITY_OBJECT_MAGIC, EntityObject,
    EntityObjectRecord, MAX_ENTITY_OBJECT_LABEL_BYTES, build_entity_object, import_entity_object,
};

pub mod value;

/// Returns a frozen entity descriptor by its exact SSMC1 tag.
#[must_use]
pub fn entity_schema(kind_tag: u16) -> Option<&'static EntitySchemaDescriptor> {
    ENTITY_SCHEMAS
        .binary_search_by_key(&kind_tag, |descriptor| descriptor.kind_tag)
        .ok()
        .map(|index| &ENTITY_SCHEMAS[index])
}

/// Returns the concrete descriptors for one closed mutation class.
pub fn operations_for(
    class: MutationClass,
) -> impl Iterator<Item = &'static MutationOperationDescriptor> {
    MUTATION_OPERATIONS
        .iter()
        .filter(move |descriptor| descriptor.class == class)
}

/// Returns the exact immutable descriptor for one operation key.
#[must_use]
pub fn mutation_operation_descriptor(
    class: MutationClass,
    target_kind: u16,
    field_tag: Option<u16>,
) -> Option<&'static MutationOperationDescriptor> {
    MUTATION_OPERATIONS.iter().find(|descriptor| {
        descriptor.class == class
            && descriptor.target_kind == target_kind
            && descriptor.field_tag == field_tag
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const CLASSES: [MutationClass; 16] = [
        MutationClass::CreateEntity,
        MutationClass::ReplaceEntityVersion,
        MutationClass::DeleteEntityBinding,
        MutationClass::SetScalarField,
        MutationClass::ReplaceTypedField,
        MutationClass::RetargetReference,
        MutationClass::InsertOrderedChild,
        MutationClass::RemoveOrderedChild,
        MutationClass::MoveOrderedChild,
        MutationClass::AddEntryPoint,
        MutationClass::RemoveEntryPoint,
        MutationClass::AddTest,
        MutationClass::ReplaceTest,
        MutationClass::AddContract,
        MutationClass::ReplaceContract,
        MutationClass::UpdateDependencyBinding,
    ];

    #[test]
    fn generated_schema_reproduces_the_frozen_manifest_digest() {
        assert_eq!(
            SOURCE_SCHEMA_BLAKE3,
            sley_schema::SSMC1_EPOCH1_MANIFEST_BLAKE3
        );
        assert_eq!(
            *blake3::hash(sley_schema::SSMC1_EPOCH1_MANIFEST).as_bytes(),
            SOURCE_SCHEMA_BLAKE3
        );
    }

    #[test]
    fn all_eighteen_entity_kinds_are_closed_and_ordered() {
        assert_eq!(ENTITY_SCHEMAS.len(), 18);
        for (index, descriptor) in ENTITY_SCHEMAS.iter().enumerate() {
            assert_eq!(usize::from(descriptor.kind_tag), index + 1);
            assert!(entity_schema(descriptor.kind_tag).is_some());
        }
        assert!(entity_schema(0).is_none());
        assert!(entity_schema(19).is_none());
    }

    #[test]
    fn all_sixteen_mutation_classes_are_present_and_tagged() {
        for (index, class) in CLASSES.into_iter().enumerate() {
            assert_eq!(usize::from(class.tag()), index + 1);
            assert!(operations_for(class).next().is_some());
        }
    }

    #[test]
    fn every_entity_field_has_exactly_one_typed_replacement() {
        let field_count: usize = ENTITY_SCHEMAS
            .iter()
            .map(|descriptor| descriptor.fields.len())
            .sum();
        assert_eq!(
            operations_for(MutationClass::ReplaceTypedField).count(),
            field_count
        );
    }

    #[test]
    fn field_affordances_follow_generated_type_shapes() {
        for entity in ENTITY_SCHEMAS {
            for field in entity.fields {
                let has = |class| {
                    operations_for(class).any(|operation| {
                        operation.target_kind == entity.kind_tag
                            && operation.field_tag == Some(field.tag)
                    })
                };
                assert_eq!(
                    has(MutationClass::SetScalarField),
                    field.mutation_shape == FieldMutationShape::Scalar
                );
                assert_eq!(
                    has(MutationClass::RetargetReference),
                    field.mutation_shape == FieldMutationShape::DirectEntityReference
                );
                for class in [
                    MutationClass::InsertOrderedChild,
                    MutationClass::RemoveOrderedChild,
                    MutationClass::MoveOrderedChild,
                ] {
                    assert_eq!(
                        has(class),
                        field.mutation_shape == FieldMutationShape::OrderedEntityChildren
                    );
                }
            }
        }
    }

    #[test]
    fn operation_keys_are_unique() {
        let keys: BTreeSet<_> = MUTATION_OPERATIONS
            .iter()
            .map(|descriptor| {
                (
                    descriptor.class.tag(),
                    descriptor.target_kind,
                    descriptor.field_tag,
                )
            })
            .collect();
        assert_eq!(keys.len(), MUTATION_OPERATIONS.len());
    }

    #[test]
    fn creation_requires_absence_and_every_other_class_requires_exact_preimage() {
        for operation in MUTATION_OPERATIONS {
            if operation.class == MutationClass::CreateEntity {
                assert_eq!(
                    operation.preimage,
                    PreimageRequirement::ExpectedIdentityAbsent
                );
            } else {
                assert_ne!(
                    operation.preimage,
                    PreimageRequirement::ExpectedIdentityAbsent
                );
            }
        }
    }

    #[test]
    fn special_entity_classes_are_narrowly_targeted() {
        let targets = |class| {
            operations_for(class)
                .map(|descriptor| descriptor.target_kind)
                .collect::<Vec<_>>()
        };
        assert_eq!(targets(MutationClass::AddEntryPoint), vec![16]);
        assert_eq!(targets(MutationClass::RemoveEntryPoint), vec![16]);
        assert_eq!(targets(MutationClass::AddTest), vec![14]);
        assert_eq!(targets(MutationClass::ReplaceTest), vec![14]);
        assert_eq!(targets(MutationClass::AddContract), vec![13]);
        assert_eq!(targets(MutationClass::ReplaceContract), vec![13]);
        assert_eq!(targets(MutationClass::UpdateDependencyBinding), vec![18]);
    }
}
