//! Closed S20-350a proposal-value host model.
//!
//! This module intentionally supplies only closed host values and exact
//! type-selection admission. It supplies no binary codec, candidate
//! construction, semantic validation, authority, or state mutation.

use core::fmt;

use sley_id::{EntityId, StateRoot};

use crate::MutationClass;

/// Canonical raw-ID-ordered set of unique entity identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityIdSet(Vec<EntityId>);

/// Failure to construct a canonical entity-identity set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntityIdSetError {
    /// The input contained one identity more than once.
    Duplicate,
}

impl fmt::Display for EntityIdSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MUTATION_VALUE_SET_DUPLICATE")
    }
}

impl std::error::Error for EntityIdSetError {}

impl EntityIdSet {
    /// Canonicalizes arbitrary input order and rejects duplicate identities.
    ///
    /// # Errors
    ///
    /// Returns [`EntityIdSetError::Duplicate`] when an identity occurs twice.
    pub fn from_unsorted(mut values: Vec<EntityId>) -> Result<Self, EntityIdSetError> {
        values.sort_unstable();
        if values.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EntityIdSetError::Duplicate);
        }
        Ok(Self(values))
    }

    /// Returns the canonical raw-ID-ordered identities.
    #[must_use]
    pub fn as_slice(&self) -> &[EntityId] {
        &self.0
    }

    /// Consumes the set and returns its canonical ordered representation.
    #[must_use]
    pub fn into_vec(self) -> Vec<EntityId> {
        self.0
    }
}

/// Closed entry-point exposure declared by the exact SSMC1 manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryExposure {
    /// Locally callable only.
    Local,
    /// Exposed through the deterministic protocol surface.
    Protocol,
}

impl EntryExposure {
    /// Returns the exact frozen SSMC1 tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Local => 1,
            Self::Protocol => 2,
        }
    }
}

include!("value_generated.rs");

/// Stable failure from closed descriptor-to-value-kind admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueBindingError {
    /// No immutable S20-340 descriptor has the supplied exact key.
    DescriptorUnknown,
    /// The proposal value has a different closed body or field kind.
    ValueKindMismatch,
}

impl fmt::Display for ValueBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DescriptorUnknown => f.write_str("MUTATION_VALUE_DESCRIPTOR_UNKNOWN"),
            Self::ValueKindMismatch => f.write_str("MUTATION_VALUE_KIND_MISMATCH"),
        }
    }
}

impl std::error::Error for ValueBindingError {}

/// Returns the exact generated typed-value binding for one immutable descriptor key.
#[must_use]
pub fn typed_value_binding(
    class: MutationClass,
    target_kind: u16,
    field_tag: Option<u16>,
) -> Option<&'static TypedValueBinding> {
    TYPED_VALUE_BINDINGS.iter().find(|binding| {
        binding.class == class
            && binding.target_kind == target_kind
            && binding.field_tag == field_tag
    })
}

/// Admits one closed proposal host value against one exact immutable descriptor.
///
/// This function performs type selection only. It does not encode bytes,
/// evaluate preconditions, construct a candidate, establish authority, or
/// mutate state.
///
/// # Errors
///
/// Returns [`ValueBindingError::DescriptorUnknown`] for an unknown descriptor
/// key and [`ValueBindingError::ValueKindMismatch`] for a differently typed
/// body or field value.
pub fn admit_proposal_value(
    class: MutationClass,
    target_kind: u16,
    field_tag: Option<u16>,
    value: &ProposalValue,
) -> Result<(), ValueBindingError> {
    let binding = typed_value_binding(class, target_kind, field_tag)
        .ok_or(ValueBindingError::DescriptorUnknown)?;
    if binding.value_kind == value.value_kind() {
        Ok(())
    } else {
        Err(ValueBindingError::ValueKindMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    #[test]
    fn entity_id_set_canonicalizes_before_proposal_construction() {
        let set = EntityIdSet::from_unsorted(vec![id(3), id(1), id(2)]).unwrap();
        assert_eq!(set.as_slice(), &[id(1), id(2), id(3)]);
        assert_eq!(
            EntityIdSet::from_unsorted(vec![id(1), id(1)]),
            Err(EntityIdSetError::Duplicate)
        );
    }

    #[test]
    fn generated_host_inventory_is_exact_and_digest_bound() {
        assert_eq!(ENTITY_BODY_VALUE_COUNT, 18);
        assert_eq!(FIELD_VALUE_COUNT, 75);
        assert_eq!(
            VALUE_HOST_SOURCE_SCHEMA_BLAKE3,
            sley_schema::SSMC1_EPOCH1_MANIFEST_BLAKE3
        );
    }

    #[test]
    fn generated_values_carry_closed_schema_keys_without_runtime_names() {
        let body = EntityBodyValue::Workspace(WorkspaceBody {
            packages: EntityIdSet::from_unsorted(vec![]).unwrap(),
            root_namespace: id(1),
            capability_requirements: EntityIdSet::from_unsorted(vec![]).unwrap(),
            contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
            tests: EntityIdSet::from_unsorted(vec![]).unwrap(),
        });
        let field = FieldValue::DependencyBindingLocalNamespace(id(2));
        assert_eq!(body.kind_tag(), 1);
        assert_eq!(field.field_key(), (18, 3));
    }

    #[test]
    fn optional_record_field_preserves_absence_as_a_typed_value() {
        let body = ContractBody {
            target: id(1),
            contract_kind: sley_ssmc::ContractKind::Precondition,
            predicate: id(2),
            bindings: vec![],
            resource_limits: None,
        };
        let field = FieldValue::ContractResourceLimits(None);
        assert_eq!(body.resource_limits, None);
        assert_eq!(field.field_key(), (13, 5));
    }

    #[test]
    fn generated_typed_bindings_cover_every_immutable_descriptor_once() {
        assert_eq!(TYPED_VALUE_BINDING_COUNT, 179);
        assert_eq!(TYPED_VALUE_BINDINGS.len(), 179);
        let binding_keys: BTreeSet<_> = TYPED_VALUE_BINDINGS
            .iter()
            .map(|binding| (binding.class.tag(), binding.target_kind, binding.field_tag))
            .collect();
        let descriptor_keys: BTreeSet<_> = crate::MUTATION_OPERATIONS
            .iter()
            .map(|descriptor| {
                (
                    descriptor.class.tag(),
                    descriptor.target_kind,
                    descriptor.field_tag,
                )
            })
            .collect();
        assert_eq!(binding_keys.len(), 179);
        assert_eq!(binding_keys, descriptor_keys);
    }

    #[test]
    fn descriptor_admission_rejects_unknown_keys_and_typed_confusion() {
        let workspace = ProposalValue::EntityBody(EntityBodyValue::Workspace(WorkspaceBody {
            packages: EntityIdSet::from_unsorted(vec![]).unwrap(),
            root_namespace: id(1),
            capability_requirements: EntityIdSet::from_unsorted(vec![]).unwrap(),
            contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
            tests: EntityIdSet::from_unsorted(vec![]).unwrap(),
        }));
        let local_namespace =
            ProposalValue::Field(FieldValue::DependencyBindingLocalNamespace(id(2)));

        assert_eq!(
            admit_proposal_value(MutationClass::CreateEntity, 1, None, &workspace),
            Ok(())
        );
        assert_eq!(
            admit_proposal_value(MutationClass::CreateEntity, 2, None, &workspace),
            Err(ValueBindingError::ValueKindMismatch)
        );
        assert_eq!(
            admit_proposal_value(
                MutationClass::ReplaceTypedField,
                18,
                Some(3),
                &local_namespace
            ),
            Ok(())
        );
        assert_eq!(
            admit_proposal_value(MutationClass::AddEntryPoint, 1, None, &workspace),
            Err(ValueBindingError::DescriptorUnknown)
        );
    }
}
