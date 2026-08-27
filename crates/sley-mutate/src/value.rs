//! Closed S20-350a proposal-value host model.
//!
//! This module intentionally supplies no binary codec, descriptor admission,
//! candidate construction, validation, authority, or state mutation.

use core::fmt;

use sley_id::{EntityId, StateRoot};

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

#[cfg(test)]
mod tests {
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
}
