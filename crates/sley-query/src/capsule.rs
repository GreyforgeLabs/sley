//! Restricted complete-query evidence capsules.

use core::fmt;
use std::collections::BTreeSet;

use sley_id::{EntityId, RestrictedQueryCapsuleId, StateRoot};

use crate::{
    ImpactKind, IndexCompleteness, QueryLimits, RestrictedQueryResponse, RestrictedQueryResult,
    SnapshotContext,
};

const MAGIC: &[u8; 8] = b"SLEYRQC1";
const RESPONSE_MAGIC: &[u8; 8] = b"SLEYQRS1";
const FORMAT_VERSION: u32 = 1;
const PROFILE_VERSION: u32 = 1;
const LIMITS_PROFILE: u32 = 1;
const INDEX_COMPLETENESS_RESTRICTED: u32 = 1;
const CAPSULE_COMPLETENESS_COMPLETE: u32 = 1;
const TRUNCATION_FALSE: u32 = 1;
const CONTINUATION_NONE: u32 = 1;
const OPTION_NONE: u32 = 1;
const OPTION_SOME: u32 = 2;

/// Maximum source response bytes accepted by the restricted capsule profile.
pub const MAX_CAPSULE_SOURCE_RESPONSE_BYTES: u64 = 33_554_432;
/// Maximum entity dictionary entries.
pub const MAX_CAPSULE_ENTITIES: usize = 65_535;
/// Maximum relationship entries.
pub const MAX_CAPSULE_RELATIONSHIPS: usize = 400_000;
/// Maximum complete capsule-record bytes.
pub const MAX_RESTRICTED_CAPSULE_BYTES: u64 = 67_108_864;
/// Maximum charged derivation and encoding work.
pub const MAX_RESTRICTED_CAPSULE_WORK: u64 = 100_000_000;

/// Stable restricted S20-320 capsule failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestrictedCapsuleErrorCode {
    /// `RESTRICTED_CAPSULE_PROFILE_UNSUPPORTED`.
    ProfileUnsupported,
    /// `RESTRICTED_CAPSULE_SOURCE_INVALID`.
    SourceInvalid,
    /// `RESTRICTED_CAPSULE_DICTIONARY_INVALID`.
    DictionaryInvalid,
    /// `RESTRICTED_CAPSULE_RELATIONSHIP_INVALID`.
    RelationshipInvalid,
    /// `RESTRICTED_CAPSULE_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `RESTRICTED_CAPSULE_OMISSION_UNSUPPORTED`.
    OmissionUnsupported,
    /// `RESTRICTED_CAPSULE_CONTINUATION_UNSUPPORTED`.
    ContinuationUnsupported,
    /// `RESTRICTED_CAPSULE_INTERNAL_INVARIANT`.
    InternalInvariant,
}

impl RestrictedCapsuleErrorCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileUnsupported => "RESTRICTED_CAPSULE_PROFILE_UNSUPPORTED",
            Self::SourceInvalid => "RESTRICTED_CAPSULE_SOURCE_INVALID",
            Self::DictionaryInvalid => "RESTRICTED_CAPSULE_DICTIONARY_INVALID",
            Self::RelationshipInvalid => "RESTRICTED_CAPSULE_RELATIONSHIP_INVALID",
            Self::ResourceLimit => "RESTRICTED_CAPSULE_RESOURCE_LIMIT",
            Self::OmissionUnsupported => "RESTRICTED_CAPSULE_OMISSION_UNSUPPORTED",
            Self::ContinuationUnsupported => "RESTRICTED_CAPSULE_CONTINUATION_UNSUPPORTED",
            Self::InternalInvariant => "RESTRICTED_CAPSULE_INTERNAL_INVARIANT",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::ProfileUnsupported => 32_000,
            Self::SourceInvalid => 32_001,
            Self::DictionaryInvalid => 32_002,
            Self::RelationshipInvalid => 32_003,
            Self::ResourceLimit => 32_004,
            Self::OmissionUnsupported => 32_005,
            Self::ContinuationUnsupported => 32_006,
            Self::InternalInvariant => 32_007,
        }
    }
}

impl fmt::Display for RestrictedCapsuleErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable restricted-capsule construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictedCapsuleError(RestrictedCapsuleErrorCode);

impl RestrictedCapsuleError {
    /// Constructs a failure.
    #[must_use]
    pub const fn new(code: RestrictedCapsuleErrorCode) -> Self {
        Self(code)
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(self) -> RestrictedCapsuleErrorCode {
        self.0
    }
}

impl fmt::Display for RestrictedCapsuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for RestrictedCapsuleError {}

/// Fixed completeness status of every restricted capsule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestrictedCapsuleCompleteness {
    /// The complete successful restricted-query result is present.
    CompleteRestrictedResult,
}

/// One exact dictionary-indexed direct relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestrictedCapsuleRelationship {
    /// Zero-based dependent position in the entity dictionary.
    pub dependent_index: u32,
    /// Zero-based dependency position in the entity dictionary.
    pub dependency_index: u32,
    /// Exact S20-250 relationship kind.
    pub kind: ImpactKind,
}

/// Deterministic, derived-only complete restricted-query capsule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedQueryCapsule {
    capsule_id: RestrictedQueryCapsuleId,
    query_id: sley_id::QueryId,
    snapshot_id: sley_id::IndexSnapshotId,
    context: SnapshotContext,
    index_completeness: IndexCompleteness,
    limits: QueryLimits,
    query_kind: u32,
    returned_entities: u64,
    returned_edges: u64,
    reached_depth: u32,
    query_charged_work: u64,
    response_bytes: u64,
    entity_dictionary: Vec<EntityId>,
    relationships: Vec<RestrictedCapsuleRelationship>,
    record: Vec<u8>,
}

impl RestrictedQueryCapsule {
    /// Returns the derived capsule identifier.
    #[must_use]
    pub const fn capsule_id(&self) -> RestrictedQueryCapsuleId {
        self.capsule_id
    }

    /// Returns the exact source query identifier.
    #[must_use]
    pub const fn query_id(&self) -> sley_id::QueryId {
        self.query_id
    }

    /// Returns the exact source snapshot identifier.
    #[must_use]
    pub const fn snapshot_id(&self) -> sley_id::IndexSnapshotId {
        self.snapshot_id
    }

    /// Returns the exact source snapshot context.
    #[must_use]
    pub const fn context(&self) -> SnapshotContext {
        self.context
    }

    /// Returns the restricted source-index completeness arm.
    #[must_use]
    pub const fn index_completeness(&self) -> IndexCompleteness {
        self.index_completeness
    }

    /// Returns the fixed capsule completeness arm.
    #[must_use]
    pub const fn completeness(&self) -> RestrictedCapsuleCompleteness {
        RestrictedCapsuleCompleteness::CompleteRestrictedResult
    }

    /// Returns whether the capsule is truncated; always false.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        false
    }

    /// Returns whether a continuation exists; always false.
    #[must_use]
    pub const fn has_continuation(&self) -> bool {
        false
    }

    /// Returns the exact applied source-query limits.
    #[must_use]
    pub const fn limits(&self) -> QueryLimits {
        self.limits
    }

    /// Returns the frozen source query-kind tag.
    #[must_use]
    pub const fn query_kind(&self) -> u32 {
        self.query_kind
    }

    /// Returns the source response entity count.
    #[must_use]
    pub const fn returned_entities(&self) -> u64 {
        self.returned_entities
    }

    /// Returns the source response edge count.
    #[must_use]
    pub const fn returned_edges(&self) -> u64 {
        self.returned_edges
    }

    /// Returns the source response reached depth.
    #[must_use]
    pub const fn reached_depth(&self) -> u32 {
        self.reached_depth
    }

    /// Returns the source query's charged work.
    #[must_use]
    pub const fn query_charged_work(&self) -> u64 {
        self.query_charged_work
    }

    /// Returns the copied source-response byte count.
    #[must_use]
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    /// Returns the strict raw-ID-sorted entity dictionary.
    #[must_use]
    pub fn entity_dictionary(&self) -> &[EntityId] {
        &self.entity_dictionary
    }

    /// Returns the exact dictionary-indexed relationship table.
    #[must_use]
    pub fn relationships(&self) -> &[RestrictedCapsuleRelationship] {
        &self.relationships
    }

    /// Returns the complete canonical record including the ID trailer.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }
}

/// Builds a derived-only capsule from one successful complete query response.
///
/// # Errors
///
/// Returns a source, dictionary, relationship, resource, or invariant failure
/// without a partial capsule.
pub fn build_restricted_query_capsule(
    response: &RestrictedQueryResponse,
) -> Result<RestrictedQueryCapsule, RestrictedCapsuleError> {
    validate_source(response)?;
    let mut work = 0_u64;
    let entity_dictionary = derive_dictionary(response.result(), &mut work)?;
    let relationships = derive_relationships(response.result(), &entity_dictionary, &mut work)?;
    validate_counts(response, &entity_dictionary, &relationships)?;

    let mut record = encode_preimage(response, &entity_dictionary, &relationships, &mut work)?;
    let capsule_id = RestrictedQueryCapsuleId::derive(&record);
    append(&mut record, capsule_id.as_bytes(), &mut work)?;
    Ok(RestrictedQueryCapsule {
        capsule_id,
        query_id: response.query_id(),
        snapshot_id: response.snapshot_id(),
        context: response.context(),
        index_completeness: response.completeness(),
        limits: response.applied_limits(),
        query_kind: response.query_kind(),
        returned_entities: response.returned_entities(),
        returned_edges: response.returned_edges(),
        reached_depth: response.reached_depth(),
        query_charged_work: response.charged_work(),
        response_bytes: response.response_bytes(),
        entity_dictionary,
        relationships,
        record,
    })
}

fn validate_source(response: &RestrictedQueryResponse) -> Result<(), RestrictedCapsuleError> {
    let record = response.record();
    if record.get(..8) != Some(RESPONSE_MAGIC.as_slice())
        || u64::try_from(record.len()).ok() != Some(response.response_bytes())
    {
        return capsule_fail(RestrictedCapsuleErrorCode::SourceInvalid);
    }
    if response.response_bytes() > MAX_CAPSULE_SOURCE_RESPONSE_BYTES {
        return capsule_fail(RestrictedCapsuleErrorCode::ResourceLimit);
    }
    let expected_kind = match response.result() {
        RestrictedQueryResult::ModeledEntityKind(_) => 1,
        RestrictedQueryResult::DirectEdges(_) => response.query_kind(),
        RestrictedQueryResult::ReverseImpactClosure(_) => 4,
    };
    if expected_kind != response.query_kind()
        || matches!(response.result(), RestrictedQueryResult::DirectEdges(_))
            && !matches!(response.query_kind(), 2 | 3)
    {
        return capsule_fail(RestrictedCapsuleErrorCode::SourceInvalid);
    }
    Ok(())
}

fn derive_dictionary(
    result: &RestrictedQueryResult,
    work: &mut u64,
) -> Result<Vec<EntityId>, RestrictedCapsuleError> {
    let mut entities = BTreeSet::new();
    match result {
        RestrictedQueryResult::ModeledEntityKind(entry) => {
            charge(work, 1)?;
            entities.insert(entry.entity);
        }
        RestrictedQueryResult::DirectEdges(edges) => {
            for edge in edges {
                charge(work, 3)?;
                entities.insert(edge.dependent);
                entities.insert(edge.dependency);
            }
        }
        RestrictedQueryResult::ReverseImpactClosure(values) => {
            for entity in values {
                charge(work, 1)?;
                if !entities.insert(*entity) {
                    return capsule_fail(RestrictedCapsuleErrorCode::DictionaryInvalid);
                }
            }
        }
    }
    if entities.len() > MAX_CAPSULE_ENTITIES {
        return capsule_fail(RestrictedCapsuleErrorCode::ResourceLimit);
    }
    Ok(entities.into_iter().collect())
}

fn derive_relationships(
    result: &RestrictedQueryResult,
    dictionary: &[EntityId],
    work: &mut u64,
) -> Result<Vec<RestrictedCapsuleRelationship>, RestrictedCapsuleError> {
    let RestrictedQueryResult::DirectEdges(edges) = result else {
        return Ok(Vec::new());
    };
    if edges.len() > MAX_CAPSULE_RELATIONSHIPS {
        return capsule_fail(RestrictedCapsuleErrorCode::ResourceLimit);
    }
    let mut relationships = Vec::with_capacity(edges.len());
    for edge in edges {
        charge(work, 3)?;
        let dependent_index = dictionary.binary_search(&edge.dependent).map_err(|_| {
            RestrictedCapsuleError::new(RestrictedCapsuleErrorCode::RelationshipInvalid)
        })?;
        let dependency_index = dictionary.binary_search(&edge.dependency).map_err(|_| {
            RestrictedCapsuleError::new(RestrictedCapsuleErrorCode::RelationshipInvalid)
        })?;
        relationships.push(RestrictedCapsuleRelationship {
            dependent_index: u32::try_from(dependent_index).map_err(|_| {
                RestrictedCapsuleError::new(RestrictedCapsuleErrorCode::ResourceLimit)
            })?,
            dependency_index: u32::try_from(dependency_index).map_err(|_| {
                RestrictedCapsuleError::new(RestrictedCapsuleErrorCode::ResourceLimit)
            })?,
            kind: edge.kind,
        });
    }
    Ok(relationships)
}

fn validate_counts(
    response: &RestrictedQueryResponse,
    dictionary: &[EntityId],
    relationships: &[RestrictedCapsuleRelationship],
) -> Result<(), RestrictedCapsuleError> {
    let valid = match response.result() {
        RestrictedQueryResult::ModeledEntityKind(_) => {
            response.returned_entities() == 1
                && response.returned_edges() == 0
                && dictionary.len() == 1
                && relationships.is_empty()
        }
        RestrictedQueryResult::DirectEdges(edges) => {
            response.returned_entities() == 0
                && response.returned_edges() == u64::try_from(edges.len()).unwrap_or(u64::MAX)
                && relationships.len() == edges.len()
        }
        RestrictedQueryResult::ReverseImpactClosure(entities) => {
            response.returned_entities() == u64::try_from(entities.len()).unwrap_or(u64::MAX)
                && response.returned_edges() == 0
                && dictionary == entities.as_slice()
                && relationships.is_empty()
        }
    };
    if valid {
        Ok(())
    } else {
        capsule_fail(RestrictedCapsuleErrorCode::SourceInvalid)
    }
}

fn encode_preimage(
    response: &RestrictedQueryResponse,
    dictionary: &[EntityId],
    relationships: &[RestrictedCapsuleRelationship],
    work: &mut u64,
) -> Result<Vec<u8>, RestrictedCapsuleError> {
    let mut out = Vec::new();
    append(&mut out, MAGIC, work)?;
    push_u32(&mut out, FORMAT_VERSION, work)?;
    push_u32(&mut out, PROFILE_VERSION, work)?;
    append(&mut out, response.query_id().as_bytes(), work)?;
    append(&mut out, response.snapshot_id().as_bytes(), work)?;
    append(&mut out, response.context().schema_epoch.as_bytes(), work)?;
    encode_root(&mut out, response.context().claimed_root_context, work)?;
    push_u32(&mut out, completeness_tag(response.completeness()), work)?;
    push_u32(&mut out, LIMITS_PROFILE, work)?;
    encode_limits(&mut out, response.applied_limits(), work)?;
    push_u32(&mut out, response.query_kind(), work)?;
    push_u64(&mut out, response.returned_entities(), work)?;
    push_u64(&mut out, response.returned_edges(), work)?;
    push_u32(&mut out, response.reached_depth(), work)?;
    push_u64(&mut out, response.charged_work(), work)?;
    push_u64(&mut out, response.response_bytes(), work)?;
    push_u32(&mut out, CAPSULE_COMPLETENESS_COMPLETE, work)?;
    push_u32(&mut out, TRUNCATION_FALSE, work)?;
    push_u32(&mut out, CONTINUATION_NONE, work)?;
    push_u64(&mut out, to_u64(response.record().len())?, work)?;
    append(&mut out, response.record(), work)?;
    push_u64(&mut out, to_u64(dictionary.len())?, work)?;
    for entity in dictionary {
        append(&mut out, entity.as_bytes(), work)?;
    }
    push_u64(&mut out, to_u64(relationships.len())?, work)?;
    for relationship in relationships {
        push_u32(&mut out, relationship.dependent_index, work)?;
        push_u32(&mut out, relationship.dependency_index, work)?;
        push_u32(&mut out, relationship.kind.tag(), work)?;
    }
    if out
        .len()
        .checked_add(32)
        .and_then(|value| u64::try_from(value).ok())
        .is_none_or(|value| value > MAX_RESTRICTED_CAPSULE_BYTES)
    {
        return capsule_fail(RestrictedCapsuleErrorCode::ResourceLimit);
    }
    Ok(out)
}

fn encode_root(
    out: &mut Vec<u8>,
    root: Option<StateRoot>,
    work: &mut u64,
) -> Result<(), RestrictedCapsuleError> {
    match root {
        None => push_u32(out, OPTION_NONE, work),
        Some(root) => {
            push_u32(out, OPTION_SOME, work)?;
            append(out, root.as_bytes(), work)
        }
    }
}

fn encode_limits(
    out: &mut Vec<u8>,
    limits: QueryLimits,
    work: &mut u64,
) -> Result<(), RestrictedCapsuleError> {
    push_u64(out, limits.max_returned_entities, work)?;
    push_u64(out, limits.max_returned_edges, work)?;
    push_u32(out, limits.max_depth, work)?;
    push_u64(out, limits.max_response_bytes, work)?;
    push_u64(out, limits.max_work, work)
}

const fn completeness_tag(value: IndexCompleteness) -> u32 {
    match value {
        IndexCompleteness::RestrictedModeledKinds4To15Only => INDEX_COMPLETENESS_RESTRICTED,
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32, work: &mut u64) -> Result<(), RestrictedCapsuleError> {
    append(out, &value.to_be_bytes(), work)
}

fn push_u64(out: &mut Vec<u8>, value: u64, work: &mut u64) -> Result<(), RestrictedCapsuleError> {
    append(out, &value.to_be_bytes(), work)
}

fn append(out: &mut Vec<u8>, bytes: &[u8], work: &mut u64) -> Result<(), RestrictedCapsuleError> {
    charge(work, u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
    let next = out
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| RestrictedCapsuleError::new(RestrictedCapsuleErrorCode::ResourceLimit))?;
    if u64::try_from(next).map_or(true, |value| value > MAX_RESTRICTED_CAPSULE_BYTES) {
        return capsule_fail(RestrictedCapsuleErrorCode::ResourceLimit);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn charge(work: &mut u64, amount: u64) -> Result<(), RestrictedCapsuleError> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| RestrictedCapsuleError::new(RestrictedCapsuleErrorCode::ResourceLimit))?;
    if *work > MAX_RESTRICTED_CAPSULE_WORK {
        capsule_fail(RestrictedCapsuleErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn to_u64(value: usize) -> Result<u64, RestrictedCapsuleError> {
    u64::try_from(value)
        .map_err(|_| RestrictedCapsuleError::new(RestrictedCapsuleErrorCode::ResourceLimit))
}

fn capsule_fail<T>(code: RestrictedCapsuleErrorCode) -> Result<T, RestrictedCapsuleError> {
    Err(RestrictedCapsuleError::new(code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ImpactEntity, QueryLimits, RestrictedQuery, RestrictedQueryRunError, SnapshotContext,
        run_restricted_query,
    };
    use sley_id::{EntityId, SchemaEpochId};
    use sley_ssmc::{
        Block, CondBranchTerminator, FunctionGraph, Parameter, ParameterRole, Reachability,
        TargetEdge, Terminator, TypeExpr, ValueRef, Visibility,
    };

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn context() -> SnapshotContext {
        SnapshotContext {
            schema_epoch: SchemaEpochId::from_bytes([0x11; 32]),
            claimed_root_context: None,
        }
    }

    fn graph_fixture() -> (FunctionGraph, Parameter, Block) {
        let function = FunctionGraph {
            entity_id: id(1),
            type_parameters: Vec::new(),
            parameters: vec![id(2)],
            result_type: TypeExpr::Bool,
            effects: Vec::new(),
            entry_block: id(3),
            blocks: vec![id(3)],
            contracts: Vec::new(),
            visibility: Visibility::Private,
        };
        let parameter = Parameter {
            entity_id: id(2),
            owner: id(1),
            role: ParameterRole::Function,
            ordinal: 0,
            value_type: TypeExpr::Bool,
        };
        let block = Block {
            entity_id: id(3),
            function: id(1),
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: Terminator::CondBranch(CondBranchTerminator {
                condition: ValueRef::Parameter(id(2)),
                if_true: TargetEdge {
                    target: id(3),
                    arguments: Vec::new(),
                },
                if_false: TargetEdge {
                    target: id(3),
                    arguments: Vec::new(),
                },
            }),
            reachability: Reachability::Required,
        };
        (function, parameter, block)
    }

    fn all_kinds() -> Vec<ImpactKind> {
        vec![
            ImpactKind::Ownership,
            ImpactKind::TypeReference,
            ImpactKind::ValueReference,
            ImpactKind::ControlFlow,
            ImpactKind::Call,
            ImpactKind::Effect,
            ImpactKind::Capability,
            ImpactKind::Contract,
            ImpactKind::Initializer,
            ImpactKind::TestTarget,
            ImpactKind::Adapter,
            ImpactKind::DefinitionMember,
        ]
    }

    fn queries() -> [RestrictedQuery; 4] {
        [
            RestrictedQuery::GetModeledEntityKind { entity: id(1) },
            RestrictedQuery::ListDirectDependencies {
                entity: id(1),
                kinds: all_kinds(),
            },
            RestrictedQuery::ListDirectDependents {
                entity: id(1),
                kinds: all_kinds(),
            },
            RestrictedQuery::ReverseImpactClosure { seeds: vec![id(2)] },
        ]
    }

    fn responses() -> Vec<RestrictedQueryResponse> {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        queries()
            .into_iter()
            .map(|query| {
                run_restricted_query(context(), &entities, query, QueryLimits::profile_maximum())
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn codes_status_tags_and_limits_are_frozen() {
        let codes = [
            RestrictedCapsuleErrorCode::ProfileUnsupported,
            RestrictedCapsuleErrorCode::SourceInvalid,
            RestrictedCapsuleErrorCode::DictionaryInvalid,
            RestrictedCapsuleErrorCode::RelationshipInvalid,
            RestrictedCapsuleErrorCode::ResourceLimit,
            RestrictedCapsuleErrorCode::OmissionUnsupported,
            RestrictedCapsuleErrorCode::ContinuationUnsupported,
            RestrictedCapsuleErrorCode::InternalInvariant,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 32_000 + u32::try_from(offset).unwrap());
        }
        assert_eq!(MAX_CAPSULE_SOURCE_RESPONSE_BYTES, 33_554_432);
        assert_eq!(MAX_CAPSULE_ENTITIES, 65_535);
        assert_eq!(MAX_CAPSULE_RELATIONSHIPS, 400_000);
        assert_eq!(MAX_RESTRICTED_CAPSULE_BYTES, 67_108_864);
        assert_eq!(MAX_RESTRICTED_CAPSULE_WORK, 100_000_000);
    }

    #[test]
    fn all_four_query_capsule_vectors_are_fixed() {
        let expected = [
            (
                RestrictedQueryCapsuleId::from_bytes([
                    0x84, 0x8a, 0xb1, 0x67, 0x2e, 0x28, 0xad, 0x4f, 0x37, 0xca, 0x91, 0xb1, 0x61,
                    0xdf, 0x73, 0x18, 0x06, 0xcf, 0x4e, 0x09, 0x38, 0x74, 0x42, 0xab, 0xe5, 0x21,
                    0x2e, 0x86, 0xdd, 0x45, 0xec, 0x98,
                ]),
                540,
            ),
            (
                RestrictedQueryCapsuleId::from_bytes([
                    0x0c, 0x02, 0x02, 0x4d, 0x4b, 0x2e, 0xe2, 0x5e, 0x3c, 0x03, 0xe5, 0x92, 0xe6,
                    0x70, 0x8b, 0xe5, 0x0e, 0x80, 0xb6, 0xed, 0x62, 0x38, 0x4d, 0x87, 0xaa, 0xb1,
                    0x0d, 0x17, 0xe1, 0x7e, 0xee, 0xdc,
                ]),
                816,
            ),
            (
                RestrictedQueryCapsuleId::from_bytes([
                    0x51, 0x3a, 0x63, 0xaa, 0x13, 0x11, 0xa6, 0x61, 0x99, 0x46, 0x60, 0x9c, 0x7c,
                    0x6e, 0xd3, 0x0e, 0xa0, 0xda, 0x56, 0x66, 0x1c, 0x58, 0xae, 0xbe, 0xcd, 0x82,
                    0xbc, 0x16, 0x81, 0x76, 0x95, 0xdb,
                ]),
                736,
            ),
            (
                RestrictedQueryCapsuleId::from_bytes([
                    0xc0, 0xd1, 0x51, 0xf4, 0xa4, 0xa3, 0xf8, 0xf7, 0x4e, 0x33, 0x23, 0x99, 0x0a,
                    0x03, 0xf3, 0x8e, 0x9c, 0x05, 0x21, 0x87, 0x9d, 0x63, 0xb7, 0x3a, 0x22, 0x4c,
                    0x4e, 0x67, 0xab, 0xa5, 0x37, 0x48,
                ]),
                672,
            ),
        ];
        for (response, (expected_id, expected_len)) in responses().iter().zip(expected) {
            let capsule = build_restricted_query_capsule(response).unwrap();
            assert_eq!(capsule.capsule_id(), expected_id);
            assert_eq!(capsule.record().len(), expected_len);
        }
    }

    #[test]
    fn dictionary_and_relationship_projection_are_exact() {
        let capsules: Vec<_> = responses()
            .iter()
            .map(|response| build_restricted_query_capsule(response).unwrap())
            .collect();
        assert_eq!(capsules[0].entity_dictionary(), &[id(1)]);
        assert!(capsules[0].relationships().is_empty());
        assert_eq!(capsules[1].entity_dictionary(), &[id(1), id(2), id(3)]);
        assert_eq!(capsules[1].relationships().len(), 3);
        assert_eq!(capsules[2].entity_dictionary(), &[id(1), id(2), id(3)]);
        assert_eq!(capsules[2].relationships().len(), 2);
        assert_eq!(capsules[3].entity_dictionary(), &[id(1), id(2), id(3)]);
        assert!(capsules[3].relationships().is_empty());
        for (response, capsule) in responses().iter().zip(&capsules) {
            if let RestrictedQueryResult::DirectEdges(edges) = response.result() {
                for (edge, relationship) in edges.iter().zip(capsule.relationships()) {
                    assert_eq!(
                        capsule.entity_dictionary()
                            [usize::try_from(relationship.dependent_index).unwrap()],
                        edge.dependent
                    );
                    assert_eq!(
                        capsule.entity_dictionary()
                            [usize::try_from(relationship.dependency_index).unwrap()],
                        edge.dependency
                    );
                    assert_eq!(relationship.kind, edge.kind);
                }
            }
        }
    }

    #[test]
    fn completeness_is_fixed_without_truncation_or_continuation() {
        for response in responses() {
            let capsule = build_restricted_query_capsule(&response).unwrap();
            assert_eq!(
                capsule.completeness(),
                RestrictedCapsuleCompleteness::CompleteRestrictedResult
            );
            assert!(!capsule.is_truncated());
            assert!(!capsule.has_continuation());
            assert_eq!(capsule.query_id(), response.query_id());
            assert_eq!(capsule.snapshot_id(), response.snapshot_id());
            assert_eq!(capsule.response_bytes(), response.response_bytes());
        }
    }

    #[test]
    fn repeated_equal_capsules_are_byte_identical() {
        let response = responses().pop().unwrap();
        let expected = build_restricted_query_capsule(&response).unwrap();
        for _ in 0..128 {
            assert_eq!(build_restricted_query_capsule(&response).unwrap(), expected);
        }
    }

    #[test]
    fn dictionary_duplicates_and_missing_relationship_endpoints_fail() {
        let duplicate = RestrictedQueryResult::ReverseImpactClosure(vec![id(1), id(1)]);
        assert_eq!(
            derive_dictionary(&duplicate, &mut 0).unwrap_err().code(),
            RestrictedCapsuleErrorCode::DictionaryInvalid
        );
        let edge = crate::ImpactEdge {
            dependent: id(1),
            dependency: id(2),
            kind: ImpactKind::Ownership,
        };
        assert_eq!(
            derive_relationships(
                &RestrictedQueryResult::DirectEdges(vec![edge]),
                &[id(1)],
                &mut 0,
            )
            .unwrap_err()
            .code(),
            RestrictedCapsuleErrorCode::RelationshipInvalid
        );
    }

    #[test]
    fn resource_limits_fail_without_partial_capsule() {
        let mut work = MAX_RESTRICTED_CAPSULE_WORK;
        assert_eq!(
            charge(&mut work, 1).unwrap_err().code(),
            RestrictedCapsuleErrorCode::ResourceLimit
        );
        let mut out = Vec::new();
        let oversized = vec![0_u8; usize::try_from(MAX_RESTRICTED_CAPSULE_BYTES).unwrap() + 1];
        assert_eq!(
            append(&mut out, &oversized, &mut 0).unwrap_err().code(),
            RestrictedCapsuleErrorCode::ResourceLimit
        );
    }

    #[test]
    fn failed_or_omitted_queries_produce_no_capsule_input() {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let result = run_restricted_query(
            context(),
            &entities,
            RestrictedQuery::ReverseImpactClosure { seeds: vec![id(2)] },
            QueryLimits {
                max_returned_entities: 1,
                ..QueryLimits::profile_maximum()
            },
        );
        assert!(matches!(result, Err(RestrictedQueryRunError::Query(_))));
    }
}
