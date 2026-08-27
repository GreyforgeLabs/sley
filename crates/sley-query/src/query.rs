//! Restricted typed queries over opaque, freshly derived index snapshots.

use core::fmt;
use std::collections::BTreeMap;
use std::collections::VecDeque;

use sley_id::{EntityId, IndexSnapshotId, QueryId, StateRoot};

use crate::{
    ImpactEdge, ImpactEntity, ImpactError, ImpactKind, IndexCompleteness, IndexInventoryEntry,
    IndexSnapshot, IndexSnapshotBuildError, IndexSnapshotError, SnapshotContext,
    build_index_snapshot,
};

const QUERY_MAGIC: &[u8; 8] = b"SLEYQRY1";
const RESPONSE_MAGIC: &[u8; 8] = b"SLEYQRS1";
const FORMAT_VERSION: u32 = 1;
const PROFILE_VERSION: u32 = 1;
const LIMITS_PROFILE: u32 = 1;
const COMPLETENESS_RESTRICTED: u32 = 1;
const OPTION_NONE: u32 = 1;
const OPTION_SOME: u32 = 2;
const RESPONSE_HEADER_WITHOUT_ROOT: usize = 204;
const RESPONSE_HEADER_WITH_ROOT: usize = 236;

/// Maximum canonical restricted-query request preimage size.
pub const MAX_QUERY_REQUEST_BYTES: usize = 4_194_304;
/// Maximum returned entity entries.
pub const MAX_QUERY_RETURNED_ENTITIES: u64 = 65_535;
/// Maximum returned direct edges.
pub const MAX_QUERY_RETURNED_EDGES: u64 = 400_000;
/// Maximum reverse-closure depth.
pub const MAX_QUERY_DEPTH: u32 = 65_535;
/// Maximum deterministic response-record size.
pub const MAX_QUERY_RESPONSE_BYTES: u64 = 67_108_864;
/// Maximum charged traversal plus response-encoding work.
pub const MAX_QUERY_WORK: u64 = 100_000_000;

/// Stable restricted S20-310 query failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryErrorCode {
    /// `QUERY_PROFILE_UNSUPPORTED`.
    ProfileUnsupported,
    /// `QUERY_REQUEST_NOT_CANONICAL`.
    RequestNotCanonical,
    /// `QUERY_UNSUPPORTED`.
    Unsupported,
    /// `QUERY_SNAPSHOT_MISMATCH`.
    SnapshotMismatch,
    /// `QUERY_UNRESOLVED_ENTITY`.
    UnresolvedEntity,
    /// `QUERY_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `QUERY_REQUIRED_FACT_OMITTED`.
    RequiredFactOmitted,
    /// `QUERY_INTERNAL_INVARIANT`.
    InternalInvariant,
}

impl QueryErrorCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileUnsupported => "QUERY_PROFILE_UNSUPPORTED",
            Self::RequestNotCanonical => "QUERY_REQUEST_NOT_CANONICAL",
            Self::Unsupported => "QUERY_UNSUPPORTED",
            Self::SnapshotMismatch => "QUERY_SNAPSHOT_MISMATCH",
            Self::UnresolvedEntity => "QUERY_UNRESOLVED_ENTITY",
            Self::ResourceLimit => "QUERY_RESOURCE_LIMIT",
            Self::RequiredFactOmitted => "QUERY_REQUIRED_FACT_OMITTED",
            Self::InternalInvariant => "QUERY_INTERNAL_INVARIANT",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::ProfileUnsupported => 31_000,
            Self::RequestNotCanonical => 31_001,
            Self::Unsupported => 31_002,
            Self::SnapshotMismatch => 31_003,
            Self::UnresolvedEntity => 31_004,
            Self::ResourceLimit => 31_005,
            Self::RequiredFactOmitted => 31_006,
            Self::InternalInvariant => 31_007,
        }
    }
}

impl fmt::Display for QueryErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable restricted-query failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryError(QueryErrorCode);

impl QueryError {
    /// Constructs a query failure.
    #[must_use]
    pub const fn new(code: QueryErrorCode) -> Self {
        Self(code)
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(&self) -> QueryErrorCode {
        self.0
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for QueryError {}

/// End-to-end fresh-build/query failure preserving owning error namespaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestrictedQueryRunError {
    /// Canonical S20-250 impact extraction failed.
    Impact(ImpactError),
    /// Restricted snapshot projection or encoding failed.
    Snapshot(IndexSnapshotError),
    /// Restricted query validation or execution failed.
    Query(QueryError),
}

impl fmt::Display for RestrictedQueryRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Impact(error) => error.fmt(formatter),
            Self::Snapshot(error) => error.fmt(formatter),
            Self::Query(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RestrictedQueryRunError {}

impl From<QueryError> for RestrictedQueryRunError {
    fn from(value: QueryError) -> Self {
        Self::Query(value)
    }
}

impl From<IndexSnapshotBuildError> for RestrictedQueryRunError {
    fn from(value: IndexSnapshotBuildError) -> Self {
        match value {
            IndexSnapshotBuildError::Impact(error) => Self::Impact(error),
            IndexSnapshotBuildError::Snapshot(error) => Self::Snapshot(error),
        }
    }
}

/// Exact caller-applied restricted-query limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryLimits {
    /// Maximum returned entity entries.
    pub max_returned_entities: u64,
    /// Maximum returned direct edges.
    pub max_returned_edges: u64,
    /// Maximum reverse-closure depth.
    pub max_depth: u32,
    /// Maximum complete response-record bytes.
    pub max_response_bytes: u64,
    /// Maximum charged traversal plus response-encoding work.
    pub max_work: u64,
}

impl QueryLimits {
    /// Returns the restricted profile ceilings.
    #[must_use]
    pub const fn profile_maximum() -> Self {
        Self {
            max_returned_entities: MAX_QUERY_RETURNED_ENTITIES,
            max_returned_edges: MAX_QUERY_RETURNED_EDGES,
            max_depth: MAX_QUERY_DEPTH,
            max_response_bytes: MAX_QUERY_RESPONSE_BYTES,
            max_work: MAX_QUERY_WORK,
        }
    }
}

/// Closed typed restricted-query request body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestrictedQuery {
    /// Return one modeled inventory identity/kind entry.
    GetModeledEntityKind {
        /// Exact modeled entity.
        entity: EntityId,
    },
    /// Return filtered edges whose dependent is `entity`.
    ListDirectDependencies {
        /// Exact referring entity.
        entity: EntityId,
        /// Nonempty canonical relationship-kind filter.
        kinds: Vec<ImpactKind>,
    },
    /// Return filtered edges whose dependency is `entity`.
    ListDirectDependents {
        /// Exact referenced entity.
        entity: EntityId,
        /// Nonempty canonical relationship-kind filter.
        kinds: Vec<ImpactKind>,
    },
    /// Return reverse reachability including every seed.
    ReverseImpactClosure {
        /// Nonempty raw-ID-sorted seed set.
        seeds: Vec<EntityId>,
    },
}

impl RestrictedQuery {
    const fn tag(&self) -> u32 {
        match self {
            Self::GetModeledEntityKind { .. } => 1,
            Self::ListDirectDependencies { .. } => 2,
            Self::ListDirectDependents { .. } => 3,
            Self::ReverseImpactClosure { .. } => 4,
        }
    }
}

/// Canonically identified query request bound to one exact snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedQueryRequest {
    format_version: u32,
    profile_version: u32,
    query_id: QueryId,
    snapshot_id: IndexSnapshotId,
    context: SnapshotContext,
    completeness: IndexCompleteness,
    limits: QueryLimits,
    query: RestrictedQuery,
    preimage: Vec<u8>,
}

impl RestrictedQueryRequest {
    /// Returns the exact request digest.
    #[must_use]
    pub const fn query_id(&self) -> QueryId {
        self.query_id
    }

    /// Returns the bound snapshot ID.
    #[must_use]
    pub const fn snapshot_id(&self) -> IndexSnapshotId {
        self.snapshot_id
    }

    /// Returns the exact snapshot context.
    #[must_use]
    pub const fn context(&self) -> SnapshotContext {
        self.context
    }

    /// Returns the exact completeness arm.
    #[must_use]
    pub const fn completeness(&self) -> IndexCompleteness {
        self.completeness
    }

    /// Returns the applied limits.
    #[must_use]
    pub const fn limits(&self) -> QueryLimits {
        self.limits
    }

    /// Returns the typed request body.
    #[must_use]
    pub const fn query(&self) -> &RestrictedQuery {
        &self.query
    }

    /// Returns the exact `QueryId` preimage.
    #[must_use]
    pub fn preimage(&self) -> &[u8] {
        &self.preimage
    }
}

/// Exact derived restricted-query payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestrictedQueryResult {
    /// One modeled inventory entry.
    ModeledEntityKind(IndexInventoryEntry),
    /// Exact canonical direct-edge list.
    DirectEdges(Vec<ImpactEdge>),
    /// Exact raw-ID-sorted reverse impact closure.
    ReverseImpactClosure(Vec<EntityId>),
}

/// Complete deterministic restricted-query response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedQueryResponse {
    query_id: QueryId,
    snapshot_id: IndexSnapshotId,
    context: SnapshotContext,
    completeness: IndexCompleteness,
    applied_limits: QueryLimits,
    query_kind: u32,
    returned_entities: u64,
    returned_edges: u64,
    reached_depth: u32,
    charged_work: u64,
    result: RestrictedQueryResult,
    record: Vec<u8>,
}

impl RestrictedQueryResponse {
    /// Returns the exact request digest.
    #[must_use]
    pub const fn query_id(&self) -> QueryId {
        self.query_id
    }

    /// Returns the exact queried snapshot ID.
    #[must_use]
    pub const fn snapshot_id(&self) -> IndexSnapshotId {
        self.snapshot_id
    }

    /// Returns the exact snapshot context.
    #[must_use]
    pub const fn context(&self) -> SnapshotContext {
        self.context
    }

    /// Returns the exact restricted completeness arm.
    #[must_use]
    pub const fn completeness(&self) -> IndexCompleteness {
        self.completeness
    }

    /// Returns the exact applied limits.
    #[must_use]
    pub const fn applied_limits(&self) -> QueryLimits {
        self.applied_limits
    }

    /// Returns the frozen query-kind tag.
    #[must_use]
    pub const fn query_kind(&self) -> u32 {
        self.query_kind
    }

    /// Returns the number of entity payload entries.
    #[must_use]
    pub const fn returned_entities(&self) -> u64 {
        self.returned_entities
    }

    /// Returns the number of edge payload entries.
    #[must_use]
    pub const fn returned_edges(&self) -> u64 {
        self.returned_edges
    }

    /// Returns the maximum shortest reverse-closure depth reached.
    #[must_use]
    pub const fn reached_depth(&self) -> u32 {
        self.reached_depth
    }

    /// Returns charged traversal plus response-record bytes.
    #[must_use]
    pub const fn charged_work(&self) -> u64 {
        self.charged_work
    }

    /// Returns the complete deterministic response-record size.
    #[must_use]
    pub fn response_bytes(&self) -> u64 {
        u64::try_from(self.record.len()).unwrap_or(u64::MAX)
    }

    /// Returns the exact typed result.
    #[must_use]
    pub const fn result(&self) -> &RestrictedQueryResult {
        &self.result
    }

    /// Returns the exact deterministic response record.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }
}

/// Builds a canonical request bound to one opaque fresh snapshot.
///
/// # Errors
///
/// Returns a resource or request-canonicality failure before deriving `QueryId`.
pub fn build_restricted_query_request(
    snapshot: &IndexSnapshot,
    query: RestrictedQuery,
    limits: QueryLimits,
) -> Result<RestrictedQueryRequest, QueryError> {
    validate_limits(limits)?;
    validate_query_shape(&query)?;
    let preimage = encode_query_preimage(
        snapshot.snapshot_id(),
        snapshot.context(),
        snapshot.completeness(),
        limits,
        &query,
    )?;
    let query_id = QueryId::derive(&preimage);
    Ok(RestrictedQueryRequest {
        format_version: FORMAT_VERSION,
        profile_version: PROFILE_VERSION,
        query_id,
        snapshot_id: snapshot.snapshot_id(),
        context: snapshot.context(),
        completeness: snapshot.completeness(),
        limits,
        query,
        preimage,
    })
}

/// Executes a canonical request against its exact opaque snapshot binding.
///
/// # Errors
///
/// Fails without a partial response on profile, request, binding, resolution,
/// resource, required-fact, or internal-invariant failure.
pub fn execute_restricted_query(
    snapshot: &IndexSnapshot,
    request: &RestrictedQueryRequest,
) -> Result<RestrictedQueryResponse, QueryError> {
    verify_request(request)?;
    if request.snapshot_id != snapshot.snapshot_id()
        || request.context != snapshot.context()
        || request.completeness != snapshot.completeness()
    {
        return query_fail(QueryErrorCode::SnapshotMismatch);
    }
    resolve_query_entities(snapshot, &request.query)?;

    let mut work = 0_u64;
    let (result, reached_depth) = match &request.query {
        RestrictedQuery::GetModeledEntityKind { entity } => {
            charge_work(&mut work, 1, request.limits.max_work)?;
            let entry = inventory_entry(snapshot, *entity)
                .ok_or_else(|| QueryError::new(QueryErrorCode::InternalInvariant))?;
            (RestrictedQueryResult::ModeledEntityKind(entry), 0)
        }
        RestrictedQuery::ListDirectDependencies { entity, kinds } => {
            let edges = select_edges(snapshot, *entity, kinds, true, &mut work, request.limits)?;
            (RestrictedQueryResult::DirectEdges(edges), 0)
        }
        RestrictedQuery::ListDirectDependents { entity, kinds } => {
            let edges = select_edges(snapshot, *entity, kinds, false, &mut work, request.limits)?;
            (RestrictedQueryResult::DirectEdges(edges), 0)
        }
        RestrictedQuery::ReverseImpactClosure { seeds } => {
            let (entities, depth) = reverse_closure(snapshot, seeds, &mut work, request.limits)?;
            (RestrictedQueryResult::ReverseImpactClosure(entities), depth)
        }
    };
    build_response(request, result, reached_depth, work)
}

/// Rebuilds a restricted snapshot and executes one typed query end to end.
///
/// # Errors
///
/// Preserves exact impact, snapshot, and query error namespaces.
pub fn run_restricted_query(
    context: SnapshotContext,
    entities: &[ImpactEntity<'_>],
    query: RestrictedQuery,
    limits: QueryLimits,
) -> Result<RestrictedQueryResponse, RestrictedQueryRunError> {
    let snapshot = build_index_snapshot(context, entities)?;
    let request = build_restricted_query_request(&snapshot, query, limits)?;
    execute_restricted_query(&snapshot, &request).map_err(Into::into)
}

fn verify_request(request: &RestrictedQueryRequest) -> Result<(), QueryError> {
    validate_limits(request.limits)?;
    if request.format_version != FORMAT_VERSION || request.profile_version != PROFILE_VERSION {
        return query_fail(QueryErrorCode::ProfileUnsupported);
    }
    validate_query_shape(&request.query)?;
    let expected = encode_query_preimage(
        request.snapshot_id,
        request.context,
        request.completeness,
        request.limits,
        &request.query,
    )?;
    if expected != request.preimage || QueryId::derive(&expected) != request.query_id {
        return query_fail(QueryErrorCode::RequestNotCanonical);
    }
    Ok(())
}

fn validate_limits(limits: QueryLimits) -> Result<(), QueryError> {
    if limits.max_returned_entities == 0
        || limits.max_returned_entities > MAX_QUERY_RETURNED_ENTITIES
        || limits.max_returned_edges == 0
        || limits.max_returned_edges > MAX_QUERY_RETURNED_EDGES
        || limits.max_depth > MAX_QUERY_DEPTH
        || limits.max_response_bytes == 0
        || limits.max_response_bytes > MAX_QUERY_RESPONSE_BYTES
        || limits.max_work == 0
        || limits.max_work > MAX_QUERY_WORK
    {
        query_fail(QueryErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn validate_query_shape(query: &RestrictedQuery) -> Result<(), QueryError> {
    match query {
        RestrictedQuery::GetModeledEntityKind { .. } => Ok(()),
        RestrictedQuery::ListDirectDependencies { kinds, .. }
        | RestrictedQuery::ListDirectDependents { kinds, .. } => {
            if kinds.is_empty() || kinds.len() > 12 || !strictly_increasing(kinds) {
                query_fail(QueryErrorCode::RequestNotCanonical)
            } else {
                Ok(())
            }
        }
        RestrictedQuery::ReverseImpactClosure { seeds } => {
            if seeds.is_empty()
                || seeds.len() > usize::try_from(MAX_QUERY_RETURNED_ENTITIES).unwrap_or(usize::MAX)
                || !strictly_increasing(seeds)
            {
                query_fail(QueryErrorCode::RequestNotCanonical)
            } else {
                Ok(())
            }
        }
    }
}

fn strictly_increasing<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn encode_query_preimage(
    snapshot_id: IndexSnapshotId,
    context: SnapshotContext,
    completeness: IndexCompleteness,
    limits: QueryLimits,
    query: &RestrictedQuery,
) -> Result<Vec<u8>, QueryError> {
    let mut out = Vec::new();
    append_request(&mut out, QUERY_MAGIC)?;
    push_request_u32(&mut out, FORMAT_VERSION)?;
    push_request_u32(&mut out, PROFILE_VERSION)?;
    append_request(&mut out, snapshot_id.as_bytes())?;
    append_request(&mut out, context.schema_epoch.as_bytes())?;
    encode_root_option_request(&mut out, context.claimed_root_context)?;
    push_request_u32(&mut out, completeness_tag(completeness))?;
    push_request_u32(&mut out, LIMITS_PROFILE)?;
    encode_limits_request(&mut out, limits)?;
    push_request_u32(&mut out, query.tag())?;
    match query {
        RestrictedQuery::GetModeledEntityKind { entity } => {
            append_request(&mut out, entity.as_bytes())?;
        }
        RestrictedQuery::ListDirectDependencies { entity, kinds }
        | RestrictedQuery::ListDirectDependents { entity, kinds } => {
            append_request(&mut out, entity.as_bytes())?;
            push_request_u64(&mut out, to_u64(kinds.len())?)?;
            for kind in kinds {
                push_request_u32(&mut out, kind.tag())?;
            }
        }
        RestrictedQuery::ReverseImpactClosure { seeds } => {
            push_request_u64(&mut out, to_u64(seeds.len())?)?;
            for seed in seeds {
                append_request(&mut out, seed.as_bytes())?;
            }
        }
    }
    Ok(out)
}

fn encode_root_option_request(
    out: &mut Vec<u8>,
    root: Option<StateRoot>,
) -> Result<(), QueryError> {
    match root {
        None => push_request_u32(out, OPTION_NONE),
        Some(root) => {
            push_request_u32(out, OPTION_SOME)?;
            append_request(out, root.as_bytes())
        }
    }
}

fn encode_limits_request(out: &mut Vec<u8>, limits: QueryLimits) -> Result<(), QueryError> {
    push_request_u64(out, limits.max_returned_entities)?;
    push_request_u64(out, limits.max_returned_edges)?;
    push_request_u32(out, limits.max_depth)?;
    push_request_u64(out, limits.max_response_bytes)?;
    push_request_u64(out, limits.max_work)
}

fn resolve_query_entities(
    snapshot: &IndexSnapshot,
    query: &RestrictedQuery,
) -> Result<(), QueryError> {
    match query {
        RestrictedQuery::GetModeledEntityKind { entity }
        | RestrictedQuery::ListDirectDependencies { entity, .. }
        | RestrictedQuery::ListDirectDependents { entity, .. } => {
            if inventory_entry(snapshot, *entity).is_none() {
                return query_fail(QueryErrorCode::UnresolvedEntity);
            }
        }
        RestrictedQuery::ReverseImpactClosure { seeds } => {
            if seeds
                .iter()
                .any(|seed| inventory_entry(snapshot, *seed).is_none())
            {
                return query_fail(QueryErrorCode::UnresolvedEntity);
            }
        }
    }
    Ok(())
}

fn inventory_entry(snapshot: &IndexSnapshot, entity: EntityId) -> Option<IndexInventoryEntry> {
    snapshot
        .inventory()
        .binary_search_by_key(&entity, |entry| entry.entity)
        .ok()
        .map(|index| snapshot.inventory()[index])
}

fn select_edges(
    snapshot: &IndexSnapshot,
    entity: EntityId,
    kinds: &[ImpactKind],
    dependencies: bool,
    work: &mut u64,
    limits: QueryLimits,
) -> Result<Vec<ImpactEdge>, QueryError> {
    let mut selected = Vec::new();
    for edge in snapshot.direct_edges() {
        charge_work(work, 1, limits.max_work)?;
        let identity_matches = if dependencies {
            edge.dependent == entity
        } else {
            edge.dependency == entity
        };
        if identity_matches && kinds.binary_search(&edge.kind).is_ok() {
            selected.push(*edge);
        }
    }
    if to_u64(selected.len())? > limits.max_returned_edges {
        return query_fail(QueryErrorCode::RequiredFactOmitted);
    }
    Ok(selected)
}

fn reverse_closure(
    snapshot: &IndexSnapshot,
    seeds: &[EntityId],
    work: &mut u64,
    limits: QueryLimits,
) -> Result<(Vec<EntityId>, u32), QueryError> {
    let mut depths = BTreeMap::<EntityId, u32>::new();
    let mut queue = VecDeque::new();
    for seed in seeds {
        depths.insert(*seed, 0);
        queue.push_back((*seed, 0_u32));
    }
    let mut reached_depth = 0_u32;
    while let Some((dependency, depth)) = queue.pop_front() {
        charge_work(work, 1, limits.max_work)?;
        let dependents = snapshot
            .reverse_groups()
            .binary_search_by_key(&dependency, |group| group.dependency)
            .ok()
            .map_or(&[][..], |index| {
                snapshot.reverse_groups()[index].dependents.as_slice()
            });
        for dependent in dependents {
            charge_work(work, 1, limits.max_work)?;
            if depths.contains_key(&dependent.dependent) {
                continue;
            }
            let next_depth = depth
                .checked_add(1)
                .ok_or_else(|| QueryError::new(QueryErrorCode::ResourceLimit))?;
            depths.insert(dependent.dependent, next_depth);
            reached_depth = reached_depth.max(next_depth);
            queue.push_back((dependent.dependent, next_depth));
        }
    }
    Ok((depths.into_keys().collect(), reached_depth))
}

fn build_response(
    request: &RestrictedQueryRequest,
    result: RestrictedQueryResult,
    reached_depth: u32,
    traversal_work: u64,
) -> Result<RestrictedQueryResponse, QueryError> {
    let (returned_entities, returned_edges, payload_bytes) = match &result {
        RestrictedQueryResult::ModeledEntityKind(_) => (1, 0, 36_u64),
        RestrictedQueryResult::DirectEdges(edges) => {
            let count = to_u64(edges.len())?;
            (0, count, checked_list_bytes(count, 68)?)
        }
        RestrictedQueryResult::ReverseImpactClosure(entities) => {
            let count = to_u64(entities.len())?;
            (count, 0, checked_list_bytes(count, 32)?)
        }
    };
    let header = if request.context.claimed_root_context.is_some() {
        RESPONSE_HEADER_WITH_ROOT
    } else {
        RESPONSE_HEADER_WITHOUT_ROOT
    };
    let response_bytes = u64::try_from(header)
        .ok()
        .and_then(|value| value.checked_add(payload_bytes))
        .ok_or_else(|| QueryError::new(QueryErrorCode::ResourceLimit))?;
    if response_bytes > MAX_QUERY_RESPONSE_BYTES {
        return query_fail(QueryErrorCode::ResourceLimit);
    }
    let charged_work = traversal_work
        .checked_add(response_bytes)
        .ok_or_else(|| QueryError::new(QueryErrorCode::ResourceLimit))?;
    if charged_work > MAX_QUERY_WORK || charged_work > request.limits.max_work {
        return query_fail(QueryErrorCode::ResourceLimit);
    }
    if returned_entities > request.limits.max_returned_entities
        || returned_edges > request.limits.max_returned_edges
        || reached_depth > request.limits.max_depth
        || response_bytes > request.limits.max_response_bytes
    {
        return query_fail(QueryErrorCode::RequiredFactOmitted);
    }
    let record = encode_response(
        request,
        &result,
        returned_entities,
        returned_edges,
        reached_depth,
        charged_work,
        response_bytes,
    )?;
    Ok(RestrictedQueryResponse {
        query_id: request.query_id,
        snapshot_id: request.snapshot_id,
        context: request.context,
        completeness: request.completeness,
        applied_limits: request.limits,
        query_kind: request.query.tag(),
        returned_entities,
        returned_edges,
        reached_depth,
        charged_work,
        result,
        record,
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_response(
    request: &RestrictedQueryRequest,
    result: &RestrictedQueryResult,
    returned_entities: u64,
    returned_edges: u64,
    reached_depth: u32,
    charged_work: u64,
    response_bytes: u64,
) -> Result<Vec<u8>, QueryError> {
    let capacity = usize::try_from(response_bytes)
        .map_err(|_| QueryError::new(QueryErrorCode::ResourceLimit))?;
    let mut out = Vec::with_capacity(capacity);
    append_response(&mut out, RESPONSE_MAGIC, capacity)?;
    push_response_u32(&mut out, FORMAT_VERSION, capacity)?;
    push_response_u32(&mut out, PROFILE_VERSION, capacity)?;
    append_response(&mut out, request.query_id.as_bytes(), capacity)?;
    append_response(&mut out, request.snapshot_id.as_bytes(), capacity)?;
    append_response(&mut out, request.context.schema_epoch.as_bytes(), capacity)?;
    encode_root_option_response(&mut out, request.context.claimed_root_context, capacity)?;
    push_response_u32(&mut out, completeness_tag(request.completeness), capacity)?;
    push_response_u32(&mut out, LIMITS_PROFILE, capacity)?;
    encode_limits_response(&mut out, request.limits, capacity)?;
    push_response_u32(&mut out, request.query.tag(), capacity)?;
    push_response_u64(&mut out, returned_entities, capacity)?;
    push_response_u64(&mut out, returned_edges, capacity)?;
    push_response_u32(&mut out, reached_depth, capacity)?;
    push_response_u64(&mut out, charged_work, capacity)?;
    push_response_u64(&mut out, response_bytes, capacity)?;
    push_response_u32(&mut out, request.query.tag(), capacity)?;
    match result {
        RestrictedQueryResult::ModeledEntityKind(entry) => {
            append_response(&mut out, entry.entity.as_bytes(), capacity)?;
            push_response_u32(&mut out, entry.kind.tag(), capacity)?;
        }
        RestrictedQueryResult::DirectEdges(edges) => {
            push_response_u64(&mut out, to_u64(edges.len())?, capacity)?;
            for edge in edges {
                append_response(&mut out, edge.dependent.as_bytes(), capacity)?;
                append_response(&mut out, edge.dependency.as_bytes(), capacity)?;
                push_response_u32(&mut out, edge.kind.tag(), capacity)?;
            }
        }
        RestrictedQueryResult::ReverseImpactClosure(entities) => {
            push_response_u64(&mut out, to_u64(entities.len())?, capacity)?;
            for entity in entities {
                append_response(&mut out, entity.as_bytes(), capacity)?;
            }
        }
    }
    if out.len() != capacity {
        return query_fail(QueryErrorCode::InternalInvariant);
    }
    Ok(out)
}

fn encode_root_option_response(
    out: &mut Vec<u8>,
    root: Option<StateRoot>,
    limit: usize,
) -> Result<(), QueryError> {
    match root {
        None => push_response_u32(out, OPTION_NONE, limit),
        Some(root) => {
            push_response_u32(out, OPTION_SOME, limit)?;
            append_response(out, root.as_bytes(), limit)
        }
    }
}

fn encode_limits_response(
    out: &mut Vec<u8>,
    limits: QueryLimits,
    limit: usize,
) -> Result<(), QueryError> {
    push_response_u64(out, limits.max_returned_entities, limit)?;
    push_response_u64(out, limits.max_returned_edges, limit)?;
    push_response_u32(out, limits.max_depth, limit)?;
    push_response_u64(out, limits.max_response_bytes, limit)?;
    push_response_u64(out, limits.max_work, limit)
}

const fn completeness_tag(value: IndexCompleteness) -> u32 {
    match value {
        IndexCompleteness::RestrictedModeledKinds4To15Only => COMPLETENESS_RESTRICTED,
    }
}

fn checked_list_bytes(count: u64, item_bytes: u64) -> Result<u64, QueryError> {
    count
        .checked_mul(item_bytes)
        .and_then(|bytes| bytes.checked_add(8))
        .ok_or_else(|| QueryError::new(QueryErrorCode::ResourceLimit))
}

fn charge_work(work: &mut u64, amount: u64, applied_limit: u64) -> Result<(), QueryError> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| QueryError::new(QueryErrorCode::ResourceLimit))?;
    if *work > MAX_QUERY_WORK || *work > applied_limit {
        query_fail(QueryErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn push_request_u32(out: &mut Vec<u8>, value: u32) -> Result<(), QueryError> {
    append_request(out, &value.to_be_bytes())
}

fn push_request_u64(out: &mut Vec<u8>, value: u64) -> Result<(), QueryError> {
    append_request(out, &value.to_be_bytes())
}

fn append_request(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), QueryError> {
    let next = out
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| QueryError::new(QueryErrorCode::ResourceLimit))?;
    if next > MAX_QUERY_REQUEST_BYTES {
        return query_fail(QueryErrorCode::ResourceLimit);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_response_u32(out: &mut Vec<u8>, value: u32, limit: usize) -> Result<(), QueryError> {
    append_response(out, &value.to_be_bytes(), limit)
}

fn push_response_u64(out: &mut Vec<u8>, value: u64, limit: usize) -> Result<(), QueryError> {
    append_response(out, &value.to_be_bytes(), limit)
}

fn append_response(out: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), QueryError> {
    let next = out
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| QueryError::new(QueryErrorCode::ResourceLimit))?;
    if next > limit {
        return query_fail(QueryErrorCode::InternalInvariant);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn to_u64(value: usize) -> Result<u64, QueryError> {
    u64::try_from(value).map_err(|_| QueryError::new(QueryErrorCode::ResourceLimit))
}

fn query_fail<T>(code: QueryErrorCode) -> Result<T, QueryError> {
    Err(QueryError::new(code))
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use sley_id::SchemaEpochId;
    use sley_ssmc::{
        Block, CondBranchTerminator, ConstData, ConstValue, ConstantDefinition, FunctionGraph,
        Parameter, ParameterRole, Reachability, TargetEdge, Terminator, TypeExpr, ValueRef,
        Visibility,
    };

    use super::*;
    use crate::{
        CacheAdmission, CacheDiscardReason, ImpactErrorCode, ModeledEntityKind,
        admit_index_snapshot, build_index_snapshot,
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

    fn constant(entity: u8, value: bool) -> ConstantDefinition {
        ConstantDefinition {
            entity_id: id(entity),
            value: ConstValue {
                value_type: TypeExpr::Bool,
                data: ConstData::Bool(value),
            },
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

    fn query_set() -> [RestrictedQuery; 4] {
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

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
    }

    fn query_error(error: QueryError) -> QueryErrorCode {
        error.code()
    }

    #[test]
    fn codes_tags_and_limits_are_frozen() {
        let codes = [
            QueryErrorCode::ProfileUnsupported,
            QueryErrorCode::RequestNotCanonical,
            QueryErrorCode::Unsupported,
            QueryErrorCode::SnapshotMismatch,
            QueryErrorCode::UnresolvedEntity,
            QueryErrorCode::ResourceLimit,
            QueryErrorCode::RequiredFactOmitted,
            QueryErrorCode::InternalInvariant,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 31_000 + u32::try_from(offset).unwrap());
        }
        for (offset, query) in query_set().iter().enumerate() {
            assert_eq!(query.tag(), 1 + u32::try_from(offset).unwrap());
        }
        assert_eq!(MAX_QUERY_REQUEST_BYTES, 4_194_304);
        assert_eq!(MAX_QUERY_RETURNED_ENTITIES, 65_535);
        assert_eq!(MAX_QUERY_RETURNED_EDGES, 400_000);
        assert_eq!(MAX_QUERY_DEPTH, 65_535);
        assert_eq!(MAX_QUERY_RESPONSE_BYTES, 67_108_864);
        assert_eq!(MAX_QUERY_WORK, 100_000_000);
    }

    #[test]
    fn all_four_query_id_and_response_vectors_are_exact() {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let snapshot = build_index_snapshot(context(), &entities).unwrap();
        let expected = [
            (
                "154b4578b6074408105e3239dd0b0069461fe55db2d92318743553d0987c134a",
                "534c4559515253310000000100000001154b4578b6074408105e3239dd0b0069461fe55db2d92318743553d0987c134a85430ee4ef38be292ab2e305f143e4a6de359708e8511007992d95126157e4101111111111111111111111111111111111111111111111111111111111111111000000010000000100000001000000000000ffff0000000000061a800000ffff00000000040000000000000005f5e10000000001000000000000000100000000000000000000000000000000000000f100000000000000f000000001010101010101010101010101010101010101010101010101010101010101010100000005",
            ),
            (
                "1973d4de936fe99215294d708ae1832d9b6f9a4aef0cb3e8675cfc2271803de4",
                "534c45595152533100000001000000011973d4de936fe99215294d708ae1832d9b6f9a4aef0cb3e8675cfc2271803de485430ee4ef38be292ab2e305f143e4a6de359708e8511007992d95126157e4101111111111111111111111111111111111111111111111111111111111111111000000010000000100000001000000000000ffff0000000000061a800000ffff00000000040000000000000005f5e10000000002000000000000000000000000000000030000000000000000000001a700000000000001a0000000020000000000000003010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000101010101010101010101010101010101010101010101010101010101010101010303030303030303030303030303030303030303030303030303030303030303000000010101010101010101010101010101010101010101010101010101010101010101030303030303030303030303030303030303030303030303030303030303030300000004",
            ),
            (
                "7f0bdc667660c86deb6afdc1aa5d76f162f5dc5db508fc15d70f0cbbafb28e8d",
                "534c45595152533100000001000000017f0bdc667660c86deb6afdc1aa5d76f162f5dc5db508fc15d70f0cbbafb28e8d85430ee4ef38be292ab2e305f143e4a6de359708e8511007992d95126157e4101111111111111111111111111111111111111111111111111111111111111111000000010000000100000001000000000000ffff0000000000061a800000ffff00000000040000000000000005f5e1000000000300000000000000000000000000000002000000000000000000000163000000000000015c00000003000000000000000202020202020202020202020202020202020202020202020202020202020202020101010101010101010101010101010101010101010101010101010101010101000000010303030303030303030303030303030303030303030303030303030303030303010101010101010101010101010101010101010101010101010101010101010100000001",
            ),
            (
                "3b7aa7fa51ea8f7ad59e93c7117d0d685bd2d7d44aa0309dc4fb3162e7ef17f4",
                "534c45595152533100000001000000013b7aa7fa51ea8f7ad59e93c7117d0d685bd2d7d44aa0309dc4fb3162e7ef17f485430ee4ef38be292ab2e305f143e4a6de359708e8511007992d95126157e4101111111111111111111111111111111111111111111111111111111111111111000000010000000100000001000000000000ffff0000000000061a800000ffff00000000040000000000000005f5e100000000040000000000000003000000000000000000000001000000000000013e0000000000000134000000040000000000000003010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303",
            ),
        ];
        for (query, (expected_id, expected_record)) in query_set().into_iter().zip(expected) {
            let request =
                build_restricted_query_request(&snapshot, query, QueryLimits::profile_maximum())
                    .unwrap();
            let response = execute_restricted_query(&snapshot, &request).unwrap();
            assert_eq!(hex(request.query_id().as_bytes()), expected_id);
            assert_eq!(hex(response.record()), expected_record);
        }
    }

    #[test]
    fn direct_dependency_dependent_and_closure_results_are_exact() {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let snapshot = build_index_snapshot(context(), &entities).unwrap();
        let responses: Vec<_> = query_set()
            .into_iter()
            .map(|query| {
                let request = build_restricted_query_request(
                    &snapshot,
                    query,
                    QueryLimits::profile_maximum(),
                )
                .unwrap();
                execute_restricted_query(&snapshot, &request).unwrap()
            })
            .collect();
        assert_eq!(
            responses[0].result(),
            &RestrictedQueryResult::ModeledEntityKind(IndexInventoryEntry {
                entity: id(1),
                kind: ModeledEntityKind::Function,
            })
        );
        let RestrictedQueryResult::DirectEdges(dependencies) = responses[1].result() else {
            panic!("expected direct dependencies");
        };
        assert_eq!(dependencies.len(), 3);
        assert!(dependencies.iter().all(|edge| edge.dependent == id(1)));
        let RestrictedQueryResult::DirectEdges(dependents) = responses[2].result() else {
            panic!("expected direct dependents");
        };
        assert_eq!(dependents.len(), 2);
        assert!(dependents.iter().all(|edge| edge.dependency == id(1)));
        assert_eq!(
            responses[3].result(),
            &RestrictedQueryResult::ReverseImpactClosure(vec![id(1), id(2), id(3)])
        );
        assert_eq!(responses[3].reached_depth(), 1);
    }

    #[test]
    fn repeated_equal_queries_are_byte_identical() {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let expected = run_restricted_query(
            context(),
            &entities,
            RestrictedQuery::ReverseImpactClosure { seeds: vec![id(2)] },
            QueryLimits::profile_maximum(),
        )
        .unwrap();
        for _ in 0..128 {
            assert_eq!(
                run_restricted_query(
                    context(),
                    &entities,
                    RestrictedQuery::ReverseImpactClosure { seeds: vec![id(2)] },
                    QueryLimits::profile_maximum(),
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn filters_and_seeds_must_be_nonempty_canonical_sets() {
        let item = constant(1, true);
        let snapshot = build_index_snapshot(context(), &[ImpactEntity::Constant(&item)]).unwrap();
        for kinds in [
            Vec::new(),
            vec![ImpactKind::Ownership, ImpactKind::Ownership],
            vec![ImpactKind::Call, ImpactKind::Ownership],
        ] {
            assert_eq!(
                query_error(
                    build_restricted_query_request(
                        &snapshot,
                        RestrictedQuery::ListDirectDependencies {
                            entity: id(1),
                            kinds,
                        },
                        QueryLimits::profile_maximum(),
                    )
                    .unwrap_err()
                ),
                QueryErrorCode::RequestNotCanonical
            );
        }
        for seeds in [Vec::new(), vec![id(1), id(1)], vec![id(2), id(1)]] {
            assert_eq!(
                query_error(
                    build_restricted_query_request(
                        &snapshot,
                        RestrictedQuery::ReverseImpactClosure { seeds },
                        QueryLimits::profile_maximum(),
                    )
                    .unwrap_err()
                ),
                QueryErrorCode::RequestNotCanonical
            );
        }
    }

    #[test]
    fn request_identity_and_snapshot_binding_fail_closed() {
        let first = constant(1, true);
        let second = constant(2, false);
        let snapshot_a =
            build_index_snapshot(context(), &[ImpactEntity::Constant(&first)]).unwrap();
        let snapshot_b =
            build_index_snapshot(context(), &[ImpactEntity::Constant(&second)]).unwrap();
        let mut request = build_restricted_query_request(
            &snapshot_a,
            RestrictedQuery::GetModeledEntityKind { entity: id(1) },
            QueryLimits::profile_maximum(),
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot_b, &request).unwrap_err()),
            QueryErrorCode::SnapshotMismatch
        );
        request.query_id = QueryId::from_bytes([0; 32]);
        assert_eq!(
            query_error(execute_restricted_query(&snapshot_a, &request).unwrap_err()),
            QueryErrorCode::RequestNotCanonical
        );
        request.format_version = 2;
        request.limits.max_work = 0;
        assert_eq!(
            query_error(execute_restricted_query(&snapshot_a, &request).unwrap_err()),
            QueryErrorCode::ResourceLimit
        );
        request.limits = QueryLimits::profile_maximum();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot_a, &request).unwrap_err()),
            QueryErrorCode::ProfileUnsupported
        );
    }

    #[test]
    fn unresolved_entities_fail_before_empty_success() {
        let item = constant(1, true);
        let snapshot = build_index_snapshot(context(), &[ImpactEntity::Constant(&item)]).unwrap();
        let request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::ListDirectDependencies {
                entity: id(9),
                kinds: all_kinds(),
            },
            QueryLimits::profile_maximum(),
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &request).unwrap_err()),
            QueryErrorCode::UnresolvedEntity
        );

        let empty_request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::ListDirectDependencies {
                entity: id(1),
                kinds: all_kinds(),
            },
            QueryLimits::profile_maximum(),
        )
        .unwrap();
        let empty = execute_restricted_query(&snapshot, &empty_request).unwrap();
        assert_eq!(
            empty.result(),
            &RestrictedQueryResult::DirectEdges(Vec::new())
        );
        assert_eq!(empty.returned_edges(), 0);
    }

    #[test]
    fn applied_edge_entity_depth_and_byte_limits_omit_no_facts() {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let snapshot = build_index_snapshot(context(), &entities).unwrap();

        let mut edge_limits = QueryLimits::profile_maximum();
        edge_limits.max_returned_edges = 1;
        let edge_request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::ListDirectDependencies {
                entity: id(1),
                kinds: all_kinds(),
            },
            edge_limits,
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &edge_request).unwrap_err()),
            QueryErrorCode::RequiredFactOmitted
        );

        let mut entity_limits = QueryLimits::profile_maximum();
        entity_limits.max_returned_entities = 2;
        let entity_request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::ReverseImpactClosure { seeds: vec![id(2)] },
            entity_limits,
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &entity_request).unwrap_err()),
            QueryErrorCode::RequiredFactOmitted
        );

        let mut depth_limits = QueryLimits::profile_maximum();
        depth_limits.max_depth = 0;
        let depth_request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::ReverseImpactClosure { seeds: vec![id(2)] },
            depth_limits,
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &depth_request).unwrap_err()),
            QueryErrorCode::RequiredFactOmitted
        );

        let baseline_request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::GetModeledEntityKind { entity: id(1) },
            QueryLimits::profile_maximum(),
        )
        .unwrap();
        let baseline = execute_restricted_query(&snapshot, &baseline_request).unwrap();
        let mut byte_limits = QueryLimits::profile_maximum();
        byte_limits.max_response_bytes = u64::try_from(baseline.record().len()).unwrap() - 1;
        let byte_request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::GetModeledEntityKind { entity: id(1) },
            byte_limits,
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &byte_request).unwrap_err()),
            QueryErrorCode::RequiredFactOmitted
        );
    }

    #[test]
    fn profile_and_work_limits_fail_as_resources_without_partial_payload() {
        let item = constant(1, true);
        let snapshot = build_index_snapshot(context(), &[ImpactEntity::Constant(&item)]).unwrap();
        let mut invalid = QueryLimits::profile_maximum();
        invalid.max_returned_edges = MAX_QUERY_RETURNED_EDGES + 1;
        assert_eq!(
            query_error(
                build_restricted_query_request(
                    &snapshot,
                    RestrictedQuery::GetModeledEntityKind { entity: id(1) },
                    invalid,
                )
                .unwrap_err()
            ),
            QueryErrorCode::ResourceLimit
        );

        let mut low_work = QueryLimits::profile_maximum();
        low_work.max_work = 1;
        let request = build_restricted_query_request(
            &snapshot,
            RestrictedQuery::GetModeledEntityKind { entity: id(1) },
            low_work,
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &request).unwrap_err()),
            QueryErrorCode::ResourceLimit
        );
    }

    #[test]
    fn fanout_cycle_and_work_precedence_are_bounded() {
        let parameter_ids: Vec<_> = (2_u8..=65).map(id).collect();
        let function = FunctionGraph {
            entity_id: id(1),
            type_parameters: Vec::new(),
            parameters: parameter_ids.clone(),
            result_type: TypeExpr::Bool,
            effects: Vec::new(),
            entry_block: id(66),
            blocks: vec![id(66)],
            contracts: Vec::new(),
            visibility: Visibility::Private,
        };
        let parameters: Vec<_> = parameter_ids
            .iter()
            .enumerate()
            .map(|(ordinal, entity_id)| Parameter {
                entity_id: *entity_id,
                owner: id(1),
                role: ParameterRole::Function,
                ordinal: u32::try_from(ordinal).unwrap(),
                value_type: TypeExpr::Bool,
            })
            .collect();
        let block = Block {
            entity_id: id(66),
            function: id(1),
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: Terminator::CondBranch(CondBranchTerminator {
                condition: ValueRef::Parameter(id(2)),
                if_true: TargetEdge {
                    target: id(66),
                    arguments: Vec::new(),
                },
                if_false: TargetEdge {
                    target: id(66),
                    arguments: Vec::new(),
                },
            }),
            reachability: Reachability::Required,
        };
        let mut entities = vec![ImpactEntity::Function(&function)];
        entities.extend(parameters.iter().map(ImpactEntity::Parameter));
        entities.push(ImpactEntity::Block(&block));
        let snapshot = build_index_snapshot(context(), &entities).unwrap();
        let query = RestrictedQuery::ReverseImpactClosure { seeds: vec![id(2)] };

        let complete = build_restricted_query_request(
            &snapshot,
            query.clone(),
            QueryLimits::profile_maximum(),
        )
        .unwrap();
        let response = execute_restricted_query(&snapshot, &complete).unwrap();
        assert_eq!(response.returned_entities(), 66);
        assert_eq!(response.reached_depth(), 2);

        let omitted = build_restricted_query_request(
            &snapshot,
            query.clone(),
            QueryLimits {
                max_returned_entities: 32,
                ..QueryLimits::profile_maximum()
            },
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &omitted).unwrap_err()),
            QueryErrorCode::RequiredFactOmitted
        );

        let resource_wins = build_restricted_query_request(
            &snapshot,
            query,
            QueryLimits {
                max_returned_entities: 32,
                max_work: 10,
                ..QueryLimits::profile_maximum()
            },
        )
        .unwrap();
        assert_eq!(
            query_error(execute_restricted_query(&snapshot, &resource_wins).unwrap_err()),
            QueryErrorCode::ResourceLimit
        );
    }

    #[test]
    fn fresh_impact_failure_precedes_query_failure() {
        let first = constant(2, true);
        let second = constant(1, false);
        let error = run_restricted_query(
            context(),
            &[
                ImpactEntity::Constant(&first),
                ImpactEntity::Constant(&second),
            ],
            RestrictedQuery::ReverseImpactClosure { seeds: Vec::new() },
            QueryLimits {
                max_work: 0,
                ..QueryLimits::profile_maximum()
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            RestrictedQueryRunError::Impact(ImpactError::new(ImpactErrorCode::SetNotCanonical))
        );
    }

    #[test]
    fn claimed_root_and_applied_limits_change_query_identity() {
        let item = constant(1, true);
        let snapshot = build_index_snapshot(context(), &[ImpactEntity::Constant(&item)]).unwrap();
        let query = RestrictedQuery::GetModeledEntityKind { entity: id(1) };
        let baseline = build_restricted_query_request(
            &snapshot,
            query.clone(),
            QueryLimits::profile_maximum(),
        )
        .unwrap();
        let rooted = build_index_snapshot(
            SnapshotContext {
                schema_epoch: context().schema_epoch,
                claimed_root_context: Some(StateRoot::from_bytes([0x33; 32])),
            },
            &[ImpactEntity::Constant(&item)],
        )
        .unwrap();
        let rooted_request =
            build_restricted_query_request(&rooted, query.clone(), QueryLimits::profile_maximum())
                .unwrap();
        assert_ne!(baseline.query_id(), rooted_request.query_id());
        let mut limits = QueryLimits::profile_maximum();
        limits.max_depth -= 1;
        let limited = build_restricted_query_request(&snapshot, query, limits).unwrap();
        assert_ne!(baseline.query_id(), limited.query_id());
    }

    #[test]
    fn discarded_candidate_can_only_yield_the_same_fresh_query_surface() {
        let item = constant(1, true);
        let entities = [ImpactEntity::Constant(&item)];
        let fresh = build_index_snapshot(context(), &entities).unwrap();
        let mut corrupt = fresh.record().to_vec();
        corrupt[0] ^= 1;
        let admitted = admit_index_snapshot(context(), &entities, Some(&corrupt)).unwrap();
        let CacheAdmission::Rebuilt { reason, snapshot } = admitted else {
            panic!("corrupt candidate must be discarded");
        };
        assert_eq!(reason, CacheDiscardReason::FormatInvalid);
        let query = RestrictedQuery::GetModeledEntityKind { entity: id(1) };
        let request_a =
            build_restricted_query_request(&fresh, query.clone(), QueryLimits::profile_maximum())
                .unwrap();
        let request_b =
            build_restricted_query_request(&snapshot, query, QueryLimits::profile_maximum())
                .unwrap();
        assert_eq!(
            execute_restricted_query(&fresh, &request_a).unwrap(),
            execute_restricted_query(&snapshot, &request_b).unwrap()
        );
    }
}
