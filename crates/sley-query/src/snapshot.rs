//! Restricted, rebuild-first S20-300 index snapshot profile.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use sley_id::{EntityId, IndexSnapshotId, SchemaEpochId, StateRoot};
use sley_ssmc::fingerprint::SSMC1_FIELD_SCHEMA_HASH;

use crate::{
    ImpactEdge, ImpactEntity, ImpactError, ImpactIndex, ImpactKind, MAX_IMPACT_ENTITIES,
    ModeledEntityKind,
};

const MAGIC: &[u8; 8] = b"SLEYIDX1";
const FORMAT_VERSION: u32 = 1;
const PROFILE_VERSION: u32 = 1;
const LIMITS_PROFILE: u32 = 1;
const COMPLETENESS_RESTRICTED: u32 = 1;
const OPTION_NONE: u32 = 1;
const OPTION_SOME: u32 = 2;
const TRAILER_BYTES: usize = 32;
const INVENTORY_ENTRY_BYTES: usize = 36;
const DIRECT_EDGE_BYTES: usize = 68;
const REVERSE_ENTRY_BYTES: usize = 36;
const MIN_RECORD_BYTES: usize = 148;

/// Maximum complete snapshot-record size.
pub const MAX_SNAPSHOT_RECORD_BYTES: u64 = 67_108_864;
/// Maximum direct or reverse dependent/kind entries.
pub const MAX_SNAPSHOT_EDGES: usize = 400_000;
/// Maximum charged snapshot encode, decode, or comparison work.
pub const MAX_SNAPSHOT_WORK: u64 = 100_000_000;

/// Stable S20-300 restricted snapshot failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexSnapshotErrorCode {
    /// `INDEX_SNAPSHOT_PROFILE_UNSUPPORTED`.
    ProfileUnsupported,
    /// `INDEX_SNAPSHOT_FORMAT_INVALID`.
    FormatInvalid,
    /// `INDEX_SNAPSHOT_VERSION_UNSUPPORTED`.
    VersionUnsupported,
    /// `INDEX_SNAPSHOT_CONTEXT_MISMATCH`.
    ContextMismatch,
    /// `INDEX_SNAPSHOT_DIGEST_MISMATCH`.
    DigestMismatch,
    /// `INDEX_SNAPSHOT_COMPLETENESS_UNSUPPORTED`.
    CompletenessUnsupported,
    /// `INDEX_SNAPSHOT_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `INDEX_SNAPSHOT_INTERNAL_INVARIANT`.
    InternalInvariant,
}

impl IndexSnapshotErrorCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileUnsupported => "INDEX_SNAPSHOT_PROFILE_UNSUPPORTED",
            Self::FormatInvalid => "INDEX_SNAPSHOT_FORMAT_INVALID",
            Self::VersionUnsupported => "INDEX_SNAPSHOT_VERSION_UNSUPPORTED",
            Self::ContextMismatch => "INDEX_SNAPSHOT_CONTEXT_MISMATCH",
            Self::DigestMismatch => "INDEX_SNAPSHOT_DIGEST_MISMATCH",
            Self::CompletenessUnsupported => "INDEX_SNAPSHOT_COMPLETENESS_UNSUPPORTED",
            Self::ResourceLimit => "INDEX_SNAPSHOT_RESOURCE_LIMIT",
            Self::InternalInvariant => "INDEX_SNAPSHOT_INTERNAL_INVARIANT",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::ProfileUnsupported => 30_000,
            Self::FormatInvalid => 30_001,
            Self::VersionUnsupported => 30_002,
            Self::ContextMismatch => 30_003,
            Self::DigestMismatch => 30_004,
            Self::CompletenessUnsupported => 30_005,
            Self::ResourceLimit => 30_006,
            Self::InternalInvariant => 30_007,
        }
    }
}

impl fmt::Display for IndexSnapshotErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable snapshot construction or inspection failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexSnapshotError(IndexSnapshotErrorCode);

impl IndexSnapshotError {
    /// Constructs a failure.
    #[must_use]
    pub const fn new(code: IndexSnapshotErrorCode) -> Self {
        Self(code)
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(&self) -> IndexSnapshotErrorCode {
        self.0
    }
}

impl fmt::Display for IndexSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for IndexSnapshotError {}

/// Fresh snapshot build failure, preserving S20-250 impact errors exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexSnapshotBuildError {
    /// Canonical S20-250 extraction failed.
    Impact(ImpactError),
    /// Snapshot projection or encoding failed.
    Snapshot(IndexSnapshotError),
}

impl fmt::Display for IndexSnapshotBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Impact(error) => error.fmt(formatter),
            Self::Snapshot(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IndexSnapshotBuildError {}

impl From<ImpactError> for IndexSnapshotBuildError {
    fn from(value: ImpactError) -> Self {
        Self::Impact(value)
    }
}

impl From<IndexSnapshotError> for IndexSnapshotBuildError {
    fn from(value: IndexSnapshotError) -> Self {
        Self::Snapshot(value)
    }
}

/// Exact context bound into a restricted snapshot record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotContext {
    /// Exact SSMC schema epoch.
    pub schema_epoch: SchemaEpochId,
    /// Unverified root-context claim, if supplied by the caller.
    pub claimed_root_context: Option<StateRoot>,
}

/// Closed completeness arm for the restricted profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexCompleteness {
    /// Only SSMC kinds 4 through 15 are represented.
    RestrictedModeledKinds4To15Only,
}

/// One canonical modeled-entity inventory entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IndexInventoryEntry {
    /// Stable entity identity.
    pub entity: EntityId,
    /// Restricted modeled kind.
    pub kind: ModeledEntityKind,
}

/// One reverse dependent and relationship kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReverseDependent {
    /// Entity that depends on the group dependency.
    pub dependent: EntityId,
    /// Exact relationship kind.
    pub kind: ImpactKind,
}

/// Exact reverse-index group for one referenced dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReverseGroup {
    /// Referenced entity.
    pub dependency: EntityId,
    /// Canonically ordered reverse relationships.
    pub dependents: Vec<ReverseDependent>,
}

/// Freshly derived restricted index snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexSnapshot {
    snapshot_id: IndexSnapshotId,
    context: SnapshotContext,
    completeness: IndexCompleteness,
    inventory: Vec<IndexInventoryEntry>,
    direct_edges: Vec<ImpactEdge>,
    reverse_groups: Vec<ReverseGroup>,
    record: Vec<u8>,
}

impl IndexSnapshot {
    /// Returns the derived record identifier.
    #[must_use]
    pub const fn snapshot_id(&self) -> IndexSnapshotId {
        self.snapshot_id
    }

    /// Returns the exact bound context.
    #[must_use]
    pub const fn context(&self) -> SnapshotContext {
        self.context
    }

    /// Returns the closed completeness arm.
    #[must_use]
    pub const fn completeness(&self) -> IndexCompleteness {
        self.completeness
    }

    /// Returns the canonical modeled inventory.
    #[must_use]
    pub fn inventory(&self) -> &[IndexInventoryEntry] {
        &self.inventory
    }

    /// Returns the canonical direct impact edges.
    #[must_use]
    pub fn direct_edges(&self) -> &[ImpactEdge] {
        &self.direct_edges
    }

    /// Returns the exact reverse groups.
    #[must_use]
    pub fn reverse_groups(&self) -> &[ReverseGroup] {
        &self.reverse_groups
    }

    /// Returns the complete canonical record, including its digest trailer.
    #[must_use]
    pub fn record(&self) -> &[u8] {
        &self.record
    }
}

/// Non-authoritative reason a candidate cache record was discarded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheDiscardReason {
    /// No candidate bytes were supplied.
    Missing,
    /// Candidate structure or canonical ordering was invalid.
    FormatInvalid,
    /// Candidate format, profile, or limits version was unsupported.
    VersionUnsupported,
    /// Candidate schema epoch, field schema, or root claim differed.
    ContextMismatch,
    /// Candidate trailer did not authenticate its preimage.
    DigestMismatch,
    /// Candidate claimed an unsupported completeness arm.
    CompletenessUnsupported,
    /// Candidate exceeded a bounded decode limit.
    ResourceLimit,
    /// Candidate was valid but did not equal the fresh rebuild.
    ContentMismatch,
}

/// Rebuild-first cache admission outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheAdmission {
    /// Candidate bytes exactly matched an already-fresh rebuild.
    Hit(IndexSnapshot),
    /// Candidate was absent or discarded; the fresh rebuild is returned.
    Rebuilt {
        /// Why the candidate was not admitted.
        reason: CacheDiscardReason,
        /// Snapshot freshly rebuilt from the explicit entity request.
        snapshot: IndexSnapshot,
    },
}

/// Builds a fresh restricted snapshot from an explicit canonical modeled request.
///
/// # Errors
///
/// Preserves the first S20-250 impact error or returns a bounded snapshot
/// projection/encoding error.
pub fn build_index_snapshot(
    context: SnapshotContext,
    entities: &[ImpactEntity<'_>],
) -> Result<IndexSnapshot, IndexSnapshotBuildError> {
    let index = ImpactIndex::build(entities)?;
    if index.direct_edges().len() > MAX_SNAPSHOT_EDGES {
        return snapshot_fail(IndexSnapshotErrorCode::ResourceLimit).map_err(Into::into);
    }

    let inventory: Vec<_> = entities
        .iter()
        .map(|entity| IndexInventoryEntry {
            entity: entity.entity_id(),
            kind: entity.kind(),
        })
        .collect();
    let direct_edges = index.direct_edges().to_vec();
    let reverse_groups = invert_edges(&direct_edges)?;
    let mut work = 0_u64;
    let mut record = encode_preimage(
        context,
        &inventory,
        &direct_edges,
        &reverse_groups,
        &mut work,
    )?;
    let snapshot_id = IndexSnapshotId::derive(&record);
    append(&mut record, snapshot_id.as_bytes(), &mut work)?;
    if u64::try_from(record.len()).map_or(true, |len| len > MAX_SNAPSHOT_RECORD_BYTES) {
        return snapshot_fail(IndexSnapshotErrorCode::ResourceLimit).map_err(Into::into);
    }
    Ok(IndexSnapshot {
        snapshot_id,
        context,
        completeness: IndexCompleteness::RestrictedModeledKinds4To15Only,
        inventory,
        direct_edges,
        reverse_groups,
        record,
    })
}

/// Admits candidate bytes only after rebuilding the complete fresh snapshot.
///
/// # Errors
///
/// Returns only fresh-build failures. Candidate failures are discard outcomes.
pub fn admit_index_snapshot(
    context: SnapshotContext,
    entities: &[ImpactEntity<'_>],
    candidate: Option<&[u8]>,
) -> Result<CacheAdmission, IndexSnapshotBuildError> {
    let fresh = build_index_snapshot(context, entities)?;
    let Some(candidate) = candidate else {
        return Ok(CacheAdmission::Rebuilt {
            reason: CacheDiscardReason::Missing,
            snapshot: fresh,
        });
    };
    if let Err(error) = inspect_candidate(context, candidate) {
        return Ok(CacheAdmission::Rebuilt {
            reason: discard_reason(error.code()),
            snapshot: fresh,
        });
    }
    if candidate != fresh.record() {
        return Ok(CacheAdmission::Rebuilt {
            reason: CacheDiscardReason::ContentMismatch,
            snapshot: fresh,
        });
    }
    Ok(CacheAdmission::Hit(fresh))
}

fn invert_edges(direct: &[ImpactEdge]) -> Result<Vec<ReverseGroup>, IndexSnapshotError> {
    let mut reverse = BTreeMap::<EntityId, Vec<ReverseDependent>>::new();
    for edge in direct {
        reverse
            .entry(edge.dependency)
            .or_default()
            .push(ReverseDependent {
                dependent: edge.dependent,
                kind: edge.kind,
            });
    }
    if reverse.len() > MAX_IMPACT_ENTITIES {
        return snapshot_fail(IndexSnapshotErrorCode::ResourceLimit);
    }
    Ok(reverse
        .into_iter()
        .map(|(dependency, dependents)| ReverseGroup {
            dependency,
            dependents,
        })
        .collect())
}

fn encode_preimage(
    context: SnapshotContext,
    inventory: &[IndexInventoryEntry],
    direct: &[ImpactEdge],
    reverse: &[ReverseGroup],
    work: &mut u64,
) -> Result<Vec<u8>, IndexSnapshotError> {
    let mut out = Vec::new();
    append(&mut out, MAGIC, work)?;
    push_u32(&mut out, FORMAT_VERSION, work)?;
    push_u32(&mut out, PROFILE_VERSION, work)?;
    append(&mut out, context.schema_epoch.as_bytes(), work)?;
    append(&mut out, &SSMC1_FIELD_SCHEMA_HASH, work)?;
    push_u32(&mut out, LIMITS_PROFILE, work)?;
    match context.claimed_root_context {
        None => push_u32(&mut out, OPTION_NONE, work)?,
        Some(root) => {
            push_u32(&mut out, OPTION_SOME, work)?;
            append(&mut out, root.as_bytes(), work)?;
        }
    }
    push_u32(&mut out, COMPLETENESS_RESTRICTED, work)?;
    push_u64(&mut out, to_u64(inventory.len())?, work)?;
    for entry in inventory {
        charge(work, 1)?;
        append(&mut out, entry.entity.as_bytes(), work)?;
        push_u32(&mut out, entry.kind.tag(), work)?;
    }
    push_u64(&mut out, to_u64(direct.len())?, work)?;
    for edge in direct {
        charge(work, 1)?;
        append(&mut out, edge.dependent.as_bytes(), work)?;
        append(&mut out, edge.dependency.as_bytes(), work)?;
        push_u32(&mut out, edge.kind.tag(), work)?;
    }
    push_u64(&mut out, to_u64(reverse.len())?, work)?;
    for group in reverse {
        charge(work, 1)?;
        append(&mut out, group.dependency.as_bytes(), work)?;
        push_u64(&mut out, to_u64(group.dependents.len())?, work)?;
        for dependent in &group.dependents {
            charge(work, 1)?;
            append(&mut out, dependent.dependent.as_bytes(), work)?;
            push_u32(&mut out, dependent.kind.tag(), work)?;
        }
    }
    if out
        .len()
        .checked_add(TRAILER_BYTES)
        .and_then(|len| u64::try_from(len).ok())
        .is_none_or(|len| len > MAX_SNAPSHOT_RECORD_BYTES)
    {
        return snapshot_fail(IndexSnapshotErrorCode::ResourceLimit);
    }
    Ok(out)
}

#[allow(clippy::too_many_lines)]
fn inspect_candidate(
    expected_context: SnapshotContext,
    record: &[u8],
) -> Result<(), IndexSnapshotError> {
    if record.len() < MIN_RECORD_BYTES {
        return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
    }
    if u64::try_from(record.len()).map_or(true, |len| len > MAX_SNAPSHOT_RECORD_BYTES) {
        return snapshot_fail(IndexSnapshotErrorCode::ResourceLimit);
    }
    let preimage_len = record
        .len()
        .checked_sub(TRAILER_BYTES)
        .ok_or_else(|| IndexSnapshotError::new(IndexSnapshotErrorCode::FormatInvalid))?;
    let (preimage, trailer) = record.split_at(preimage_len);
    let mut cursor = Cursor::new(preimage);

    if cursor.fixed::<8>()? != *MAGIC {
        return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
    }
    if cursor.u32()? != FORMAT_VERSION || cursor.u32()? != PROFILE_VERSION {
        return snapshot_fail(IndexSnapshotErrorCode::VersionUnsupported);
    }
    let schema_epoch = SchemaEpochId::from_bytes(cursor.fixed::<32>()?);
    let field_schema_hash = cursor.fixed::<32>()?;
    if cursor.u32()? != LIMITS_PROFILE {
        return snapshot_fail(IndexSnapshotErrorCode::ProfileUnsupported);
    }
    let claimed_root_context = match cursor.u32()? {
        OPTION_NONE => None,
        OPTION_SOME => Some(StateRoot::from_bytes(cursor.fixed::<32>()?)),
        _ => return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid),
    };
    if schema_epoch != expected_context.schema_epoch
        || field_schema_hash != SSMC1_FIELD_SCHEMA_HASH
        || claimed_root_context != expected_context.claimed_root_context
    {
        return snapshot_fail(IndexSnapshotErrorCode::ContextMismatch);
    }
    if cursor.u32()? != COMPLETENESS_RESTRICTED {
        return snapshot_fail(IndexSnapshotErrorCode::CompletenessUnsupported);
    }

    let inventory_count = cursor.bounded_count(MAX_IMPACT_ENTITIES, INVENTORY_ENTRY_BYTES)?;
    let mut inventory = BTreeSet::new();
    let mut prior = None;
    for _ in 0..inventory_count {
        let entity = EntityId::from_bytes(cursor.fixed::<32>()?);
        let kind = modeled_kind(cursor.u32()?)?;
        if prior.is_some_and(|value| value >= entity) || !inventory.insert(entity) {
            return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
        }
        prior = Some(entity);
        let _ = kind;
    }

    let direct_count = cursor.bounded_count(MAX_SNAPSHOT_EDGES, DIRECT_EDGE_BYTES)?;
    let mut direct = Vec::with_capacity(direct_count);
    let mut prior_edge = None;
    for _ in 0..direct_count {
        let edge = ImpactEdge {
            dependent: EntityId::from_bytes(cursor.fixed::<32>()?),
            dependency: EntityId::from_bytes(cursor.fixed::<32>()?),
            kind: impact_kind(cursor.u32()?)?,
        };
        if prior_edge.is_some_and(|value| value >= edge)
            || !inventory.contains(&edge.dependent)
            || !inventory.contains(&edge.dependency)
        {
            return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
        }
        prior_edge = Some(edge);
        direct.push(edge);
    }

    let reverse_count = cursor.bounded_count(MAX_IMPACT_ENTITIES, 40)?;
    let mut decoded_reverse = Vec::with_capacity(reverse_count);
    let mut prior_dependency = None;
    let mut reverse_entries = 0_usize;
    for _ in 0..reverse_count {
        let dependency = EntityId::from_bytes(cursor.fixed::<32>()?);
        if prior_dependency.is_some_and(|value| value >= dependency)
            || !inventory.contains(&dependency)
        {
            return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
        }
        prior_dependency = Some(dependency);
        let count = cursor.bounded_count(MAX_SNAPSHOT_EDGES, REVERSE_ENTRY_BYTES)?;
        reverse_entries = reverse_entries
            .checked_add(count)
            .ok_or_else(|| IndexSnapshotError::new(IndexSnapshotErrorCode::ResourceLimit))?;
        if reverse_entries > MAX_SNAPSHOT_EDGES || count == 0 {
            return snapshot_fail(if reverse_entries > MAX_SNAPSHOT_EDGES {
                IndexSnapshotErrorCode::ResourceLimit
            } else {
                IndexSnapshotErrorCode::FormatInvalid
            });
        }
        let mut dependents = Vec::with_capacity(count);
        let mut prior_dependent = None;
        for _ in 0..count {
            let dependent = ReverseDependent {
                dependent: EntityId::from_bytes(cursor.fixed::<32>()?),
                kind: impact_kind(cursor.u32()?)?,
            };
            if prior_dependent.is_some_and(|value| value >= dependent)
                || !inventory.contains(&dependent.dependent)
            {
                return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
            }
            prior_dependent = Some(dependent);
            dependents.push(dependent);
        }
        decoded_reverse.push(ReverseGroup {
            dependency,
            dependents,
        });
    }
    cursor.finish()?;
    if decoded_reverse != invert_edges(&direct)? {
        return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
    }
    if IndexSnapshotId::derive(preimage).as_bytes() != trailer {
        return snapshot_fail(IndexSnapshotErrorCode::DigestMismatch);
    }
    Ok(())
}

fn modeled_kind(tag: u32) -> Result<ModeledEntityKind, IndexSnapshotError> {
    match tag {
        4 => Ok(ModeledEntityKind::TypeDef),
        5 => Ok(ModeledEntityKind::Function),
        6 => Ok(ModeledEntityKind::Parameter),
        7 => Ok(ModeledEntityKind::Block),
        8 => Ok(ModeledEntityKind::Operation),
        9 => Ok(ModeledEntityKind::Constant),
        10 => Ok(ModeledEntityKind::GlobalValue),
        11 => Ok(ModeledEntityKind::EffectDef),
        12 => Ok(ModeledEntityKind::CapabilityRequirement),
        13 => Ok(ModeledEntityKind::Contract),
        14 => Ok(ModeledEntityKind::TestCase),
        15 => Ok(ModeledEntityKind::AdapterImport),
        _ => snapshot_fail(IndexSnapshotErrorCode::FormatInvalid),
    }
}

fn impact_kind(tag: u32) -> Result<ImpactKind, IndexSnapshotError> {
    match tag {
        1 => Ok(ImpactKind::Ownership),
        2 => Ok(ImpactKind::TypeReference),
        3 => Ok(ImpactKind::ValueReference),
        4 => Ok(ImpactKind::ControlFlow),
        5 => Ok(ImpactKind::Call),
        6 => Ok(ImpactKind::Effect),
        7 => Ok(ImpactKind::Capability),
        8 => Ok(ImpactKind::Contract),
        9 => Ok(ImpactKind::Initializer),
        10 => Ok(ImpactKind::TestTarget),
        11 => Ok(ImpactKind::Adapter),
        12 => Ok(ImpactKind::DefinitionMember),
        _ => snapshot_fail(IndexSnapshotErrorCode::FormatInvalid),
    }
}

fn discard_reason(code: IndexSnapshotErrorCode) -> CacheDiscardReason {
    match code {
        IndexSnapshotErrorCode::ProfileUnsupported | IndexSnapshotErrorCode::VersionUnsupported => {
            CacheDiscardReason::VersionUnsupported
        }
        IndexSnapshotErrorCode::FormatInvalid | IndexSnapshotErrorCode::InternalInvariant => {
            CacheDiscardReason::FormatInvalid
        }
        IndexSnapshotErrorCode::ContextMismatch => CacheDiscardReason::ContextMismatch,
        IndexSnapshotErrorCode::DigestMismatch => CacheDiscardReason::DigestMismatch,
        IndexSnapshotErrorCode::CompletenessUnsupported => {
            CacheDiscardReason::CompletenessUnsupported
        }
        IndexSnapshotErrorCode::ResourceLimit => CacheDiscardReason::ResourceLimit,
    }
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
    work: u64,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            offset: 0,
            work: 0,
        }
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], IndexSnapshotError> {
        charge(&mut self.work, u64::try_from(N).unwrap_or(u64::MAX))?;
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| IndexSnapshotError::new(IndexSnapshotErrorCode::ResourceLimit))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| IndexSnapshotError::new(IndexSnapshotErrorCode::FormatInvalid))?;
        self.offset = end;
        bytes
            .try_into()
            .map_err(|_| IndexSnapshotError::new(IndexSnapshotErrorCode::InternalInvariant))
    }

    fn u32(&mut self) -> Result<u32, IndexSnapshotError> {
        Ok(u32::from_be_bytes(self.fixed::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, IndexSnapshotError> {
        Ok(u64::from_be_bytes(self.fixed::<8>()?))
    }

    fn bounded_count(
        &mut self,
        limit: usize,
        minimum_item_bytes: usize,
    ) -> Result<usize, IndexSnapshotError> {
        let count = usize::try_from(self.u64()?)
            .map_err(|_| IndexSnapshotError::new(IndexSnapshotErrorCode::ResourceLimit))?;
        if count > limit {
            return snapshot_fail(IndexSnapshotErrorCode::ResourceLimit);
        }
        let required = count
            .checked_mul(minimum_item_bytes)
            .ok_or_else(|| IndexSnapshotError::new(IndexSnapshotErrorCode::ResourceLimit))?;
        if required > self.input.len().saturating_sub(self.offset) {
            return snapshot_fail(IndexSnapshotErrorCode::FormatInvalid);
        }
        charge(&mut self.work, u64::try_from(count).unwrap_or(u64::MAX))?;
        Ok(count)
    }

    fn finish(self) -> Result<(), IndexSnapshotError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            snapshot_fail(IndexSnapshotErrorCode::FormatInvalid)
        }
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32, work: &mut u64) -> Result<(), IndexSnapshotError> {
    append(out, &value.to_be_bytes(), work)
}

fn push_u64(out: &mut Vec<u8>, value: u64, work: &mut u64) -> Result<(), IndexSnapshotError> {
    append(out, &value.to_be_bytes(), work)
}

fn append(out: &mut Vec<u8>, bytes: &[u8], work: &mut u64) -> Result<(), IndexSnapshotError> {
    charge(work, u64::try_from(bytes.len()).unwrap_or(u64::MAX))?;
    let next_len = out
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| IndexSnapshotError::new(IndexSnapshotErrorCode::ResourceLimit))?;
    if u64::try_from(next_len).map_or(true, |len| len > MAX_SNAPSHOT_RECORD_BYTES) {
        return snapshot_fail(IndexSnapshotErrorCode::ResourceLimit);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn charge(work: &mut u64, amount: u64) -> Result<(), IndexSnapshotError> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| IndexSnapshotError::new(IndexSnapshotErrorCode::ResourceLimit))?;
    if *work > MAX_SNAPSHOT_WORK {
        snapshot_fail(IndexSnapshotErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn to_u64(value: usize) -> Result<u64, IndexSnapshotError> {
    u64::try_from(value).map_err(|_| IndexSnapshotError::new(IndexSnapshotErrorCode::ResourceLimit))
}

fn snapshot_fail<T>(code: IndexSnapshotErrorCode) -> Result<T, IndexSnapshotError> {
    Err(IndexSnapshotError::new(code))
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::*;
    use crate::{ImpactErrorCode, ImpactKind};
    use sley_ssmc::{
        Block, CondBranchTerminator, ConstData, ConstValue, ConstantDefinition, FunctionGraph,
        Parameter, ParameterRole, Reachability, TargetEdge, Terminator, TypeExpr, ValueRef,
        Visibility,
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

    fn resign(record: &mut [u8]) {
        let preimage_len = record.len() - TRAILER_BYTES;
        let digest = IndexSnapshotId::derive(&record[..preimage_len]);
        record[preimage_len..].copy_from_slice(digest.as_bytes());
    }

    fn put_u32(record: &mut [u8], offset: usize, value: u32) {
        record[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn put_u64(record: &mut [u8], offset: usize, value: u64) {
        record[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn rebuilt_reason(admission: CacheAdmission) -> CacheDiscardReason {
        match admission {
            CacheAdmission::Rebuilt { reason, .. } => reason,
            CacheAdmission::Hit(_) => panic!("expected a discarded candidate"),
        }
    }

    #[test]
    fn codes_completeness_and_limits_are_frozen() {
        let codes = [
            IndexSnapshotErrorCode::ProfileUnsupported,
            IndexSnapshotErrorCode::FormatInvalid,
            IndexSnapshotErrorCode::VersionUnsupported,
            IndexSnapshotErrorCode::ContextMismatch,
            IndexSnapshotErrorCode::DigestMismatch,
            IndexSnapshotErrorCode::CompletenessUnsupported,
            IndexSnapshotErrorCode::ResourceLimit,
            IndexSnapshotErrorCode::InternalInvariant,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 30_000 + u32::try_from(offset).unwrap());
        }
        assert_eq!(COMPLETENESS_RESTRICTED, 1);
        assert_eq!(MAX_SNAPSHOT_EDGES, 400_000);
        assert_eq!(MAX_SNAPSHOT_RECORD_BYTES, 67_108_864);
        assert_eq!(MAX_SNAPSHOT_WORK, 100_000_000);
    }

    #[test]
    fn empty_and_nonempty_records_have_fixed_vectors() {
        let empty = build_index_snapshot(context(), &[]).unwrap();
        let item = constant(1, true);
        let nonempty = build_index_snapshot(context(), &[ImpactEntity::Constant(&item)]).unwrap();

        assert_eq!(empty.record().len(), 148);
        assert_eq!(nonempty.record().len(), 184);
        assert_eq!(
            hex(empty.record()),
            "534c455949445831000000010000000111111111111111111111111111111111111111111111111111111111111111111983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae000000010000000100000001000000000000000000000000000000000000000000000000ba36e59b7d2de0a7eb33a3515f0e13e910b745c39e35737c4ecb7b9672e7c390"
        );
        assert_eq!(
            hex(nonempty.record()),
            "534c455949445831000000010000000111111111111111111111111111111111111111111111111111111111111111111983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae00000001000000010000000100000000000000010101010101010101010101010101010101010101010101010101010101010101000000090000000000000000000000000000000092196983bb31e83d4c69e6bcfa96f54a9ef8ec2b5b738f7b53c4bdf6211b99e7"
        );
        assert_eq!(
            hex(empty.snapshot_id().as_bytes()),
            "ba36e59b7d2de0a7eb33a3515f0e13e910b745c39e35737c4ecb7b9672e7c390"
        );
        assert_eq!(
            hex(nonempty.snapshot_id().as_bytes()),
            "92196983bb31e83d4c69e6bcfa96f54a9ef8ec2b5b738f7b53c4bdf6211b99e7"
        );
    }

    #[test]
    fn graph_projection_and_128_rebuilds_are_identical() {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let expected = build_index_snapshot(context(), &entities).unwrap();
        assert_eq!(expected.inventory().len(), 3);
        assert_eq!(expected.direct_edges().len(), 7);
        assert_eq!(expected.reverse_groups().len(), 3);
        for _ in 0..128 {
            assert_eq!(
                build_index_snapshot(context(), &entities).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn missing_and_exact_candidates_return_only_fresh_snapshots() {
        let item = constant(1, true);
        let entities = [ImpactEntity::Constant(&item)];
        let fresh = build_index_snapshot(context(), &entities).unwrap();
        assert_eq!(
            admit_index_snapshot(context(), &entities, None).unwrap(),
            CacheAdmission::Rebuilt {
                reason: CacheDiscardReason::Missing,
                snapshot: fresh.clone(),
            }
        );
        assert_eq!(
            admit_index_snapshot(context(), &entities, Some(fresh.record())).unwrap(),
            CacheAdmission::Hit(fresh)
        );
    }

    #[test]
    fn format_version_context_completeness_and_digest_fail_closed() {
        let item = constant(1, true);
        let entities = [ImpactEntity::Constant(&item)];
        let fresh = build_index_snapshot(context(), &entities).unwrap();

        let mut magic = fresh.record().to_vec();
        magic[0] ^= 1;
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&magic)).unwrap()),
            CacheDiscardReason::FormatInvalid
        );

        let mut version = fresh.record().to_vec();
        put_u32(&mut version, 8, 2);
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&version)).unwrap()),
            CacheDiscardReason::VersionUnsupported
        );

        let mut profile = fresh.record().to_vec();
        put_u32(&mut profile, 80, 2);
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&profile)).unwrap()),
            CacheDiscardReason::VersionUnsupported
        );

        let different_context = SnapshotContext {
            schema_epoch: SchemaEpochId::from_bytes([0x22; 32]),
            claimed_root_context: None,
        };
        assert_eq!(
            rebuilt_reason(
                admit_index_snapshot(different_context, &entities, Some(fresh.record())).unwrap()
            ),
            CacheDiscardReason::ContextMismatch
        );

        let mut completeness = fresh.record().to_vec();
        put_u32(&mut completeness, 88, 2);
        assert_eq!(
            rebuilt_reason(
                admit_index_snapshot(context(), &entities, Some(&completeness)).unwrap()
            ),
            CacheDiscardReason::CompletenessUnsupported
        );

        let mut digest = fresh.record().to_vec();
        *digest.last_mut().unwrap() ^= 1;
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&digest)).unwrap()),
            CacheDiscardReason::DigestMismatch
        );
    }

    #[test]
    fn count_trailing_order_and_endpoint_perturbations_are_discarded() {
        let first = constant(1, true);
        let second = constant(2, false);
        let entities = [
            ImpactEntity::Constant(&first),
            ImpactEntity::Constant(&second),
        ];
        let fresh = build_index_snapshot(context(), &entities).unwrap();

        let mut count = fresh.record().to_vec();
        put_u64(
            &mut count,
            92,
            u64::try_from(MAX_IMPACT_ENTITIES).unwrap() + 1,
        );
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&count)).unwrap()),
            CacheDiscardReason::ResourceLimit
        );

        let mut trailing = fresh.record().to_vec();
        let trailer_at = trailing.len() - TRAILER_BYTES;
        trailing.insert(trailer_at, 0);
        resign(&mut trailing);
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&trailing)).unwrap()),
            CacheDiscardReason::FormatInvalid
        );

        let mut order = fresh.record().to_vec();
        let first_entry = order[100..136].to_vec();
        let second_entry = order[136..172].to_vec();
        order[100..136].copy_from_slice(&second_entry);
        order[136..172].copy_from_slice(&first_entry);
        resign(&mut order);
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&order)).unwrap()),
            CacheDiscardReason::FormatInvalid
        );

        let (function, parameter, block) = graph_fixture();
        let graph_entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let graph = build_index_snapshot(context(), &graph_entities).unwrap();
        let direct_start = 100 + 3 * INVENTORY_ENTRY_BYTES + 8;
        let mut endpoint = graph.record().to_vec();
        endpoint[direct_start + 32..direct_start + 64].copy_from_slice(id(9).as_bytes());
        resign(&mut endpoint);
        assert_eq!(
            rebuilt_reason(
                admit_index_snapshot(context(), &graph_entities, Some(&endpoint)).unwrap()
            ),
            CacheDiscardReason::FormatInvalid
        );
    }

    #[test]
    fn reverse_disagreement_and_valid_unequal_content_are_discarded() {
        let (function, parameter, block) = graph_fixture();
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let fresh = build_index_snapshot(context(), &entities).unwrap();
        let direct_start = 100 + 3 * INVENTORY_ENTRY_BYTES + 8;
        let reverse_count_at = direct_start + 7 * DIRECT_EDGE_BYTES;
        let first_reverse_kind_at = reverse_count_at + 8 + 32 + 8 + 32;
        let mut reverse = fresh.record().to_vec();
        put_u32(&mut reverse, first_reverse_kind_at, ImpactKind::Call.tag());
        resign(&mut reverse);
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&reverse)).unwrap()),
            CacheDiscardReason::FormatInvalid
        );

        let expected_item = constant(1, true);
        let other_item = constant(2, true);
        let expected_entities = [ImpactEntity::Constant(&expected_item)];
        let other =
            build_index_snapshot(context(), &[ImpactEntity::Constant(&other_item)]).unwrap();
        assert_eq!(
            rebuilt_reason(
                admit_index_snapshot(context(), &expected_entities, Some(other.record())).unwrap()
            ),
            CacheDiscardReason::ContentMismatch
        );
    }

    #[test]
    fn fresh_impact_failures_are_preserved_before_candidate_inspection() {
        let first = constant(2, true);
        let second = constant(1, false);
        let error = admit_index_snapshot(
            context(),
            &[
                ImpactEntity::Constant(&first),
                ImpactEntity::Constant(&second),
            ],
            Some(b"malformed candidate"),
        )
        .unwrap_err();
        assert_eq!(
            error,
            IndexSnapshotBuildError::Impact(ImpactError::new(ImpactErrorCode::SetNotCanonical))
        );
    }

    #[test]
    fn truncated_records_and_overlimit_records_are_bounded() {
        let item = constant(1, true);
        let entities = [ImpactEntity::Constant(&item)];
        assert_eq!(
            rebuilt_reason(
                admit_index_snapshot(context(), &entities, Some(&[0; MIN_RECORD_BYTES - 1]))
                    .unwrap()
            ),
            CacheDiscardReason::FormatInvalid
        );
        let oversized = vec![0; usize::try_from(MAX_SNAPSHOT_RECORD_BYTES).unwrap() + 1];
        assert_eq!(
            rebuilt_reason(admit_index_snapshot(context(), &entities, Some(&oversized)).unwrap()),
            CacheDiscardReason::ResourceLimit
        );
    }
}
