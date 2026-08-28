use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sley_id::{ObjectId, StateRoot};
use sley_scb1::ScbError;
use sley_state_root::{
    AcceptedStateRoot, conformance_registry as state_root_registry, import_state_root,
};
use sley_store::{CanonicalVerifier, ObjectStore, StoreErrorCode};
use sley_txn::{
    RepositoryMaintenanceGuard, acquire_exclusive_repository_maintenance,
    initialize_repository_maintenance,
};

const GC_LOCK_BYTES: &[u8; 8] = b"SLEYGC01";
const GC_LOCK_DIR: &str = "locks";
const GC_LOCK_FILE: &str = "gc.lock";
const ID_LEN: usize = 32;
const OBJECT_SUFFIX: &str = ".scb1";

/// Maximum retention anchors in one snapshot.
pub const MAX_GC_ANCHORS: usize = 65_536;
/// Maximum total anchor targets.
pub const MAX_GC_TARGETS: usize = 262_144;
/// Maximum roots in the caller-owned catalog.
pub const MAX_GC_ROOTS: usize = 65_536;
/// Maximum traversed root-dependency edges.
pub const MAX_GC_DEPENDENCY_EDGES: usize = 1_000_000;
/// Maximum traversed object-reference edges.
pub const MAX_GC_OBJECT_REFERENCE_EDGES: usize = 1_000_000;
/// Maximum inventory objects.
pub const MAX_GC_INVENTORY_OBJECTS: usize = 262_144;
/// Maximum ID entries across successful report lists.
pub const MAX_GC_REPORT_ENTRIES: usize = 786_432;
/// Approximate GC-owned allocation budget.
pub const MAX_GC_ALLOCATION: usize = 134_217_728;

/// Stable garbage-collection failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcErrorCode {
    /// `GC_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `GC_ANCHOR_MALFORMED`.
    AnchorMalformed,
    /// `GC_ANCHOR_UNRESOLVED`.
    AnchorUnresolved,
    /// `GC_ROOT_MISSING`.
    RootMissing,
    /// `GC_ROOT_INVALID`.
    RootInvalid,
    /// `GC_DEPENDENCY_MISSING`.
    DependencyMissing,
    /// `GC_OBJECT_REFERENCE_MALFORMED`.
    ObjectReferenceMalformed,
    /// `GC_OBJECT_MISSING`.
    ObjectMissing,
    /// `GC_INVENTORY_INVALID`.
    InventoryInvalid,
    /// Reserved `GC_DRY_RUN_REQUIRED`.
    DryRunRequired,
    /// `GC_EXCLUSIVE_LOCK_REQUIRED`.
    ExclusiveLockRequired,
    /// `GC_DELETE_IO`.
    DeleteIo,
    /// `GC_REACHABILITY_VIOLATION`.
    ReachabilityViolation,
    /// `GC_INTERNAL_INVARIANT`.
    InternalInvariant,
}

impl GcErrorCode {
    /// Returns the exact stable symbol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResourceLimit => "GC_RESOURCE_LIMIT",
            Self::AnchorMalformed => "GC_ANCHOR_MALFORMED",
            Self::AnchorUnresolved => "GC_ANCHOR_UNRESOLVED",
            Self::RootMissing => "GC_ROOT_MISSING",
            Self::RootInvalid => "GC_ROOT_INVALID",
            Self::DependencyMissing => "GC_DEPENDENCY_MISSING",
            Self::ObjectReferenceMalformed => "GC_OBJECT_REFERENCE_MALFORMED",
            Self::ObjectMissing => "GC_OBJECT_MISSING",
            Self::InventoryInvalid => "GC_INVENTORY_INVALID",
            Self::DryRunRequired => "GC_DRY_RUN_REQUIRED",
            Self::ExclusiveLockRequired => "GC_EXCLUSIVE_LOCK_REQUIRED",
            Self::DeleteIo => "GC_DELETE_IO",
            Self::ReachabilityViolation => "GC_REACHABILITY_VIOLATION",
            Self::InternalInvariant => "GC_INTERNAL_INVARIANT",
        }
    }
}

/// Garbage-collection error with an optional partial deletion report.
#[derive(Debug)]
pub struct GcError {
    symbol: &'static str,
    partial_report: Option<Box<GcReport>>,
    source: Option<io::Error>,
}

impl GcError {
    const fn gc(code: GcErrorCode) -> Self {
        Self {
            symbol: code.as_str(),
            partial_report: None,
            source: None,
        }
    }

    const fn upstream(symbol: &'static str) -> Self {
        Self {
            symbol,
            partial_report: None,
            source: None,
        }
    }

    fn io(code: GcErrorCode, error: io::Error) -> Self {
        Self {
            symbol: code.as_str(),
            partial_report: None,
            source: Some(error),
        }
    }

    fn partial(error: io::Error, report: GcReport) -> Self {
        Self {
            symbol: GcErrorCode::DeleteIo.as_str(),
            partial_report: Some(Box::new(report)),
            source: Some(error),
        }
    }

    /// Returns the exact stable failure symbol.
    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        self.symbol
    }

    /// Returns the partial collect report when deletion or sync failed.
    #[must_use]
    pub fn partial_report(&self) -> Option<&GcReport> {
        self.partial_report.as_deref()
    }
}

impl fmt::Display for GcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol)
    }
}

impl std::error::Error for GcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

type Result<T> = core::result::Result<T, GcError>;

/// Closed retention-anchor kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RetentionKind {
    /// Caller-resolved retained ref.
    Ref = 1,
    /// Caller-resolved retained tag.
    Tag = 2,
    /// Caller-declared active lease.
    Lease = 3,
    /// Caller-resolved retained transaction.
    Transaction = 4,
    /// Caller-resolved retained pack manifest.
    PackManifest = 5,
    /// Caller-declared protected root.
    ProtectedRoot = 6,
    /// Caller-declared active session pin.
    SessionPin = 7,
}

/// One exact retention target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetentionTarget {
    /// Exact semantic root.
    StateRoot(StateRoot),
    /// Exact immutable object.
    Object(ObjectId),
}

/// One caller-owned explicit retention anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionAnchor {
    kind: RetentionKind,
    anchor_id: [u8; ID_LEN],
    targets: Vec<RetentionTarget>,
}

impl RetentionAnchor {
    /// Creates an anchor. Snapshot construction validates target presence and uniqueness.
    #[must_use]
    pub fn new(
        kind: RetentionKind,
        anchor_id: [u8; ID_LEN],
        targets: Vec<RetentionTarget>,
    ) -> Self {
        Self {
            kind,
            anchor_id,
            targets,
        }
    }

    /// Returns the closed anchor kind.
    #[must_use]
    pub const fn kind(&self) -> RetentionKind {
        self.kind
    }

    /// Returns the opaque caller-owned anchor ID.
    #[must_use]
    pub const fn anchor_id(&self) -> &[u8; ID_LEN] {
        &self.anchor_id
    }

    /// Returns canonicalized targets after snapshot construction.
    #[must_use]
    pub fn targets(&self) -> &[RetentionTarget] {
        &self.targets
    }
}

/// Canonical key emitted for an examined anchor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionAnchorKey {
    /// Closed kind.
    pub kind: RetentionKind,
    /// Opaque caller-owned ID.
    pub anchor_id: [u8; ID_LEN],
}

/// Validated caller-owned retention snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionSnapshot {
    anchors: Vec<RetentionAnchor>,
    roots: Vec<AcceptedStateRoot>,
}

impl RetentionSnapshot {
    /// Canonicalizes unordered anchors/targets/roots and rejects duplicates.
    ///
    /// # Errors
    ///
    /// Returns a stable GC error for empty/duplicate anchors, duplicate targets,
    /// duplicate roots, or closed count limits.
    pub fn new(
        mut anchors: Vec<RetentionAnchor>,
        mut roots: Vec<AcceptedStateRoot>,
    ) -> Result<Self> {
        if anchors.len() > MAX_GC_ANCHORS || roots.len() > MAX_GC_ROOTS {
            return Err(GcError::gc(GcErrorCode::ResourceLimit));
        }
        let mut target_count = 0_usize;
        for anchor in &mut anchors {
            if anchor.targets.is_empty() {
                return Err(GcError::gc(GcErrorCode::AnchorMalformed));
            }
            target_count = target_count
                .checked_add(anchor.targets.len())
                .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))?;
            if target_count > MAX_GC_TARGETS {
                return Err(GcError::gc(GcErrorCode::ResourceLimit));
            }
            anchor.targets.sort_unstable();
            if anchor.targets.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(GcError::gc(GcErrorCode::AnchorMalformed));
            }
        }
        anchors.sort_by_key(|anchor| (anchor.kind, anchor.anchor_id));
        if anchors
            .windows(2)
            .any(|pair| (pair[0].kind, pair[0].anchor_id) == (pair[1].kind, pair[1].anchor_id))
        {
            return Err(GcError::gc(GcErrorCode::AnchorMalformed));
        }
        roots.sort_by_key(|root| root.root);
        if roots.windows(2).any(|pair| pair[0].root == pair[1].root) {
            return Err(GcError::gc(GcErrorCode::RootInvalid));
        }
        Ok(Self { anchors, roots })
    }

    /// Returns canonical anchors.
    #[must_use]
    pub fn anchors(&self) -> &[RetentionAnchor] {
        &self.anchors
    }

    /// Returns canonical root catalog entries.
    #[must_use]
    pub fn roots(&self) -> &[AcceptedStateRoot] {
        &self.roots
    }
}

/// Canonical verifier plus schema-selected object-reference extraction.
pub trait GcObjectVerifier: CanonicalVerifier {
    /// Returns every `ObjectId` referenced by this already bounded standalone record.
    ///
    /// # Errors
    ///
    /// Returns an exact SCB error when the selected reference shape is malformed.
    fn references(&self, record: &[u8]) -> core::result::Result<Vec<ObjectId>, ScbError>;
}

/// Successful GC decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcDecision {
    /// Mark/report only; no mutation occurred.
    DryRun,
    /// Every planned unreachable object was deleted and synced.
    Collected,
    /// Host deletion or sync failed after zero or more completed deletions.
    PartialDeleteFailure,
}

/// Deterministic machine-readable GC report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcReport {
    /// Canonical examined anchor keys.
    pub examined_anchors: Vec<RetentionAnchorKey>,
    /// Retained roots including dependency closure.
    pub retained_roots: Vec<StateRoot>,
    /// Complete reachable object closure.
    pub reachable_objects: Vec<ObjectId>,
    /// Complete verified store inventory.
    pub inventory_objects: Vec<ObjectId>,
    /// Verified inventory objects absent from reachability.
    pub deletion_candidates: Vec<ObjectId>,
    /// Aggregate inventory bytes.
    pub inventory_bytes: u64,
    /// Aggregate candidate bytes.
    pub candidate_bytes: u64,
    /// Run decision.
    pub decision: GcDecision,
    /// Successfully deleted and synced objects.
    pub deleted_objects: Vec<ObjectId>,
    /// Object whose delete or directory sync failed.
    pub failed_object: Option<ObjectId>,
}

#[derive(Clone, Debug)]
struct InventoryEntry {
    object_id: ObjectId,
    path: PathBuf,
    bytes: u64,
}

struct Reachability {
    examined_anchors: Vec<RetentionAnchorKey>,
    retained_roots: BTreeSet<StateRoot>,
    reachable_objects: BTreeSet<ObjectId>,
}

/// Exclusive local GC guard for one exact real store root.
#[derive(Debug)]
pub struct ExclusiveGcGuard {
    store_root: PathBuf,
    lock_path: PathBuf,
    maintenance: RepositoryMaintenanceGuard,
    active: bool,
}

impl ExclusiveGcGuard {
    /// Returns the exact canonical store root bound to this guard.
    #[must_use]
    pub fn store_root(&self) -> &Path {
        &self.store_root
    }

    /// Explicitly releases the guard and syncs the lock directory.
    ///
    /// # Errors
    ///
    /// Returns `GC_EXCLUSIVE_LOCK_REQUIRED` when removal or sync fails.
    pub fn release(mut self) -> Result<()> {
        self.release_inner()?;
        self.active = false;
        Ok(())
    }

    fn release_inner(&self) -> Result<()> {
        fs::remove_file(&self.lock_path)
            .and_then(|()| sync_dir(self.lock_path.parent().expect("lock has parent")))
            .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))
    }
}

impl Drop for ExclusiveGcGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.lock_path);
            if let Some(parent) = self.lock_path.parent() {
                let _ = sync_dir(parent);
            }
        }
    }
}

/// Atomically acquires the local exclusive GC guard.
///
/// The returned guard owns both the durable GC witness and the exclusive
/// repository-maintenance lock. Cooperating transaction and ref operations
/// cannot run until it is released.
///
/// # Errors
///
/// Returns `GC_EXCLUSIVE_LOCK_REQUIRED` for an invalid root, existing guard, or
/// lock creation/sync failure.
pub fn acquire_exclusive_gc(store: &ObjectStore) -> Result<ExclusiveGcGuard> {
    let root_metadata = fs::symlink_metadata(store.root())
        .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))?;
    if !root_metadata.file_type().is_dir() {
        return Err(GcError::gc(GcErrorCode::ExclusiveLockRequired));
    }
    let store_root = fs::canonicalize(store.root())
        .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))?;
    let lock_dir = store_root.join(GC_LOCK_DIR);
    create_real_dir(&store_root, &lock_dir)?;
    initialize_repository_maintenance(&store_root)
        .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))?;
    let lock_path = lock_dir.join(GC_LOCK_FILE);
    let mut lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))?;
    if let Err(error) = lock
        .write_all(GC_LOCK_BYTES)
        .and_then(|()| lock.sync_all())
        .and_then(|()| sync_dir(&lock_dir))
    {
        let _ = fs::remove_file(&lock_path);
        return Err(GcError::io(GcErrorCode::ExclusiveLockRequired, error));
    }
    let maintenance = match acquire_exclusive_repository_maintenance(&store_root) {
        Ok(maintenance) => maintenance,
        Err(error) => {
            let _ = fs::remove_file(&lock_path);
            let _ = sync_dir(&lock_dir);
            return Err(GcError::io(GcErrorCode::ExclusiveLockRequired, error));
        }
    };
    Ok(ExclusiveGcGuard {
        store_root,
        lock_path,
        maintenance,
        active: true,
    })
}

/// Computes a complete deterministic dry-run report without mutation.
///
/// # Errors
///
/// Fails closed on any malformed/unresolved anchor, root, dependency,
/// reference, inventory entry, object, or resource bound.
pub fn gc_dry_run<V: GcObjectVerifier>(
    store: &ObjectStore,
    snapshot: &RetentionSnapshot,
    verifier: &V,
) -> Result<GcReport> {
    plan_gc(store, snapshot, verifier)
}

/// Replans under the exact exclusive guard and deletes only verified candidates.
///
/// # Errors
///
/// Returns planning errors before deletion. A delete/sync host failure returns
/// `GC_DELETE_IO` with `partial_report()` populated.
pub fn gc_collect<V: GcObjectVerifier>(
    store: &ObjectStore,
    snapshot: &RetentionSnapshot,
    verifier: &V,
    guard: &ExclusiveGcGuard,
) -> Result<GcReport> {
    collect_inner(store, snapshot, verifier, guard, DeleteFault::None)
}

fn plan_gc<V: GcObjectVerifier>(
    store: &ObjectStore,
    snapshot: &RetentionSnapshot,
    verifier: &V,
) -> Result<GcReport> {
    let inventory = inventory(store)?;
    let inventory_ids = inventory
        .iter()
        .map(|entry| entry.object_id)
        .collect::<BTreeSet<_>>();
    let inventory_bytes = inventory.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.bytes)
            .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))
    })?;
    let roots = validate_roots(snapshot)?;
    let reachability = resolve_reachability(store, snapshot, verifier, &roots, &inventory_ids)?;
    for entry in &inventory {
        if !reachability.reachable_objects.contains(&entry.object_id) {
            store
                .read(entry.object_id, verifier)
                .map_err(|error| map_store_error(&error))?;
        }
    }
    let deletion_candidates = inventory_ids
        .difference(&reachability.reachable_objects)
        .copied()
        .collect::<Vec<_>>();
    let candidate_set = deletion_candidates.iter().copied().collect::<BTreeSet<_>>();
    let candidate_bytes = inventory.iter().try_fold(0_u64, |total, entry| {
        if candidate_set.contains(&entry.object_id) {
            total
                .checked_add(entry.bytes)
                .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))
        } else {
            Ok(total)
        }
    })?;
    let report_entries = reachability
        .examined_anchors
        .len()
        .checked_add(reachability.retained_roots.len())
        .and_then(|count| count.checked_add(reachability.reachable_objects.len()))
        .and_then(|count| count.checked_add(inventory.len()))
        .and_then(|count| count.checked_add(deletion_candidates.len()))
        .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))?;
    if report_entries > MAX_GC_REPORT_ENTRIES {
        return Err(GcError::gc(GcErrorCode::ResourceLimit));
    }
    check_allocation(report_entries, &inventory)?;
    Ok(GcReport {
        examined_anchors: reachability.examined_anchors,
        retained_roots: reachability.retained_roots.into_iter().collect(),
        reachable_objects: reachability.reachable_objects.into_iter().collect(),
        inventory_objects: inventory_ids.into_iter().collect(),
        deletion_candidates,
        inventory_bytes,
        candidate_bytes,
        decision: GcDecision::DryRun,
        deleted_objects: Vec::new(),
        failed_object: None,
    })
}

fn resolve_reachability<V: GcObjectVerifier>(
    store: &ObjectStore,
    snapshot: &RetentionSnapshot,
    verifier: &V,
    roots: &BTreeMap<StateRoot, AcceptedStateRoot>,
    inventory_ids: &BTreeSet<ObjectId>,
) -> Result<Reachability> {
    let (examined_anchors, root_queue, mut object_queue) =
        seed_anchor_targets(snapshot, roots, inventory_ids)?;
    let retained_roots = traverse_roots(root_queue, &mut object_queue, roots)?;
    let reachable_objects = traverse_objects(store, verifier, inventory_ids, object_queue)?;
    Ok(Reachability {
        examined_anchors,
        retained_roots,
        reachable_objects,
    })
}

fn seed_anchor_targets(
    snapshot: &RetentionSnapshot,
    roots: &BTreeMap<StateRoot, AcceptedStateRoot>,
    inventory_ids: &BTreeSet<ObjectId>,
) -> Result<(
    Vec<RetentionAnchorKey>,
    VecDeque<StateRoot>,
    VecDeque<ObjectId>,
)> {
    let mut examined = Vec::with_capacity(snapshot.anchors.len());
    let mut root_queue = VecDeque::new();
    let mut object_queue = VecDeque::new();
    for anchor in &snapshot.anchors {
        examined.push(RetentionAnchorKey {
            kind: anchor.kind,
            anchor_id: anchor.anchor_id,
        });
        for target in &anchor.targets {
            match target {
                RetentionTarget::StateRoot(root) if roots.contains_key(root) => {
                    root_queue.push_back(*root);
                }
                RetentionTarget::StateRoot(_) => {
                    return Err(GcError::gc(GcErrorCode::RootMissing));
                }
                RetentionTarget::Object(object) if inventory_ids.contains(object) => {
                    object_queue.push_back(*object);
                }
                RetentionTarget::Object(_) => {
                    return Err(GcError::gc(GcErrorCode::AnchorUnresolved));
                }
            }
        }
    }
    Ok((examined, root_queue, object_queue))
}

fn traverse_roots(
    mut queue: VecDeque<StateRoot>,
    object_queue: &mut VecDeque<ObjectId>,
    roots: &BTreeMap<StateRoot, AcceptedStateRoot>,
) -> Result<BTreeSet<StateRoot>> {
    let mut retained = BTreeSet::new();
    let mut edge_count = 0_usize;
    while let Some(root_id) = queue.pop_front() {
        if !retained.insert(root_id) {
            continue;
        }
        let root = roots
            .get(&root_id)
            .ok_or_else(|| GcError::gc(GcErrorCode::DependencyMissing))?;
        for dependency in &root.record.dependency_roots {
            edge_count = edge_count
                .checked_add(1)
                .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))?;
            if edge_count > MAX_GC_DEPENDENCY_EDGES {
                return Err(GcError::gc(GcErrorCode::ResourceLimit));
            }
            if !roots.contains_key(dependency) {
                return Err(GcError::gc(GcErrorCode::DependencyMissing));
            }
            queue.push_back(*dependency);
        }
        object_queue.push_back(root.record.contract_root);
        object_queue.push_back(root.record.test_root);
        object_queue.extend(
            root.record
                .entity_bindings
                .iter()
                .map(|(_, object_id)| *object_id),
        );
    }
    Ok(retained)
}

fn traverse_objects<V: GcObjectVerifier>(
    store: &ObjectStore,
    verifier: &V,
    inventory_ids: &BTreeSet<ObjectId>,
    mut queue: VecDeque<ObjectId>,
) -> Result<BTreeSet<ObjectId>> {
    let mut reachable = BTreeSet::new();
    let mut edge_count = 0_usize;
    while let Some(object_id) = queue.pop_front() {
        if !reachable.insert(object_id) {
            continue;
        }
        if !inventory_ids.contains(&object_id) {
            return Err(GcError::gc(GcErrorCode::ObjectMissing));
        }
        let record = store
            .read(object_id, verifier)
            .map_err(|error| map_store_error(&error))?;
        let mut references = verifier
            .references(&record)
            .map_err(|_| GcError::gc(GcErrorCode::ObjectReferenceMalformed))?;
        references.sort_unstable();
        references.dedup();
        edge_count = edge_count
            .checked_add(references.len())
            .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))?;
        if edge_count > MAX_GC_OBJECT_REFERENCE_EDGES {
            return Err(GcError::gc(GcErrorCode::ResourceLimit));
        }
        for reference in references {
            if !inventory_ids.contains(&reference) {
                return Err(GcError::gc(GcErrorCode::ObjectMissing));
            }
            queue.push_back(reference);
        }
    }
    Ok(reachable)
}

fn validate_roots(snapshot: &RetentionSnapshot) -> Result<BTreeMap<StateRoot, AcceptedStateRoot>> {
    let registry =
        state_root_registry().map_err(|error| GcError::upstream(error.code().as_str()))?;
    let mut roots = BTreeMap::new();
    for candidate in &snapshot.roots {
        let imported = import_state_root(&registry, &candidate.stored_bytes)
            .map_err(|error| GcError::upstream(error.code_str()))?;
        if imported.root != candidate.root || imported.record != candidate.record {
            return Err(GcError::gc(GcErrorCode::RootInvalid));
        }
        if roots.insert(imported.root, imported).is_some() {
            return Err(GcError::gc(GcErrorCode::RootInvalid));
        }
    }
    let mut edge_count = 0_usize;
    for root in roots.values() {
        for dependency in &root.record.dependency_roots {
            edge_count = edge_count
                .checked_add(1)
                .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))?;
            if edge_count > MAX_GC_DEPENDENCY_EDGES {
                return Err(GcError::gc(GcErrorCode::ResourceLimit));
            }
            if !roots.contains_key(dependency) {
                return Err(GcError::gc(GcErrorCode::DependencyMissing));
            }
        }
    }
    Ok(roots)
}

fn inventory(store: &ObjectStore) -> Result<Vec<InventoryEntry>> {
    ensure_real_dir(store.root(), GcErrorCode::InventoryInvalid)?;
    let object_root = store.root().join("objects");
    if !real_dir_or_absent(&object_root)? {
        return Ok(Vec::new());
    }
    let scb1_root = object_root.join("scb1");
    if !real_dir_or_absent(&scb1_root)? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for first in sorted_entries(&scb1_root)? {
        require_hex_dir(&first, 2)?;
        let first_file_name = first.file_name();
        let first_name = os_text(&first_file_name)?;
        for second in sorted_entries(&first.path())? {
            require_hex_dir(&second, 2)?;
            let second_file_name = second.file_name();
            let second_name = os_text(&second_file_name)?;
            for object in sorted_entries(&second.path())? {
                let file_type = object
                    .file_type()
                    .map_err(|error| GcError::io(GcErrorCode::InventoryInvalid, error))?;
                if !file_type.is_file() {
                    return Err(GcError::gc(GcErrorCode::InventoryInvalid));
                }
                let object_file_name = object.file_name();
                let name = os_text(&object_file_name)?;
                let hex = name
                    .strip_suffix(OBJECT_SUFFIX)
                    .ok_or_else(|| GcError::gc(GcErrorCode::InventoryInvalid))?;
                let object_id = parse_object_id(hex)?;
                if first_name != &hex[0..2] || second_name != &hex[2..4] {
                    return Err(GcError::gc(GcErrorCode::InventoryInvalid));
                }
                if object.path() != store.object_path(object_id) {
                    return Err(GcError::gc(GcErrorCode::InventoryInvalid));
                }
                let metadata = fs::symlink_metadata(object.path())
                    .map_err(|error| GcError::io(GcErrorCode::InventoryInvalid, error))?;
                if !metadata.file_type().is_file() {
                    return Err(GcError::gc(GcErrorCode::InventoryInvalid));
                }
                out.push(InventoryEntry {
                    object_id,
                    path: object.path(),
                    bytes: metadata.len(),
                });
                if out.len() > MAX_GC_INVENTORY_OBJECTS {
                    return Err(GcError::gc(GcErrorCode::ResourceLimit));
                }
            }
        }
    }
    out.sort_by_key(|entry| entry.object_id);
    if out
        .windows(2)
        .any(|pair| pair[0].object_id == pair[1].object_id)
    {
        return Err(GcError::gc(GcErrorCode::InventoryInvalid));
    }
    Ok(out)
}

fn collect_inner<V: GcObjectVerifier>(
    store: &ObjectStore,
    snapshot: &RetentionSnapshot,
    verifier: &V,
    guard: &ExclusiveGcGuard,
    fault: DeleteFault,
) -> Result<GcReport> {
    require_guard(store, guard)?;
    let mut report = plan_gc(store, snapshot, verifier)?;
    let reachable = report
        .reachable_objects
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for object_id in report.deletion_candidates.clone() {
        if reachable.contains(&object_id) {
            return Err(GcError::gc(GcErrorCode::ReachabilityViolation));
        }
        store
            .read(object_id, verifier)
            .map_err(|error| map_store_error(&error))?;
        let path = store.object_path(object_id);
        let metadata = fs::symlink_metadata(&path).map_err(map_delete_io)?;
        if !metadata.file_type().is_file() {
            return Err(GcError::gc(GcErrorCode::InventoryInvalid));
        }
        if fault == DeleteFault::BeforeDelete(object_id) {
            report.decision = GcDecision::PartialDeleteFailure;
            report.failed_object = Some(object_id);
            return Err(GcError::partial(
                io::Error::other("injected delete failure"),
                report,
            ));
        }
        if let Err(error) = fs::remove_file(&path) {
            report.decision = GcDecision::PartialDeleteFailure;
            report.failed_object = Some(object_id);
            return Err(GcError::partial(error, report));
        }
        report.deleted_objects.push(object_id);
        if fault == DeleteFault::AfterDeleteBeforeSync(object_id) {
            report.decision = GcDecision::PartialDeleteFailure;
            report.failed_object = Some(object_id);
            return Err(GcError::partial(
                io::Error::other("injected directory sync failure"),
                report,
            ));
        }
        if let Err(error) = sync_dir(path.parent().expect("object path has parent")) {
            report.decision = GcDecision::PartialDeleteFailure;
            report.failed_object = Some(object_id);
            return Err(GcError::partial(error, report));
        }
    }
    report.decision = GcDecision::Collected;
    Ok(report)
}

fn require_guard(store: &ObjectStore, guard: &ExclusiveGcGuard) -> Result<()> {
    if !guard.active {
        return Err(GcError::gc(GcErrorCode::ExclusiveLockRequired));
    }
    let store_root = fs::canonicalize(store.root())
        .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))?;
    if store_root != guard.store_root {
        return Err(GcError::gc(GcErrorCode::ExclusiveLockRequired));
    }
    if !guard.maintenance.is_exclusive() || !guard.maintenance.covers(store.root()) {
        return Err(GcError::gc(GcErrorCode::ExclusiveLockRequired));
    }
    let lock_metadata = fs::symlink_metadata(&guard.lock_path)
        .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))?;
    if !lock_metadata.file_type().is_file() {
        return Err(GcError::gc(GcErrorCode::ExclusiveLockRequired));
    }
    let lock_bytes = fs::read(&guard.lock_path)
        .map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))?;
    if lock_bytes != GC_LOCK_BYTES {
        return Err(GcError::gc(GcErrorCode::ExclusiveLockRequired));
    }
    Ok(())
}

fn check_allocation(report_entries: usize, inventory: &[InventoryEntry]) -> Result<()> {
    let id_budget = report_entries
        .checked_mul(128)
        .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))?;
    let path_budget = inventory.iter().try_fold(0_usize, |total, entry| {
        total
            .checked_add(entry.path.as_os_str().len())
            .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))
    })?;
    let estimated = id_budget
        .checked_add(path_budget)
        .ok_or_else(|| GcError::gc(GcErrorCode::ResourceLimit))?;
    if estimated > MAX_GC_ALLOCATION {
        return Err(GcError::gc(GcErrorCode::ResourceLimit));
    }
    Ok(())
}

fn map_store_error(error: &sley_store::StoreError) -> GcError {
    if error.code() == StoreErrorCode::StoreObjectNotFound {
        GcError::gc(GcErrorCode::ObjectMissing)
    } else {
        GcError::upstream(error.symbol())
    }
}

fn map_delete_io(error: io::Error) -> GcError {
    GcError::io(GcErrorCode::DeleteIo, error)
}

fn create_real_dir(parent: &Path, path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            sync_dir(parent).map_err(|error| GcError::io(GcErrorCode::ExclusiveLockRequired, error))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure_real_dir(path, GcErrorCode::ExclusiveLockRequired)
        }
        Err(error) => Err(GcError::io(GcErrorCode::ExclusiveLockRequired, error)),
    }
}

fn ensure_real_dir(path: &Path, code: GcErrorCode) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| GcError::io(code, error))?;
    if metadata.file_type().is_dir() {
        Ok(())
    } else {
        Err(GcError::gc(code))
    }
}

fn real_dir_or_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(GcError::gc(GcErrorCode::InventoryInvalid)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(GcError::io(GcErrorCode::InventoryInvalid, error)),
    }
}

fn sorted_entries(path: &Path) -> Result<Vec<fs::DirEntry>> {
    let reader =
        fs::read_dir(path).map_err(|error| GcError::io(GcErrorCode::InventoryInvalid, error))?;
    let mut entries = Vec::new();
    for entry in reader {
        entries.push(entry.map_err(|error| GcError::io(GcErrorCode::InventoryInvalid, error))?);
        if entries.len() > MAX_GC_INVENTORY_OBJECTS {
            return Err(GcError::gc(GcErrorCode::ResourceLimit));
        }
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn require_hex_dir(entry: &fs::DirEntry, length: usize) -> Result<()> {
    let file_type = entry
        .file_type()
        .map_err(|error| GcError::io(GcErrorCode::InventoryInvalid, error))?;
    let file_name = entry.file_name();
    let name = os_text(&file_name)?;
    if !file_type.is_dir() || name.len() != length || !name.bytes().all(is_lower_hex) {
        return Err(GcError::gc(GcErrorCode::InventoryInvalid));
    }
    Ok(())
}

fn os_text(name: &std::ffi::OsStr) -> Result<&str> {
    name.to_str()
        .ok_or_else(|| GcError::gc(GcErrorCode::InventoryInvalid))
}

fn parse_object_id(hex: &str) -> Result<ObjectId> {
    if hex.len() != ID_LEN * 2 || !hex.bytes().all(is_lower_hex) {
        return Err(GcError::gc(GcErrorCode::InventoryInvalid));
    }
    let mut bytes = [0_u8; ID_LEN];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(ObjectId::from_bytes(bytes))
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(GcError::gc(GcErrorCode::InventoryInvalid)),
    }
}

fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path).and_then(|directory| directory.sync_all())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeleteFault {
    None,
    BeforeDelete(ObjectId),
    AfterDeleteBeforeSync(ObjectId),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use sley_id::{EntityId, PolicyRootId, WorkspaceId};
    use sley_scb1::{
        FixtureContract, MAX_STANDALONE_BYTES, ScbErrorCode, decode_standalone_fixture,
        encode_bool, encode_record, encode_standalone_fixture,
    };
    use sley_state_root::{StateRootBuilder, conformance_registry};

    use super::*;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("sley2-gc-{label}-{}-{counter}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct FixtureVerifier {
        references: BTreeMap<ObjectId, Vec<ObjectId>>,
        reject_references: BTreeSet<ObjectId>,
    }

    impl CanonicalVerifier for FixtureVerifier {
        fn verify(&self, record: &[u8]) -> core::result::Result<ObjectId, ScbError> {
            decode_standalone_fixture(record, FixtureContract::EmptyObject)
                .or_else(|_| decode_standalone_fixture(record, FixtureContract::RequiredBool))
                .map(|fixture| fixture.object_id)
        }
    }

    impl GcObjectVerifier for FixtureVerifier {
        fn references(&self, record: &[u8]) -> core::result::Result<Vec<ObjectId>, ScbError> {
            let object_id = self.verify(record)?;
            if self.reject_references.contains(&object_id) {
                return Err(ScbError::new(ScbErrorCode::FieldUnknown));
            }
            Ok(self.references.get(&object_id).cloned().unwrap_or_default())
        }
    }

    fn empty_object() -> (Vec<u8>, ObjectId) {
        encode_standalone_fixture(FixtureContract::EmptyObject, &encode_record(&[]).unwrap())
            .unwrap()
    }

    fn bool_object(value: bool) -> (Vec<u8>, ObjectId) {
        let payload = encode_record(&[(1, encode_bool(value))]).unwrap();
        encode_standalone_fixture(FixtureContract::RequiredBool, &payload).unwrap()
    }

    fn root(
        contract_root: ObjectId,
        test_root: ObjectId,
        bound: ObjectId,
        dependency: Option<StateRoot>,
    ) -> AcceptedStateRoot {
        let registry = conformance_registry().unwrap();
        let mut builder = StateRootBuilder::new(
            WorkspaceId::from_bytes([7; 32]),
            contract_root,
            test_root,
            PolicyRootId::from_bytes([9; 32]),
        )
        .entity_binding(EntityId::from_bytes([8; 32]), bound)
        .entry_point(EntityId::from_bytes([8; 32]));
        if let Some(dependency) = dependency {
            builder = builder.dependency_root(dependency);
        }
        builder.build(&registry).unwrap()
    }

    fn anchor(kind: RetentionKind, byte: u8, targets: Vec<RetentionTarget>) -> RetentionAnchor {
        RetentionAnchor::new(kind, [byte; 32], targets)
    }

    struct Fixture {
        _temp: TempRoot,
        store: ObjectStore,
        retained: AcceptedStateRoot,
        unreachable_id: ObjectId,
        child_id: ObjectId,
        verifier: FixtureVerifier,
    }

    fn fixture() -> Fixture {
        let temp = TempRoot::new("fixture");
        let store = ObjectStore::new(&temp.0);
        let (contract, contract_id) = empty_object();
        let (child, child_id) = bool_object(true);
        let (unreachable, unreachable_id) = bool_object(false);
        let verifier = FixtureVerifier {
            references: BTreeMap::from([(contract_id, vec![child_id])]),
            reject_references: BTreeSet::new(),
        };
        for (bytes, id) in [
            (&contract, contract_id),
            (&child, child_id),
            (&unreachable, unreachable_id),
        ] {
            store.put(id, bytes, &verifier).unwrap();
        }
        let retained = root(contract_id, contract_id, contract_id, None);
        Fixture {
            _temp: temp,
            store,
            retained,
            unreachable_id,
            child_id,
            verifier,
        }
    }

    #[test]
    fn dry_run_marks_root_and_transitive_object_references() {
        let fixture = fixture();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                1,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        let report = gc_dry_run(&fixture.store, &snapshot, &fixture.verifier).unwrap();
        assert_eq!(report.decision, GcDecision::DryRun);
        assert!(report.reachable_objects.contains(&fixture.child_id));
        assert_eq!(report.deletion_candidates, vec![fixture.unreachable_id]);
        assert!(fixture.store.object_path(fixture.unreachable_id).is_file());
    }

    #[test]
    fn every_anchor_kind_retains_the_same_root_closure() {
        let fixture = fixture();
        for (index, kind) in [
            RetentionKind::Ref,
            RetentionKind::Tag,
            RetentionKind::Lease,
            RetentionKind::Transaction,
            RetentionKind::PackManifest,
            RetentionKind::ProtectedRoot,
            RetentionKind::SessionPin,
        ]
        .into_iter()
        .enumerate()
        {
            let snapshot = RetentionSnapshot::new(
                vec![anchor(
                    kind,
                    u8::try_from(index).unwrap(),
                    vec![RetentionTarget::StateRoot(fixture.retained.root)],
                )],
                vec![fixture.retained.clone()],
            )
            .unwrap();
            let report = gc_dry_run(&fixture.store, &snapshot, &fixture.verifier).unwrap();
            assert!(report.reachable_objects.contains(&fixture.child_id));
            assert_eq!(report.deletion_candidates, vec![fixture.unreachable_id]);
        }
    }

    #[test]
    fn dependency_roots_are_retained_transitively() {
        let fixture = fixture();
        let dependency = fixture.retained.clone();
        let parent = root(
            dependency.record.contract_root,
            dependency.record.test_root,
            dependency.record.contract_root,
            Some(dependency.root),
        );
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Tag,
                2,
                vec![RetentionTarget::StateRoot(parent.root)],
            )],
            vec![parent.clone(), dependency.clone()],
        )
        .unwrap();
        let report = gc_dry_run(&fixture.store, &snapshot, &fixture.verifier).unwrap();
        let mut expected = vec![dependency.root, parent.root];
        expected.sort_unstable();
        assert_eq!(report.retained_roots, expected);
    }

    #[test]
    fn missing_dependency_fails_closed() {
        let fixture = fixture();
        let parent = root(
            fixture.retained.record.contract_root,
            fixture.retained.record.test_root,
            fixture.retained.record.contract_root,
            Some(fixture.retained.root),
        );
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                3,
                vec![RetentionTarget::StateRoot(parent.root)],
            )],
            vec![parent],
        )
        .unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &snapshot, &fixture.verifier)
                .unwrap_err()
                .symbol(),
            "GC_DEPENDENCY_MISSING"
        );
    }

    #[test]
    fn unresolved_direct_object_anchor_fails_closed() {
        let fixture = fixture();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::ProtectedRoot,
                4,
                vec![RetentionTarget::Object(ObjectId::from_bytes([0xfe; 32]))],
            )],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &snapshot, &fixture.verifier)
                .unwrap_err()
                .symbol(),
            "GC_ANCHOR_UNRESOLVED"
        );
    }

    #[test]
    fn empty_retention_snapshot_marks_all_verified_objects_as_candidates() {
        let fixture = fixture();
        let snapshot = RetentionSnapshot::new(Vec::new(), Vec::new()).unwrap();
        let report = gc_dry_run(&fixture.store, &snapshot, &fixture.verifier).unwrap();
        assert!(report.examined_anchors.is_empty());
        assert!(report.retained_roots.is_empty());
        assert!(report.reachable_objects.is_empty());
        assert_eq!(report.deletion_candidates, report.inventory_objects);
        assert_eq!(report.deletion_candidates.len(), 3);
    }

    #[test]
    fn missing_transitive_object_fails_closed() {
        let fixture = fixture();
        fs::remove_file(fixture.store.object_path(fixture.child_id)).unwrap();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                14,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &snapshot, &fixture.verifier)
                .unwrap_err()
                .symbol(),
            "GC_OBJECT_MISSING"
        );
    }

    #[test]
    fn corrupt_unreachable_object_is_not_silently_deleted() {
        let fixture = fixture();
        let path = fixture.store.object_path(fixture.unreachable_id);
        let mut bytes = fs::read(&path).unwrap();
        bytes[10] ^= 1;
        fs::write(&path, bytes).unwrap();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Lease,
                15,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &snapshot, &fixture.verifier)
                .unwrap_err()
                .symbol(),
            "SCB_DIGEST_MISMATCH"
        );
        assert!(path.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inventory_object_fails_closed() {
        use std::os::unix::fs::symlink;

        let fixture = fixture();
        let path = fixture.store.object_path(fixture.unreachable_id);
        fs::remove_file(&path).unwrap();
        symlink(
            fixture
                .store
                .object_path(fixture.retained.record.contract_root),
            &path,
        )
        .unwrap();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                16,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &snapshot, &fixture.verifier)
                .unwrap_err()
                .symbol(),
            "GC_INVENTORY_INVALID"
        );
    }

    #[test]
    fn malformed_reference_shape_fails_before_deletion() {
        let mut fixture = fixture();
        fixture
            .verifier
            .reject_references
            .insert(fixture.retained.record.contract_root);
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Lease,
                5,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &snapshot, &fixture.verifier)
                .unwrap_err()
                .symbol(),
            "GC_OBJECT_REFERENCE_MALFORMED"
        );
        assert!(fixture.store.object_path(fixture.unreachable_id).is_file());
    }

    #[test]
    fn malformed_inventory_path_fails_closed() {
        let fixture = fixture();
        fs::write(
            fixture.store.root().join("objects/scb1/not-a-fanout"),
            b"foreign",
        )
        .unwrap();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                6,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &snapshot, &fixture.verifier)
                .unwrap_err()
                .symbol(),
            "GC_INVENTORY_INVALID"
        );
    }

    #[test]
    fn collect_deletes_only_unreachable_and_is_idempotent() {
        let fixture = fixture();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::SessionPin,
                7,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        let guard = acquire_exclusive_gc(&fixture.store).unwrap();
        let first = gc_collect(&fixture.store, &snapshot, &fixture.verifier, &guard).unwrap();
        assert_eq!(first.decision, GcDecision::Collected);
        assert_eq!(first.deleted_objects, vec![fixture.unreachable_id]);
        assert!(!fixture.store.object_path(fixture.unreachable_id).exists());
        for object in &first.reachable_objects {
            assert!(fixture.store.object_path(*object).is_file());
        }
        let second = gc_collect(&fixture.store, &snapshot, &fixture.verifier, &guard).unwrap();
        assert!(second.deletion_candidates.is_empty());
        assert!(second.deleted_objects.is_empty());
    }

    #[test]
    fn concurrent_or_wrong_store_guard_fails_closed() {
        let fixture = fixture();
        let other_temp = TempRoot::new("other");
        let other = ObjectStore::new(&other_temp.0);
        let guard = acquire_exclusive_gc(&fixture.store).unwrap();
        assert_eq!(
            acquire_exclusive_gc(&fixture.store).unwrap_err().symbol(),
            "GC_EXCLUSIVE_LOCK_REQUIRED"
        );
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                8,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        assert_eq!(
            gc_collect(&other, &snapshot, &fixture.verifier, &guard)
                .unwrap_err()
                .symbol(),
            "GC_EXCLUSIVE_LOCK_REQUIRED"
        );
    }

    #[test]
    fn injected_delete_failure_returns_partial_report() {
        let fixture = fixture();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                9,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        let guard = acquire_exclusive_gc(&fixture.store).unwrap();
        let error = collect_inner(
            &fixture.store,
            &snapshot,
            &fixture.verifier,
            &guard,
            DeleteFault::BeforeDelete(fixture.unreachable_id),
        )
        .unwrap_err();
        assert_eq!(error.symbol(), "GC_DELETE_IO");
        let report = error.partial_report().unwrap();
        assert_eq!(report.decision, GcDecision::PartialDeleteFailure);
        assert_eq!(report.failed_object, Some(fixture.unreachable_id));
        assert!(report.deleted_objects.is_empty());
        assert!(fixture.store.object_path(fixture.unreachable_id).is_file());
    }

    #[test]
    fn injected_sync_failure_reports_already_deleted_object() {
        let fixture = fixture();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Ref,
                10,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        let guard = acquire_exclusive_gc(&fixture.store).unwrap();
        let error = collect_inner(
            &fixture.store,
            &snapshot,
            &fixture.verifier,
            &guard,
            DeleteFault::AfterDeleteBeforeSync(fixture.unreachable_id),
        )
        .unwrap_err();
        let report = error.partial_report().unwrap();
        assert_eq!(report.deleted_objects, vec![fixture.unreachable_id]);
        assert!(!fixture.store.object_path(fixture.unreachable_id).exists());
    }

    #[test]
    fn unordered_snapshot_produces_identical_report() {
        let fixture = fixture();
        let a = anchor(
            RetentionKind::Tag,
            11,
            vec![RetentionTarget::StateRoot(fixture.retained.root)],
        );
        let b = anchor(
            RetentionKind::ProtectedRoot,
            12,
            vec![RetentionTarget::Object(fixture.child_id)],
        );
        let one =
            RetentionSnapshot::new(vec![a.clone(), b.clone()], vec![fixture.retained.clone()])
                .unwrap();
        let two = RetentionSnapshot::new(vec![b, a], vec![fixture.retained.clone()]).unwrap();
        assert_eq!(
            gc_dry_run(&fixture.store, &one, &fixture.verifier).unwrap(),
            gc_dry_run(&fixture.store, &two, &fixture.verifier).unwrap()
        );
    }

    #[test]
    fn duplicate_and_empty_anchors_fail_closed() {
        let target = RetentionTarget::Object(ObjectId::from_bytes([1; 32]));
        assert_eq!(
            RetentionSnapshot::new(
                vec![anchor(RetentionKind::Ref, 1, vec![target, target])],
                Vec::new(),
            )
            .unwrap_err()
            .symbol(),
            "GC_ANCHOR_MALFORMED"
        );
        assert_eq!(
            RetentionSnapshot::new(vec![anchor(RetentionKind::Ref, 1, Vec::new())], Vec::new(),)
                .unwrap_err()
                .symbol(),
            "GC_ANCHOR_MALFORMED"
        );
    }

    #[test]
    fn t40_seed_reachable_candidate_assertion_is_effective() {
        let fixture = fixture();
        let snapshot = RetentionSnapshot::new(
            vec![anchor(
                RetentionKind::Lease,
                13,
                vec![RetentionTarget::StateRoot(fixture.retained.root)],
            )],
            vec![fixture.retained.clone()],
        )
        .unwrap();
        let report = gc_dry_run(&fixture.store, &snapshot, &fixture.verifier).unwrap();
        assert!(
            report
                .reachable_objects
                .iter()
                .all(|object| !report.deletion_candidates.contains(object))
        );
        assert!(report.reachable_objects.contains(&fixture.child_id));
    }

    #[test]
    fn stable_gc_error_symbols_are_frozen() {
        assert_eq!(GcErrorCode::DryRunRequired.as_str(), "GC_DRY_RUN_REQUIRED");
        assert_eq!(
            GcErrorCode::ReachabilityViolation.as_str(),
            "GC_REACHABILITY_VIOLATION"
        );
        assert_eq!(MAX_STANDALONE_BYTES, 67_108_864);
    }
}
