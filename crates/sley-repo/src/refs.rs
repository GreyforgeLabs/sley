//! Native S20-500 named refs over fully verified durable transactions.

use core::fmt;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sley_id::{PolicyRootId, SchemaEpochId, StateRoot, TransactionId, WorkspaceId};
use sley_scb1::{
    MAX_COLLECTION_ELEMENTS, MAX_STANDALONE_BYTES, ScbErrorCode, ScbValueCursor, encode_bytes,
    encode_list, encode_record, encode_uvar,
};
use sley_txn::{CommitError, RepositoryMaintenanceGuard, TransactionRepository, VerifiedRevision};

const BRANCH_MAGIC: [u8; 8] = *b"SLEYBR01";
const REF_MAGIC: [u8; 8] = *b"SLEYRF01";
const NAME_KEY_MAGIC: [u8; 8] = *b"SLEYBNM1";
const ENVELOPE_VERSION: u64 = 1;
const RECORD_VERSION: u32 = 1;
const BRANCH_FIELD_COUNT: u64 = 8;
const REF_FIELD_COUNT: u64 = 9;
const BRANCH_DIGEST_DOMAIN: &[u8] = b"sley2.branch-record.v1";
const REF_DIGEST_DOMAIN: &[u8] = b"sley2.branch-ref.v1";
const NAME_KEY_DOMAIN: &[u8] = b"sley2.branch-name-path.v1";
const DIGEST_LEN: usize = 32;
const MAX_BRANCH_NAME_BYTES: usize = 255;
const MAX_BRANCH_COMPONENTS: usize = 8;
const MAX_BRANCH_COMPONENT_BYTES: usize = 63;
const MAX_BRANCHES: usize = 4_096;
const MAX_BRANCH_ORIGINS: usize = 65_536;
const MAX_ANCESTRY_NODES: usize = 65_536;
const MAX_STAGE_ATTEMPTS: u64 = 1_024;
const BRANCH_STAGE_PREFIX: &str = ".sley-branch-stage-";
const REF_STAGE_PREFIX: &str = ".sley-ref-stage-";
const STAGE_SUFFIX: &str = ".tmp";

static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

const RESERVED_COMPONENTS: &[&[u8]] = &[
    b"accepted",
    b"branch",
    b"branches",
    b"head",
    b"heads",
    b"lock",
    b"locks",
    b"object",
    b"objects",
    b"ref",
    b"refs",
    b"tag",
    b"tags",
    b"transaction",
    b"transactions",
];

/// Stable S20-500 native-ref failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchErrorCode {
    /// `REF_FORMAT_VERSION`.
    RefFormatVersion,
    /// `REF_NAME_INVALID`.
    RefNameInvalid,
    /// `REF_NAME_RESERVED`.
    RefNameReserved,
    /// `REF_DIGEST_MISMATCH`.
    RefDigestMismatch,
    /// `REF_FIELD_SHAPE`.
    RefFieldShape,
    /// `REF_BRANCH_BINDING_MISMATCH`.
    RefBranchBindingMismatch,
    /// `REF_NOT_FOUND`.
    RefNotFound,
    /// `REF_ALREADY_EXISTS`.
    RefAlreadyExists,
    /// `REF_NAME_COLLISION`.
    RefNameCollision,
    /// `REF_TARGET_MISMATCH`.
    RefTargetMismatch,
    /// `REF_NAMED_CAS_STALE`.
    RefNamedCasStale,
    /// `BRANCH_RECORD_FORMAT_VERSION`.
    BranchRecordFormatVersion,
    /// `BRANCH_RECORD_DIGEST_MISMATCH`.
    BranchRecordDigestMismatch,
    /// `BRANCH_RECORD_FIELD_SHAPE`.
    BranchRecordFieldShape,
    /// `BRANCH_ORIGIN_MISMATCH`.
    BranchOriginMismatch,
    /// `BRANCH_NOT_FAST_FORWARD`.
    BranchNotFastForward,
    /// `BRANCH_ANCESTRY_CYCLE`.
    BranchAncestryCycle,
    /// `BRANCH_RESOURCE_LIMIT`.
    BranchResourceLimit,
    /// `RECOVERY_NAMED_REF_INCOMPLETE`.
    RecoveryNamedRefIncomplete,
    /// `REF_IO`.
    RefIo,
    /// `REF_INTERNAL_INVARIANT`.
    RefInternalInvariant,
}

impl BranchErrorCode {
    /// Every code in numeric order.
    pub const ALL: [Self; 21] = [
        Self::RefFormatVersion,
        Self::RefNameInvalid,
        Self::RefNameReserved,
        Self::RefDigestMismatch,
        Self::RefFieldShape,
        Self::RefBranchBindingMismatch,
        Self::RefNotFound,
        Self::RefAlreadyExists,
        Self::RefNameCollision,
        Self::RefTargetMismatch,
        Self::RefNamedCasStale,
        Self::BranchRecordFormatVersion,
        Self::BranchRecordDigestMismatch,
        Self::BranchRecordFieldShape,
        Self::BranchOriginMismatch,
        Self::BranchNotFastForward,
        Self::BranchAncestryCycle,
        Self::BranchResourceLimit,
        Self::RecoveryNamedRefIncomplete,
        Self::RefIo,
        Self::RefInternalInvariant,
    ];

    /// Returns the exact stable symbol.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::RefFormatVersion => "REF_FORMAT_VERSION",
            Self::RefNameInvalid => "REF_NAME_INVALID",
            Self::RefNameReserved => "REF_NAME_RESERVED",
            Self::RefDigestMismatch => "REF_DIGEST_MISMATCH",
            Self::RefFieldShape => "REF_FIELD_SHAPE",
            Self::RefBranchBindingMismatch => "REF_BRANCH_BINDING_MISMATCH",
            Self::RefNotFound => "REF_NOT_FOUND",
            Self::RefAlreadyExists => "REF_ALREADY_EXISTS",
            Self::RefNameCollision => "REF_NAME_COLLISION",
            Self::RefTargetMismatch => "REF_TARGET_MISMATCH",
            Self::RefNamedCasStale => "REF_NAMED_CAS_STALE",
            Self::BranchRecordFormatVersion => "BRANCH_RECORD_FORMAT_VERSION",
            Self::BranchRecordDigestMismatch => "BRANCH_RECORD_DIGEST_MISMATCH",
            Self::BranchRecordFieldShape => "BRANCH_RECORD_FIELD_SHAPE",
            Self::BranchOriginMismatch => "BRANCH_ORIGIN_MISMATCH",
            Self::BranchNotFastForward => "BRANCH_NOT_FAST_FORWARD",
            Self::BranchAncestryCycle => "BRANCH_ANCESTRY_CYCLE",
            Self::BranchResourceLimit => "BRANCH_RESOURCE_LIMIT",
            Self::RecoveryNamedRefIncomplete => "RECOVERY_NAMED_REF_INCOMPLETE",
            Self::RefIo => "REF_IO",
            Self::RefInternalInvariant => "REF_INTERNAL_INVARIANT",
        }
    }

    /// Returns the exact stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::RefFormatVersion => 50_000,
            Self::RefNameInvalid => 50_001,
            Self::RefNameReserved => 50_002,
            Self::RefDigestMismatch => 50_003,
            Self::RefFieldShape => 50_004,
            Self::RefBranchBindingMismatch => 50_005,
            Self::RefNotFound => 50_006,
            Self::RefAlreadyExists => 50_007,
            Self::RefNameCollision => 50_008,
            Self::RefTargetMismatch => 50_009,
            Self::RefNamedCasStale => 50_010,
            Self::BranchRecordFormatVersion => 50_011,
            Self::BranchRecordDigestMismatch => 50_012,
            Self::BranchRecordFieldShape => 50_013,
            Self::BranchOriginMismatch => 50_014,
            Self::BranchNotFastForward => 50_015,
            Self::BranchAncestryCycle => 50_016,
            Self::BranchResourceLimit => 50_017,
            Self::RecoveryNamedRefIncomplete => 50_018,
            Self::RefIo => 50_019,
            Self::RefInternalInvariant => 50_020,
        }
    }
}

/// Native-ref failure preserving transaction-owned errors.
#[derive(Debug)]
pub enum BranchError {
    /// S20-500-owned semantic or codec failure.
    Branch(BranchErrorCode),
    /// Exact upstream transaction, receipt, root, policy, SCB1, or store failure.
    Transaction(CommitError),
    /// Local host I/O failure.
    Io(io::Error),
}

impl BranchError {
    /// Returns the exact stable source symbol.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Branch(code) => code.symbol(),
            Self::Transaction(error) => error.code(),
            Self::Io(_) => BranchErrorCode::RefIo.symbol(),
        }
    }

    /// Returns the exact numeric code when the owning layer froze one.
    #[must_use]
    pub fn numeric_code(&self) -> Option<u32> {
        match self {
            Self::Branch(code) => Some(code.numeric()),
            Self::Transaction(error) => error.numeric_code(),
            Self::Io(_) => Some(BranchErrorCode::RefIo.numeric()),
        }
    }
}

impl fmt::Display for BranchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for BranchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transaction(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Branch(_) => None,
        }
    }
}

impl From<CommitError> for BranchError {
    fn from(value: CommitError) -> Self {
        Self::Transaction(value)
    }
}

impl From<io::Error> for BranchError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Exact validated lowercase ASCII branch name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchName(Vec<u8>);

impl BranchName {
    /// Validates exact bytes without rewriting them.
    ///
    /// # Errors
    ///
    /// Returns `REF_NAME_RESERVED` for an otherwise-valid reserved component
    /// and `REF_NAME_INVALID` for every other grammar failure.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, BranchError> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() || bytes.len() > MAX_BRANCH_NAME_BYTES {
            return Err(branch_error(BranchErrorCode::RefNameInvalid));
        }
        let components = bytes.split(|byte| *byte == b'/').collect::<Vec<_>>();
        if components.is_empty() || components.len() > MAX_BRANCH_COMPONENTS {
            return Err(branch_error(BranchErrorCode::RefNameInvalid));
        }
        for component in &components {
            if component.is_empty() || component.len() > MAX_BRANCH_COMPONENT_BYTES {
                return Err(branch_error(BranchErrorCode::RefNameInvalid));
            }
            if !component.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(*byte, b'.' | b'_' | b'-')
            }) || !component.first().is_some_and(u8::is_ascii_alphanumeric)
                || !component.last().is_some_and(u8::is_ascii_alphanumeric)
                || component.ends_with(b".lock")
            {
                return Err(branch_error(BranchErrorCode::RefNameInvalid));
            }
        }
        if components
            .iter()
            .any(|component| RESERVED_COMPONENTS.contains(component))
        {
            return Err(branch_error(BranchErrorCode::RefNameReserved));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Returns the exact canonical bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the canonical ASCII spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Construction admits ASCII only, so this fallback is unreachable
        // through the public API and keeps this accessor panic-free.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }

    /// Returns the domain-separated host-path key.
    #[must_use]
    pub fn path_key(&self) -> [u8; DIGEST_LEN] {
        let mut preimage = Vec::with_capacity(NAME_KEY_MAGIC.len() + 12 + self.0.len());
        preimage.extend_from_slice(&NAME_KEY_MAGIC);
        preimage.extend_from_slice(&encode_uvar(ENVELOPE_VERSION));
        preimage.extend_from_slice(&encode_uvar(self.0.len() as u64));
        preimage.extend_from_slice(&self.0);
        digest(NAME_KEY_DOMAIN, &preimage)
    }
}

impl fmt::Debug for BranchName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BranchName")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for BranchName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Integrity digest for one immutable branch-origin record.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchRecordDigest([u8; DIGEST_LEN]);

impl BranchRecordDigest {
    /// Constructs a digest from exact raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns exact raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

impl fmt::Debug for BranchRecordDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BranchRecordDigest")
            .field(&hex_digest(&self.0))
            .finish()
    }
}

/// Canonical immutable branch-origin facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchRecord {
    /// Exact record version.
    pub format_version: u32,
    /// Exact canonical branch name.
    pub branch_name: BranchName,
    /// Immutable origin workspace.
    pub workspace_id: WorkspaceId,
    /// Fully verified origin transaction.
    pub origin_transaction_id: TransactionId,
    /// Origin semantic state root.
    pub origin_state_root: StateRoot,
    /// Origin schema epoch.
    pub schema_epoch_id: SchemaEpochId,
    /// Origin protected policy root.
    pub policy_root_id: PolicyRootId,
    /// Exact sorted dependency roots at origin.
    pub dependency_roots: Vec<StateRoot>,
}

/// Strictly imported immutable branch-origin record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedBranchRecord {
    /// Strict canonical record.
    pub record: BranchRecord,
    /// Domain-separated integrity digest.
    pub digest: BranchRecordDigest,
    /// Exact digest preimage.
    pub preimage: Vec<u8>,
    /// Exact stored envelope bytes including digest trailer.
    pub stored_bytes: Vec<u8>,
}

/// Canonical mutable visible-ref facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchRefRecord {
    /// Exact record version.
    pub format_version: u32,
    /// Exact canonical branch name.
    pub branch_name: BranchName,
    /// Digest of the immutable origin record.
    pub branch_record_digest: BranchRecordDigest,
    /// Current verified workspace.
    pub workspace_id: WorkspaceId,
    /// Current verified transaction.
    pub head_transaction_id: TransactionId,
    /// Current semantic root.
    pub head_state_root: StateRoot,
    /// Current schema epoch.
    pub schema_epoch_id: SchemaEpochId,
    /// Current protected policy root.
    pub policy_root_id: PolicyRootId,
    /// Current exact sorted dependency roots.
    pub dependency_roots: Vec<StateRoot>,
}

/// Strictly imported visible branch ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedBranchRef {
    /// Strict canonical record.
    pub record: BranchRefRecord,
    /// Domain-separated ref integrity digest.
    pub digest: [u8; DIGEST_LEN],
    /// Exact digest preimage.
    pub preimage: Vec<u8>,
    /// Exact stored envelope bytes including digest trailer.
    pub stored_bytes: Vec<u8>,
}

/// Closed native-ref mutation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchUpdateStatus {
    /// Origin and visible ref were durably created by this call.
    Created,
    /// Visible ref was durably advanced by this call.
    Advanced,
    /// The exact requested visible state was already durable and verified.
    Present,
}

impl BranchUpdateStatus {
    /// Returns the frozen wire tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Created => 1,
            Self::Advanced => 2,
            Self::Present => 3,
        }
    }

    /// Resolves one exact frozen wire tag.
    #[must_use]
    pub const fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Created),
            2 => Some(Self::Advanced),
            3 => Some(Self::Present),
            _ => None,
        }
    }

    /// Returns the frozen result symbol.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Advanced => "ADVANCED",
            Self::Present => "PRESENT",
        }
    }
}

/// Encodes and derives one immutable branch-origin record.
///
/// # Errors
///
/// Returns the exact S20-500 version, field, or resource failure.
pub fn build_branch_record(record: &BranchRecord) -> Result<ImportedBranchRecord, BranchError> {
    if record.format_version != RECORD_VERSION {
        return Err(branch_error(BranchErrorCode::BranchRecordFormatVersion));
    }
    validate_dependencies(
        &record.dependency_roots,
        BranchErrorCode::BranchRecordFieldShape,
    )?;
    let dependencies = encode_dependencies(&record.dependency_roots)?;
    let payload = encode_record(&[
        (1, encode_uvar(u64::from(record.format_version))),
        (
            2,
            encode_bytes(record.branch_name.as_bytes())
                .map_err(|_| branch_error(BranchErrorCode::BranchRecordFieldShape))?,
        ),
        (3, record.workspace_id.as_bytes().to_vec()),
        (4, record.origin_transaction_id.as_bytes().to_vec()),
        (5, record.origin_state_root.as_bytes().to_vec()),
        (6, record.schema_epoch_id.as_bytes().to_vec()),
        (7, record.policy_root_id.as_bytes().to_vec()),
        (8, dependencies),
    ])
    .map_err(|_| branch_error(BranchErrorCode::BranchRecordFieldShape))?;
    let (preimage, digest, stored_bytes) = build_envelope(
        BRANCH_MAGIC,
        BRANCH_DIGEST_DOMAIN,
        &payload,
        BranchErrorCode::BranchResourceLimit,
    )?;
    Ok(ImportedBranchRecord {
        record: record.clone(),
        digest: BranchRecordDigest::from_bytes(digest),
        preimage,
        stored_bytes,
    })
}

/// Strictly imports one immutable branch-origin record.
///
/// # Errors
///
/// Returns the first exact envelope, digest, name, field, or resource failure.
pub fn import_branch_record(stored: &[u8]) -> Result<ImportedBranchRecord, BranchError> {
    let (payload, preimage, digest) = decode_envelope(
        stored,
        BRANCH_MAGIC,
        BRANCH_DIGEST_DOMAIN,
        BranchErrorCode::BranchRecordFormatVersion,
        BranchErrorCode::BranchRecordDigestMismatch,
        BranchErrorCode::BranchRecordFieldShape,
    )?;
    let fields = decode_required_record(
        payload,
        BRANCH_FIELD_COUNT,
        BranchErrorCode::BranchRecordFieldShape,
    )?;
    let format_version = read_u32(fields[0], BranchErrorCode::BranchRecordFieldShape)?;
    if format_version != RECORD_VERSION {
        return Err(branch_error(BranchErrorCode::BranchRecordFormatVersion));
    }
    let branch_name = BranchName::parse(read_bytes(
        fields[1],
        BranchErrorCode::BranchRecordFieldShape,
    )?)?;
    let record = BranchRecord {
        format_version,
        branch_name,
        workspace_id: WorkspaceId::from_bytes(read_fixed(
            fields[2],
            BranchErrorCode::BranchRecordFieldShape,
        )?),
        origin_transaction_id: TransactionId::from_bytes(read_fixed(
            fields[3],
            BranchErrorCode::BranchRecordFieldShape,
        )?),
        origin_state_root: StateRoot::from_bytes(read_fixed(
            fields[4],
            BranchErrorCode::BranchRecordFieldShape,
        )?),
        schema_epoch_id: SchemaEpochId::from_bytes(read_fixed(
            fields[5],
            BranchErrorCode::BranchRecordFieldShape,
        )?),
        policy_root_id: PolicyRootId::from_bytes(read_fixed(
            fields[6],
            BranchErrorCode::BranchRecordFieldShape,
        )?),
        dependency_roots: decode_dependencies(fields[7], BranchErrorCode::BranchRecordFieldShape)?,
    };
    Ok(ImportedBranchRecord {
        record,
        digest: BranchRecordDigest::from_bytes(digest),
        preimage,
        stored_bytes: stored.to_vec(),
    })
}

/// Encodes and derives one visible branch ref.
///
/// # Errors
///
/// Returns the exact S20-500 version, field, or resource failure.
pub fn build_branch_ref(record: &BranchRefRecord) -> Result<ImportedBranchRef, BranchError> {
    if record.format_version != RECORD_VERSION {
        return Err(branch_error(BranchErrorCode::RefFormatVersion));
    }
    validate_dependencies(&record.dependency_roots, BranchErrorCode::RefFieldShape)?;
    let dependencies = encode_dependencies(&record.dependency_roots)?;
    let payload = encode_record(&[
        (1, encode_uvar(u64::from(record.format_version))),
        (
            2,
            encode_bytes(record.branch_name.as_bytes())
                .map_err(|_| branch_error(BranchErrorCode::RefFieldShape))?,
        ),
        (3, record.branch_record_digest.as_bytes().to_vec()),
        (4, record.workspace_id.as_bytes().to_vec()),
        (5, record.head_transaction_id.as_bytes().to_vec()),
        (6, record.head_state_root.as_bytes().to_vec()),
        (7, record.schema_epoch_id.as_bytes().to_vec()),
        (8, record.policy_root_id.as_bytes().to_vec()),
        (9, dependencies),
    ])
    .map_err(|_| branch_error(BranchErrorCode::RefFieldShape))?;
    let (preimage, digest, stored_bytes) = build_envelope(
        REF_MAGIC,
        REF_DIGEST_DOMAIN,
        &payload,
        BranchErrorCode::BranchResourceLimit,
    )?;
    Ok(ImportedBranchRef {
        record: record.clone(),
        digest,
        preimage,
        stored_bytes,
    })
}

/// Strictly imports one visible branch ref.
///
/// # Errors
///
/// Returns the first exact envelope, digest, name, field, or resource failure.
pub fn import_branch_ref(stored: &[u8]) -> Result<ImportedBranchRef, BranchError> {
    let (payload, preimage, digest) = decode_envelope(
        stored,
        REF_MAGIC,
        REF_DIGEST_DOMAIN,
        BranchErrorCode::RefFormatVersion,
        BranchErrorCode::RefDigestMismatch,
        BranchErrorCode::RefFieldShape,
    )?;
    let fields = decode_required_record(payload, REF_FIELD_COUNT, BranchErrorCode::RefFieldShape)?;
    let format_version = read_u32(fields[0], BranchErrorCode::RefFieldShape)?;
    if format_version != RECORD_VERSION {
        return Err(branch_error(BranchErrorCode::RefFormatVersion));
    }
    let record = BranchRefRecord {
        format_version,
        branch_name: BranchName::parse(read_bytes(fields[1], BranchErrorCode::RefFieldShape)?)?,
        branch_record_digest: BranchRecordDigest::from_bytes(read_fixed(
            fields[2],
            BranchErrorCode::RefFieldShape,
        )?),
        workspace_id: WorkspaceId::from_bytes(read_fixed(
            fields[3],
            BranchErrorCode::RefFieldShape,
        )?),
        head_transaction_id: TransactionId::from_bytes(read_fixed(
            fields[4],
            BranchErrorCode::RefFieldShape,
        )?),
        head_state_root: StateRoot::from_bytes(read_fixed(
            fields[5],
            BranchErrorCode::RefFieldShape,
        )?),
        schema_epoch_id: SchemaEpochId::from_bytes(read_fixed(
            fields[6],
            BranchErrorCode::RefFieldShape,
        )?),
        policy_root_id: PolicyRootId::from_bytes(read_fixed(
            fields[7],
            BranchErrorCode::RefFieldShape,
        )?),
        dependency_roots: decode_dependencies(fields[8], BranchErrorCode::RefFieldShape)?,
    };
    Ok(ImportedBranchRef {
        record,
        digest,
        preimage,
        stored_bytes: stored.to_vec(),
    })
}

/// One fully resolved visible branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedBranch {
    /// Strict immutable origin record.
    pub origin: ImportedBranchRecord,
    /// Strict current visible ref.
    pub reference: ImportedBranchRef,
    /// Fully verified current durable revision.
    pub revision: VerifiedRevision,
}

/// One deterministic head-first ancestry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchAncestryEntry {
    /// Exact transaction identity.
    pub transaction_id: TransactionId,
    /// Ancestry-independent semantic root.
    pub state_root: StateRoot,
    /// Ordered direct parent transaction identities.
    pub parent_transaction_ids: Vec<TransactionId>,
}

/// One immutable origin record with no visible ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanBranchOrigin {
    /// Exact canonical branch name.
    pub branch_name: BranchName,
    /// Immutable origin-record digest.
    pub branch_record_digest: BranchRecordDigest,
    /// Fully recorded origin transaction.
    pub origin_transaction_id: TransactionId,
}

/// Idempotent S20-500-owned recovery summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefRecoveryReport {
    /// Removed immutable-origin staging remnants.
    pub removed_branch_stages: u64,
    /// Removed mutable-ref staging remnants.
    pub removed_ref_stages: u64,
    /// Number of visible refs fully verified after cleanup.
    pub visible_branches: u64,
    /// Sorted immutable origins without a visible ref.
    pub orphan_origins: Vec<OrphanBranchOrigin>,
}

/// Repository-rooted native branch/ref owner.
#[derive(Clone, Debug)]
pub struct BranchRepository {
    root: PathBuf,
    transactions: TransactionRepository,
}

impl BranchRepository {
    /// Creates a repository handle. The explicit root must already exist.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            transactions: TransactionRepository::new(root.clone()),
            root,
        }
    }

    /// Returns the configured repository root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Creates one named branch at an already durable verified transaction.
    ///
    /// # Errors
    ///
    /// Returns the first exact name, layout, origin, conflict, persistence, or
    /// upstream transaction failure.
    pub fn create_branch(
        &self,
        name: impl AsRef<[u8]>,
        origin_transaction_id: TransactionId,
    ) -> Result<BranchUpdateStatus, BranchError> {
        self.create_branch_inner(name, origin_transaction_id, None)
    }

    fn create_branch_inner(
        &self,
        name: impl AsRef<[u8]>,
        origin_transaction_id: TransactionId,
        directory_fault_path: Option<&Path>,
    ) -> Result<BranchUpdateStatus, BranchError> {
        let name = BranchName::parse(name)?;
        let maintenance = self.prepare_operation_inner(directory_fault_path)?;
        let _lock = self.acquire_refs_lock()?;
        let branch_path = ensure_key_path_with_fault(
            &self.branches_dir(),
            &name,
            ".branch.scb1",
            directory_fault_path,
        )?;
        let ref_path =
            ensure_key_path_with_fault(&self.refs_dir(), &name, ".ref.scb1", directory_fault_path)?;
        let branch_exists = path_exists(&branch_path)?;
        let ref_exists = path_exists(&ref_path)?;

        if ref_exists && !branch_exists {
            return Err(branch_error(BranchErrorCode::RecoveryNamedRefIncomplete));
        }

        let existing_origin = branch_exists
            .then(|| self.read_branch_at(&branch_path))
            .transpose()?;
        let existing_ref = ref_exists
            .then(|| self.read_ref_at(&ref_path))
            .transpose()?;

        if let (Some(origin), Some(reference)) = (existing_origin.as_ref(), existing_ref.as_ref()) {
            return self.resolve_existing_create(
                &maintenance,
                origin_transaction_id,
                &branch_path,
                &ref_path,
                origin,
                reference,
            );
        }

        if let Some(origin) = existing_origin {
            return self.finish_orphan_create(
                &maintenance,
                &branch_path,
                &ref_path,
                &name,
                origin_transaction_id,
                &origin,
            );
        }

        self.create_fresh(
            &maintenance,
            &branch_path,
            &ref_path,
            &name,
            origin_transaction_id,
        )
    }

    fn resolve_existing_create(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
        requested_origin: TransactionId,
        branch_path: &Path,
        ref_path: &Path,
        origin: &ImportedBranchRecord,
        reference: &ImportedBranchRef,
    ) -> Result<BranchUpdateStatus, BranchError> {
        validate_origin_ref_binding(origin, reference)?;
        let origin_revision = self
            .transactions
            .verified_revision_with_maintenance(maintenance, origin.record.origin_transaction_id)?;
        verify_origin_target(&origin.record, &origin_revision)?;
        let current = self.transactions.verified_revision_with_maintenance(
            maintenance,
            reference.record.head_transaction_id,
        )?;
        verify_ref_target(&reference.record, &current)?;
        if reference.record.workspace_id != origin.record.workspace_id
            || origin.record.origin_transaction_id != requested_origin
        {
            return Err(branch_error(BranchErrorCode::BranchOriginMismatch));
        }
        if reference.record.head_transaction_id != requested_origin {
            return Err(branch_error(BranchErrorCode::RefAlreadyExists));
        }
        redurabilize_branch(branch_path, origin)?;
        redurabilize_ref(ref_path, reference)?;
        Ok(BranchUpdateStatus::Present)
    }

    fn finish_orphan_create(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
        branch_path: &Path,
        ref_path: &Path,
        name: &BranchName,
        requested_origin: TransactionId,
        origin: &ImportedBranchRecord,
    ) -> Result<BranchUpdateStatus, BranchError> {
        let revision = self
            .transactions
            .verified_revision_with_maintenance(maintenance, origin.record.origin_transaction_id)?;
        verify_origin_target(&origin.record, &revision)?;
        if origin.record.origin_transaction_id != requested_origin {
            return Err(branch_error(BranchErrorCode::BranchOriginMismatch));
        }
        self.validate_new_visible_capacity()?;
        redurabilize_branch(branch_path, origin)?;
        let desired_ref = build_branch_ref(&ref_record(name, origin.digest, &revision))?;
        persist_expected_ref(ref_path, &desired_ref)?;
        let visible = self.resolve_locked(maintenance, name)?;
        if visible.reference != desired_ref {
            return Err(branch_error(BranchErrorCode::RefInternalInvariant));
        }
        Ok(BranchUpdateStatus::Created)
    }

    fn create_fresh(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
        branch_path: &Path,
        ref_path: &Path,
        name: &BranchName,
        origin_transaction_id: TransactionId,
    ) -> Result<BranchUpdateStatus, BranchError> {
        self.create_fresh_with_origin_limit(
            maintenance,
            branch_path,
            ref_path,
            name,
            origin_transaction_id,
            MAX_BRANCH_ORIGINS,
        )
    }

    fn create_fresh_with_origin_limit(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
        branch_path: &Path,
        ref_path: &Path,
        name: &BranchName,
        origin_transaction_id: TransactionId,
        maximum_origins: usize,
    ) -> Result<BranchUpdateStatus, BranchError> {
        let revision = self
            .transactions
            .verified_revision_with_maintenance(maintenance, origin_transaction_id)?;
        let desired_origin = build_branch_record(&origin_record(name, &revision))?;
        let desired_ref = build_branch_ref(&ref_record(name, desired_origin.digest, &revision))?;
        self.validate_new_origin_capacity(maximum_origins)?;
        self.validate_new_visible_capacity()?;
        persist_no_overwrite(
            branch_path,
            &desired_origin.stored_bytes,
            BRANCH_STAGE_PREFIX,
            BranchErrorCode::BranchOriginMismatch,
            |bytes| {
                if import_branch_record(bytes)? == desired_origin {
                    Ok(())
                } else {
                    Err(branch_error(BranchErrorCode::BranchOriginMismatch))
                }
            },
        )?;
        persist_expected_ref(ref_path, &desired_ref)?;
        let visible = self.resolve_locked(maintenance, name)?;
        if visible.reference != desired_ref {
            return Err(branch_error(BranchErrorCode::RefInternalInvariant));
        }
        Ok(BranchUpdateStatus::Created)
    }

    fn validate_new_origin_capacity(&self, maximum: usize) -> Result<(), BranchError> {
        let origin_count = enumerate_record_paths(
            &self.branches_dir(),
            ".branch.scb1",
            maximum,
            Some(BRANCH_STAGE_PREFIX),
        )?
        .len();
        validate_origin_capacity(origin_count, maximum)
    }

    fn validate_new_visible_capacity(&self) -> Result<(), BranchError> {
        let visible_count = enumerate_record_paths(
            &self.refs_dir(),
            ".ref.scb1",
            MAX_BRANCHES,
            Some(REF_STAGE_PREFIX),
        )?
        .len();
        validate_visible_capacity(visible_count)
    }

    /// Resolves one visible branch through immutable records and durable
    /// transaction evidence.
    ///
    /// # Errors
    ///
    /// Returns no partial branch and preserves the first exact owning failure.
    pub fn resolve_branch(&self, name: impl AsRef<[u8]>) -> Result<ResolvedBranch, BranchError> {
        let name = BranchName::parse(name)?;
        let maintenance = self.prepare_operation()?;
        let _lock = self.acquire_refs_lock()?;
        self.resolve_locked(&maintenance, &name)
    }

    /// Lists one deterministic, fully verified snapshot of visible branches.
    ///
    /// # Errors
    ///
    /// Fails closed on an invalid limit, unknown path, malformed record, or
    /// any unresolved visible branch.
    pub fn list_branches(&self, limit: usize) -> Result<Vec<ResolvedBranch>, BranchError> {
        validate_branch_limit(limit)?;
        let maintenance = self.prepare_operation()?;
        let _lock = self.acquire_refs_lock()?;
        self.list_branches_locked(&maintenance, limit)
    }

    /// Advances one visible branch by an exact direct-parent compare-and-swap.
    ///
    /// # Errors
    ///
    /// Returns exact stale and non-fast-forward failures without
    /// last-write-wins behavior.
    pub fn advance_branch(
        &self,
        name: impl AsRef<[u8]>,
        expected_head: TransactionId,
        new_head: TransactionId,
    ) -> Result<BranchUpdateStatus, BranchError> {
        let name = BranchName::parse(name)?;
        let maintenance = self.prepare_operation()?;
        let _lock = self.acquire_refs_lock()?;
        let current = self.resolve_locked(&maintenance, &name)?;
        if current.reference.record.head_transaction_id == new_head {
            redurabilize_branch(&self.checked_branch_path(&name)?, &current.origin)?;
            redurabilize_ref(&self.checked_ref_path(&name)?, &current.reference)?;
            return Ok(BranchUpdateStatus::Present);
        }
        if current.reference.record.head_transaction_id != expected_head {
            return Err(branch_error(BranchErrorCode::RefNamedCasStale));
        }
        let revision = self
            .transactions
            .verified_revision_with_maintenance(&maintenance, new_head)?;
        if revision.state_root().record.workspace_id != current.origin.record.workspace_id {
            return Err(branch_error(BranchErrorCode::BranchOriginMismatch));
        }
        let parents = &revision.receipt().transaction.record.parent_transaction_ids;
        if parents
            .iter()
            .filter(|parent| **parent == expected_head)
            .count()
            != 1
        {
            return Err(branch_error(BranchErrorCode::BranchNotFastForward));
        }
        let desired = build_branch_ref(&ref_record(&name, current.origin.digest, &revision))?;
        let path = self.checked_ref_path(&name)?;
        replace_ref(&path, &desired)?;
        let visible = self.resolve_locked(&maintenance, &name)?;
        if visible.reference != desired {
            return Err(branch_error(BranchErrorCode::RefInternalInvariant));
        }
        Ok(BranchUpdateStatus::Advanced)
    }

    /// Traverses deterministic head-first verified transaction ancestry.
    ///
    /// # Errors
    ///
    /// Returns a hard resource or cycle failure with no partial success and
    /// preserves exact upstream revision failures.
    pub fn branch_ancestry(
        &self,
        name: impl AsRef<[u8]>,
        max_nodes: usize,
    ) -> Result<Vec<BranchAncestryEntry>, BranchError> {
        validate_ancestry_limit(max_nodes)?;
        let name = BranchName::parse(name)?;
        let maintenance = self.prepare_operation()?;
        let _lock = self.acquire_refs_lock()?;
        let branch = self.resolve_locked(&maintenance, &name)?;
        walk_ancestry(
            branch.reference.record.head_transaction_id,
            max_nodes,
            |transaction_id| {
                let revision = self
                    .transactions
                    .verified_revision_with_maintenance(&maintenance, transaction_id)?;
                Ok(BranchAncestryEntry {
                    transaction_id,
                    state_root: revision.state_root().root,
                    parent_transaction_ids: revision
                        .receipt()
                        .transaction
                        .record
                        .parent_transaction_ids
                        .clone(),
                })
            },
        )
    }

    /// Removes only S20-500-owned staging remnants, verifies every visible
    /// branch, and reports immutable orphan origins without deleting them.
    ///
    /// # Errors
    ///
    /// Returns the first exact confinement, cleanup, record, or target failure.
    pub fn recover_refs(&self) -> Result<RefRecoveryReport, BranchError> {
        let maintenance = self.prepare_operation()?;
        let _lock = self.acquire_refs_lock()?;
        let removed_branch_stages =
            remove_stages_recursive(&self.branches_dir(), BRANCH_STAGE_PREFIX, 2)?;
        let removed_ref_stages = remove_stages_recursive(&self.refs_dir(), REF_STAGE_PREFIX, 2)?;
        let visible = self.list_branches_locked(&maintenance, MAX_BRANCHES)?;
        let visible_digests = visible
            .iter()
            .map(|branch| branch.origin.digest)
            .collect::<BTreeSet<_>>();
        let branch_paths = enumerate_record_paths(
            &self.branches_dir(),
            ".branch.scb1",
            MAX_BRANCH_ORIGINS,
            None,
        )?;
        let mut orphan_origins = Vec::new();
        for path in branch_paths {
            let origin = self.read_branch_at(&path)?;
            if !visible_digests.contains(&origin.digest) {
                orphan_origins.push(OrphanBranchOrigin {
                    branch_name: origin.record.branch_name,
                    branch_record_digest: origin.digest,
                    origin_transaction_id: origin.record.origin_transaction_id,
                });
            }
        }
        orphan_origins.sort_by(|left, right| left.branch_name.cmp(&right.branch_name));
        Ok(RefRecoveryReport {
            removed_branch_stages,
            removed_ref_stages,
            visible_branches: usize_to_u64(visible.len())?,
            orphan_origins,
        })
    }

    fn resolve_locked(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
        name: &BranchName,
    ) -> Result<ResolvedBranch, BranchError> {
        let ref_path = self.checked_ref_path(name)?;
        let branch_path = self.checked_branch_path(name)?;
        if !path_exists(&ref_path)? {
            return Err(branch_error(BranchErrorCode::RefNotFound));
        }
        if !path_exists(&branch_path)? {
            return Err(branch_error(BranchErrorCode::RecoveryNamedRefIncomplete));
        }
        let origin = self.read_branch_at(&branch_path)?;
        let reference = self.read_ref_at(&ref_path)?;
        if origin.record.branch_name != *name || reference.record.branch_name != *name {
            return Err(branch_error(BranchErrorCode::RefNameCollision));
        }
        validate_origin_ref_binding(&origin, &reference)?;
        let origin_revision = self
            .transactions
            .verified_revision_with_maintenance(maintenance, origin.record.origin_transaction_id)?;
        verify_origin_target(&origin.record, &origin_revision)?;
        let revision = self.transactions.verified_revision_with_maintenance(
            maintenance,
            reference.record.head_transaction_id,
        )?;
        verify_ref_target(&reference.record, &revision)?;
        if reference.record.workspace_id != origin.record.workspace_id {
            return Err(branch_error(BranchErrorCode::BranchOriginMismatch));
        }
        Ok(ResolvedBranch {
            origin,
            reference,
            revision,
        })
    }

    fn list_branches_locked(
        &self,
        maintenance: &RepositoryMaintenanceGuard,
        limit: usize,
    ) -> Result<Vec<ResolvedBranch>, BranchError> {
        let paths = enumerate_record_paths(&self.refs_dir(), ".ref.scb1", MAX_BRANCHES, None)?;
        if paths.len() > limit {
            return Err(branch_error(BranchErrorCode::BranchResourceLimit));
        }
        let mut names = Vec::with_capacity(paths.len());
        for path in paths {
            names.push(self.read_ref_at(&path)?.record.branch_name);
        }
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(branch_error(BranchErrorCode::RefNameCollision));
        }
        names
            .iter()
            .map(|name| self.resolve_locked(maintenance, name))
            .collect()
    }

    fn read_branch_at(&self, path: &Path) -> Result<ImportedBranchRecord, BranchError> {
        let imported = import_branch_record(&bounded_read(path, MAX_STANDALONE_BYTES)?)?;
        if self.branch_path(&imported.record.branch_name) != path {
            return Err(branch_error(BranchErrorCode::RefNameCollision));
        }
        Ok(imported)
    }

    fn read_ref_at(&self, path: &Path) -> Result<ImportedBranchRef, BranchError> {
        let imported = import_branch_ref(&bounded_read(path, MAX_STANDALONE_BYTES)?)?;
        if self.ref_path(&imported.record.branch_name) != path {
            return Err(branch_error(BranchErrorCode::RefNameCollision));
        }
        Ok(imported)
    }

    fn prepare_operation(&self) -> Result<RepositoryMaintenanceGuard, BranchError> {
        self.prepare_operation_inner(None)
    }

    fn prepare_operation_inner(
        &self,
        directory_fault_path: Option<&Path>,
    ) -> Result<RepositoryMaintenanceGuard, BranchError> {
        let maintenance = self.transactions.acquire_shared_maintenance()?;
        self.ensure_layout_under_maintenance(directory_fault_path)?;
        Ok(maintenance)
    }

    #[cfg(test)]
    fn ensure_layout(&self) -> Result<(), BranchError> {
        let _maintenance = self.prepare_operation()?;
        Ok(())
    }

    fn ensure_layout_under_maintenance(
        &self,
        directory_fault_path: Option<&Path>,
    ) -> Result<(), BranchError> {
        ensure_existing_directory(&self.root)?;
        let branches =
            create_dir_component_with_fault(&self.root, "branches", directory_fault_path)?;
        create_dir_component_with_fault(&branches, "v1", directory_fault_path)?;
        let refs = create_dir_component_with_fault(&self.root, "refs", directory_fault_path)?;
        create_dir_component_with_fault(&refs, "v1", directory_fault_path)?;
        create_dir_component_with_fault(&self.root, "locks", directory_fault_path)?;
        Ok(())
    }

    fn acquire_refs_lock(&self) -> Result<File, BranchError> {
        let path = self.root.join("locks").join("refs.lock");
        reject_symlink_if_present(&path)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(branch_error(BranchErrorCode::RefIo));
        }
        file.lock()?;
        Ok(file)
    }

    #[cfg(test)]
    fn ensure_branch_path(&self, name: &BranchName) -> Result<PathBuf, BranchError> {
        ensure_key_path(&self.branches_dir(), name, ".branch.scb1")
    }

    #[cfg(test)]
    fn ensure_ref_path(&self, name: &BranchName) -> Result<PathBuf, BranchError> {
        ensure_key_path(&self.refs_dir(), name, ".ref.scb1")
    }

    fn checked_branch_path(&self, name: &BranchName) -> Result<PathBuf, BranchError> {
        checked_key_path(&self.branches_dir(), name, ".branch.scb1")
    }

    fn checked_ref_path(&self, name: &BranchName) -> Result<PathBuf, BranchError> {
        checked_key_path(&self.refs_dir(), name, ".ref.scb1")
    }

    fn branch_path(&self, name: &BranchName) -> PathBuf {
        key_path(&self.branches_dir(), name, ".branch.scb1")
    }

    fn ref_path(&self, name: &BranchName) -> PathBuf {
        key_path(&self.refs_dir(), name, ".ref.scb1")
    }

    fn branches_dir(&self) -> PathBuf {
        self.root.join("branches").join("v1")
    }

    fn refs_dir(&self) -> PathBuf {
        self.root.join("refs").join("v1")
    }
}

fn origin_record(name: &BranchName, revision: &VerifiedRevision) -> BranchRecord {
    BranchRecord {
        format_version: RECORD_VERSION,
        branch_name: name.clone(),
        workspace_id: revision.state_root().record.workspace_id,
        origin_transaction_id: revision.transaction_id(),
        origin_state_root: revision.state_root().root,
        schema_epoch_id: revision.state_root().record.schema_epoch_id,
        policy_root_id: revision.policy_root().root(),
        dependency_roots: revision.state_root().record.dependency_roots.clone(),
    }
}

fn ref_record(
    name: &BranchName,
    branch_record_digest: BranchRecordDigest,
    revision: &VerifiedRevision,
) -> BranchRefRecord {
    BranchRefRecord {
        format_version: RECORD_VERSION,
        branch_name: name.clone(),
        branch_record_digest,
        workspace_id: revision.state_root().record.workspace_id,
        head_transaction_id: revision.transaction_id(),
        head_state_root: revision.state_root().root,
        schema_epoch_id: revision.state_root().record.schema_epoch_id,
        policy_root_id: revision.policy_root().root(),
        dependency_roots: revision.state_root().record.dependency_roots.clone(),
    }
}

fn verify_origin_target(
    record: &BranchRecord,
    revision: &VerifiedRevision,
) -> Result<(), BranchError> {
    let expected = origin_record(&record.branch_name, revision);
    if *record == expected {
        Ok(())
    } else {
        Err(branch_error(BranchErrorCode::BranchOriginMismatch))
    }
}

fn verify_ref_target(
    record: &BranchRefRecord,
    revision: &VerifiedRevision,
) -> Result<(), BranchError> {
    let expected = ref_record(&record.branch_name, record.branch_record_digest, revision);
    if *record == expected {
        Ok(())
    } else {
        Err(branch_error(BranchErrorCode::RefTargetMismatch))
    }
}

fn validate_origin_ref_binding(
    origin: &ImportedBranchRecord,
    reference: &ImportedBranchRef,
) -> Result<(), BranchError> {
    if origin.record.branch_name != reference.record.branch_name
        || origin.digest != reference.record.branch_record_digest
    {
        return Err(branch_error(BranchErrorCode::RefBranchBindingMismatch));
    }
    Ok(())
}

fn walk_ancestry<F>(
    head: TransactionId,
    max_nodes: usize,
    mut load: F,
) -> Result<Vec<BranchAncestryEntry>, BranchError>
where
    F: FnMut(TransactionId) -> Result<BranchAncestryEntry, BranchError>,
{
    let mut active = BTreeSet::new();
    let mut completed = BTreeSet::new();
    let mut output = Vec::new();
    let mut stack = vec![(head, false)];
    while let Some((transaction_id, exiting)) = stack.pop() {
        if exiting {
            active.remove(&transaction_id);
            completed.insert(transaction_id);
            continue;
        }
        if completed.contains(&transaction_id) {
            continue;
        }
        if active.contains(&transaction_id) {
            return Err(branch_error(BranchErrorCode::BranchAncestryCycle));
        }
        if output.len() >= max_nodes {
            return Err(branch_error(BranchErrorCode::BranchResourceLimit));
        }
        let entry = load(transaction_id)?;
        if entry.transaction_id != transaction_id {
            return Err(branch_error(BranchErrorCode::RefInternalInvariant));
        }
        active.insert(transaction_id);
        stack.push((transaction_id, true));
        for parent in entry.parent_transaction_ids.iter().rev() {
            stack.push((*parent, false));
        }
        output.push(entry);
    }
    Ok(output)
}

type BuiltEnvelope = (Vec<u8>, [u8; DIGEST_LEN], Vec<u8>);
type DecodedEnvelope<'a> = (&'a [u8], Vec<u8>, [u8; DIGEST_LEN]);

fn build_envelope(
    magic: [u8; 8],
    domain: &[u8],
    payload: &[u8],
    limit_code: BranchErrorCode,
) -> Result<BuiltEnvelope, BranchError> {
    let mut preimage = Vec::with_capacity(magic.len() + payload.len() + 12);
    preimage.extend_from_slice(&magic);
    preimage.extend_from_slice(&encode_uvar(ENVELOPE_VERSION));
    preimage.extend_from_slice(&encode_uvar(
        u64::try_from(payload.len()).map_err(|_| branch_error(limit_code))?,
    ));
    preimage.extend_from_slice(payload);
    let digest = digest(domain, &preimage);
    let total = preimage
        .len()
        .checked_add(DIGEST_LEN)
        .ok_or_else(|| branch_error(limit_code))?;
    if total > MAX_STANDALONE_BYTES {
        return Err(branch_error(limit_code));
    }
    let mut stored = preimage.clone();
    stored.extend_from_slice(&digest);
    Ok((preimage, digest, stored))
}

fn decode_envelope<'a>(
    stored: &'a [u8],
    magic: [u8; 8],
    domain: &[u8],
    version_code: BranchErrorCode,
    digest_code: BranchErrorCode,
    shape_code: BranchErrorCode,
) -> Result<DecodedEnvelope<'a>, BranchError> {
    if stored.len() > MAX_STANDALONE_BYTES {
        return Err(branch_error(BranchErrorCode::BranchResourceLimit));
    }
    let mut cursor = ScbValueCursor::new(stored).map_err(|_| branch_error(shape_code))?;
    let actual_magic = cursor
        .read_fixed_bytes::<8>()
        .map_err(|_| branch_error(shape_code))?;
    if actual_magic != magic {
        return Err(branch_error(shape_code));
    }
    let version = cursor.read_uvar(64).map_err(|_| branch_error(shape_code))?;
    if version != ENVELOPE_VERSION {
        return Err(branch_error(version_code));
    }
    let payload = cursor
        .read_sized_payload()
        .map_err(|_| branch_error(shape_code))?;
    let preimage_end = cursor.position();
    let stored_digest = cursor
        .read_fixed_bytes::<DIGEST_LEN>()
        .map_err(|_| branch_error(shape_code))?;
    cursor
        .check_finished()
        .map_err(|_| branch_error(shape_code))?;
    let expected = digest(domain, &stored[..preimage_end]);
    if stored_digest != expected {
        return Err(branch_error(digest_code));
    }
    Ok((payload, stored[..preimage_end].to_vec(), stored_digest))
}

fn decode_required_record(
    input: &[u8],
    expected_count: u64,
    code: BranchErrorCode,
) -> Result<Vec<&[u8]>, BranchError> {
    let mut cursor = ScbValueCursor::new(input).map_err(|_| branch_error(code))?;
    let count = cursor
        .read_record_field_count()
        .map_err(|_| branch_error(code))?;
    if count != expected_count {
        return Err(branch_error(code));
    }
    let mut fields =
        Vec::with_capacity(usize::try_from(expected_count).map_err(|_| branch_error(code))?);
    for expected_tag in 1..=expected_count {
        let tag = cursor.read_uvar(32).map_err(|_| branch_error(code))?;
        if tag != expected_tag {
            return Err(branch_error(code));
        }
        fields.push(
            cursor
                .read_sized_payload()
                .map_err(|_| branch_error(code))?,
        );
    }
    cursor.check_finished().map_err(|_| branch_error(code))?;
    Ok(fields)
}

fn read_u32(input: &[u8], code: BranchErrorCode) -> Result<u32, BranchError> {
    let mut cursor = ScbValueCursor::new(input).map_err(|_| branch_error(code))?;
    let value = cursor.read_uvar(32).map_err(|_| branch_error(code))?;
    cursor.check_finished().map_err(|_| branch_error(code))?;
    u32::try_from(value).map_err(|_| branch_error(code))
}

fn read_fixed(input: &[u8], code: BranchErrorCode) -> Result<[u8; DIGEST_LEN], BranchError> {
    let mut cursor = ScbValueCursor::new(input).map_err(|_| branch_error(code))?;
    let value = cursor
        .read_fixed_bytes::<DIGEST_LEN>()
        .map_err(|_| branch_error(code))?;
    cursor.check_finished().map_err(|_| branch_error(code))?;
    Ok(value)
}

fn read_bytes(input: &[u8], code: BranchErrorCode) -> Result<&[u8], BranchError> {
    let mut cursor = ScbValueCursor::new(input).map_err(|_| branch_error(code))?;
    let value = cursor.read_bytes().map_err(|_| branch_error(code))?;
    cursor.check_finished().map_err(|_| branch_error(code))?;
    Ok(value)
}

fn encode_dependencies(values: &[StateRoot]) -> Result<Vec<u8>, BranchError> {
    if u64::try_from(values.len()).map_or(true, |count| count > MAX_COLLECTION_ELEMENTS) {
        return Err(branch_error(BranchErrorCode::BranchResourceLimit));
    }
    encode_list(
        &values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>(),
    )
    .map_err(|_| branch_error(BranchErrorCode::BranchResourceLimit))
}

fn decode_dependencies(input: &[u8], code: BranchErrorCode) -> Result<Vec<StateRoot>, BranchError> {
    let mut cursor = ScbValueCursor::new(input).map_err(|_| branch_error(code))?;
    let count = cursor.read_list_count().map_err(|error| {
        if error.code() == ScbErrorCode::ResourceLimit {
            branch_error(BranchErrorCode::BranchResourceLimit)
        } else {
            branch_error(code)
        }
    })?;
    let count =
        usize::try_from(count).map_err(|_| branch_error(BranchErrorCode::BranchResourceLimit))?;
    let minimum_remaining = count
        .checked_mul(DIGEST_LEN + 1)
        .ok_or_else(|| branch_error(BranchErrorCode::BranchResourceLimit))?;
    if minimum_remaining > input.len().saturating_sub(cursor.position()) {
        return Err(branch_error(code));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let payload = cursor
            .read_sized_payload()
            .map_err(|_| branch_error(code))?;
        values.push(StateRoot::from_bytes(read_fixed(payload, code)?));
    }
    cursor.check_finished().map_err(|_| branch_error(code))?;
    validate_dependencies(&values, code)?;
    Ok(values)
}

fn validate_dependencies(values: &[StateRoot], code: BranchErrorCode) -> Result<(), BranchError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(branch_error(code));
    }
    Ok(())
}

fn digest(domain: &[u8], preimage: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(preimage);
    *hasher.finalize().as_bytes()
}

fn hex_digest(bytes: &[u8; DIGEST_LEN]) -> String {
    use fmt::Write as _;
    let mut output = String::with_capacity(DIGEST_LEN * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_branch_limit(limit: usize) -> Result<(), BranchError> {
    if limit == 0 || limit > MAX_BRANCHES {
        Err(branch_error(BranchErrorCode::BranchResourceLimit))
    } else {
        Ok(())
    }
}

fn validate_visible_capacity(current: usize) -> Result<(), BranchError> {
    if current >= MAX_BRANCHES {
        Err(branch_error(BranchErrorCode::BranchResourceLimit))
    } else {
        Ok(())
    }
}

fn validate_origin_capacity(current: usize, maximum: usize) -> Result<(), BranchError> {
    if current >= maximum {
        Err(branch_error(BranchErrorCode::BranchResourceLimit))
    } else {
        Ok(())
    }
}

fn validate_ancestry_limit(limit: usize) -> Result<(), BranchError> {
    if limit == 0 || limit > MAX_ANCESTRY_NODES {
        Err(branch_error(BranchErrorCode::BranchResourceLimit))
    } else {
        Ok(())
    }
}

fn key_path(root: &Path, name: &BranchName, suffix: &str) -> PathBuf {
    let hex = hex_digest(&name.path_key());
    root.join(&hex[0..2])
        .join(&hex[2..4])
        .join(format!("{hex}{suffix}"))
}

#[cfg(test)]
fn ensure_key_path(root: &Path, name: &BranchName, suffix: &str) -> Result<PathBuf, BranchError> {
    ensure_key_path_with_fault(root, name, suffix, None)
}

fn ensure_key_path_with_fault(
    root: &Path,
    name: &BranchName,
    suffix: &str,
    directory_fault_path: Option<&Path>,
) -> Result<PathBuf, BranchError> {
    let hex = hex_digest(&name.path_key());
    let first = create_dir_component_with_fault(root, &hex[0..2], directory_fault_path)?;
    let second = create_dir_component_with_fault(&first, &hex[2..4], directory_fault_path)?;
    Ok(second.join(format!("{hex}{suffix}")))
}

fn checked_key_path(root: &Path, name: &BranchName, suffix: &str) -> Result<PathBuf, BranchError> {
    let hex = hex_digest(&name.path_key());
    let final_path = root
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(format!("{hex}{suffix}"));
    ensure_existing_directory(root)?;
    let mut current = root.to_path_buf();
    for component in [&hex[0..2], &hex[2..4]] {
        let next = current.join(component);
        match fs::symlink_metadata(&next) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(branch_error(BranchErrorCode::RefIo));
            }
            Ok(_) => current = next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(final_path)
}

fn enumerate_record_paths(
    root: &Path,
    suffix: &str,
    maximum: usize,
    allowed_stage_prefix: Option<&str>,
) -> Result<Vec<PathBuf>, BranchError> {
    ensure_existing_directory(root)?;
    let mut paths = Vec::new();
    for first in fs::read_dir(root)? {
        let first = first?;
        let first_type = first.file_type()?;
        let first_name = exact_utf8_name(&first)?;
        if !first_type.is_dir() || !is_fanout_component(&first_name) {
            return Err(branch_error(BranchErrorCode::RefIo));
        }
        ensure_existing_directory(&first.path())?;
        for second in fs::read_dir(first.path())? {
            let second = second?;
            let second_type = second.file_type()?;
            let second_name = exact_utf8_name(&second)?;
            if !second_type.is_dir() || !is_fanout_component(&second_name) {
                return Err(branch_error(BranchErrorCode::RefIo));
            }
            ensure_existing_directory(&second.path())?;
            for record in fs::read_dir(second.path())? {
                let record = record?;
                if !record.file_type()?.is_file() {
                    return Err(branch_error(BranchErrorCode::RefIo));
                }
                let filename = exact_utf8_name(&record)?;
                if allowed_stage_prefix.is_some_and(|prefix| is_owned_stage_name(&filename, prefix))
                {
                    continue;
                }
                let Some(hex) = filename.strip_suffix(suffix) else {
                    return Err(branch_error(BranchErrorCode::RefIo));
                };
                if hex.len() != DIGEST_LEN * 2
                    || !hex.as_bytes().iter().all(u8::is_ascii_hexdigit)
                    || hex.as_bytes().iter().any(u8::is_ascii_uppercase)
                    || hex[0..2] != first_name
                    || hex[2..4] != second_name
                {
                    return Err(branch_error(BranchErrorCode::RefIo));
                }
                paths.push(record.path());
                if paths.len() > maximum {
                    return Err(branch_error(BranchErrorCode::BranchResourceLimit));
                }
            }
        }
    }
    paths.sort();
    Ok(paths)
}

fn exact_utf8_name(entry: &fs::DirEntry) -> Result<String, BranchError> {
    entry
        .file_name()
        .into_string()
        .map_err(|_| branch_error(BranchErrorCode::RefIo))
}

fn is_fanout_component(value: &str) -> bool {
    value.len() == 2
        && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && !value.as_bytes().iter().any(u8::is_ascii_uppercase)
}

fn ensure_existing_directory(path: &Path) -> Result<(), BranchError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(branch_error(BranchErrorCode::RefIo));
    }
    Ok(())
}

fn create_dir_component_with_fault(
    parent: &Path,
    component: &str,
    directory_fault_path: Option<&Path>,
) -> Result<PathBuf, BranchError> {
    let path = parent.join(component);
    create_dir_component_inner(
        parent,
        component,
        directory_fault_path.is_some_and(|fault_path| fault_path == path),
    )
}

fn create_dir_component_inner(
    parent: &Path,
    component: &str,
    fail_before_parent_sync: bool,
) -> Result<PathBuf, BranchError> {
    ensure_existing_directory(parent)?;
    let path = parent.join(component);
    match fs::create_dir(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    ensure_existing_directory(&path)?;
    if fail_before_parent_sync {
        return Err(io::Error::other("injected before-parent-sync failure").into());
    }
    sync_dir(parent)?;
    Ok(path)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), BranchError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(branch_error(BranchErrorCode::RefIo))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn path_exists(path: &Path) -> Result<bool, BranchError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(branch_error(BranchErrorCode::RefIo))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn bounded_read(path: &Path, maximum: usize) -> Result<Vec<u8>, BranchError> {
    reject_symlink_if_present(path)?;
    let file = File::open(path)?;
    let length = usize::try_from(file.metadata()?.len())
        .map_err(|_| branch_error(BranchErrorCode::BranchResourceLimit))?;
    if length > maximum {
        return Err(branch_error(BranchErrorCode::BranchResourceLimit));
    }
    let mut bytes = Vec::with_capacity(length);
    file.take(u64::try_from(maximum.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(branch_error(BranchErrorCode::BranchResourceLimit));
    }
    Ok(bytes)
}

fn reserve_stage(dir: &Path, prefix: &str) -> Result<(PathBuf, File), BranchError> {
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
    Err(branch_error(BranchErrorCode::RefIo))
}

fn persist_no_overwrite<F>(
    final_path: &Path,
    bytes: &[u8],
    stage_prefix: &str,
    collision_code: BranchErrorCode,
    verify: F,
) -> Result<(), BranchError>
where
    F: Fn(&[u8]) -> Result<(), BranchError>,
{
    persist_no_overwrite_inner(
        final_path,
        bytes,
        stage_prefix,
        collision_code,
        verify,
        false,
    )
}

fn persist_expected_ref(path: &Path, expected: &ImportedBranchRef) -> Result<(), BranchError> {
    persist_no_overwrite(
        path,
        &expected.stored_bytes,
        REF_STAGE_PREFIX,
        BranchErrorCode::RefAlreadyExists,
        |bytes| {
            if import_branch_ref(bytes)? == *expected {
                Ok(())
            } else {
                Err(branch_error(BranchErrorCode::RefAlreadyExists))
            }
        },
    )
}

fn persist_no_overwrite_inner<F>(
    final_path: &Path,
    bytes: &[u8],
    stage_prefix: &str,
    collision_code: BranchErrorCode,
    verify: F,
    fail_after_link_before_sync: bool,
) -> Result<(), BranchError>
where
    F: Fn(&[u8]) -> Result<(), BranchError>,
{
    let final_dir = final_path
        .parent()
        .ok_or_else(|| branch_error(BranchErrorCode::RefIo))?;
    let (stage_path, mut stage) = reserve_stage(final_dir, stage_prefix)?;
    stage.write_all(bytes)?;
    stage.flush()?;
    stage.sync_all()?;
    drop(stage);
    verify(&bounded_read(&stage_path, MAX_STANDALONE_BYTES)?)?;
    match fs::hard_link(&stage_path, final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let existing = bounded_read(final_path, MAX_STANDALONE_BYTES)?;
            if existing != bytes {
                return Err(branch_error(collision_code));
            }
            verify(&existing)?;
            File::open(final_path)?.sync_all()?;
            remove_file_if_exists(&stage_path)?;
            sync_dir(final_dir)?;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    }
    if fail_after_link_before_sync {
        return Err(io::Error::other("injected after-link-before-sync failure").into());
    }
    sync_dir(final_dir)?;
    remove_file_if_exists(&stage_path)?;
    sync_dir(final_dir)?;
    let final_bytes = bounded_read(final_path, MAX_STANDALONE_BYTES)?;
    if final_bytes != bytes {
        return Err(branch_error(collision_code));
    }
    verify(&final_bytes)
}

fn redurabilize_branch(path: &Path, expected: &ImportedBranchRecord) -> Result<(), BranchError> {
    redurabilize_record(path, &expected.stored_bytes, |bytes| {
        if import_branch_record(bytes)? == *expected {
            Ok(())
        } else {
            Err(branch_error(BranchErrorCode::BranchOriginMismatch))
        }
    })
}

fn redurabilize_ref(path: &Path, expected: &ImportedBranchRef) -> Result<(), BranchError> {
    redurabilize_record(path, &expected.stored_bytes, |bytes| {
        if import_branch_ref(bytes)? == *expected {
            Ok(())
        } else {
            Err(branch_error(BranchErrorCode::RefTargetMismatch))
        }
    })
}

fn redurabilize_record<F>(path: &Path, expected: &[u8], verify: F) -> Result<(), BranchError>
where
    F: Fn(&[u8]) -> Result<(), BranchError>,
{
    let first = bounded_read(path, MAX_STANDALONE_BYTES)?;
    if first != expected {
        return Err(branch_error(BranchErrorCode::RefInternalInvariant));
    }
    verify(&first)?;
    File::open(path)?.sync_all()?;
    sync_dir(
        path.parent()
            .ok_or_else(|| branch_error(BranchErrorCode::RefIo))?,
    )?;
    let second = bounded_read(path, MAX_STANDALONE_BYTES)?;
    if second != expected {
        return Err(branch_error(BranchErrorCode::RefInternalInvariant));
    }
    verify(&second)
}

fn replace_ref(path: &Path, expected: &ImportedBranchRef) -> Result<(), BranchError> {
    replace_ref_inner(path, expected, false)
}

fn replace_ref_inner(
    path: &Path,
    expected: &ImportedBranchRef,
    fail_after_rename_before_sync: bool,
) -> Result<(), BranchError> {
    reject_symlink_if_present(path)?;
    let directory = path
        .parent()
        .ok_or_else(|| branch_error(BranchErrorCode::RefIo))?;
    let (stage_path, mut stage) = reserve_stage(directory, REF_STAGE_PREFIX)?;
    stage.write_all(&expected.stored_bytes)?;
    stage.flush()?;
    stage.sync_all()?;
    drop(stage);
    if import_branch_ref(&bounded_read(&stage_path, MAX_STANDALONE_BYTES)?)? != *expected {
        return Err(branch_error(BranchErrorCode::RefInternalInvariant));
    }
    reject_symlink_if_present(path)?;
    fs::rename(&stage_path, path)?;
    if fail_after_rename_before_sync {
        return Err(io::Error::other("injected after-rename-before-sync failure").into());
    }
    sync_dir(directory)?;
    if import_branch_ref(&bounded_read(path, MAX_STANDALONE_BYTES)?)? != *expected {
        return Err(branch_error(BranchErrorCode::RefInternalInvariant));
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), BranchError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), BranchError> {
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
) -> Result<u64, BranchError> {
    let mut fail_next_leaf_sync = false;
    remove_stages_recursive_inner(root, prefix, remaining_depth, &mut fail_next_leaf_sync)
}

fn remove_stages_recursive_inner(
    root: &Path,
    prefix: &str,
    remaining_depth: usize,
    fail_next_leaf_sync: &mut bool,
) -> Result<u64, BranchError> {
    validate_recovery_tree(root, remaining_depth)?;
    remove_stages_from_validated_tree(root, prefix, remaining_depth, fail_next_leaf_sync)
}

fn validate_recovery_tree(root: &Path, remaining_depth: usize) -> Result<(), BranchError> {
    ensure_existing_directory(root)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if remaining_depth > 0 {
            let name = exact_utf8_name(&entry)?;
            if !file_type.is_dir() || !is_fanout_component(&name) {
                return Err(branch_error(BranchErrorCode::RefIo));
            }
            validate_recovery_tree(&entry.path(), remaining_depth - 1)?;
        } else if !file_type.is_file() {
            return Err(branch_error(BranchErrorCode::RefIo));
        }
    }
    Ok(())
}

fn remove_stages_from_validated_tree(
    root: &Path,
    prefix: &str,
    remaining_depth: usize,
    fail_next_leaf_sync: &mut bool,
) -> Result<u64, BranchError> {
    let mut removed = 0_u64;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() && remaining_depth > 0 {
            removed = removed
                .checked_add(remove_stages_from_validated_tree(
                    &path,
                    prefix,
                    remaining_depth - 1,
                    fail_next_leaf_sync,
                )?)
                .ok_or_else(|| branch_error(BranchErrorCode::BranchResourceLimit))?;
        } else if file_type.is_file() && remaining_depth == 0 {
            let name = exact_utf8_name(&entry)?;
            if is_owned_stage_name(&name, prefix) {
                fs::remove_file(&path)?;
                removed = removed
                    .checked_add(1)
                    .ok_or_else(|| branch_error(BranchErrorCode::BranchResourceLimit))?;
            }
        }
    }
    if remaining_depth == 0 || removed > 0 {
        if remaining_depth == 0 && *fail_next_leaf_sync {
            *fail_next_leaf_sync = false;
            return Err(io::Error::other("injected recovery directory sync failure").into());
        }
        sync_dir(root)?;
    }
    Ok(removed)
}

fn is_owned_stage_name(name: &str, prefix: &str) -> bool {
    let Some(body) = name
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(STAGE_SUFFIX))
    else {
        return false;
    };
    let Some((pid, token)) = body.split_once('-') else {
        return false;
    };
    let Ok(pid_value) = pid.parse::<u32>() else {
        return false;
    };
    pid_value > 0
        && pid_value.to_string() == pid
        && token.len() == 16
        && token.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && !token.as_bytes().iter().any(u8::is_ascii_uppercase)
}

fn usize_to_u64(value: usize) -> Result<u64, BranchError> {
    u64::try_from(value).map_err(|_| branch_error(BranchErrorCode::BranchResourceLimit))
}

fn branch_error(code: BranchErrorCode) -> BranchError {
    BranchError::Branch(code)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    use sley_id::{CandidateNonce, EntityId, ObjectId, PrincipalId, ReceiptId};
    use sley_mutate::{
        BoundPrecondition, CandidateExpiry, CandidateRecord, EntityObjectRecord,
        ExpectedIdentityAbsent, ImportedCandidate, MutationClass, MutationOperation,
        MutationPayload, PreconditionPayload, PreimageRequirement, build_candidate,
        build_entity_object, full_validation_profile_id,
        value::{EntityBodyValue, EntityIdSet, NamespaceBody},
    };
    use sley_policy::{
        AcceptedPolicyRoot, CandidateValidationLimits, PolicyResourceCeilings, PolicyRootBuilder,
        PrincipalGrantBuilder, build_capability_summary_projection,
        conformance_registry as policy_registry,
    };
    use sley_state_root::{
        AcceptedStateRoot, StateRootBuilder, conformance_epoch_id as state_epoch_id,
        conformance_registry as state_registry,
    };
    use sley_store::ObjectStore;
    use sley_txn::{
        CommitInput, TrustedGenesisInput, build_transaction, build_transaction_receipt,
    };

    use crate::acquire_exclusive_gc;

    use super::*;

    const NOW: u64 = 1_000;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let sequence = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sley-refs-{label}-{}-{sequence:016x}",
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
        transactions: TransactionRepository,
        branches: BranchRepository,
        principal_id: PrincipalId,
        genesis_transaction_id: TransactionId,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            Self::new_with_workspace(label, 1)
        }

        fn new_with_workspace(label: &str, workspace_byte: u8) -> Self {
            let temp = TempDir::new(label);
            let transactions = TransactionRepository::new(&temp.path);
            let branches = BranchRepository::new(&temp.path);
            let workspace_id = fixed(workspace_byte, WorkspaceId::from_bytes);
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
            let genesis = transactions
                .initialize_trusted_genesis(TrustedGenesisInput::new(
                    &base_state,
                    &policy,
                    core::slice::from_ref(&base_object),
                    &[],
                ))
                .unwrap();
            Self {
                temp,
                transactions,
                branches,
                principal_id,
                genesis_transaction_id: genesis.transaction_id(),
            }
        }

        fn commit_child(&self, nonce_byte: u8) -> TransactionId {
            let head = self.transactions.accepted_head().unwrap();
            let candidate = candidate_for(
                head.state_root().record.workspace_id,
                self.principal_id,
                head.transaction_id(),
                head.state_root(),
                head.policy_root(),
                nonce_byte,
            );
            self.transactions
                .commit(CommitInput::new(
                    head.transaction_id(),
                    &candidate.stored_bytes,
                    self.principal_id,
                    &[],
                    NOW,
                    CandidateValidationLimits::full_v1(),
                ))
                .unwrap()
                .transaction_id()
        }
    }

    fn fixed<T>(byte: u8, constructor: impl FnOnce([u8; 32]) -> T) -> T {
        constructor([byte; 32])
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let destination_path = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &destination_path);
            } else {
                fs::copy(entry.path(), destination_path).unwrap();
            }
        }
    }

    fn import_fixture_revisions(source: &Fixture, destination: &Fixture) {
        for relative in [Path::new("transactions/v1"), Path::new("objects/scb1")] {
            copy_tree(
                &source.temp.path.join(relative),
                &destination.temp.path.join(relative),
            );
        }
    }

    fn transaction_receipt_path(root: &Path, transaction_id: TransactionId) -> PathBuf {
        let hex = hex_digest(transaction_id.as_bytes());
        root.join("transactions")
            .join("v1")
            .join(&hex[0..2])
            .join(&hex[2..4])
            .join(format!("{hex}.receipt.scb1"))
    }

    fn corrupt_nested_receipt(
        receipt: &sley_txn::ImportedTransactionReceipt,
        nested: &[u8],
    ) -> Vec<u8> {
        let mut bytes = receipt.stored_bytes.clone();
        let offset = bytes
            .windows(nested.len())
            .position(|window| window == nested)
            .unwrap();
        bytes[offset + nested.len() - 1] ^= 1;
        let preimage_len = bytes.len() - DIGEST_LEN;
        let digest = ReceiptId::derive(&bytes[..preimage_len]);
        bytes[preimage_len..].copy_from_slice(digest.as_bytes());
        bytes
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

    fn synthetic_origin(name: &str) -> BranchRecord {
        BranchRecord {
            format_version: RECORD_VERSION,
            branch_name: BranchName::parse(name).unwrap(),
            workspace_id: fixed(1, WorkspaceId::from_bytes),
            origin_transaction_id: fixed(2, TransactionId::from_bytes),
            origin_state_root: fixed(3, StateRoot::from_bytes),
            schema_epoch_id: fixed(4, SchemaEpochId::from_bytes),
            policy_root_id: fixed(5, PolicyRootId::from_bytes),
            dependency_roots: vec![
                fixed(6, StateRoot::from_bytes),
                fixed(7, StateRoot::from_bytes),
            ],
        }
    }

    fn synthetic_ref(origin: &ImportedBranchRecord) -> BranchRefRecord {
        BranchRefRecord {
            format_version: RECORD_VERSION,
            branch_name: origin.record.branch_name.clone(),
            branch_record_digest: origin.digest,
            workspace_id: origin.record.workspace_id,
            head_transaction_id: origin.record.origin_transaction_id,
            head_state_root: origin.record.origin_state_root,
            schema_epoch_id: origin.record.schema_epoch_id,
            policy_root_id: origin.record.policy_root_id,
            dependency_roots: origin.record.dependency_roots.clone(),
        }
    }

    fn rehash(stored: &mut [u8], domain: &[u8]) {
        let preimage_len = stored.len() - DIGEST_LEN;
        let replacement = digest(domain, &stored[..preimage_len]);
        stored[preimage_len..].copy_from_slice(&replacement);
    }

    fn payload_offset(stored: &[u8]) -> usize {
        let mut cursor = ScbValueCursor::new(stored).unwrap();
        cursor.read_fixed_bytes::<8>().unwrap();
        cursor.read_uvar(64).unwrap();
        let payload = cursor.read_sized_payload().unwrap();
        payload.as_ptr() as usize - stored.as_ptr() as usize
    }

    #[test]
    fn error_codes_and_update_statuses_are_closed_and_contiguous() {
        let expected_symbols = [
            "REF_FORMAT_VERSION",
            "REF_NAME_INVALID",
            "REF_NAME_RESERVED",
            "REF_DIGEST_MISMATCH",
            "REF_FIELD_SHAPE",
            "REF_BRANCH_BINDING_MISMATCH",
            "REF_NOT_FOUND",
            "REF_ALREADY_EXISTS",
            "REF_NAME_COLLISION",
            "REF_TARGET_MISMATCH",
            "REF_NAMED_CAS_STALE",
            "BRANCH_RECORD_FORMAT_VERSION",
            "BRANCH_RECORD_DIGEST_MISMATCH",
            "BRANCH_RECORD_FIELD_SHAPE",
            "BRANCH_ORIGIN_MISMATCH",
            "BRANCH_NOT_FAST_FORWARD",
            "BRANCH_ANCESTRY_CYCLE",
            "BRANCH_RESOURCE_LIMIT",
            "RECOVERY_NAMED_REF_INCOMPLETE",
            "REF_IO",
            "REF_INTERNAL_INVARIANT",
        ];
        for (offset, (code, symbol)) in BranchErrorCode::ALL
            .into_iter()
            .zip(expected_symbols)
            .enumerate()
        {
            assert_eq!(code.numeric(), 50_000 + u32::try_from(offset).unwrap());
            assert_eq!(code.symbol(), symbol);
        }
        for (tag, status, symbol) in [
            (1, BranchUpdateStatus::Created, "CREATED"),
            (2, BranchUpdateStatus::Advanced, "ADVANCED"),
            (3, BranchUpdateStatus::Present, "PRESENT"),
        ] {
            assert_eq!(BranchUpdateStatus::from_tag(tag), Some(status));
            assert_eq!(status.tag(), tag);
            assert_eq!(status.symbol(), symbol);
        }
        assert_eq!(BranchUpdateStatus::from_tag(0), None);
        assert_eq!(BranchUpdateStatus::from_tag(4), None);
        assert!(validate_visible_capacity(MAX_BRANCHES - 1).is_ok());
        assert_eq!(
            validate_visible_capacity(MAX_BRANCHES).unwrap_err().code(),
            "BRANCH_RESOURCE_LIMIT"
        );
        assert!(validate_origin_capacity(MAX_BRANCH_ORIGINS - 1, MAX_BRANCH_ORIGINS).is_ok());
        assert_eq!(
            validate_origin_capacity(MAX_BRANCH_ORIGINS, MAX_BRANCH_ORIGINS)
                .unwrap_err()
                .code(),
            "BRANCH_RESOURCE_LIMIT"
        );
    }

    #[test]
    fn branch_name_grammar_is_exact_and_non_normalizing() {
        let component = format!("a{}z", "x".repeat(61));
        let maximum = [component.as_str(); 4].join("/");
        assert_eq!(maximum.len(), MAX_BRANCH_NAME_BYTES);
        for valid in [
            b"a".as_slice(),
            b"a1".as_slice(),
            b"feature/x-1".as_slice(),
            b"release/2.0_alpha".as_slice(),
            maximum.as_bytes(),
        ] {
            let parsed = BranchName::parse(valid).unwrap();
            assert_eq!(parsed.as_bytes(), valid);
        }
        let invalid = [
            Vec::new(),
            b"Main".to_vec(),
            "café".as_bytes().to_vec(),
            b"/a".to_vec(),
            b"a/".to_vec(),
            b"a//b".to_vec(),
            b".".to_vec(),
            b"..".to_vec(),
            b"a\\b".to_vec(),
            b"a:b".to_vec(),
            b"a.lock".to_vec(),
            b"-a".to_vec(),
            b"a_".to_vec(),
            format!("a{}z", "x".repeat(62)).into_bytes(),
            b"a/a/a/a/a/a/a/a/a".to_vec(),
            vec![b'a'; MAX_BRANCH_NAME_BYTES + 1],
        ];
        for name in invalid {
            assert_eq!(
                BranchName::parse(name).unwrap_err().code(),
                "REF_NAME_INVALID"
            );
        }
        for reserved in [b"refs".as_slice(), b"ok/transactions".as_slice()] {
            assert_eq!(
                BranchName::parse(reserved).unwrap_err().code(),
                "REF_NAME_RESERVED"
            );
        }
        for reserved in RESERVED_COMPONENTS {
            assert_eq!(
                BranchName::parse(reserved).unwrap_err().code(),
                "REF_NAME_RESERVED"
            );
            let nested = [b"ok/".as_slice(), *reserved, b"/x".as_slice()].concat();
            assert_eq!(
                BranchName::parse(nested).unwrap_err().code(),
                "REF_NAME_RESERVED"
            );
        }
        for byte in 0_u8..=u8::MAX {
            let candidate = [b'a', byte, b'b'];
            let admitted = byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/');
            assert_eq!(
                BranchName::parse(candidate).is_ok(),
                admitted,
                "unexpected byte classification for 0x{byte:02x}"
            );
        }
        assert!(BranchName::parse("a/a/a/a/a/a/a/a").is_ok());
        assert!(BranchName::parse([b'a'; MAX_BRANCH_COMPONENT_BYTES]).is_ok());
        assert_ne!(
            BranchName::parse("feature/a").unwrap().path_key(),
            BranchName::parse("feature/b").unwrap().path_key()
        );
        assert_eq!(
            BranchName::parse("feature/a").unwrap().path_key(),
            BranchName::parse("feature/a").unwrap().path_key()
        );
        assert_eq!(
            hex_digest(&BranchName::parse("feature/a").unwrap().path_key()),
            "c43b584a5dadee3c14d8d4c37751bf66f06324d4b54380ebbe68474d31c8dcdd"
        );
    }

    #[test]
    fn branch_and_ref_codecs_round_trip_and_reject_rehashed_shape_changes() {
        let origin_record = synthetic_origin("feature/a");
        let origin = build_branch_record(&origin_record).unwrap();
        assert_eq!(import_branch_record(&origin.stored_bytes).unwrap(), origin);
        let reference = build_branch_ref(&synthetic_ref(&origin)).unwrap();
        assert_eq!(
            import_branch_ref(&reference.stored_bytes).unwrap(),
            reference
        );

        let mut corrupt_origin = origin.stored_bytes.clone();
        *corrupt_origin.last_mut().unwrap() ^= 1;
        assert_eq!(
            import_branch_record(&corrupt_origin).unwrap_err().code(),
            "BRANCH_RECORD_DIGEST_MISMATCH"
        );
        let mut corrupt_ref = reference.stored_bytes.clone();
        *corrupt_ref.last_mut().unwrap() ^= 1;
        assert_eq!(
            import_branch_ref(&corrupt_ref).unwrap_err().code(),
            "REF_DIGEST_MISMATCH"
        );

        let mut bad_origin_version = origin.stored_bytes.clone();
        let origin_payload = payload_offset(&bad_origin_version);
        bad_origin_version[origin_payload + 3] = 2;
        rehash(&mut bad_origin_version, BRANCH_DIGEST_DOMAIN);
        assert_eq!(
            import_branch_record(&bad_origin_version)
                .unwrap_err()
                .code(),
            "BRANCH_RECORD_FORMAT_VERSION"
        );
        let mut bad_ref_shape = reference.stored_bytes.clone();
        let ref_payload = payload_offset(&bad_ref_shape);
        bad_ref_shape[ref_payload] = 8;
        rehash(&mut bad_ref_shape, REF_DIGEST_DOMAIN);
        assert_eq!(
            import_branch_ref(&bad_ref_shape).unwrap_err().code(),
            "REF_FIELD_SHAPE"
        );

        let mut unsorted = origin_record;
        unsorted.dependency_roots.reverse();
        assert_eq!(
            build_branch_record(&unsorted).unwrap_err().code(),
            "BRANCH_RECORD_FIELD_SHAPE"
        );
    }

    #[test]
    fn dependency_codec_uses_the_scb1_collection_ceiling_not_ancestry_limit() {
        let dependency_roots = (0_u32..65_537)
            .map(|ordinal| {
                let mut bytes = [0_u8; DIGEST_LEN];
                bytes[..4].copy_from_slice(&ordinal.to_be_bytes());
                StateRoot::from_bytes(bytes)
            })
            .collect::<Vec<_>>();
        let mut record = synthetic_origin("codec/large");
        record.dependency_roots = dependency_roots;
        let origin = build_branch_record(&record).unwrap();
        assert_eq!(import_branch_record(&origin.stored_bytes).unwrap(), origin);
        let reference = build_branch_ref(&synthetic_ref(&origin)).unwrap();
        assert_eq!(
            import_branch_ref(&reference.stored_bytes).unwrap(),
            reference
        );

        let impossible_count = encode_uvar(MAX_COLLECTION_ELEMENTS + 1);
        assert_eq!(
            decode_dependencies(&impossible_count, BranchErrorCode::BranchRecordFieldShape,)
                .unwrap_err()
                .code(),
            "BRANCH_RESOURCE_LIMIT"
        );
    }

    #[test]
    fn every_branch_and_ref_semantic_field_perturbation_changes_its_digest() {
        let base_origin_record = synthetic_origin("feature/a");
        let base_origin = build_branch_record(&base_origin_record).unwrap();
        let mut origin_variants = Vec::new();
        let mut variant = base_origin_record.clone();
        variant.branch_name = BranchName::parse("feature/b").unwrap();
        origin_variants.push(variant);
        let mut variant = base_origin_record.clone();
        variant.workspace_id = fixed(11, WorkspaceId::from_bytes);
        origin_variants.push(variant);
        let mut variant = base_origin_record.clone();
        variant.origin_transaction_id = fixed(12, TransactionId::from_bytes);
        origin_variants.push(variant);
        let mut variant = base_origin_record.clone();
        variant.origin_state_root = fixed(13, StateRoot::from_bytes);
        origin_variants.push(variant);
        let mut variant = base_origin_record.clone();
        variant.schema_epoch_id = fixed(14, SchemaEpochId::from_bytes);
        origin_variants.push(variant);
        let mut variant = base_origin_record.clone();
        variant.policy_root_id = fixed(15, PolicyRootId::from_bytes);
        origin_variants.push(variant);
        let mut variant = base_origin_record.clone();
        variant
            .dependency_roots
            .push(fixed(8, StateRoot::from_bytes));
        origin_variants.push(variant);
        for variant in origin_variants {
            let imported = build_branch_record(&variant).unwrap();
            assert_ne!(imported.digest, base_origin.digest);
            assert_eq!(
                import_branch_record(&imported.stored_bytes).unwrap(),
                imported
            );
        }

        let base_ref_record = synthetic_ref(&base_origin);
        let base_ref = build_branch_ref(&base_ref_record).unwrap();
        let mut ref_variants = Vec::new();
        let mut variant = base_ref_record.clone();
        variant.branch_name = BranchName::parse("feature/b").unwrap();
        ref_variants.push(variant);
        let mut variant = base_ref_record.clone();
        variant.branch_record_digest = BranchRecordDigest::from_bytes([16; DIGEST_LEN]);
        ref_variants.push(variant);
        let mut variant = base_ref_record.clone();
        variant.workspace_id = fixed(17, WorkspaceId::from_bytes);
        ref_variants.push(variant);
        let mut variant = base_ref_record.clone();
        variant.head_transaction_id = fixed(18, TransactionId::from_bytes);
        ref_variants.push(variant);
        let mut variant = base_ref_record.clone();
        variant.head_state_root = fixed(19, StateRoot::from_bytes);
        ref_variants.push(variant);
        let mut variant = base_ref_record.clone();
        variant.schema_epoch_id = fixed(20, SchemaEpochId::from_bytes);
        ref_variants.push(variant);
        let mut variant = base_ref_record.clone();
        variant.policy_root_id = fixed(21, PolicyRootId::from_bytes);
        ref_variants.push(variant);
        let mut variant = base_ref_record;
        variant
            .dependency_roots
            .push(fixed(8, StateRoot::from_bytes));
        ref_variants.push(variant);
        for variant in ref_variants {
            let imported = build_branch_ref(&variant).unwrap();
            assert_ne!(imported.digest, base_ref.digest);
            assert_eq!(import_branch_ref(&imported.stored_bytes).unwrap(), imported);
        }
    }

    #[test]
    fn create_resolve_list_and_exact_retry_are_durable() {
        let fixture = Fixture::new("create-resolve");
        assert_eq!(
            fixture
                .branches
                .create_branch("feature/a", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Created
        );
        assert_eq!(
            fixture
                .branches
                .create_branch("feature/a", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Present
        );
        let resolved = fixture.branches.resolve_branch("feature/a").unwrap();
        assert_eq!(
            resolved.reference.record.head_transaction_id,
            fixture.genesis_transaction_id
        );
        assert_eq!(resolved.origin.record.branch_name.as_str(), "feature/a");
        let listed = fixture.branches.list_branches(1).unwrap();
        assert_eq!(listed, vec![resolved]);
        assert_eq!(
            fixture.branches.list_branches(0).unwrap_err().code(),
            "BRANCH_RESOURCE_LIMIT"
        );
        let path = fixture
            .branches
            .branch_path(&BranchName::parse("feature/a").unwrap());
        assert!(!path.to_string_lossy().contains("feature"));
        assert_eq!(
            path.extension().and_then(|value| value.to_str()),
            Some("scb1")
        );
    }

    #[test]
    fn directory_creation_retry_redurabilizes_layout_and_fanout_before_branch_success() {
        let fixture = Fixture::new("directory-retry-durability");
        let layout_name = BranchName::parse("layout-retry").unwrap();
        let layout_fault = fixture.branches.root().join("branches").join("v1");
        for _ in 0..2 {
            assert_eq!(
                fixture
                    .branches
                    .create_branch_inner(
                        "layout-retry",
                        fixture.genesis_transaction_id,
                        Some(&layout_fault),
                    )
                    .unwrap_err()
                    .code(),
                "REF_IO"
            );
            assert!(layout_fault.is_dir());
            assert!(!fixture.branches.branch_path(&layout_name).exists());
            assert!(!fixture.branches.ref_path(&layout_name).exists());
        }
        assert_eq!(
            fixture
                .branches
                .create_branch("layout-retry", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Created
        );

        let fanout_name = BranchName::parse("fanout-retry").unwrap();
        let fanout_hex = hex_digest(&fanout_name.path_key());
        let fanout_fault = fixture.branches.branches_dir().join(&fanout_hex[0..2]);
        for _ in 0..2 {
            assert_eq!(
                fixture
                    .branches
                    .create_branch_inner(
                        "fanout-retry",
                        fixture.genesis_transaction_id,
                        Some(&fanout_fault),
                    )
                    .unwrap_err()
                    .code(),
                "REF_IO"
            );
            assert!(fanout_fault.is_dir());
            assert!(!fixture.branches.branch_path(&fanout_name).exists());
            assert!(!fixture.branches.ref_path(&fanout_name).exists());
        }
        assert_eq!(
            fixture
                .branches
                .create_branch("fanout-retry", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Created
        );
        assert_eq!(
            fixture
                .branches
                .resolve_branch("fanout-retry")
                .unwrap()
                .reference
                .record
                .head_transaction_id,
            fixture.genesis_transaction_id
        );
    }

    #[test]
    fn interrupted_install_retries_redurabilize_visible_records() {
        let fixture = Fixture::new("retry-durability");
        fixture.branches.ensure_layout().unwrap();
        let revision = fixture
            .transactions
            .verified_revision(fixture.genesis_transaction_id)
            .unwrap();

        let origin_fault_name = BranchName::parse("origin-fault").unwrap();
        let origin_fault =
            build_branch_record(&origin_record(&origin_fault_name, &revision)).unwrap();
        let origin_fault_path = fixture
            .branches
            .ensure_branch_path(&origin_fault_name)
            .unwrap();
        let expected_origin = origin_fault.clone();
        assert_eq!(
            persist_no_overwrite_inner(
                &origin_fault_path,
                &origin_fault.stored_bytes,
                BRANCH_STAGE_PREFIX,
                BranchErrorCode::BranchOriginMismatch,
                |bytes| {
                    if import_branch_record(bytes)? == expected_origin {
                        Ok(())
                    } else {
                        Err(branch_error(BranchErrorCode::BranchOriginMismatch))
                    }
                },
                true,
            )
            .unwrap_err()
            .code(),
            "REF_IO"
        );
        assert!(origin_fault_path.is_file());
        assert_eq!(
            fixture
                .branches
                .create_branch("origin-fault", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Created
        );

        let ref_fault_name = BranchName::parse("ref-fault").unwrap();
        let ref_fault_origin =
            build_branch_record(&origin_record(&ref_fault_name, &revision)).unwrap();
        let ref_fault_reference = build_branch_ref(&ref_record(
            &ref_fault_name,
            ref_fault_origin.digest,
            &revision,
        ))
        .unwrap();
        let ref_fault_origin_path = fixture
            .branches
            .ensure_branch_path(&ref_fault_name)
            .unwrap();
        persist_no_overwrite(
            &ref_fault_origin_path,
            &ref_fault_origin.stored_bytes,
            BRANCH_STAGE_PREFIX,
            BranchErrorCode::BranchOriginMismatch,
            |_| Ok(()),
        )
        .unwrap();
        let ref_fault_path = fixture.branches.ensure_ref_path(&ref_fault_name).unwrap();
        let expected_ref = ref_fault_reference.clone();
        assert_eq!(
            persist_no_overwrite_inner(
                &ref_fault_path,
                &ref_fault_reference.stored_bytes,
                REF_STAGE_PREFIX,
                BranchErrorCode::RefAlreadyExists,
                |bytes| {
                    if import_branch_ref(bytes)? == expected_ref {
                        Ok(())
                    } else {
                        Err(branch_error(BranchErrorCode::RefAlreadyExists))
                    }
                },
                true,
            )
            .unwrap_err()
            .code(),
            "REF_IO"
        );
        assert_eq!(
            fixture
                .branches
                .create_branch("ref-fault", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Present
        );
    }

    #[test]
    fn interrupted_advance_retry_redurabilizes_the_renamed_ref() {
        let fixture = Fixture::new("advance-retry-durability");
        let child = fixture.commit_child(30);
        fixture
            .branches
            .create_branch("advance-fault", fixture.genesis_transaction_id)
            .unwrap();
        let advance_name = BranchName::parse("advance-fault").unwrap();
        let current = fixture.branches.resolve_branch("advance-fault").unwrap();
        let child_revision = fixture.transactions.verified_revision(child).unwrap();
        let advanced = build_branch_ref(&ref_record(
            &advance_name,
            current.origin.digest,
            &child_revision,
        ))
        .unwrap();
        let advance_path = fixture.branches.checked_ref_path(&advance_name).unwrap();
        assert_eq!(
            replace_ref_inner(&advance_path, &advanced, true)
                .unwrap_err()
                .code(),
            "REF_IO"
        );
        assert_eq!(
            fixture
                .branches
                .advance_branch("advance-fault", fixed(99, TransactionId::from_bytes), child,)
                .unwrap(),
            BranchUpdateStatus::Present
        );
    }

    #[test]
    fn orphan_retry_ignores_exact_owned_ref_stage_during_capacity_scan() {
        let fixture = Fixture::new("owned-stage-capacity");
        fixture.branches.ensure_layout().unwrap();
        let name = BranchName::parse("stage-retry").unwrap();
        let revision = fixture
            .transactions
            .verified_revision(fixture.genesis_transaction_id)
            .unwrap();
        let origin = build_branch_record(&origin_record(&name, &revision)).unwrap();
        let origin_path = fixture.branches.ensure_branch_path(&name).unwrap();
        persist_no_overwrite(
            &origin_path,
            &origin.stored_bytes,
            BRANCH_STAGE_PREFIX,
            BranchErrorCode::BranchOriginMismatch,
            |_| Ok(()),
        )
        .unwrap();
        let ref_path = fixture.branches.ensure_ref_path(&name).unwrap();
        let (stage_path, mut stage) =
            reserve_stage(ref_path.parent().unwrap(), REF_STAGE_PREFIX).unwrap();
        stage.write_all(b"interrupted").unwrap();
        stage.sync_all().unwrap();
        drop(stage);

        assert_eq!(
            fixture
                .branches
                .create_branch("stage-retry", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Created
        );
        assert!(stage_path.is_file());
        assert_eq!(
            fixture.branches.recover_refs().unwrap().removed_ref_stages,
            1
        );
    }

    #[test]
    fn origin_capacity_boundary_rejects_before_origin_or_ref_write() {
        let fixture = Fixture::new("origin-capacity");
        fixture
            .branches
            .create_branch("existing", fixture.genesis_transaction_id)
            .unwrap();
        let existing = BranchName::parse("existing").unwrap();
        fs::remove_file(fixture.branches.ref_path(&existing)).unwrap();

        let blocked = BranchName::parse("blocked").unwrap();
        let branch_path = fixture.branches.branch_path(&blocked);
        let ref_path = fixture.branches.ref_path(&blocked);
        let maintenance = fixture.branches.prepare_operation().unwrap();
        let lock = fixture.branches.acquire_refs_lock().unwrap();
        assert_eq!(
            fixture
                .branches
                .create_fresh_with_origin_limit(
                    &maintenance,
                    &branch_path,
                    &ref_path,
                    &blocked,
                    fixture.genesis_transaction_id,
                    1,
                )
                .unwrap_err()
                .code(),
            "BRANCH_RESOURCE_LIMIT"
        );
        assert!(!branch_path.exists());
        assert!(!ref_path.exists());
        drop(lock);
        drop(maintenance);
        assert_eq!(
            fixture
                .branches
                .recover_refs()
                .unwrap()
                .orphan_origins
                .len(),
            1
        );
    }

    #[test]
    fn create_conflicts_and_interrupted_origin_precedence_are_exact() {
        let fixture = Fixture::new("create-conflicts");
        fixture
            .branches
            .create_branch("mainline", fixture.genesis_transaction_id)
            .unwrap();
        let child = fixture.commit_child(30);
        assert_eq!(
            fixture
                .branches
                .create_branch("mainline", child)
                .unwrap_err()
                .code(),
            "BRANCH_ORIGIN_MISMATCH"
        );

        let name = BranchName::parse("mainline").unwrap();
        fs::remove_file(fixture.branches.ref_path(&name)).unwrap();
        assert_eq!(
            fixture
                .branches
                .create_branch("mainline", fixture.genesis_transaction_id)
                .unwrap(),
            BranchUpdateStatus::Created
        );
        fs::remove_file(fixture.branches.branch_path(&name)).unwrap();
        assert_eq!(
            fixture
                .branches
                .resolve_branch("mainline")
                .unwrap_err()
                .code(),
            "RECOVERY_NAMED_REF_INCOMPLETE"
        );
        assert_eq!(
            fixture
                .branches
                .create_branch("mainline", fixed(98, TransactionId::from_bytes))
                .unwrap_err()
                .code(),
            "RECOVERY_NAMED_REF_INCOMPLETE"
        );
    }

    #[test]
    fn create_combined_conflicts_follow_the_frozen_precedence_table() {
        let different_origin = Fixture::new("precedence-different-origin");
        different_origin
            .branches
            .create_branch("mainline", different_origin.genesis_transaction_id)
            .unwrap();
        assert_eq!(
            different_origin
                .branches
                .create_branch("mainline", fixed(90, TransactionId::from_bytes))
                .unwrap_err()
                .code(),
            "BRANCH_ORIGIN_MISMATCH"
        );

        let corrupt_origin = Fixture::new("precedence-corrupt-origin");
        corrupt_origin
            .branches
            .create_branch("mainline", corrupt_origin.genesis_transaction_id)
            .unwrap();
        let name = BranchName::parse("mainline").unwrap();
        let origin_path = corrupt_origin.branches.branch_path(&name);
        let mut bytes = fs::read(&origin_path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&origin_path, bytes).unwrap();
        assert_eq!(
            corrupt_origin
                .branches
                .create_branch("mainline", fixed(91, TransactionId::from_bytes))
                .unwrap_err()
                .code(),
            "BRANCH_RECORD_DIGEST_MISMATCH"
        );

        for (label, mutate, expected) in [
            ("version", 0_u8, "BRANCH_RECORD_FORMAT_VERSION"),
            ("shape", 1_u8, "BRANCH_RECORD_FIELD_SHAPE"),
        ] {
            let fixture = Fixture::new(&format!("precedence-origin-{label}"));
            fixture
                .branches
                .create_branch("mainline", fixture.genesis_transaction_id)
                .unwrap();
            let path = fixture.branches.branch_path(&name);
            let mut bytes = fs::read(&path).unwrap();
            let payload = payload_offset(&bytes);
            if mutate == 0 {
                bytes[payload + 3] = 2;
            } else {
                bytes[payload] = 7;
            }
            rehash(&mut bytes, BRANCH_DIGEST_DOMAIN);
            fs::write(path, bytes).unwrap();
            assert_eq!(
                fixture
                    .branches
                    .create_branch("mainline", fixed(93, TransactionId::from_bytes))
                    .unwrap_err()
                    .code(),
                expected
            );
        }
    }

    #[test]
    fn create_binding_advanced_and_path_conflicts_have_exact_precedence() {
        let name = BranchName::parse("mainline").unwrap();
        let bad_binding = Fixture::new("precedence-binding");
        bad_binding
            .branches
            .create_branch("mainline", bad_binding.genesis_transaction_id)
            .unwrap();
        let ref_path = bad_binding.branches.ref_path(&name);
        let mut reference = import_branch_ref(&fs::read(&ref_path).unwrap()).unwrap();
        reference.record.branch_record_digest = BranchRecordDigest::from_bytes([77; DIGEST_LEN]);
        fs::write(
            &ref_path,
            build_branch_ref(&reference.record).unwrap().stored_bytes,
        )
        .unwrap();
        assert_eq!(
            bad_binding
                .branches
                .create_branch("mainline", fixed(92, TransactionId::from_bytes))
                .unwrap_err()
                .code(),
            "REF_BRANCH_BINDING_MISMATCH"
        );

        let advanced = Fixture::new("precedence-advanced");
        advanced
            .branches
            .create_branch("mainline", advanced.genesis_transaction_id)
            .unwrap();
        let child = advanced.commit_child(30);
        advanced
            .branches
            .advance_branch("mainline", advanced.genesis_transaction_id, child)
            .unwrap();
        assert_eq!(
            advanced
                .branches
                .create_branch("mainline", advanced.genesis_transaction_id)
                .unwrap_err()
                .code(),
            "REF_ALREADY_EXISTS"
        );

        let wrong_key = Fixture::new("precedence-name-key");
        for branch in ["alpha", "beta"] {
            wrong_key
                .branches
                .create_branch(branch, wrong_key.genesis_transaction_id)
                .unwrap();
        }
        let alpha = BranchName::parse("alpha").unwrap();
        let beta = BranchName::parse("beta").unwrap();
        fs::write(
            wrong_key.branches.branch_path(&beta),
            fs::read(wrong_key.branches.branch_path(&alpha)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            wrong_key
                .branches
                .create_branch("beta", fixed(94, TransactionId::from_bytes))
                .unwrap_err()
                .code(),
            "REF_NAME_COLLISION"
        );
    }

    #[test]
    fn advance_preserves_present_stale_and_non_fast_forward_distinctions() {
        let fixture = Fixture::new("advance");
        fixture
            .branches
            .create_branch("mainline", fixture.genesis_transaction_id)
            .unwrap();
        let child = fixture.commit_child(30);
        assert_eq!(
            fixture
                .branches
                .advance_branch("mainline", fixture.genesis_transaction_id, child)
                .unwrap(),
            BranchUpdateStatus::Advanced
        );
        assert_eq!(
            fixture
                .branches
                .advance_branch("mainline", fixed(88, TransactionId::from_bytes), child,)
                .unwrap(),
            BranchUpdateStatus::Present
        );
        assert_eq!(
            fixture
                .branches
                .advance_branch(
                    "mainline",
                    fixture.genesis_transaction_id,
                    fixed(89, TransactionId::from_bytes),
                )
                .unwrap_err()
                .code(),
            "REF_NAMED_CAS_STALE"
        );
        assert_eq!(
            fixture
                .branches
                .advance_branch("mainline", child, fixture.genesis_transaction_id)
                .unwrap_err()
                .code(),
            "BRANCH_NOT_FAST_FORWARD"
        );

        let child_revision = fixture.transactions.verified_revision(child).unwrap();
        let mut duplicate_parent = child_revision.receipt().transaction.record.clone();
        duplicate_parent
            .parent_transaction_ids
            .push(fixture.genesis_transaction_id);
        duplicate_parent
            .parent_roots
            .push(duplicate_parent.parent_roots[0]);
        assert_eq!(
            build_transaction(&duplicate_parent).unwrap_err().code(),
            "TXN_PARENT_SHAPE"
        );
    }

    #[test]
    fn cross_workspace_advance_and_existing_current_ref_report_origin_mismatch() {
        let primary = Fixture::new_with_workspace("workspace-primary", 1);
        let secondary = Fixture::new_with_workspace("workspace-secondary", 9);
        import_fixture_revisions(&secondary, &primary);
        primary
            .branches
            .create_branch("mainline", primary.genesis_transaction_id)
            .unwrap();
        assert_eq!(
            primary
                .branches
                .advance_branch(
                    "mainline",
                    primary.genesis_transaction_id,
                    secondary.genesis_transaction_id,
                )
                .unwrap_err()
                .code(),
            "BRANCH_ORIGIN_MISMATCH"
        );

        let name = BranchName::parse("mainline").unwrap();
        let origin = primary.branches.resolve_branch("mainline").unwrap().origin;
        let foreign = primary
            .transactions
            .verified_revision(secondary.genesis_transaction_id)
            .unwrap();
        let foreign_ref = build_branch_ref(&ref_record(&name, origin.digest, &foreign)).unwrap();
        fs::write(primary.branches.ref_path(&name), foreign_ref.stored_bytes).unwrap();
        assert_eq!(
            primary
                .branches
                .create_branch("mainline", primary.genesis_transaction_id)
                .unwrap_err()
                .code(),
            "BRANCH_ORIGIN_MISMATCH"
        );
    }

    #[test]
    fn concurrent_create_and_advance_have_one_mutating_winner() {
        let fixture = Fixture::new("concurrent");
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let repository = fixture.branches.clone();
            let barrier = Arc::clone(&barrier);
            let origin = fixture.genesis_transaction_id;
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                repository.create_branch("race", origin)
            }));
        }
        barrier.wait();
        let mut create_statuses = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        create_statuses.sort_by_key(|status| status.tag());
        assert_eq!(
            create_statuses,
            vec![BranchUpdateStatus::Created, BranchUpdateStatus::Present]
        );

        let child = fixture.commit_child(30);
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let repository = fixture.branches.clone();
            let barrier = Arc::clone(&barrier);
            let origin = fixture.genesis_transaction_id;
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                repository.advance_branch("race", origin, child)
            }));
        }
        barrier.wait();
        let mut advance_statuses = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        advance_statuses.sort_by_key(|status| status.tag());
        assert_eq!(
            advance_statuses,
            vec![BranchUpdateStatus::Advanced, BranchUpdateStatus::Present]
        );
    }

    #[test]
    fn competing_distinct_create_and_advance_targets_have_one_cas_winner() {
        let create_fixture = Fixture::new("distinct-create-race");
        let create_child = create_fixture.commit_child(30);
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for origin in [create_fixture.genesis_transaction_id, create_child] {
            let repository = create_fixture.branches.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                repository.create_branch("distinct-create", origin)
            }));
        }
        barrier.wait();
        let create_results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            create_results
                .iter()
                .filter(|result| matches!(result, Ok(BranchUpdateStatus::Created)))
                .count(),
            1
        );
        assert_eq!(
            create_results
                .iter()
                .filter(|result| {
                    result
                        .as_ref()
                        .is_err_and(|error| error.code() == "BRANCH_ORIGIN_MISMATCH")
                })
                .count(),
            1
        );

        let primary = Fixture::new("distinct-advance-primary");
        let secondary = Fixture::new("distinct-advance-secondary");
        assert_eq!(
            primary.genesis_transaction_id,
            secondary.genesis_transaction_id
        );
        primary
            .branches
            .create_branch("distinct-advance", primary.genesis_transaction_id)
            .unwrap();
        let left = primary.commit_child(30);
        let right = secondary.commit_child(31);
        import_fixture_revisions(&secondary, &primary);
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for target in [left, right] {
            let repository = primary.branches.clone();
            let barrier = Arc::clone(&barrier);
            let expected = primary.genesis_transaction_id;
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                repository.advance_branch("distinct-advance", expected, target)
            }));
        }
        barrier.wait();
        let advance_results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            advance_results
                .iter()
                .filter(|result| matches!(result, Ok(BranchUpdateStatus::Advanced)))
                .count(),
            1
        );
        assert_eq!(
            advance_results
                .iter()
                .filter(|result| {
                    result
                        .as_ref()
                        .is_err_and(|error| error.code() == "REF_NAMED_CAS_STALE")
                })
                .count(),
            1
        );
    }

    #[test]
    fn exclusive_gc_ownership_serializes_transaction_and_ref_mutation() {
        let fixture = Fixture::new("gc-maintenance-race");
        let head = fixture.transactions.accepted_head().unwrap();
        let candidate = candidate_for(
            head.state_root().record.workspace_id,
            fixture.principal_id,
            head.transaction_id(),
            head.state_root(),
            head.policy_root(),
            30,
        );
        let repository = fixture.transactions.clone();
        let principal_id = fixture.principal_id;
        let parent = head.transaction_id();
        let store = ObjectStore::new(&fixture.temp.path);
        let guard = acquire_exclusive_gc(&store).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let transaction_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = repository
                .commit(CommitInput::new(
                    parent,
                    &candidate.stored_bytes,
                    principal_id,
                    &[],
                    NOW,
                    CandidateValidationLimits::full_v1(),
                ))
                .map(|output| output.transaction_id());
            finished_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        drop(guard);
        let child = finished_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        transaction_thread.join().unwrap();

        let guard = acquire_exclusive_gc(&store).unwrap();
        let branches = fixture.branches.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let ref_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx
                .send(branches.create_branch("gc-serialized", child))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            finished_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        drop(guard);
        assert_eq!(
            finished_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            BranchUpdateStatus::Created
        );
        ref_thread.join().unwrap();
    }

    #[test]
    fn target_mismatch_cross_path_substitution_and_unknown_files_fail_closed() {
        let fixture = Fixture::new("confinement");
        for name in ["alpha", "beta"] {
            fixture
                .branches
                .create_branch(name, fixture.genesis_transaction_id)
                .unwrap();
        }
        let alpha = BranchName::parse("alpha").unwrap();
        let beta = BranchName::parse("beta").unwrap();
        let alpha_origin = fs::read(fixture.branches.branch_path(&alpha)).unwrap();
        fs::write(fixture.branches.branch_path(&beta), alpha_origin).unwrap();
        assert_eq!(
            fixture.branches.resolve_branch("beta").unwrap_err().code(),
            "REF_NAME_COLLISION"
        );

        let reference_path = fixture.branches.ref_path(&alpha);
        let mut reference = import_branch_ref(&fs::read(&reference_path).unwrap()).unwrap();
        reference.record.head_state_root = fixed(99, StateRoot::from_bytes);
        let forged = build_branch_ref(&reference.record).unwrap();
        fs::write(&reference_path, forged.stored_bytes).unwrap();
        assert_eq!(
            fixture.branches.resolve_branch("alpha").unwrap_err().code(),
            "REF_TARGET_MISMATCH"
        );

        fs::write(fixture.branches.refs_dir().join("unknown"), b"foreign").unwrap();
        assert_eq!(
            fixture.branches.list_branches(10).unwrap_err().code(),
            "REF_IO"
        );
    }

    #[test]
    fn branch_resolution_preserves_receipt_root_policy_object_and_manifest_failures() {
        let missing_receipt = Fixture::new("resolve-missing-receipt");
        missing_receipt
            .branches
            .create_branch("mainline", missing_receipt.genesis_transaction_id)
            .unwrap();
        fs::remove_file(transaction_receipt_path(
            &missing_receipt.temp.path,
            missing_receipt.genesis_transaction_id,
        ))
        .unwrap();
        assert_eq!(
            missing_receipt
                .branches
                .resolve_branch("mainline")
                .unwrap_err()
                .code(),
            "RECOVERY_RECEIPT_INCOMPLETE"
        );

        let corrupt_root = Fixture::new("resolve-corrupt-root");
        corrupt_root
            .branches
            .create_branch("mainline", corrupt_root.genesis_transaction_id)
            .unwrap();
        let revision = corrupt_root
            .transactions
            .verified_revision(corrupt_root.genesis_transaction_id)
            .unwrap();
        fs::write(
            transaction_receipt_path(&corrupt_root.temp.path, corrupt_root.genesis_transaction_id),
            corrupt_nested_receipt(
                revision.receipt(),
                &revision.receipt().record.stored_state_root,
            ),
        )
        .unwrap();
        assert_eq!(
            corrupt_root
                .branches
                .resolve_branch("mainline")
                .unwrap_err()
                .code(),
            "SCB_DIGEST_MISMATCH"
        );

        let corrupt_policy = Fixture::new("resolve-corrupt-policy");
        corrupt_policy
            .branches
            .create_branch("mainline", corrupt_policy.genesis_transaction_id)
            .unwrap();
        let revision = corrupt_policy
            .transactions
            .verified_revision(corrupt_policy.genesis_transaction_id)
            .unwrap();
        fs::write(
            transaction_receipt_path(
                &corrupt_policy.temp.path,
                corrupt_policy.genesis_transaction_id,
            ),
            corrupt_nested_receipt(
                revision.receipt(),
                &revision.receipt().record.stored_policy_root,
            ),
        )
        .unwrap();
        assert_eq!(
            corrupt_policy
                .branches
                .resolve_branch("mainline")
                .unwrap_err()
                .code(),
            "SCB_DIGEST_MISMATCH"
        );
    }

    #[test]
    fn branch_resolution_preserves_object_and_manifest_failures() {
        let missing_object = Fixture::new("resolve-missing-object");
        missing_object
            .branches
            .create_branch("mainline", missing_object.genesis_transaction_id)
            .unwrap();
        let object = missing_object
            .transactions
            .verified_revision(missing_object.genesis_transaction_id)
            .unwrap()
            .objects()[0]
            .object_id();
        let store = ObjectStore::new(&missing_object.temp.path);
        fs::remove_file(store.object_path(object)).unwrap();
        assert_eq!(
            missing_object
                .branches
                .resolve_branch("mainline")
                .unwrap_err()
                .code(),
            "STORE_OBJECT_NOT_FOUND"
        );

        let corrupt_object = Fixture::new("resolve-corrupt-object");
        corrupt_object
            .branches
            .create_branch("mainline", corrupt_object.genesis_transaction_id)
            .unwrap();
        let object = corrupt_object
            .transactions
            .verified_revision(corrupt_object.genesis_transaction_id)
            .unwrap()
            .objects()[0]
            .object_id();
        let store = ObjectStore::new(&corrupt_object.temp.path);
        let object_path = store.object_path(object);
        let mut bytes = fs::read(&object_path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(object_path, bytes).unwrap();
        assert_eq!(
            corrupt_object
                .branches
                .resolve_branch("mainline")
                .unwrap_err()
                .code(),
            "SCB_DIGEST_MISMATCH"
        );

        let corrupt_manifest = Fixture::new("resolve-corrupt-manifest");
        corrupt_manifest
            .branches
            .create_branch("mainline", corrupt_manifest.genesis_transaction_id)
            .unwrap();
        let revision = corrupt_manifest
            .transactions
            .verified_revision(corrupt_manifest.genesis_transaction_id)
            .unwrap();
        let mut record = revision.receipt().record.clone();
        record.object_manifest[0].stored_length += 1;
        let forged = build_transaction_receipt(&record).unwrap();
        fs::write(
            transaction_receipt_path(
                &corrupt_manifest.temp.path,
                corrupt_manifest.genesis_transaction_id,
            ),
            forged.stored_bytes,
        )
        .unwrap();
        assert_eq!(
            corrupt_manifest
                .branches
                .resolve_branch("mainline")
                .unwrap_err()
                .code(),
            "TXN_OBJECT_INVENTORY_MISMATCH"
        );
    }

    #[test]
    fn forged_origin_and_every_current_fact_fail_against_durable_evidence() {
        let origin_fixture = Fixture::new("forged-origin-facts");
        origin_fixture
            .branches
            .create_branch("mainline", origin_fixture.genesis_transaction_id)
            .unwrap();
        let name = BranchName::parse("mainline").unwrap();
        let origin_path = origin_fixture.branches.branch_path(&name);
        let ref_path = origin_fixture.branches.ref_path(&name);
        let base_origin = import_branch_record(&fs::read(&origin_path).unwrap()).unwrap();
        let base_ref = import_branch_ref(&fs::read(&ref_path).unwrap()).unwrap();
        let mut variants = Vec::new();
        let mut variant = base_origin.record.clone();
        variant.workspace_id = fixed(61, WorkspaceId::from_bytes);
        variants.push(variant);
        let mut variant = base_origin.record.clone();
        variant.origin_state_root = fixed(62, StateRoot::from_bytes);
        variants.push(variant);
        let mut variant = base_origin.record.clone();
        variant.schema_epoch_id = fixed(63, SchemaEpochId::from_bytes);
        variants.push(variant);
        let mut variant = base_origin.record.clone();
        variant.policy_root_id = fixed(64, PolicyRootId::from_bytes);
        variants.push(variant);
        let mut variant = base_origin.record.clone();
        variant.dependency_roots = vec![fixed(65, StateRoot::from_bytes)];
        variants.push(variant);
        for variant in variants {
            let forged_origin = build_branch_record(&variant).unwrap();
            let mut forged_ref_record = base_ref.record.clone();
            forged_ref_record.branch_record_digest = forged_origin.digest;
            fs::write(&origin_path, forged_origin.stored_bytes).unwrap();
            fs::write(
                &ref_path,
                build_branch_ref(&forged_ref_record).unwrap().stored_bytes,
            )
            .unwrap();
            assert_eq!(
                origin_fixture
                    .branches
                    .resolve_branch("mainline")
                    .unwrap_err()
                    .code(),
                "BRANCH_ORIGIN_MISMATCH"
            );
        }

        let current_fixture = Fixture::new("forged-current-facts");
        current_fixture
            .branches
            .create_branch("mainline", current_fixture.genesis_transaction_id)
            .unwrap();
        let child = current_fixture.commit_child(30);
        let ref_path = current_fixture.branches.ref_path(&name);
        let base_ref = import_branch_ref(&fs::read(&ref_path).unwrap()).unwrap();
        let mut variants = Vec::new();
        let mut variant = base_ref.record.clone();
        variant.workspace_id = fixed(71, WorkspaceId::from_bytes);
        variants.push(variant);
        let mut variant = base_ref.record.clone();
        variant.head_transaction_id = child;
        variants.push(variant);
        let mut variant = base_ref.record.clone();
        variant.head_state_root = fixed(72, StateRoot::from_bytes);
        variants.push(variant);
        let mut variant = base_ref.record.clone();
        variant.schema_epoch_id = fixed(73, SchemaEpochId::from_bytes);
        variants.push(variant);
        let mut variant = base_ref.record.clone();
        variant.policy_root_id = fixed(74, PolicyRootId::from_bytes);
        variants.push(variant);
        let mut variant = base_ref.record;
        variant.dependency_roots = vec![fixed(75, StateRoot::from_bytes)];
        variants.push(variant);
        for variant in variants {
            fs::write(&ref_path, build_branch_ref(&variant).unwrap().stored_bytes).unwrap();
            assert_eq!(
                current_fixture
                    .branches
                    .resolve_branch("mainline")
                    .unwrap_err()
                    .code(),
                "REF_TARGET_MISMATCH"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_roots_locks_and_records_fail_closed() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new("symlink-root");
        let outside = TempDir::new("symlink-outside");
        symlink(&outside.path, root.path.join("refs")).unwrap();
        assert_eq!(
            BranchRepository::new(&root.path)
                .resolve_branch("alpha")
                .unwrap_err()
                .code(),
            "REF_IO"
        );

        let fanout_root = TempDir::new("symlink-fanout");
        let fanout_repository = BranchRepository::new(&fanout_root.path);
        fanout_repository.ensure_layout().unwrap();
        let fanout_name = BranchName::parse("alpha").unwrap();
        let fanout_hex = hex_digest(&fanout_name.path_key());
        symlink(
            &outside.path,
            fanout_root
                .path
                .join("refs")
                .join("v1")
                .join(&fanout_hex[0..2]),
        )
        .unwrap();
        assert_eq!(
            fanout_repository
                .resolve_branch("alpha")
                .unwrap_err()
                .code(),
            "REF_IO"
        );

        let lock_fixture = Fixture::new("symlink-lock");
        let lock_target = outside.path.join("foreign-lock");
        fs::write(&lock_target, b"foreign").unwrap();
        symlink(
            &lock_target,
            lock_fixture.temp.path.join("locks").join("refs.lock"),
        )
        .unwrap();
        assert_eq!(
            lock_fixture
                .branches
                .create_branch("alpha", lock_fixture.genesis_transaction_id)
                .unwrap_err()
                .code(),
            "REF_IO"
        );

        let fixture = Fixture::new("symlink-record");
        fixture
            .branches
            .create_branch("alpha", fixture.genesis_transaction_id)
            .unwrap();
        let name = BranchName::parse("alpha").unwrap();
        let ref_path = fixture.branches.ref_path(&name);
        fs::remove_file(&ref_path).unwrap();
        symlink(fixture.branches.branch_path(&name), &ref_path).unwrap();
        assert_eq!(
            fixture.branches.resolve_branch("alpha").unwrap_err().code(),
            "REF_IO"
        );
    }

    #[test]
    fn ancestry_is_head_first_bounded_convergent_and_cycle_checked() {
        let fixture = Fixture::new("ancestry");
        fixture
            .branches
            .create_branch("lineage", fixture.genesis_transaction_id)
            .unwrap();
        let child = fixture.commit_child(30);
        fixture
            .branches
            .advance_branch("lineage", fixture.genesis_transaction_id, child)
            .unwrap();
        let grandchild = fixture.commit_child(31);
        fixture
            .branches
            .advance_branch("lineage", child, grandchild)
            .unwrap();
        let ancestry = fixture.branches.branch_ancestry("lineage", 3).unwrap();
        assert_eq!(
            ancestry
                .iter()
                .map(|entry| entry.transaction_id)
                .collect::<Vec<_>>(),
            vec![grandchild, child, fixture.genesis_transaction_id]
        );
        assert_eq!(
            fixture
                .branches
                .branch_ancestry("lineage", 2)
                .unwrap_err()
                .code(),
            "BRANCH_RESOURCE_LIMIT"
        );

        let head = fixed(40, TransactionId::from_bytes);
        let left = fixed(41, TransactionId::from_bytes);
        let right = fixed(42, TransactionId::from_bytes);
        let shared = fixed(43, TransactionId::from_bytes);
        let graph = BTreeMap::from([
            (head, vec![left, right]),
            (left, vec![shared]),
            (right, vec![shared]),
            (shared, vec![]),
        ]);
        let convergent = walk_ancestry(head, 4, |transaction_id| {
            Ok(BranchAncestryEntry {
                transaction_id,
                state_root: fixed(50, StateRoot::from_bytes),
                parent_transaction_ids: graph[&transaction_id].clone(),
            })
        })
        .unwrap();
        assert_eq!(
            convergent
                .iter()
                .map(|entry| entry.transaction_id)
                .collect::<Vec<_>>(),
            vec![head, left, shared, right]
        );

        let cycle = BTreeMap::from([(left, vec![right]), (right, vec![left])]);
        assert_eq!(
            walk_ancestry(left, 3, |transaction_id| {
                Ok(BranchAncestryEntry {
                    transaction_id,
                    state_root: fixed(51, StateRoot::from_bytes),
                    parent_transaction_ids: cycle[&transaction_id].clone(),
                })
            })
            .unwrap_err()
            .code(),
            "BRANCH_ANCESTRY_CYCLE"
        );
    }

    #[test]
    fn recovery_removes_only_exact_owned_stages_and_reports_orphans() {
        let fixture = Fixture::new("recovery");
        fixture
            .branches
            .create_branch("orphan", fixture.genesis_transaction_id)
            .unwrap();
        let name = BranchName::parse("orphan").unwrap();
        let branch_path = fixture.branches.branch_path(&name);
        let ref_path = fixture.branches.ref_path(&name);
        fs::remove_file(&ref_path).unwrap();
        let branch_stage = branch_path.parent().unwrap().join(format!(
            "{BRANCH_STAGE_PREFIX}{}-0000000000000001{STAGE_SUFFIX}",
            std::process::id()
        ));
        let ref_stage = ref_path.parent().unwrap().join(format!(
            "{REF_STAGE_PREFIX}{}-0000000000000002{STAGE_SUFFIX}",
            std::process::id()
        ));
        fs::write(&branch_stage, b"partial").unwrap();
        fs::write(&ref_stage, b"partial").unwrap();
        let report = fixture.branches.recover_refs().unwrap();
        assert_eq!(report.removed_branch_stages, 1);
        assert_eq!(report.removed_ref_stages, 1);
        assert_eq!(report.visible_branches, 0);
        assert_eq!(report.orphan_origins.len(), 1);
        assert_eq!(report.orphan_origins[0].branch_name, name);
        assert!(!branch_stage.exists());
        assert!(!ref_stage.exists());

        let foreign = branch_path
            .parent()
            .unwrap()
            .join(".sley-branch-stage-foreign.tmp");
        fs::write(&foreign, b"foreign").unwrap();
        assert_eq!(
            fixture.branches.recover_refs().unwrap_err().code(),
            "REF_IO"
        );
        assert!(foreign.exists());
    }

    #[test]
    fn recovery_retry_syncs_leaf_even_after_prior_delete_sync_failure() {
        let fixture = Fixture::new("recovery-sync-retry");
        fixture
            .branches
            .create_branch("sync-retry", fixture.genesis_transaction_id)
            .unwrap();
        let name = BranchName::parse("sync-retry").unwrap();
        let branch_path = fixture.branches.branch_path(&name);
        let stage_path = branch_path.parent().unwrap().join(format!(
            "{BRANCH_STAGE_PREFIX}{}-0000000000000003{STAGE_SUFFIX}",
            std::process::id()
        ));
        fs::write(&stage_path, b"interrupted").unwrap();
        let mut fail_next_leaf_sync = true;
        assert_eq!(
            remove_stages_recursive_inner(
                &fixture.branches.branches_dir(),
                BRANCH_STAGE_PREFIX,
                2,
                &mut fail_next_leaf_sync,
            )
            .unwrap_err()
            .code(),
            "REF_IO"
        );
        assert!(!stage_path.exists());
        assert_eq!(
            remove_stages_recursive(&fixture.branches.branches_dir(), BRANCH_STAGE_PREFIX, 2)
                .unwrap(),
            0
        );
    }

    #[test]
    fn stage_name_ownership_requires_the_complete_generated_shape() {
        assert!(is_owned_stage_name(
            ".sley-ref-stage-123-0123456789abcdef.tmp",
            REF_STAGE_PREFIX
        ));
        for foreign in [
            ".sley-ref-stage-user.tmp",
            ".sley-ref-stage-123-short.tmp",
            ".sley-ref-stage-123-0123456789ABCDEF.tmp",
            ".sley-ref-stage-0123-0123456789abcdef.tmp",
            ".sley-ref-stage-0-0123456789abcdef.tmp",
            ".sley-ref-stage--0123456789abcdef.tmp",
            ".sley-ref-stage-123-0123456789abcdef.tmp.extra",
        ] {
            assert!(!is_owned_stage_name(foreign, REF_STAGE_PREFIX));
        }
    }
}
