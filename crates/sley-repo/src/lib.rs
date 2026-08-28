#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod gc;
mod refs;

pub use gc::*;
pub use refs::*;

use core::fmt;
use std::collections::BTreeSet;

use sley_id::{ObjectId, RepositoryPackId, SchemaEpochId, StateRoot};
use sley_scb1::{
    MAX_STANDALONE_BYTES, ScbError, ScbErrorCode, encode_list, encode_record, encode_union,
    encode_uvar,
};
use sley_schema::{
    ContractDescriptor, EpochDecoder, EpochLimits, RegistryEntry, SchemaEpochRecordV1,
    SchemaEpochRegistry, UnicodeVersion, bootstrap_preimage, import_bootstrap_preimage,
};
use sley_state_root::{
    AcceptedStateRoot, conformance_epoch_record, conformance_registry as state_root_registry,
    import_state_root,
};
use sley_store::{CanonicalVerifier, ObjectStore, PutStatus};

const MAGIC: &[u8; 8] = b"SLEYSCB1";
const FORMAT_VERSION: u64 = 1;
const CONTRACT_TAG: u32 = 170;
const DIGEST_DOMAIN_TAG: u32 = 18;
const KIND_TAG: u32 = 170;
const FIELD_COUNT: u64 = 9;
const ID_LEN: usize = 32;
const DIGEST_TRAILER_LEN: usize = 32;
const TREE_ALGORITHM_TAG: u64 = 1;
const COMPRESSION_NONE: u64 = 0;
const EPOCH_SECTION: u64 = 1;
const ROOT_SECTION: u64 = 2;
const OBJECT_SECTION: u64 = 3;
const LEAF_DOMAIN: &[u8] = b"sley2.repository-pack-leaf.v1";
const NODE_DOMAIN: &[u8] = b"sley2.repository-pack-node.v1";

/// Maximum accepted stored pack bytes.
pub const MAX_PACK_BYTES: usize = 67_108_864;
/// Maximum total embedded epoch, root, and object bytes.
pub const MAX_EXPANDED_BYTES: usize = 67_108_864;
/// Maximum epoch entries.
pub const MAX_PACK_EPOCHS: usize = 256;
/// Maximum root entries.
pub const MAX_PACK_ROOTS: usize = 4_096;
/// Maximum object entries.
pub const MAX_PACK_OBJECTS: usize = 65_536;
/// Maximum digest leaves.
pub const MAX_PACK_LEAVES: usize = 69_888;
/// Maximum decoder allocation budget.
pub const MAX_PACK_ALLOCATION: usize = 134_217_728;

const FIELD_SCHEMA_HASH: [u8; ID_LEN] = [
    0x72, 0x31, 0xa3, 0x1c, 0x5d, 0x9c, 0xc1, 0x59, 0xce, 0x9d, 0x16, 0x1e, 0xcc, 0x43, 0x4c, 0x4b,
    0x98, 0x61, 0x3f, 0x97, 0xa0, 0x0e, 0x07, 0xfd, 0x07, 0x28, 0xc4, 0x51, 0x28, 0xf9, 0x4e, 0x21,
];
const DECODER_LIMITS_HASH: [u8; ID_LEN] = [
    0x38, 0xa8, 0x07, 0x92, 0x28, 0x70, 0xba, 0xe9, 0xac, 0xa1, 0xbb, 0xd0, 0xaf, 0xb8, 0xd8, 0x7f,
    0x25, 0x11, 0xc8, 0x76, 0xbc, 0x08, 0x7c, 0xe1, 0x61, 0x6c, 0xbb, 0x7c, 0x7c, 0xc9, 0x5e, 0x00,
];

/// Stable repository-pack failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackErrorCode {
    /// `PACK_VERSION_UNSUPPORTED`.
    VersionUnsupported,
    /// `PACK_DIGEST_MISMATCH`.
    DigestMismatch,
    /// `PACK_DIGEST_TREE_MISMATCH`.
    DigestTreeMismatch,
    /// `PACK_CANONICAL_ORDER`.
    CanonicalOrder,
    /// `PACK_DUPLICATE_ENTRY`.
    DuplicateEntry,
    /// `PACK_SCHEMA_UNSUPPORTED`.
    SchemaUnsupported,
    /// `PACK_ROOT_INVALID`.
    RootInvalid,
    /// `PACK_OBJECT_MISSING`.
    ObjectMissing,
    /// `PACK_OBJECT_UNEXPECTED`.
    ObjectUnexpected,
    /// `PACK_OBJECT_CORRUPT`.
    ObjectCorrupt,
    /// `PACK_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `PACK_COMPRESSION_UNSUPPORTED`.
    CompressionUnsupported,
    /// Reserved `PACK_DECOMPRESSION_LIMIT`.
    DecompressionLimit,
    /// `PACK_PROFILE_UNSUPPORTED`.
    ProfileUnsupported,
}

impl PackErrorCode {
    /// Returns the exact stable symbol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VersionUnsupported => "PACK_VERSION_UNSUPPORTED",
            Self::DigestMismatch => "PACK_DIGEST_MISMATCH",
            Self::DigestTreeMismatch => "PACK_DIGEST_TREE_MISMATCH",
            Self::CanonicalOrder => "PACK_CANONICAL_ORDER",
            Self::DuplicateEntry => "PACK_DUPLICATE_ENTRY",
            Self::SchemaUnsupported => "PACK_SCHEMA_UNSUPPORTED",
            Self::RootInvalid => "PACK_ROOT_INVALID",
            Self::ObjectMissing => "PACK_OBJECT_MISSING",
            Self::ObjectUnexpected => "PACK_OBJECT_UNEXPECTED",
            Self::ObjectCorrupt => "PACK_OBJECT_CORRUPT",
            Self::ResourceLimit => "PACK_RESOURCE_LIMIT",
            Self::CompressionUnsupported => "PACK_COMPRESSION_UNSUPPORTED",
            Self::DecompressionLimit => "PACK_DECOMPRESSION_LIMIT",
            Self::ProfileUnsupported => "PACK_PROFILE_UNSUPPORTED",
        }
    }
}

/// Exact pack or preserved lower-layer error symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackError {
    symbol: &'static str,
}

impl PackError {
    const fn pack(code: PackErrorCode) -> Self {
        Self {
            symbol: code.as_str(),
        }
    }

    const fn upstream(symbol: &'static str) -> Self {
        Self { symbol }
    }

    /// Returns the exact stable failure symbol.
    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        self.symbol
    }
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.symbol)
    }
}

impl std::error::Error for PackError {}

type Result<T> = core::result::Result<T, PackError>;

/// Exact embedded schema-epoch bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackEpochEntry {
    /// Declared schema epoch.
    pub schema_epoch_id: SchemaEpochId,
    /// Exact `SLEYEP01` bootstrap preimage.
    pub bootstrap_preimage: Vec<u8>,
}

/// Exact embedded root bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackRootEntry {
    /// Declared semantic root.
    pub state_root: StateRoot,
    /// Exact standalone root bytes.
    pub stored_bytes: Vec<u8>,
}

/// Exact embedded object bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackObjectEntry {
    /// Declared object identifier.
    pub object_id: ObjectId,
    /// Exact standalone object bytes.
    pub stored_bytes: Vec<u8>,
}

/// Canonical accepted repository pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedRepositoryPack {
    /// Derived pack identifier.
    pub pack_id: RepositoryPackId,
    /// Exact standalone pack bytes.
    pub stored_bytes: Vec<u8>,
    /// Exact ordered epochs.
    pub epochs: Vec<PackEpochEntry>,
    /// Exact ordered roots.
    pub roots: Vec<PackRootEntry>,
    /// Exact ordered objects.
    pub objects: Vec<PackObjectEntry>,
    /// Verified digest-tree root.
    pub digest_tree_root: [u8; ID_LEN],
}

/// Successful clean-store import report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportReport {
    /// Imported pack identifier.
    pub pack_id: RepositoryPackId,
    /// Strictly reconstructed roots.
    pub roots: Vec<AcceptedStateRoot>,
    /// Newly promoted object count.
    pub promoted_objects: usize,
    /// Already-present verified object count.
    pub present_objects: usize,
}

#[derive(Clone, Debug)]
struct DecodedPack {
    version: u64,
    epochs: Vec<PackEpochEntry>,
    roots: Vec<PackRootEntry>,
    objects: Vec<PackObjectEntry>,
    compression_profile: u64,
    leaves: Vec<[u8; ID_LEN]>,
    digest_tree_root: [u8; ID_LEN],
}

struct PayloadSections<'a> {
    epochs: &'a [PackEpochEntry],
    roots: &'a [PackRootEntry],
    objects: &'a [PackObjectEntry],
    refs: &'a [Vec<u8>],
    transactions: &'a [Vec<u8>],
    compression_profile: u64,
    leaves: &'a [[u8; ID_LEN]],
    tree_root: [u8; ID_LEN],
    signature: Option<&'a [u8]>,
}

/// Preserved decoder for the exact S20-170 pack schema epoch.
#[derive(Clone, Debug)]
pub struct PackEpoch1Decoder {
    epoch_id: SchemaEpochId,
}

impl EpochDecoder for PackEpoch1Decoder {
    fn epoch_id(&self) -> SchemaEpochId {
        self.epoch_id
    }

    fn decode_contract(
        &self,
        contract_tag: u32,
        input: &[u8],
    ) -> core::result::Result<(), ScbError> {
        if contract_tag != CONTRACT_TAG {
            return Err(ScbError::new(ScbErrorCode::ContractUnknown));
        }
        decode_payload(input).map(|_| ()).map_err(|error| {
            let code = match error.symbol() {
                "PACK_RESOURCE_LIMIT" => ScbErrorCode::ResourceLimit,
                "PACK_CANONICAL_ORDER" => ScbErrorCode::MapOrder,
                "PACK_DUPLICATE_ENTRY" => ScbErrorCode::MapDuplicate,
                "PACK_VERSION_UNSUPPORTED" => ScbErrorCode::VersionUnsupported,
                _ => ScbErrorCode::FieldUnknown,
            };
            ScbError::new(code)
        })
    }
}

/// Returns the frozen pack schema-epoch record.
#[must_use]
pub fn pack_epoch_record() -> SchemaEpochRecordV1 {
    SchemaEpochRecordV1 {
        epoch_number: 1,
        scb_format_version: 1,
        hash_algorithm_tag: 1,
        unicode_nfc_version: UnicodeVersion::EPOCH_1,
        limits: EpochLimits::EPOCH_1,
        contracts: vec![ContractDescriptor {
            contract_tag: CONTRACT_TAG,
            digest_domain_tag: DIGEST_DOMAIN_TAG,
            kind_tag: KIND_TAG,
            field_schema_hash: FIELD_SCHEMA_HASH,
            required_fields: (1..=9).collect(),
            optional_fields: Vec::new(),
            variant_tags: Vec::new(),
            decoder_limits_hash: DECODER_LIMITS_HASH,
        }],
        extensions: Vec::new(),
        predecessor: None,
        migration_contracts: Vec::new(),
    }
}

/// Returns the exact pack schema epoch ID.
///
/// # Errors
///
/// Returns the frozen schema-layer error if the descriptor record drifts.
pub fn pack_epoch_id() -> Result<SchemaEpochId> {
    pack_epoch_record()
        .schema_epoch_id()
        .map_err(|error| PackError::upstream(error.code().as_str()))
}

fn pack_registry() -> Result<SchemaEpochRegistry<PackEpoch1Decoder>> {
    let record = pack_epoch_record();
    let epoch_id = record
        .schema_epoch_id()
        .map_err(|error| PackError::upstream(error.code().as_str()))?;
    let entry = RegistryEntry::new(epoch_id, record, PackEpoch1Decoder { epoch_id })
        .map_err(|error| PackError::upstream(error.code().as_str()))?;
    SchemaEpochRegistry::new(vec![entry])
        .map_err(|error| PackError::upstream(error.code().as_str()))
}

/// Exports a canonical S20-170 pack from exact accepted roots and object bytes.
///
/// # Errors
///
/// Fails closed on unsupported roots, incomplete dependency closure, missing or
/// corrupt objects, resource limits, or canonical encoding errors.
pub fn export_conformance_pack<V: CanonicalVerifier>(
    store: &ObjectStore,
    roots: &[AcceptedStateRoot],
    verifier: &V,
) -> Result<AcceptedRepositoryPack> {
    if roots.is_empty() || roots.len() > MAX_PACK_ROOTS {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    let root_registry =
        state_root_registry().map_err(|error| PackError::upstream(error.code().as_str()))?;
    let expected_root_epoch = conformance_epoch_record()
        .schema_epoch_id()
        .map_err(|error| PackError::upstream(error.code().as_str()))?;

    let mut accepted = Vec::with_capacity(roots.len());
    for root in roots {
        let imported = import_state_root(&root_registry, &root.stored_bytes)
            .map_err(|_| PackError::pack(PackErrorCode::RootInvalid))?;
        if imported.root != root.root || imported.record.schema_epoch_id != expected_root_epoch {
            return Err(PackError::pack(PackErrorCode::RootInvalid));
        }
        accepted.push(imported);
    }
    accepted.sort_by_key(|root| root.root);
    if accepted.windows(2).any(|pair| pair[0].root == pair[1].root) {
        return Err(PackError::pack(PackErrorCode::DuplicateEntry));
    }
    validate_dependency_closure(&accepted)?;

    let required_objects = required_object_ids(&accepted);
    if required_objects.len() > MAX_PACK_OBJECTS {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    let mut objects = Vec::with_capacity(required_objects.len());
    for object_id in required_objects {
        let stored_bytes = store
            .read(object_id, verifier)
            .map_err(|error| PackError::upstream(error.symbol()))?;
        objects.push(PackObjectEntry {
            object_id,
            stored_bytes,
        });
    }

    let pack_epoch = pack_epoch_record();
    let root_epoch = conformance_epoch_record();
    let mut epochs = vec![epoch_entry(&pack_epoch)?, epoch_entry(&root_epoch)?];
    epochs.sort_by_key(|entry| entry.schema_epoch_id);
    if epochs
        .windows(2)
        .any(|pair| pair[0].schema_epoch_id == pair[1].schema_epoch_id)
    {
        return Err(PackError::pack(PackErrorCode::SchemaUnsupported));
    }
    let root_entries = accepted
        .iter()
        .map(|root| PackRootEntry {
            state_root: root.root,
            stored_bytes: root.stored_bytes.clone(),
        })
        .collect::<Vec<_>>();
    build_pack(epochs, root_entries, objects)
}

/// Strictly imports a S20-170 pack and promotes objects only after complete preflight.
///
/// # Errors
///
/// Returns an exact stable pack, SCB1, schema, state-root, store, or verifier
/// symbol. Failed preflight performs no object-store writes.
pub fn import_conformance_pack<V: CanonicalVerifier>(
    store: &ObjectStore,
    input: &[u8],
    verifier: &V,
) -> Result<ImportReport> {
    let (pack_epoch, payload, pack_id) = decode_envelope(input)?;
    let decoded = decode_payload(payload)?;
    validate_profile(&decoded)?;
    let registry = pack_registry()?;
    registry
        .lookup_contract(pack_epoch, CONTRACT_TAG)
        .map_err(|error| PackError::upstream(error.code().as_str()))?;
    registry
        .decode_contract(pack_epoch, CONTRACT_TAG, payload)
        .map_err(|error| match error {
            sley_schema::EpochDecodeError::Schema(schema) => {
                PackError::upstream(schema.code().as_str())
            }
            sley_schema::EpochDecodeError::Scb(scb) => PackError::upstream(scb.code().as_str()),
        })?;
    validate_epochs(&decoded.epochs, pack_epoch)?;
    verify_digest_tree(&decoded)?;

    let root_registry =
        state_root_registry().map_err(|error| PackError::upstream(error.code().as_str()))?;
    let mut roots = Vec::with_capacity(decoded.roots.len());
    for entry in &decoded.roots {
        let root = import_state_root(&root_registry, &entry.stored_bytes)
            .map_err(|_| PackError::pack(PackErrorCode::RootInvalid))?;
        if root.root != entry.state_root {
            return Err(PackError::pack(PackErrorCode::RootInvalid));
        }
        roots.push(root);
    }
    validate_dependency_closure(&roots)?;
    validate_object_closure(&roots, &decoded.objects)?;

    for object in &decoded.objects {
        preflight_object(object, verifier)?;
    }

    let mut promoted_objects = 0;
    let mut present_objects = 0;
    for object in &decoded.objects {
        match store
            .put(object.object_id, &object.stored_bytes, verifier)
            .map_err(|error| PackError::upstream(error.symbol()))?
        {
            PutStatus::Promoted => promoted_objects += 1,
            PutStatus::Present => present_objects += 1,
        }
    }
    Ok(ImportReport {
        pack_id,
        roots,
        promoted_objects,
        present_objects,
    })
}

fn epoch_entry(record: &SchemaEpochRecordV1) -> Result<PackEpochEntry> {
    let canonical = record
        .canonical_bytes()
        .map_err(|error| PackError::upstream(error.code().as_str()))?;
    let bytes = bootstrap_preimage(&canonical)
        .map_err(|error| PackError::upstream(error.code().as_str()))?;
    let schema_epoch_id = record
        .schema_epoch_id()
        .map_err(|error| PackError::upstream(error.code().as_str()))?;
    Ok(PackEpochEntry {
        schema_epoch_id,
        bootstrap_preimage: bytes,
    })
}

fn build_pack(
    epochs: Vec<PackEpochEntry>,
    roots: Vec<PackRootEntry>,
    objects: Vec<PackObjectEntry>,
) -> Result<AcceptedRepositoryPack> {
    check_counts(epochs.len(), roots.len(), objects.len())?;
    let leaves = compute_leaves(&epochs, &roots, &objects)?;
    let digest_tree_root = merkle_root(&leaves)?;
    let payload = encode_payload(&PayloadSections {
        epochs: &epochs,
        roots: &roots,
        objects: &objects,
        refs: &[],
        transactions: &[],
        compression_profile: COMPRESSION_NONE,
        leaves: &leaves,
        tree_root: digest_tree_root,
        signature: None,
    })?;
    let (stored_bytes, pack_id) = stored_pack_bytes(&payload)?;
    Ok(AcceptedRepositoryPack {
        pack_id,
        stored_bytes,
        epochs,
        roots,
        objects,
        digest_tree_root,
    })
}

fn stored_pack_bytes(payload: &[u8]) -> Result<(Vec<u8>, RepositoryPackId)> {
    let epoch_id = pack_epoch_id()?;
    let mut preimage = Vec::with_capacity(payload.len() + 96);
    preimage.extend_from_slice(MAGIC);
    preimage.extend_from_slice(&encode_uvar(FORMAT_VERSION));
    preimage.extend_from_slice(&encode_uvar(u64::from(CONTRACT_TAG)));
    preimage.extend_from_slice(epoch_id.as_bytes());
    preimage.extend_from_slice(&encode_uvar(payload.len() as u64));
    preimage.extend_from_slice(payload);
    let pack_id = RepositoryPackId::derive(&preimage);
    preimage.extend_from_slice(pack_id.as_bytes());
    if preimage.len() > MAX_PACK_BYTES {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    Ok((preimage, pack_id))
}

fn encode_payload(sections: &PayloadSections<'_>) -> Result<Vec<u8>> {
    let epoch_elements = sections
        .epochs
        .iter()
        .map(|entry| {
            encode_record(&[
                (1, entry.schema_epoch_id.as_bytes().to_vec()),
                (2, entry.bootstrap_preimage.clone()),
            ])
        })
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|error| scb_error(&error))?;
    let root_elements = sections
        .roots
        .iter()
        .map(|entry| {
            encode_record(&[
                (1, entry.state_root.as_bytes().to_vec()),
                (2, entry.stored_bytes.clone()),
            ])
        })
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|error| scb_error(&error))?;
    let object_elements = sections
        .objects
        .iter()
        .map(|entry| {
            encode_record(&[
                (1, entry.object_id.as_bytes().to_vec()),
                (2, encode_uvar(entry.stored_bytes.len() as u64)),
                (3, entry.stored_bytes.clone()),
            ])
        })
        .collect::<core::result::Result<Vec<_>, _>>()
        .map_err(|error| scb_error(&error))?;
    let leaf_elements = sections
        .leaves
        .iter()
        .map(|leaf| leaf.to_vec())
        .collect::<Vec<_>>();
    let encoded_refs = encode_list(sections.refs).map_err(|error| scb_error(&error))?;
    let encoded_transactions =
        encode_list(sections.transactions).map_err(|error| scb_error(&error))?;
    let encoded_signature = match sections.signature {
        None => encode_union(0, &[]),
        Some(bytes) => encode_union(1, bytes),
    }
    .map_err(|error| scb_error(&error))?;
    let tree = encode_record(&[
        (1, encode_uvar(TREE_ALGORITHM_TAG)),
        (2, encode_uvar(sections.leaves.len() as u64)),
        (
            3,
            encode_list(&leaf_elements).map_err(|error| scb_error(&error))?,
        ),
        (4, sections.tree_root.to_vec()),
    ])
    .map_err(|error| scb_error(&error))?;
    encode_record(&[
        (1, encode_uvar(FORMAT_VERSION)),
        (
            2,
            encode_list(&epoch_elements).map_err(|error| scb_error(&error))?,
        ),
        (
            3,
            encode_list(&root_elements).map_err(|error| scb_error(&error))?,
        ),
        (4, encoded_refs),
        (
            5,
            encode_list(&object_elements).map_err(|error| scb_error(&error))?,
        ),
        (6, encoded_transactions),
        (7, encode_uvar(sections.compression_profile)),
        (8, tree),
        (9, encoded_signature),
    ])
    .map_err(|error| scb_error(&error))
}

fn decode_envelope(input: &[u8]) -> Result<(SchemaEpochId, &[u8], RepositoryPackId)> {
    if input.len() > MAX_PACK_BYTES {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    let mut reader = Reader::new(input);
    if reader.take_exact(MAGIC.len())? != MAGIC {
        return Err(PackError::upstream(ScbErrorCode::MagicInvalid.as_str()));
    }
    if reader.read_uvar()? != FORMAT_VERSION {
        return Err(PackError::upstream(
            ScbErrorCode::VersionUnsupported.as_str(),
        ));
    }
    if reader.read_uvar()? != u64::from(CONTRACT_TAG) {
        return Err(PackError::upstream(ScbErrorCode::ContractUnknown.as_str()));
    }
    let epoch_id = SchemaEpochId::from_bytes(reader.take_array()?);
    let payload_len = reader.read_len(MAX_PACK_BYTES)?;
    let payload = reader.take_exact(payload_len)?;
    let trailer = reader.take_array::<ID_LEN>()?;
    if !reader.is_finished() {
        return Err(PackError::upstream(ScbErrorCode::TrailingBytes.as_str()));
    }
    let pack_id = RepositoryPackId::derive(&input[..input.len() - DIGEST_TRAILER_LEN]);
    if trailer != *pack_id.as_bytes() {
        return Err(PackError::pack(PackErrorCode::DigestMismatch));
    }
    Ok((epoch_id, payload, pack_id))
}

fn decode_payload(input: &[u8]) -> Result<DecodedPack> {
    let mut record = RecordReader::new(input)?;
    let version_bytes = record.required(1)?;
    let epochs_bytes = record.required(2)?;
    let roots_bytes = record.required(3)?;
    let refs_bytes = record.required(4)?;
    let objects_bytes = record.required(5)?;
    let transactions_bytes = record.required(6)?;
    let compression_bytes = record.required(7)?;
    let tree_bytes = record.required(8)?;
    let signature_bytes = record.required(9)?;
    record.finish()?;

    let version = read_single_uvar(version_bytes)?;
    if version != FORMAT_VERSION {
        return Err(PackError::pack(PackErrorCode::VersionUnsupported));
    }
    decode_empty_section(refs_bytes)?;
    decode_empty_section(transactions_bytes)?;
    let compression_profile = read_single_uvar(compression_bytes)?;
    if compression_profile != COMPRESSION_NONE {
        return Err(PackError::pack(PackErrorCode::CompressionUnsupported));
    }
    decode_absent_signature(signature_bytes)?;

    let epochs = decode_epochs(epochs_bytes)?;
    let roots = decode_roots(roots_bytes)?;
    let objects = decode_objects(objects_bytes)?;
    let (leaves, digest_tree_root) = decode_tree(tree_bytes)?;
    check_counts(epochs.len(), roots.len(), objects.len())?;
    check_expanded_bytes(&epochs, &roots, &objects)?;
    Ok(DecodedPack {
        version,
        epochs,
        roots,
        objects,
        compression_profile,
        leaves,
        digest_tree_root,
    })
}

fn decode_epochs(input: &[u8]) -> Result<Vec<PackEpochEntry>> {
    let elements = decode_list(input, MAX_PACK_EPOCHS)?;
    let mut out = Vec::with_capacity(elements.len());
    for element in elements {
        let mut record = RecordReader::new(element)?;
        let schema_epoch_id = SchemaEpochId::from_bytes(exact_array(record.required(1)?)?);
        let bootstrap_preimage = record.required(2)?.to_vec();
        record.finish()?;
        out.push(PackEpochEntry {
            schema_epoch_id,
            bootstrap_preimage,
        });
    }
    check_id_order(out.iter().map(|entry| entry.schema_epoch_id.as_bytes()))?;
    Ok(out)
}

fn decode_roots(input: &[u8]) -> Result<Vec<PackRootEntry>> {
    let elements = decode_list(input, MAX_PACK_ROOTS)?;
    if elements.is_empty() {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    let mut out = Vec::with_capacity(elements.len());
    for element in elements {
        let mut record = RecordReader::new(element)?;
        let state_root = StateRoot::from_bytes(exact_array(record.required(1)?)?);
        let stored_bytes = record.required(2)?.to_vec();
        record.finish()?;
        out.push(PackRootEntry {
            state_root,
            stored_bytes,
        });
    }
    check_id_order(out.iter().map(|entry| entry.state_root.as_bytes()))?;
    Ok(out)
}

fn decode_objects(input: &[u8]) -> Result<Vec<PackObjectEntry>> {
    let elements = decode_list(input, MAX_PACK_OBJECTS)?;
    let mut out = Vec::with_capacity(elements.len());
    for element in elements {
        let mut record = RecordReader::new(element)?;
        let object_id = ObjectId::from_bytes(exact_array(record.required(1)?)?);
        let declared_len = read_single_uvar(record.required(2)?)?;
        let stored_bytes = record.required(3)?.to_vec();
        record.finish()?;
        if declared_len != stored_bytes.len() as u64 {
            return Err(PackError::pack(PackErrorCode::ObjectCorrupt));
        }
        out.push(PackObjectEntry {
            object_id,
            stored_bytes,
        });
    }
    check_id_order(out.iter().map(|entry| entry.object_id.as_bytes()))?;
    Ok(out)
}

fn decode_tree(input: &[u8]) -> Result<(Vec<[u8; ID_LEN]>, [u8; ID_LEN])> {
    let mut record = RecordReader::new(input)?;
    if read_single_uvar(record.required(1)?)? != TREE_ALGORITHM_TAG {
        return Err(PackError::pack(PackErrorCode::DigestTreeMismatch));
    }
    let count = read_single_uvar(record.required(2)?)?;
    let elements = decode_list(record.required(3)?, MAX_PACK_LEAVES)?;
    let root = exact_array(record.required(4)?)?;
    record.finish()?;
    if count != elements.len() as u64 || elements.is_empty() {
        return Err(PackError::pack(PackErrorCode::DigestTreeMismatch));
    }
    let leaves = elements
        .into_iter()
        .map(exact_array)
        .collect::<Result<Vec<_>>>()?;
    Ok((leaves, root))
}

fn validate_profile(pack: &DecodedPack) -> Result<()> {
    if pack.version != FORMAT_VERSION {
        return Err(PackError::pack(PackErrorCode::VersionUnsupported));
    }
    if pack.compression_profile != COMPRESSION_NONE {
        return Err(PackError::pack(PackErrorCode::CompressionUnsupported));
    }
    Ok(())
}

fn validate_epochs(epochs: &[PackEpochEntry], envelope_epoch: SchemaEpochId) -> Result<()> {
    let root_epoch = conformance_epoch_record()
        .schema_epoch_id()
        .map_err(|_| PackError::pack(PackErrorCode::SchemaUnsupported))?;
    let expected = BTreeSet::from([envelope_epoch, root_epoch]);
    let actual = epochs
        .iter()
        .map(|entry| entry.schema_epoch_id)
        .collect::<BTreeSet<_>>();
    if actual != expected || epochs.len() != expected.len() {
        return Err(PackError::pack(PackErrorCode::SchemaUnsupported));
    }
    for entry in epochs {
        let (derived, _) = import_bootstrap_preimage(&entry.bootstrap_preimage)
            .map_err(|_| PackError::pack(PackErrorCode::SchemaUnsupported))?;
        if derived != entry.schema_epoch_id {
            return Err(PackError::pack(PackErrorCode::SchemaUnsupported));
        }
    }
    Ok(())
}

fn validate_dependency_closure(roots: &[AcceptedStateRoot]) -> Result<()> {
    let ids = roots.iter().map(|root| root.root).collect::<BTreeSet<_>>();
    if roots.iter().any(|root| {
        root.record
            .dependency_roots
            .iter()
            .any(|dependency| !ids.contains(dependency))
    }) {
        return Err(PackError::pack(PackErrorCode::RootInvalid));
    }
    Ok(())
}

fn required_object_ids(roots: &[AcceptedStateRoot]) -> BTreeSet<ObjectId> {
    let mut ids = BTreeSet::new();
    for root in roots {
        ids.insert(root.record.contract_root);
        ids.insert(root.record.test_root);
        ids.extend(
            root.record
                .entity_bindings
                .iter()
                .map(|(_, object)| *object),
        );
    }
    ids
}

fn validate_object_closure(roots: &[AcceptedStateRoot], objects: &[PackObjectEntry]) -> Result<()> {
    let required = required_object_ids(roots);
    let actual = objects
        .iter()
        .map(|object| object.object_id)
        .collect::<BTreeSet<_>>();
    if let Some(_missing) = required.difference(&actual).next() {
        return Err(PackError::pack(PackErrorCode::ObjectMissing));
    }
    if let Some(_unexpected) = actual.difference(&required).next() {
        return Err(PackError::pack(PackErrorCode::ObjectUnexpected));
    }
    Ok(())
}

fn preflight_object<V: CanonicalVerifier>(object: &PackObjectEntry, verifier: &V) -> Result<()> {
    if object.stored_bytes.len() < DIGEST_TRAILER_LEN
        || object.stored_bytes.len() > MAX_STANDALONE_BYTES
    {
        return Err(PackError::pack(PackErrorCode::ObjectCorrupt));
    }
    let preimage_len = object.stored_bytes.len() - DIGEST_TRAILER_LEN;
    let derived = ObjectId::derive(&object.stored_bytes[..preimage_len]);
    if derived != object.object_id || object.stored_bytes[preimage_len..] != *derived.as_bytes() {
        return Err(PackError::pack(PackErrorCode::ObjectCorrupt));
    }
    let verifier_id = verifier
        .verify(&object.stored_bytes)
        .map_err(|_| PackError::pack(PackErrorCode::ObjectCorrupt))?;
    if verifier_id != object.object_id {
        return Err(PackError::pack(PackErrorCode::ObjectCorrupt));
    }
    Ok(())
}

fn verify_digest_tree(pack: &DecodedPack) -> Result<()> {
    let expected = compute_leaves(&pack.epochs, &pack.roots, &pack.objects)?;
    if pack.leaves != expected || merkle_root(&expected)? != pack.digest_tree_root {
        return Err(PackError::pack(PackErrorCode::DigestTreeMismatch));
    }
    Ok(())
}

fn compute_leaves(
    epochs: &[PackEpochEntry],
    roots: &[PackRootEntry],
    objects: &[PackObjectEntry],
) -> Result<Vec<[u8; ID_LEN]>> {
    let count = epochs
        .len()
        .checked_add(roots.len())
        .and_then(|count| count.checked_add(objects.len()))
        .ok_or_else(|| PackError::pack(PackErrorCode::ResourceLimit))?;
    if count == 0 || count > MAX_PACK_LEAVES {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    let mut leaves = Vec::with_capacity(count);
    for entry in epochs {
        leaves.push(content_leaf(
            EPOCH_SECTION,
            entry.schema_epoch_id.as_bytes(),
            &entry.bootstrap_preimage,
        )?);
    }
    for entry in roots {
        leaves.push(content_leaf(
            ROOT_SECTION,
            entry.state_root.as_bytes(),
            &entry.stored_bytes,
        )?);
    }
    for entry in objects {
        leaves.push(content_leaf(
            OBJECT_SECTION,
            entry.object_id.as_bytes(),
            &entry.stored_bytes,
        )?);
    }
    Ok(leaves)
}

fn content_leaf(section: u64, id: &[u8; ID_LEN], bytes: &[u8]) -> Result<[u8; ID_LEN]> {
    let length =
        u64::try_from(bytes.len()).map_err(|_| PackError::pack(PackErrorCode::ResourceLimit))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(&encode_uvar(section));
    hasher.update(id);
    hasher.update(&encode_uvar(length));
    hasher.update(bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn merkle_root(leaves: &[[u8; ID_LEN]]) -> Result<[u8; ID_LEN]> {
    if leaves.is_empty() || leaves.len() > MAX_PACK_LEAVES {
        return Err(PackError::pack(PackErrorCode::DigestTreeMismatch));
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 1 {
                next.push(pair[0]);
            } else {
                let mut hasher = blake3::Hasher::new();
                hasher.update(NODE_DOMAIN);
                hasher.update(&pair[0]);
                hasher.update(&pair[1]);
                next.push(*hasher.finalize().as_bytes());
            }
        }
        level = next;
    }
    Ok(level[0])
}

fn check_counts(epochs: usize, roots: usize, objects: usize) -> Result<()> {
    if epochs == 0
        || epochs > MAX_PACK_EPOCHS
        || roots == 0
        || roots > MAX_PACK_ROOTS
        || objects > MAX_PACK_OBJECTS
    {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    Ok(())
}

fn check_expanded_bytes(
    epochs: &[PackEpochEntry],
    roots: &[PackRootEntry],
    objects: &[PackObjectEntry],
) -> Result<()> {
    let total = epochs
        .iter()
        .map(|entry| entry.bootstrap_preimage.len())
        .chain(roots.iter().map(|entry| entry.stored_bytes.len()))
        .chain(objects.iter().map(|entry| entry.stored_bytes.len()))
        .try_fold(0_usize, usize::checked_add)
        .ok_or_else(|| PackError::pack(PackErrorCode::ResourceLimit))?;
    if total > MAX_EXPANDED_BYTES || total > MAX_PACK_ALLOCATION {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    Ok(())
}

fn check_id_order<'a>(ids: impl Iterator<Item = &'a [u8; ID_LEN]>) -> Result<()> {
    let mut previous: Option<&[u8; ID_LEN]> = None;
    for id in ids {
        if let Some(before) = previous {
            if before == id {
                return Err(PackError::pack(PackErrorCode::DuplicateEntry));
            }
            if before > id {
                return Err(PackError::pack(PackErrorCode::CanonicalOrder));
            }
        }
        previous = Some(id);
    }
    Ok(())
}

fn decode_empty_section(input: &[u8]) -> Result<()> {
    let mut reader = Reader::new(input);
    let count = reader.read_uvar()?;
    if count != 0 {
        return Err(PackError::pack(PackErrorCode::ProfileUnsupported));
    }
    if !reader.is_finished() {
        return Err(PackError::upstream(ScbErrorCode::TrailingBytes.as_str()));
    }
    Ok(())
}

fn decode_absent_signature(input: &[u8]) -> Result<()> {
    let mut reader = Reader::new(input);
    let tag = reader.read_uvar()?;
    let payload_len = reader.read_len(MAX_PACK_BYTES)?;
    let payload = reader.take_exact(payload_len)?;
    if !reader.is_finished() {
        return Err(PackError::upstream(ScbErrorCode::TrailingBytes.as_str()));
    }
    match (tag, payload.is_empty()) {
        (0, true) => Ok(()),
        (1, _) => Err(PackError::pack(PackErrorCode::ProfileUnsupported)),
        _ => Err(PackError::upstream(ScbErrorCode::UnionInvalid.as_str())),
    }
}

fn decode_list(input: &[u8], maximum: usize) -> Result<Vec<&[u8]>> {
    let mut reader = Reader::new(input);
    let count = usize::try_from(reader.read_uvar()?)
        .map_err(|_| PackError::pack(PackErrorCode::ResourceLimit))?;
    if count > maximum || count > reader.remaining() {
        return Err(PackError::pack(PackErrorCode::ResourceLimit));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = reader.read_len(MAX_PACK_BYTES)?;
        out.push(reader.take_exact(len)?);
    }
    if !reader.is_finished() {
        return Err(PackError::upstream(ScbErrorCode::TrailingBytes.as_str()));
    }
    Ok(out)
}

fn read_single_uvar(input: &[u8]) -> Result<u64> {
    let mut reader = Reader::new(input);
    let value = reader.read_uvar()?;
    if !reader.is_finished() {
        return Err(PackError::upstream(ScbErrorCode::TrailingBytes.as_str()));
    }
    Ok(value)
}

fn exact_array<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    input
        .try_into()
        .map_err(|_| PackError::upstream(ScbErrorCode::LengthOverflow.as_str()))
}

fn scb_error(error: &ScbError) -> PackError {
    PackError::upstream(error.code().as_str())
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }

    fn take_exact(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| PackError::upstream(ScbErrorCode::LengthOverflow.as_str()))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| PackError::upstream(ScbErrorCode::LengthOverflow.as_str()))?;
        self.offset = end;
        Ok(bytes)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        exact_array(self.take_exact(N)?)
    }

    fn read_len(&mut self, maximum: usize) -> Result<usize> {
        let value = self.read_uvar()?;
        let value = usize::try_from(value)
            .map_err(|_| PackError::upstream(ScbErrorCode::LengthOverflow.as_str()))?;
        if value > maximum {
            return Err(PackError::pack(PackErrorCode::ResourceLimit));
        }
        Ok(value)
    }

    fn read_uvar(&mut self) -> Result<u64> {
        let start = self.offset;
        let mut value = 0_u64;
        for shift in (0..70).step_by(7) {
            let byte = *self
                .input
                .get(self.offset)
                .ok_or_else(|| PackError::upstream(ScbErrorCode::LengthOverflow.as_str()))?;
            self.offset += 1;
            if shift == 63 && byte > 1 {
                return Err(PackError::upstream(ScbErrorCode::IntegerOverflow.as_str()));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if self.offset - start != encode_uvar(value).len() {
                    return Err(PackError::upstream(ScbErrorCode::VarintNonMinimal.as_str()));
                }
                return Ok(value);
            }
        }
        Err(PackError::upstream(ScbErrorCode::IntegerOverflow.as_str()))
    }
}

struct RecordReader<'a> {
    reader: Reader<'a>,
    remaining: u64,
    previous_tag: Option<u64>,
}

impl<'a> RecordReader<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let remaining = reader.read_uvar()?;
        if remaining > FIELD_COUNT.max(65_535) {
            return Err(PackError::pack(PackErrorCode::ResourceLimit));
        }
        Ok(Self {
            reader,
            remaining,
            previous_tag: None,
        })
    }

    fn required(&mut self, expected: u64) -> Result<&'a [u8]> {
        if self.remaining == 0 {
            return Err(PackError::upstream(ScbErrorCode::FieldMissing.as_str()));
        }
        let tag = self.reader.read_uvar()?;
        if self.previous_tag.is_some_and(|previous| tag <= previous) {
            return Err(PackError::upstream(if self.previous_tag == Some(tag) {
                ScbErrorCode::FieldDuplicate.as_str()
            } else {
                ScbErrorCode::FieldOrder.as_str()
            }));
        }
        if tag != expected {
            return Err(PackError::upstream(if tag > expected {
                ScbErrorCode::FieldMissing.as_str()
            } else {
                ScbErrorCode::FieldUnknown.as_str()
            }));
        }
        let len = self.reader.read_len(MAX_PACK_BYTES)?;
        let value = self.reader.take_exact(len)?;
        self.previous_tag = Some(tag);
        self.remaining -= 1;
        Ok(value)
    }

    fn finish(self) -> Result<()> {
        if self.remaining != 0 {
            return Err(PackError::upstream(ScbErrorCode::FieldUnknown.as_str()));
        }
        if !self.reader.is_finished() {
            return Err(PackError::upstream(ScbErrorCode::TrailingBytes.as_str()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use sley_id::{EntityId, ObjectId, PolicyRootId, WorkspaceId};
    use sley_scb1::{FixtureContract, decode_standalone_fixture, encode_standalone_fixture};
    use sley_state_root::{StateRootBuilder, conformance_registry};
    use sley_store::StoreErrorCode;

    use super::*;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sley2-pack-{label}-{}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn verifier(record: &[u8]) -> core::result::Result<ObjectId, ScbError> {
        decode_standalone_fixture(record, FixtureContract::EmptyObject)
            .or_else(|_| decode_standalone_fixture(record, FixtureContract::RequiredBool))
            .map(|fixture| fixture.object_id)
    }

    fn fixture() -> (TempRoot, ObjectStore, AcceptedStateRoot, Vec<Vec<u8>>) {
        let temp = TempRoot::new("fixture");
        let store = ObjectStore::new(&temp.0);
        let (first, first_id) =
            encode_standalone_fixture(FixtureContract::EmptyObject, &encode_record(&[]).unwrap())
                .unwrap();
        let bool_payload = encode_record(&[(1, vec![1])]).unwrap();
        let (second, second_id) =
            encode_standalone_fixture(FixtureContract::RequiredBool, &bool_payload).unwrap();
        store.put(first_id, &first, &verifier).unwrap();
        store.put(second_id, &second, &verifier).unwrap();
        let registry = conformance_registry().unwrap();
        let root = StateRootBuilder::new(
            WorkspaceId::from_bytes([7; 32]),
            first_id,
            second_id,
            PolicyRootId::from_bytes([9; 32]),
        )
        .entity_binding(EntityId::from_bytes([8; 32]), first_id)
        .entry_point(EntityId::from_bytes([8; 32]))
        .build(&registry)
        .unwrap();
        (temp, store, root, vec![first, second])
    }

    #[allow(clippy::too_many_arguments)]
    fn custom_pack(
        pack: &AcceptedRepositoryPack,
        objects: &[PackObjectEntry],
        refs: &[Vec<u8>],
        transactions: &[Vec<u8>],
        compression_profile: u64,
        leaves: &[[u8; ID_LEN]],
        tree_root: [u8; ID_LEN],
        signature: Option<&[u8]>,
    ) -> Vec<u8> {
        let payload = encode_payload(&PayloadSections {
            epochs: &pack.epochs,
            roots: &pack.roots,
            objects,
            refs,
            transactions,
            compression_profile,
            leaves,
            tree_root,
            signature,
        })
        .unwrap();
        stored_pack_bytes(&payload).unwrap().0
    }

    #[test]
    fn clean_import_reconstructs_exact_root_and_is_idempotent() {
        let (_source_temp, source, root, _) = fixture();
        let pack =
            export_conformance_pack(&source, std::slice::from_ref(&root), &verifier).unwrap();
        let clean_temp = TempRoot::new("clean");
        let clean = ObjectStore::new(&clean_temp.0);
        let first = import_conformance_pack(&clean, &pack.stored_bytes, &verifier).unwrap();
        assert_eq!(first.pack_id, pack.pack_id);
        assert_eq!(first.roots, vec![root.clone()]);
        assert_eq!(first.promoted_objects, 2);
        let second = import_conformance_pack(&clean, &pack.stored_bytes, &verifier).unwrap();
        assert_eq!(second.roots, vec![root]);
        assert_eq!(second.present_objects, 2);
    }

    #[test]
    fn export_root_order_is_canonical() {
        let (_source_temp, source, root, _) = fixture();
        let one = export_conformance_pack(&source, std::slice::from_ref(&root), &verifier).unwrap();
        let two = export_conformance_pack(&source, &[root], &verifier).unwrap();
        assert_eq!(one.stored_bytes, two.stored_bytes);
    }

    #[test]
    fn outer_digest_tamper_fails_before_promotion() {
        let (_source_temp, source, root, _) = fixture();
        let mut bytes = export_conformance_pack(&source, &[root], &verifier)
            .unwrap()
            .stored_bytes;
        let index = bytes.len() - 1;
        bytes[index] ^= 1;
        let clean_temp = TempRoot::new("tamper");
        let clean = ObjectStore::new(&clean_temp.0);
        let error = import_conformance_pack(&clean, &bytes, &verifier).unwrap_err();
        assert_eq!(error.symbol(), "PACK_DIGEST_MISMATCH");
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn object_verifier_failure_precedes_all_promotions() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let clean_temp = TempRoot::new("verifier");
        let clean = ObjectStore::new(&clean_temp.0);
        let reject = |_record: &[u8]| Err(ScbError::new(ScbErrorCode::ContractUnknown));
        let error = import_conformance_pack(&clean, &pack.stored_bytes, &reject).unwrap_err();
        assert_eq!(error.symbol(), "PACK_OBJECT_CORRUPT");
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn dependency_requires_included_root() {
        let (_source_temp, source, root, _) = fixture();
        let registry = conformance_registry().unwrap();
        let dependent = StateRootBuilder::new(
            root.record.workspace_id,
            root.record.contract_root,
            root.record.test_root,
            root.record.policy_root,
        )
        .dependency_root(root.root)
        .build(&registry)
        .unwrap();
        let error = export_conformance_pack(&source, &[dependent], &verifier).unwrap_err();
        assert_eq!(error.symbol(), "PACK_ROOT_INVALID");
    }

    #[test]
    fn duplicate_root_is_rejected() {
        let (_source_temp, source, root, _) = fixture();
        let error = export_conformance_pack(&source, &[root.clone(), root], &verifier).unwrap_err();
        assert_eq!(error.symbol(), "PACK_DUPLICATE_ENTRY");
    }

    #[test]
    fn pack_epoch_descriptor_is_frozen() {
        let record = pack_epoch_record();
        let descriptor = &record.contracts[0];
        assert_eq!(descriptor.contract_tag, 170);
        assert_eq!(descriptor.digest_domain_tag, 18);
        assert_eq!(descriptor.kind_tag, 170);
        assert_eq!(descriptor.field_schema_hash, FIELD_SCHEMA_HASH);
        assert_eq!(descriptor.decoder_limits_hash, DECODER_LIMITS_HASH);
        assert_ne!(pack_epoch_id().unwrap().as_bytes(), &[0; 32]);
    }

    #[test]
    fn tree_changes_when_content_changes() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let mut object = pack.objects[0].clone();
        object.stored_bytes[0] ^= 1;
        let changed = compute_leaves(&pack.epochs, &pack.roots, &[object]).unwrap();
        assert_ne!(changed, pack.leaves_for_test());
    }

    impl AcceptedRepositoryPack {
        fn leaves_for_test(&self) -> Vec<[u8; ID_LEN]> {
            compute_leaves(&self.epochs, &self.roots, &self.objects).unwrap()
        }
    }

    #[test]
    fn nonminimal_outer_varint_is_rejected() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let mut bytes = pack.stored_bytes;
        bytes.splice(8..9, [0x81, 0x00]);
        let clean_temp = TempRoot::new("nonminimal");
        let clean = ObjectStore::new(&clean_temp.0);
        assert_eq!(
            import_conformance_pack(&clean, &bytes, &verifier)
                .unwrap_err()
                .symbol(),
            "SCB_VARINT_NON_MINIMAL"
        );
    }

    #[test]
    fn stable_reserved_error_symbol_exists() {
        assert_eq!(
            PackErrorCode::DecompressionLimit.as_str(),
            "PACK_DECOMPRESSION_LIMIT"
        );
        assert_eq!(
            StoreErrorCode::StoreObjectSubstitution.symbol(),
            "STORE_OBJECT_SUBSTITUTION"
        );
    }

    #[test]
    fn missing_object_fails_before_promotion() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let objects = &pack.objects[..1];
        let leaves = compute_leaves(&pack.epochs, &pack.roots, objects).unwrap();
        let bytes = custom_pack(
            &pack,
            objects,
            &[],
            &[],
            0,
            &leaves,
            merkle_root(&leaves).unwrap(),
            None,
        );
        let clean_temp = TempRoot::new("missing");
        let clean = ObjectStore::new(&clean_temp.0);
        assert_eq!(
            import_conformance_pack(&clean, &bytes, &verifier)
                .unwrap_err()
                .symbol(),
            "PACK_OBJECT_MISSING"
        );
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn surplus_object_fails_before_promotion() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let payload = encode_record(&[(1, vec![0])]).unwrap();
        let (stored_bytes, object_id) =
            encode_standalone_fixture(FixtureContract::RequiredBool, &payload).unwrap();
        let mut objects = pack.objects.clone();
        objects.push(PackObjectEntry {
            object_id,
            stored_bytes,
        });
        objects.sort_by_key(|object| object.object_id);
        let leaves = compute_leaves(&pack.epochs, &pack.roots, &objects).unwrap();
        let bytes = custom_pack(
            &pack,
            &objects,
            &[],
            &[],
            0,
            &leaves,
            merkle_root(&leaves).unwrap(),
            None,
        );
        let clean_temp = TempRoot::new("surplus");
        let clean = ObjectStore::new(&clean_temp.0);
        assert_eq!(
            import_conformance_pack(&clean, &bytes, &verifier)
                .unwrap_err()
                .symbol(),
            "PACK_OBJECT_UNEXPECTED"
        );
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn reordered_inventory_fails_before_promotion() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let mut objects = pack.objects.clone();
        objects.reverse();
        let leaves = compute_leaves(&pack.epochs, &pack.roots, &objects).unwrap();
        let bytes = custom_pack(
            &pack,
            &objects,
            &[],
            &[],
            0,
            &leaves,
            merkle_root(&leaves).unwrap(),
            None,
        );
        let clean_temp = TempRoot::new("order");
        let clean = ObjectStore::new(&clean_temp.0);
        assert_eq!(
            import_conformance_pack(&clean, &bytes, &verifier)
                .unwrap_err()
                .symbol(),
            "PACK_CANONICAL_ORDER"
        );
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn substituted_object_fails_before_promotion() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let mut objects = pack.objects.clone();
        objects[0].stored_bytes[0] ^= 1;
        let leaves = compute_leaves(&pack.epochs, &pack.roots, &objects).unwrap();
        let bytes = custom_pack(
            &pack,
            &objects,
            &[],
            &[],
            0,
            &leaves,
            merkle_root(&leaves).unwrap(),
            None,
        );
        let clean_temp = TempRoot::new("substitution");
        let clean = ObjectStore::new(&clean_temp.0);
        assert_eq!(
            import_conformance_pack(&clean, &bytes, &verifier)
                .unwrap_err()
                .symbol(),
            "PACK_OBJECT_CORRUPT"
        );
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn altered_tree_with_valid_outer_id_is_rejected() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let mut leaves = pack.leaves_for_test();
        leaves[0][0] ^= 1;
        let bytes = custom_pack(
            &pack,
            &pack.objects,
            &[],
            &[],
            0,
            &leaves,
            pack.digest_tree_root,
            None,
        );
        let clean_temp = TempRoot::new("tree");
        let clean = ObjectStore::new(&clean_temp.0);
        assert_eq!(
            import_conformance_pack(&clean, &bytes, &verifier)
                .unwrap_err()
                .symbol(),
            "PACK_DIGEST_TREE_MISMATCH"
        );
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn later_profiles_fail_closed() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let leaves = pack.leaves_for_test();
        let clean_temp = TempRoot::new("profiles");
        let clean = ObjectStore::new(&clean_temp.0);
        for (bytes, expected) in [
            (
                custom_pack(
                    &pack,
                    &pack.objects,
                    &[],
                    &[],
                    1,
                    &leaves,
                    pack.digest_tree_root,
                    None,
                ),
                "PACK_COMPRESSION_UNSUPPORTED",
            ),
            (
                custom_pack(
                    &pack,
                    &pack.objects,
                    &[Vec::new()],
                    &[],
                    0,
                    &leaves,
                    pack.digest_tree_root,
                    None,
                ),
                "PACK_PROFILE_UNSUPPORTED",
            ),
            (
                custom_pack(
                    &pack,
                    &pack.objects,
                    &[],
                    &[Vec::new()],
                    0,
                    &leaves,
                    pack.digest_tree_root,
                    None,
                ),
                "PACK_PROFILE_UNSUPPORTED",
            ),
            (
                custom_pack(
                    &pack,
                    &pack.objects,
                    &[],
                    &[],
                    0,
                    &leaves,
                    pack.digest_tree_root,
                    Some(b"signature"),
                ),
                "PACK_PROFILE_UNSUPPORTED",
            ),
        ] {
            assert_eq!(
                import_conformance_pack(&clean, &bytes, &verifier)
                    .unwrap_err()
                    .symbol(),
                expected
            );
        }
        assert!(!clean.root().join("objects").exists());
    }

    #[test]
    fn bounded_pack_import_fuzz_smoke_rejects_rehashed_mutations() {
        let (_source_temp, source, root, _) = fixture();
        let pack = export_conformance_pack(&source, &[root], &verifier).unwrap();
        let preimage_len = pack.stored_bytes.len() - ID_LEN;
        let mutable_len = preimage_len - MAGIC.len();
        for seed in 0..128_usize {
            let mut bytes = pack.stored_bytes.clone();
            let index = MAGIC.len() + (seed.wrapping_mul(2_654_435_761) % mutable_len);
            bytes[index] ^= 1_u8 << (seed % 8);
            let mutated_id = RepositoryPackId::derive(&bytes[..preimage_len]);
            bytes[preimage_len..].copy_from_slice(mutated_id.as_bytes());
            let clean_temp = TempRoot::new("pack-fuzz-smoke");
            let clean = ObjectStore::new(&clean_temp.0);
            assert!(import_conformance_pack(&clean, &bytes, &verifier).is_err());
            assert!(!clean.root().join("objects").exists());
        }
    }
}
