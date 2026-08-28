#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;

use sley_id::{SchemaEpochId, StateRoot};
use sley_scb1::{
    MAX_COLLECTION_ELEMENTS, MAX_RECORD_FIELDS, MAX_STANDALONE_BYTES, ScbError, encode_list,
    encode_record, encode_union, encode_uvar,
};

/// Exact frozen SSMC1 epoch-1 schema manifest used by generated schema consumers.
pub const SSMC1_EPOCH1_MANIFEST: &[u8] =
    include_bytes!("../../../docs/spec/SSMC1_EPOCH1_SCHEMA.txt");

/// BLAKE3-256 of [`SSMC1_EPOCH1_MANIFEST`].
pub const SSMC1_EPOCH1_MANIFEST_BLAKE3: [u8; 32] = [
    0x19, 0x83, 0xbc, 0x8d, 0x6a, 0xd9, 0xac, 0x3c, 0xb5, 0x39, 0x08, 0x53, 0xf4, 0x39, 0x59, 0xcf,
    0x2c, 0x3d, 0xc0, 0xae, 0x8e, 0x0c, 0xa1, 0x8c, 0xa8, 0x26, 0x4c, 0xa4, 0x96, 0x01, 0x33, 0xae,
];

const BOOTSTRAP_MAGIC: &[u8; 8] = b"SLEYEP01";
const BOOTSTRAP_VERSION: u64 = 1;
const SCB_FORMAT_VERSION: u32 = 1;
const HASH_ALGORITHM_BLAKE3_256: u32 = 1;
const ID_LEN: usize = 32;
const NAMESPACE_LEN: usize = 16;

/// Stable S20-140 schema failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaErrorCode {
    /// `SCHEMA_EPOCH_MISMATCH`
    EpochMismatch,
    /// `SCHEMA_DOWNGRADE`
    Downgrade,
    /// `SCHEMA_CONTRACT_UNKNOWN`
    ContractUnknown,
    /// `SCHEMA_MIGRATION_UNSUPPORTED`
    MigrationUnsupported,
    /// `SCHEMA_EQUIVALENCE_FAILED`
    EquivalenceFailed,
    /// `SCHEMA_SELF_MODIFICATION`
    SelfModification,
    /// `SCHEMA_ROOT_OVERWRITE_FORBIDDEN`
    RootOverwriteForbidden,
    /// `SCHEMA_RECORD_INVALID`
    RecordInvalid,
}

impl SchemaErrorCode {
    /// Returns the exact stable error code string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EpochMismatch => "SCHEMA_EPOCH_MISMATCH",
            Self::Downgrade => "SCHEMA_DOWNGRADE",
            Self::ContractUnknown => "SCHEMA_CONTRACT_UNKNOWN",
            Self::MigrationUnsupported => "SCHEMA_MIGRATION_UNSUPPORTED",
            Self::EquivalenceFailed => "SCHEMA_EQUIVALENCE_FAILED",
            Self::SelfModification => "SCHEMA_SELF_MODIFICATION",
            Self::RootOverwriteForbidden => "SCHEMA_ROOT_OVERWRITE_FORBIDDEN",
            Self::RecordInvalid => "SCHEMA_RECORD_INVALID",
        }
    }
}

impl fmt::Display for SchemaErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Schema-layer error with a stable failure code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaError {
    code: SchemaErrorCode,
}

impl SchemaError {
    /// Constructs a schema error from a stable code.
    #[must_use]
    pub const fn new(code: SchemaErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable schema failure code.
    #[must_use]
    pub const fn code(&self) -> SchemaErrorCode {
        self.code
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(f)
    }
}

impl std::error::Error for SchemaError {}

/// Exact failure from registry selection or the preserved epoch decoder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochDecodeError {
    /// Registry/schema selection failed before decoding.
    Schema(SchemaError),
    /// The exact selected decoder returned its stable SCB1 failure.
    Scb(ScbError),
}

impl fmt::Display for EpochDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(error) => error.fmt(f),
            Self::Scb(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for EpochDecodeError {}

impl From<ScbError> for SchemaError {
    fn from(_value: ScbError) -> Self {
        Self::new(SchemaErrorCode::RecordInvalid)
    }
}

/// Schema crate result type.
pub type Result<T> = core::result::Result<T, SchemaError>;

/// Fixed 32-byte schema-adjacent digest.
pub type FixedDigest = [u8; ID_LEN];

/// Fixed 16-byte extension namespace identifier.
pub type NamespaceId = [u8; NAMESPACE_LEN];

/// Frozen Unicode version record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnicodeVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl UnicodeVersion {
    /// S20-140 epoch-1 Unicode version.
    pub const EPOCH_1: Self = Self {
        major: 16,
        minor: 0,
        patch: 0,
    };

    fn encode(self) -> Result<Vec<u8>> {
        encode_record(&[
            (1, encode_uvar(u64::from(self.major))),
            (2, encode_uvar(u64::from(self.minor))),
            (3, encode_uvar(u64::from(self.patch))),
        ])
        .map_err(Into::into)
    }

    fn validate(self) -> Result<()> {
        if self == Self::EPOCH_1 {
            Ok(())
        } else {
            Err(SchemaError::new(SchemaErrorCode::RecordInvalid))
        }
    }
}

/// S20-140 epoch limits record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochLimits {
    /// Maximum standalone stored bytes.
    pub standalone_stored_bytes: u64,
    /// Maximum byte, text, label, or extension payload bytes.
    pub payload_bytes: u64,
    /// Maximum nesting depth.
    pub nesting_depth: u64,
    /// Maximum fields per record.
    pub fields_per_record: u64,
    /// Maximum elements per list, set, or map.
    pub collection_elements: u64,
    /// Maximum decoded standalone values per request.
    pub decoded_standalone_values_per_request: u64,
    /// Maximum decoder allocation per standalone value.
    pub decoder_allocation_per_standalone_value: u64,
}

impl EpochLimits {
    /// S20-140 epoch-1 limits.
    pub const EPOCH_1: Self = Self {
        standalone_stored_bytes: 67_108_864,
        payload_bytes: 16_777_216,
        nesting_depth: 64,
        fields_per_record: 65_535,
        collection_elements: 1_000_000,
        decoded_standalone_values_per_request: 1_000_000,
        decoder_allocation_per_standalone_value: 134_217_728,
    };

    fn encode(self) -> Result<Vec<u8>> {
        encode_record(&[
            (1, encode_uvar(self.standalone_stored_bytes)),
            (2, encode_uvar(self.payload_bytes)),
            (3, encode_uvar(self.nesting_depth)),
            (4, encode_uvar(self.fields_per_record)),
            (5, encode_uvar(self.collection_elements)),
            (6, encode_uvar(self.decoded_standalone_values_per_request)),
            (7, encode_uvar(self.decoder_allocation_per_standalone_value)),
        ])
        .map_err(Into::into)
    }

    fn validate(self) -> Result<()> {
        if self == Self::EPOCH_1 {
            Ok(())
        } else {
            Err(SchemaError::new(SchemaErrorCode::RecordInvalid))
        }
    }
}

/// Frozen contract descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDescriptor {
    /// Epoch-unique contract tag.
    pub contract_tag: u32,
    /// Epoch-unique digest-domain tag.
    pub digest_domain_tag: u32,
    /// Epoch-unique kind tag.
    pub kind_tag: u32,
    /// Hash of the separately frozen exact field schema.
    pub field_schema_hash: FixedDigest,
    /// Required field tags.
    pub required_fields: Vec<u32>,
    /// Optional field tags.
    pub optional_fields: Vec<u32>,
    /// Variant tags.
    pub variant_tags: Vec<u32>,
    /// Hash of decoder limits.
    pub decoder_limits_hash: FixedDigest,
}

impl ContractDescriptor {
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_record(&[
            (1, encode_uvar(u64::from(self.contract_tag))),
            (2, encode_uvar(u64::from(self.digest_domain_tag))),
            (3, encode_uvar(u64::from(self.kind_tag))),
            (4, self.field_schema_hash.to_vec()),
            (5, encode_u32_set(&self.required_fields)?),
            (6, encode_u32_set(&self.optional_fields)?),
            (7, encode_u32_set(&self.variant_tags)?),
            (8, self.decoder_limits_hash.to_vec()),
        ])
        .map_err(Into::into)
    }

    fn validate(&self) -> Result<()> {
        validate_sorted_unique_u32(&self.required_fields)?;
        validate_sorted_unique_u32(&self.optional_fields)?;
        validate_sorted_unique_u32(&self.variant_tags)?;
        if intersects_sorted(&self.required_fields, &self.optional_fields) {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        Ok(())
    }
}

/// Frozen extension descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionDescriptor {
    /// Epoch-unique extension namespace.
    pub namespace_id: NamespaceId,
    /// Epoch-unique type tag under the namespace tuple.
    pub type_tag: u32,
    /// Extension version.
    pub version: u32,
    /// Hash of the extension payload schema.
    pub payload_schema_hash: FixedDigest,
}

impl ExtensionDescriptor {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_record(&[
            (1, self.namespace_id.to_vec()),
            (2, encode_uvar(u64::from(self.type_tag))),
            (3, encode_uvar(u64::from(self.version))),
            (4, self.payload_schema_hash.to_vec()),
        ])
        .map_err(Into::into)
    }
}

/// Frozen migration contract descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationContractDescriptor {
    /// Exact predecessor epoch.
    pub predecessor_epoch: SchemaEpochId,
    /// Exact contract identifier.
    pub contract_id: FixedDigest,
    /// Exact equivalence verifier identifier.
    pub verifier_id: FixedDigest,
    /// Exact migration scope hash.
    pub scope_hash: FixedDigest,
}

impl MigrationContractDescriptor {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_record(&[
            (1, self.predecessor_epoch.as_bytes().to_vec()),
            (2, self.contract_id.to_vec()),
            (3, self.verifier_id.to_vec()),
            (4, self.scope_hash.to_vec()),
        ])
        .map_err(Into::into)
    }

    fn matches_plan(&self, plan: &MigrationPlan) -> bool {
        self.predecessor_epoch == plan.old_epoch
            && self.contract_id == plan.contract_id
            && self.verifier_id == plan.verifier_id
            && self.scope_hash == plan.scope_hash
    }
}

/// Canonical schema epoch record v1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaEpochRecordV1 {
    /// Monotonic epoch number.
    pub epoch_number: u32,
    /// Closed SCB format version. S20-140 permits only `1`.
    pub scb_format_version: u32,
    /// Closed hash algorithm tag. S20-140 permits only `1` for BLAKE3-256.
    pub hash_algorithm_tag: u32,
    /// Frozen Unicode version.
    pub unicode_nfc_version: UnicodeVersion,
    /// Frozen epoch limits.
    pub limits: EpochLimits,
    /// Contract descriptors sorted by complete canonical bytes.
    pub contracts: Vec<ContractDescriptor>,
    /// Extension descriptors sorted by complete canonical bytes.
    pub extensions: Vec<ExtensionDescriptor>,
    /// Exact predecessor epoch, if any.
    pub predecessor: Option<SchemaEpochId>,
    /// Migration descriptors sorted by complete canonical bytes.
    pub migration_contracts: Vec<MigrationContractDescriptor>,
}

impl SchemaEpochRecordV1 {
    /// Returns canonical SCB1 record bytes for this frozen meta-schema record.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_RECORD_INVALID` if the record violates S20-140 invariants.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_record(&[
            (1, encode_uvar(u64::from(self.epoch_number))),
            (2, encode_uvar(u64::from(self.scb_format_version))),
            (3, encode_uvar(u64::from(self.hash_algorithm_tag))),
            (4, self.unicode_nfc_version.encode()?),
            (5, self.limits.encode()?),
            (
                6,
                encode_descriptor_set(&self.contracts, ContractDescriptor::encode)?,
            ),
            (
                7,
                encode_descriptor_set(&self.extensions, ExtensionDescriptor::encode)?,
            ),
            (8, encode_option_epoch(self.predecessor)?),
            (
                9,
                encode_descriptor_set(
                    &self.migration_contracts,
                    MigrationContractDescriptor::encode,
                )?,
            ),
        ])
        .map_err(Into::into)
    }

    /// Derives the exact `SchemaEpochId` using the fixed SLEYEP01 bootstrap preimage.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_RECORD_INVALID` if canonical record encoding fails.
    pub fn schema_epoch_id(&self) -> Result<SchemaEpochId> {
        Ok(SchemaEpochId::derive(bootstrap_preimage(
            &self.canonical_bytes()?,
        )?))
    }

    /// Validates the epoch record against S20-140 v1 constraints.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_RECORD_INVALID` if any closed tag, descriptor set, or uniqueness
    /// invariant is violated.
    pub fn validate(&self) -> Result<()> {
        if self.epoch_number == 0
            || (self.epoch_number == 1 && self.predecessor.is_some())
            || (self.epoch_number > 1 && self.predecessor.is_none())
            || self.scb_format_version != SCB_FORMAT_VERSION
            || self.hash_algorithm_tag != HASH_ALGORITHM_BLAKE3_256
        {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        self.unicode_nfc_version.validate()?;
        self.limits.validate()?;
        validate_descriptor_set(&self.contracts, ContractDescriptor::encode)?;
        validate_descriptor_set(&self.extensions, ExtensionDescriptor::encode)?;
        validate_descriptor_set(
            &self.migration_contracts,
            MigrationContractDescriptor::encode,
        )?;
        validate_contract_uniqueness(&self.contracts)?;
        validate_extension_uniqueness(&self.extensions)?;
        if self
            .migration_contracts
            .iter()
            .any(|descriptor| Some(descriptor.predecessor_epoch) != self.predecessor)
        {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        Ok(())
    }

    fn migration_descriptor(&self, plan: &MigrationPlan) -> Option<&MigrationContractDescriptor> {
        self.migration_contracts
            .iter()
            .find(|descriptor| descriptor.matches_plan(plan))
    }
}

/// Builds the exact SLEYEP01 bootstrap preimage from canonical record bytes.
///
/// # Errors
///
/// Returns `SCHEMA_RECORD_INVALID` if the record length cannot be encoded.
pub fn bootstrap_preimage(epoch_record: &[u8]) -> Result<Vec<u8>> {
    if epoch_record.len() > MAX_STANDALONE_BYTES {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    let record_len = u64::try_from(epoch_record.len())
        .map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
    let mut out = Vec::with_capacity(BOOTSTRAP_MAGIC.len() + 10 + 10 + epoch_record.len());
    out.extend_from_slice(BOOTSTRAP_MAGIC);
    out.extend_from_slice(&encode_uvar(BOOTSTRAP_VERSION));
    out.extend_from_slice(&encode_uvar(record_len));
    out.extend_from_slice(epoch_record);
    Ok(out)
}

/// Imports a SLEYEP01 bootstrap preimage and returns the decoded record plus derived ID.
///
/// # Errors
///
/// Returns `SCHEMA_RECORD_INVALID` for non-minimal lengths, trailing data, or invalid records.
pub fn import_bootstrap_preimage(input: &[u8]) -> Result<(SchemaEpochId, SchemaEpochRecordV1)> {
    let mut reader = Reader::new(input);
    if reader.take_exact(BOOTSTRAP_MAGIC.len())? != BOOTSTRAP_MAGIC {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    if reader.read_uvar_width(64)? != BOOTSTRAP_VERSION {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    let record_len = reader.read_len(MAX_STANDALONE_BYTES)?;
    let record_bytes = reader.take_exact(record_len)?;
    if !reader.is_finished() {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    let record = decode_epoch_record(record_bytes)?;
    let epoch_id = SchemaEpochId::derive(input);
    if record.canonical_bytes()? != record_bytes {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    Ok((epoch_id, record))
}

/// Decoder preserved for one exact schema epoch.
pub trait EpochDecoder {
    /// Returns the exact epoch this decoder is allowed to decode.
    fn epoch_id(&self) -> SchemaEpochId;

    /// Decodes one exact contract under this preserved epoch implementation.
    ///
    /// # Errors
    ///
    /// Returns the decoder's original stable SCB1 failure without translation.
    fn decode_contract(
        &self,
        contract_tag: u32,
        input: &[u8],
    ) -> core::result::Result<(), ScbError>;
}

/// Immutable registry entry.
#[derive(Clone, Debug)]
pub struct RegistryEntry<D> {
    epoch_id: SchemaEpochId,
    record: SchemaEpochRecordV1,
    decoder: D,
}

impl<D: EpochDecoder> RegistryEntry<D> {
    /// Constructs a registry entry after checking the record and decoder binding.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_EPOCH_MISMATCH` when the key, record ID, or decoder epoch differ.
    pub fn new(epoch_id: SchemaEpochId, record: SchemaEpochRecordV1, decoder: D) -> Result<Self> {
        if record.schema_epoch_id()? != epoch_id || decoder.epoch_id() != epoch_id {
            return Err(SchemaError::new(SchemaErrorCode::EpochMismatch));
        }
        Ok(Self {
            epoch_id,
            record,
            decoder,
        })
    }
}

/// Immutable, exact-ID schema epoch registry.
#[derive(Clone, Debug)]
pub struct SchemaEpochRegistry<D> {
    entries: Vec<RegistryEntry<D>>,
}

impl<D: EpochDecoder> SchemaEpochRegistry<D> {
    /// Constructs a registry from a strictly ID-sorted static entry set.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_EPOCH_MISMATCH` for unsorted, duplicate, mismatched, or
    /// decoder-mismatched entries.
    pub fn new(entries: Vec<RegistryEntry<D>>) -> Result<Self> {
        if entries
            .windows(2)
            .any(|pair| pair[0].epoch_id >= pair[1].epoch_id)
        {
            return Err(SchemaError::new(SchemaErrorCode::EpochMismatch));
        }
        for entry in &entries {
            if entry.record.schema_epoch_id()? != entry.epoch_id
                || entry.decoder.epoch_id() != entry.epoch_id
            {
                return Err(SchemaError::new(SchemaErrorCode::EpochMismatch));
            }
        }
        Ok(Self { entries })
    }

    /// Returns the exact registry entry for an epoch ID.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_EPOCH_MISMATCH` when the exact ID is absent.
    pub fn lookup(&self, epoch_id: SchemaEpochId) -> Result<&RegistryEntry<D>> {
        self.entries
            .binary_search_by_key(&epoch_id, |entry| entry.epoch_id)
            .map(|index| &self.entries[index])
            .map_err(|_| SchemaError::new(SchemaErrorCode::EpochMismatch))
    }

    /// Looks up an epoch while enforcing an equal-or-newer epoch-number requirement.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_DOWNGRADE` when the selected epoch number is below the requirement.
    /// Returns `SCHEMA_EPOCH_MISMATCH` when the exact ID is absent.
    pub fn lookup_equal_or_newer(
        &self,
        epoch_id: SchemaEpochId,
        minimum_epoch_number: u32,
    ) -> Result<&RegistryEntry<D>> {
        let entry = self.lookup(epoch_id)?;
        if entry.record.epoch_number < minimum_epoch_number {
            return Err(SchemaError::new(SchemaErrorCode::Downgrade));
        }
        Ok(entry)
    }

    /// Performs exact contract lookup inside one selected epoch.
    ///
    /// # Errors
    ///
    /// Returns `SCHEMA_CONTRACT_UNKNOWN` when the exact contract tag is absent.
    /// Returns `SCHEMA_EPOCH_MISMATCH` when the exact epoch ID is absent.
    pub fn lookup_contract(
        &self,
        epoch_id: SchemaEpochId,
        contract_tag: u32,
    ) -> Result<&ContractDescriptor> {
        self.lookup(epoch_id)?
            .record
            .contracts
            .iter()
            .find(|contract| contract.contract_tag == contract_tag)
            .ok_or_else(|| SchemaError::new(SchemaErrorCode::ContractUnknown))
    }

    /// Selects one exact epoch and contract, then invokes only its preserved decoder.
    ///
    /// # Errors
    ///
    /// Returns the exact schema-selection or SCB1 decode error without fallback.
    pub fn decode_contract(
        &self,
        epoch_id: SchemaEpochId,
        contract_tag: u32,
        input: &[u8],
    ) -> core::result::Result<(), EpochDecodeError> {
        let entry = self.lookup(epoch_id).map_err(EpochDecodeError::Schema)?;
        if !entry
            .record
            .contracts
            .iter()
            .any(|contract| contract.contract_tag == contract_tag)
        {
            return Err(EpochDecodeError::Schema(SchemaError::new(
                SchemaErrorCode::ContractUnknown,
            )));
        }
        entry
            .decoder
            .decode_contract(contract_tag, input)
            .map_err(EpochDecodeError::Scb)
    }

    /// Validates an evidence-only migration draft against a plan and exact registry state.
    ///
    /// # Errors
    ///
    /// Returns a stable schema error if epochs, predecessor, descriptor, roots, or target
    /// slot are invalid.
    pub fn validate_migration_draft(
        &self,
        plan: &MigrationPlan,
        draft: &MigrationTransactionDraft,
        approved_plan_id: FixedDigest,
        target_slot: TargetRootSlot,
    ) -> Result<()> {
        if target_slot != TargetRootSlot::Empty || draft.old_root == draft.new_root {
            return Err(SchemaError::new(SchemaErrorCode::RootOverwriteForbidden));
        }
        if plan.old_epoch == plan.new_epoch || draft.old_epoch == draft.new_epoch {
            return Err(SchemaError::new(SchemaErrorCode::MigrationUnsupported));
        }
        if draft.old_epoch != plan.old_epoch || draft.new_epoch != plan.new_epoch {
            return Err(SchemaError::new(SchemaErrorCode::MigrationUnsupported));
        }
        if draft.plan_id != approved_plan_id {
            return Err(SchemaError::new(SchemaErrorCode::MigrationUnsupported));
        }
        let old_entry = self.lookup(plan.old_epoch)?;
        let new_entry = self.lookup(plan.new_epoch)?;
        if new_entry.record.epoch_number <= old_entry.record.epoch_number {
            return Err(SchemaError::new(SchemaErrorCode::Downgrade));
        }
        if new_entry.record.predecessor != Some(old_entry.epoch_id) {
            return Err(SchemaError::new(SchemaErrorCode::MigrationUnsupported));
        }
        new_entry
            .record
            .migration_descriptor(plan)
            .ok_or_else(|| SchemaError::new(SchemaErrorCode::MigrationUnsupported))?;
        Ok(())
    }

    /// Validates a draft and reproduces its equivalence evidence with an approved verifier.
    ///
    /// The state views are already decoded canonical values. This method performs no state
    /// construction, persistence, or mutation.
    ///
    /// # Errors
    ///
    /// Returns a stable schema failure for verifier mismatch, rejection, or evidence mismatch.
    pub fn validate_and_verify_migration<V: EquivalenceVerifier>(
        &self,
        plan: &MigrationPlan,
        draft: &MigrationTransactionDraft,
        verification: &MigrationVerification<'_, V>,
    ) -> Result<()> {
        self.validate_migration_draft(
            plan,
            draft,
            verification.approved_plan_id,
            verification.target_slot,
        )?;
        if verification.verifier.verifier_id() != plan.verifier_id {
            return Err(SchemaError::new(SchemaErrorCode::MigrationUnsupported));
        }
        let old_epoch = self.lookup(plan.old_epoch)?;
        let new_epoch = self.lookup(plan.new_epoch)?;
        let evidence = verification
            .verifier
            .verify(
                plan,
                old_epoch.record(),
                new_epoch.record(),
                verification.old_state,
                verification.new_state,
            )
            .ok_or_else(|| SchemaError::new(SchemaErrorCode::EquivalenceFailed))?;
        if evidence != draft.equivalence_evidence_digest {
            return Err(SchemaError::new(SchemaErrorCode::EquivalenceFailed));
        }
        Ok(())
    }
}

impl<D> RegistryEntry<D> {
    /// Returns the exact epoch ID key.
    #[must_use]
    pub const fn epoch_id(&self) -> SchemaEpochId {
        self.epoch_id
    }

    /// Returns the canonical epoch record.
    #[must_use]
    pub const fn record(&self) -> &SchemaEpochRecordV1 {
        &self.record
    }

    /// Returns the preserved decoder bound to this exact epoch.
    #[must_use]
    pub const fn decoder(&self) -> &D {
        &self.decoder
    }
}

/// Evidence-only migration plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationPlan {
    /// Exact old epoch.
    pub old_epoch: SchemaEpochId,
    /// Exact new epoch.
    pub new_epoch: SchemaEpochId,
    /// Exact contract identifier.
    pub contract_id: FixedDigest,
    /// Exact equivalence verifier identifier.
    pub verifier_id: FixedDigest,
    /// Exact migration scope hash.
    pub scope_hash: FixedDigest,
}

/// Approved semantic-equivalence verifier for one migration contract.
pub trait EquivalenceVerifier {
    /// Returns the exact verifier identifier frozen in the migration descriptor.
    fn verifier_id(&self) -> FixedDigest;

    /// Verifies already-decoded canonical state views and returns evidence on success.
    ///
    /// Returning `None` is an exact equivalence failure. The verifier receives no registry,
    /// decoder-selection, storage, policy, or mutation capability.
    fn verify(
        &self,
        plan: &MigrationPlan,
        old_epoch: &SchemaEpochRecordV1,
        new_epoch: &SchemaEpochRecordV1,
        old_state: &[u8],
        new_state: &[u8],
    ) -> Option<FixedDigest>;
}

/// Approved inputs for reproducing migration equivalence evidence.
pub struct MigrationVerification<'a, V> {
    /// Externally approved plan identifier that the draft must bind.
    pub approved_plan_id: FixedDigest,
    /// Observed target-root slot occupancy.
    pub target_slot: TargetRootSlot,
    /// Exact verifier implementation approved by the migration descriptor.
    pub verifier: &'a V,
    /// Already-decoded old canonical state view.
    pub old_state: &'a [u8],
    /// Already-decoded new canonical state view.
    pub new_state: &'a [u8],
}

/// Evidence-only migration transaction draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationTransactionDraft {
    /// Exact old state root.
    pub old_root: StateRoot,
    /// Exact new state root.
    pub new_root: StateRoot,
    /// Exact old epoch.
    pub old_epoch: SchemaEpochId,
    /// Exact new epoch.
    pub new_epoch: SchemaEpochId,
    /// Externally supplied plan identifier evidence.
    pub plan_id: FixedDigest,
    /// Equivalence evidence digest returned by an approved verifier.
    pub equivalence_evidence_digest: FixedDigest,
}

/// Target root slot occupancy observed by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetRootSlot {
    /// The target root slot is empty.
    Empty,
    /// The target root slot is already occupied.
    Occupied,
}

fn encode_option_epoch(epoch_id: Option<SchemaEpochId>) -> Result<Vec<u8>> {
    match epoch_id {
        None => encode_union(0, &[]),
        Some(epoch_id) => encode_union(1, epoch_id.as_bytes()),
    }
    .map_err(Into::into)
}

fn encode_u32_set(values: &[u32]) -> Result<Vec<u8>> {
    validate_sorted_unique_u32(values)?;
    let elements = values
        .iter()
        .map(|value| encode_uvar(u64::from(*value)))
        .collect::<Vec<_>>();
    encode_list(&elements).map_err(Into::into)
}

fn encode_descriptor_set<T>(
    values: &[T],
    encode: impl Fn(&T) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let elements = values
        .iter()
        .map(encode)
        .collect::<Result<Vec<Vec<u8>>>>()?;
    validate_strict_bytes_order(&elements)?;
    encode_list(&elements).map_err(Into::into)
}

fn validate_descriptor_set<T>(values: &[T], encode: impl Fn(&T) -> Result<Vec<u8>>) -> Result<()> {
    let elements = values
        .iter()
        .map(encode)
        .collect::<Result<Vec<Vec<u8>>>>()?;
    validate_strict_bytes_order(&elements)
}

fn validate_strict_bytes_order(values: &[Vec<u8>]) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    Ok(())
}

fn validate_sorted_unique_u32(values: &[u32]) -> Result<()> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    Ok(())
}

fn intersects_sorted(left: &[u32], right: &[u32]) -> bool {
    let (mut left_index, mut right_index) = (0_usize, 0_usize);
    while let (Some(left_value), Some(right_value)) = (left.get(left_index), right.get(right_index))
    {
        match left_value.cmp(right_value) {
            core::cmp::Ordering::Less => left_index += 1,
            core::cmp::Ordering::Equal => return true,
            core::cmp::Ordering::Greater => right_index += 1,
        }
    }
    false
}

fn validate_contract_uniqueness(contracts: &[ContractDescriptor]) -> Result<()> {
    let mut contract_tags = Vec::with_capacity(contracts.len());
    let mut domain_tags = Vec::with_capacity(contracts.len());
    let mut kind_tags = Vec::with_capacity(contracts.len());
    for contract in contracts {
        contract.validate()?;
        contract_tags.push(contract.contract_tag);
        domain_tags.push(contract.digest_domain_tag);
        kind_tags.push(contract.kind_tag);
    }
    contract_tags.sort_unstable();
    domain_tags.sort_unstable();
    kind_tags.sort_unstable();
    validate_sorted_unique_u32(&contract_tags)?;
    validate_sorted_unique_u32(&domain_tags)?;
    validate_sorted_unique_u32(&kind_tags)
}

fn validate_extension_uniqueness(extensions: &[ExtensionDescriptor]) -> Result<()> {
    let mut tuples = Vec::with_capacity(extensions.len());
    for extension in extensions {
        tuples.push((
            extension.namespace_id,
            extension.type_tag,
            extension.version,
        ));
    }
    tuples.sort_unstable();
    if tuples.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    Ok(())
}

fn decode_epoch_record(input: &[u8]) -> Result<SchemaEpochRecordV1> {
    let mut record = RecordReader::new(input)?;
    let epoch_number = read_required_u32(&mut record, 1)?;
    let scb_format_version = read_required_u32(&mut record, 2)?;
    let hash_algorithm_tag = read_required_u32(&mut record, 3)?;
    let unicode_nfc_version = decode_unicode(read_required(&mut record, 4)?)?;
    let limits = decode_limits(read_required(&mut record, 5)?)?;
    let contracts = decode_descriptor_set(read_required(&mut record, 6)?, decode_contract)?;
    let extensions = decode_descriptor_set(read_required(&mut record, 7)?, decode_extension)?;
    let predecessor = decode_option_epoch(read_required(&mut record, 8)?)?;
    let migration_contracts =
        decode_descriptor_set(read_required(&mut record, 9)?, decode_migration)?;
    record.finish()?;
    let out = SchemaEpochRecordV1 {
        epoch_number,
        scb_format_version,
        hash_algorithm_tag,
        unicode_nfc_version,
        limits,
        contracts,
        extensions,
        predecessor,
        migration_contracts,
    };
    out.validate()?;
    Ok(out)
}

fn decode_unicode(input: &[u8]) -> Result<UnicodeVersion> {
    let mut record = RecordReader::new(input)?;
    let out = UnicodeVersion {
        major: read_required_u32(&mut record, 1)?,
        minor: read_required_u32(&mut record, 2)?,
        patch: read_required_u32(&mut record, 3)?,
    };
    record.finish()?;
    out.validate()?;
    Ok(out)
}

fn decode_limits(input: &[u8]) -> Result<EpochLimits> {
    let mut record = RecordReader::new(input)?;
    let out = EpochLimits {
        standalone_stored_bytes: read_required_u64(&mut record, 1)?,
        payload_bytes: read_required_u64(&mut record, 2)?,
        nesting_depth: read_required_u64(&mut record, 3)?,
        fields_per_record: read_required_u64(&mut record, 4)?,
        collection_elements: read_required_u64(&mut record, 5)?,
        decoded_standalone_values_per_request: read_required_u64(&mut record, 6)?,
        decoder_allocation_per_standalone_value: read_required_u64(&mut record, 7)?,
    };
    record.finish()?;
    out.validate()?;
    Ok(out)
}

fn decode_contract(input: &[u8]) -> Result<ContractDescriptor> {
    let mut record = RecordReader::new(input)?;
    let out = ContractDescriptor {
        contract_tag: read_required_u32(&mut record, 1)?,
        digest_domain_tag: read_required_u32(&mut record, 2)?,
        kind_tag: read_required_u32(&mut record, 3)?,
        field_schema_hash: read_required_array(&mut record, 4)?,
        required_fields: decode_u32_set(read_required(&mut record, 5)?)?,
        optional_fields: decode_u32_set(read_required(&mut record, 6)?)?,
        variant_tags: decode_u32_set(read_required(&mut record, 7)?)?,
        decoder_limits_hash: read_required_array(&mut record, 8)?,
    };
    record.finish()?;
    out.validate()?;
    Ok(out)
}

fn decode_extension(input: &[u8]) -> Result<ExtensionDescriptor> {
    let mut record = RecordReader::new(input)?;
    let out = ExtensionDescriptor {
        namespace_id: read_required_array(&mut record, 1)?,
        type_tag: read_required_u32(&mut record, 2)?,
        version: read_required_u32(&mut record, 3)?,
        payload_schema_hash: read_required_array(&mut record, 4)?,
    };
    record.finish()?;
    Ok(out)
}

fn decode_migration(input: &[u8]) -> Result<MigrationContractDescriptor> {
    let mut record = RecordReader::new(input)?;
    let out = MigrationContractDescriptor {
        predecessor_epoch: SchemaEpochId::from_bytes(read_required_array(&mut record, 1)?),
        contract_id: read_required_array(&mut record, 2)?,
        verifier_id: read_required_array(&mut record, 3)?,
        scope_hash: read_required_array(&mut record, 4)?,
    };
    record.finish()?;
    Ok(out)
}

fn decode_descriptor_set<T>(input: &[u8], decode: impl Fn(&[u8]) -> Result<T>) -> Result<Vec<T>> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count =
        usize::try_from(count).map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
    if count > reader.remaining() / 2 {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    let mut previous: Option<Vec<u8>> = None;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = reader.read_sized(MAX_STANDALONE_BYTES)?;
        if previous.as_deref().is_some_and(|prev| prev >= bytes) {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        values.push(decode(bytes)?);
        previous = Some(bytes.to_vec());
    }
    if !reader.is_finished() {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    Ok(values)
}

fn decode_u32_set(input: &[u8]) -> Result<Vec<u32>> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count =
        usize::try_from(count).map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
    if count > reader.remaining() / 2 {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let element = reader.read_sized(MAX_STANDALONE_BYTES)?;
        let mut nested = Reader::new(element);
        let value = nested.read_uvar_width(32)?;
        if !nested.is_finished() {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        values.push(
            u32::try_from(value).map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))?,
        );
    }
    if !reader.is_finished() {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    validate_sorted_unique_u32(&values)?;
    Ok(values)
}

fn decode_option_epoch(input: &[u8]) -> Result<Option<SchemaEpochId>> {
    let mut reader = Reader::new(input);
    let tag = reader.read_uvar_width(32)?;
    let payload = reader.read_sized(MAX_STANDALONE_BYTES)?;
    if !reader.is_finished() {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    match tag {
        0 if payload.is_empty() => Ok(None),
        1 if payload.len() == ID_LEN => Ok(Some(SchemaEpochId::from_bytes(array_from(payload)?))),
        _ => Err(SchemaError::new(SchemaErrorCode::RecordInvalid)),
    }
}

fn read_required<'a>(record: &mut RecordReader<'a>, tag: u32) -> Result<&'a [u8]> {
    record
        .take(tag)
        .ok_or_else(|| SchemaError::new(SchemaErrorCode::RecordInvalid))
}

fn read_required_u32(record: &mut RecordReader<'_>, tag: u32) -> Result<u32> {
    let mut reader = Reader::new(read_required(record, tag)?);
    let value = reader.read_uvar_width(32)?;
    if !reader.is_finished() {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    u32::try_from(value).map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))
}

fn read_required_u64(record: &mut RecordReader<'_>, tag: u32) -> Result<u64> {
    let mut reader = Reader::new(read_required(record, tag)?);
    let value = reader.read_uvar_width(64)?;
    if !reader.is_finished() {
        return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
    }
    Ok(value)
}

fn read_required_array<const N: usize>(record: &mut RecordReader<'_>, tag: u32) -> Result<[u8; N]> {
    array_from(read_required(record, tag)?)
}

fn array_from<const N: usize>(input: &[u8]) -> Result<[u8; N]> {
    input
        .try_into()
        .map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))
}

struct RecordReader<'a> {
    fields: Vec<(u32, &'a [u8])>,
}

impl<'a> RecordReader<'a> {
    fn new(input: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(input);
        let field_count = reader.read_record_field_count()?;
        let field_count = usize::try_from(field_count)
            .map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
        if field_count > reader.remaining() / 2 {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        let mut fields = Vec::with_capacity(field_count);
        let mut previous_tag = None;
        for _ in 0..field_count {
            let tag = reader.read_uvar_width(32)?;
            let tag =
                u32::try_from(tag).map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
            if previous_tag.is_some_and(|previous| previous >= tag) {
                return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
            }
            let value = reader.read_sized(MAX_STANDALONE_BYTES)?;
            fields.push((tag, value));
            previous_tag = Some(tag);
        }
        if !reader.is_finished() {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        Ok(Self { fields })
    }

    fn take(&mut self, tag: u32) -> Option<&'a [u8]> {
        match self
            .fields
            .binary_search_by_key(&tag, |(field_tag, _)| *field_tag)
        {
            Ok(index) => Some(self.fields.remove(index).1),
            Err(_) => None,
        }
    }

    fn finish(self) -> Result<()> {
        if self.fields.is_empty() {
            Ok(())
        } else {
            Err(SchemaError::new(SchemaErrorCode::RecordInvalid))
        }
    }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
        if end > self.input.len() {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        let slice = &self.input[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8> {
        self.take_exact(1)?
            .first()
            .copied()
            .ok_or_else(|| SchemaError::new(SchemaErrorCode::RecordInvalid))
    }

    fn read_uvar_width(&mut self, width: u8) -> Result<u64> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        let mut bytes_read = 0_u8;
        loop {
            let byte = self.read_u8()?;
            bytes_read += 1;
            let payload = u64::from(byte & 0x7f);
            if shift >= 64 && payload != 0 {
                return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
            }
            if shift < 64 {
                if shift == 63 && payload > 1 {
                    return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
                }
                value |= payload
                    .checked_shl(shift)
                    .ok_or_else(|| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
            }
            if byte & 0x80 == 0 {
                if bytes_read > 1 && payload == 0 {
                    return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
                }
                if width < 64 && value >= (1_u64 << width) {
                    return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
                }
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 + 7 {
                return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
            }
        }
    }

    fn read_len(&mut self, max: usize) -> Result<usize> {
        let len = self.read_uvar_width(64)?;
        let len =
            usize::try_from(len).map_err(|_| SchemaError::new(SchemaErrorCode::RecordInvalid))?;
        if len > max {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        Ok(len)
    }

    fn read_sized(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.read_len(max)?;
        self.take_exact(len)
    }

    fn read_count(&mut self) -> Result<u64> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_COLLECTION_ELEMENTS {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        Ok(count)
    }

    fn read_record_field_count(&mut self) -> Result<u64> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_RECORD_FIELDS {
            return Err(SchemaError::new(SchemaErrorCode::RecordInvalid));
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;
    use sley_scb1::{
        MAX_BYTE_PAYLOAD, MAX_TOTAL_ALLOCATION, ScbErrorCode, Schema, decode_payload_exact,
    };

    #[derive(Clone, Debug)]
    struct TestDecoder {
        epoch_id: SchemaEpochId,
        schema: Schema,
    }

    impl EpochDecoder for TestDecoder {
        fn epoch_id(&self) -> SchemaEpochId {
            self.epoch_id
        }

        fn decode_contract(
            &self,
            contract_tag: u32,
            input: &[u8],
        ) -> core::result::Result<(), ScbError> {
            if contract_tag != 1 {
                return Err(ScbError::new(ScbErrorCode::ContractUnknown));
            }
            decode_payload_exact(&self.schema, input)
        }
    }

    struct TestVerifier {
        verifier_id: FixedDigest,
        evidence: Option<FixedDigest>,
    }

    impl EquivalenceVerifier for TestVerifier {
        fn verifier_id(&self) -> FixedDigest {
            self.verifier_id
        }

        fn verify(
            &self,
            _plan: &MigrationPlan,
            _old_epoch: &SchemaEpochRecordV1,
            _new_epoch: &SchemaEpochRecordV1,
            old_state: &[u8],
            new_state: &[u8],
        ) -> Option<FixedDigest> {
            if old_state == b"old" && new_state == b"new" {
                self.evidence
            } else {
                None
            }
        }
    }

    fn digest(byte: u8) -> FixedDigest {
        [byte; ID_LEN]
    }

    fn root(byte: u8) -> StateRoot {
        StateRoot::from_bytes(digest(byte))
    }

    fn descriptor(tag: u32) -> ContractDescriptor {
        let tag_byte = u8::try_from(tag).unwrap();
        let next_tag_byte = tag_byte.checked_add(1).unwrap();
        ContractDescriptor {
            contract_tag: tag,
            digest_domain_tag: tag + 100,
            kind_tag: tag + 200,
            field_schema_hash: digest(tag_byte),
            required_fields: vec![1, 3],
            optional_fields: vec![5],
            variant_tags: Vec::new(),
            decoder_limits_hash: digest(next_tag_byte),
        }
    }

    fn epoch(
        number: u32,
        predecessor: Option<SchemaEpochId>,
        contracts: Vec<ContractDescriptor>,
        migrations: Vec<MigrationContractDescriptor>,
    ) -> SchemaEpochRecordV1 {
        SchemaEpochRecordV1 {
            epoch_number: number,
            scb_format_version: SCB_FORMAT_VERSION,
            hash_algorithm_tag: HASH_ALGORITHM_BLAKE3_256,
            unicode_nfc_version: UnicodeVersion::EPOCH_1,
            limits: EpochLimits::EPOCH_1,
            contracts,
            extensions: Vec::new(),
            predecessor,
            migration_contracts: migrations,
        }
    }

    fn entry(record: SchemaEpochRecordV1) -> RegistryEntry<TestDecoder> {
        let epoch_id = record.schema_epoch_id().unwrap();
        let schema = if record.epoch_number == 1 {
            Schema::Bool
        } else {
            Schema::UInt(8)
        };
        RegistryEntry::new(epoch_id, record, TestDecoder { epoch_id, schema }).unwrap()
    }

    fn registry_pair() -> (
        SchemaEpochRegistry<TestDecoder>,
        SchemaEpochId,
        SchemaEpochId,
        MigrationPlan,
    ) {
        let old = epoch(1, None, vec![descriptor(1)], Vec::new());
        let old_id = old.schema_epoch_id().unwrap();
        let plan = MigrationPlan {
            old_epoch: old_id,
            new_epoch: SchemaEpochId::from_bytes([9; ID_LEN]),
            contract_id: digest(7),
            verifier_id: digest(8),
            scope_hash: digest(9),
        };
        let migration = MigrationContractDescriptor {
            predecessor_epoch: old_id,
            contract_id: plan.contract_id,
            verifier_id: plan.verifier_id,
            scope_hash: plan.scope_hash,
        };
        let new = epoch(2, Some(old_id), vec![descriptor(1)], vec![migration]);
        let new_id = new.schema_epoch_id().unwrap();
        let plan = MigrationPlan {
            new_epoch: new_id,
            ..plan
        };
        let mut entries = vec![entry(old), entry(new)];
        entries.sort_by_key(RegistryEntry::epoch_id);
        (
            SchemaEpochRegistry::new(entries).unwrap(),
            old_id,
            new_id,
            plan,
        )
    }

    #[test]
    fn bootstrap_vector_is_fixed_and_import_round_trips() {
        let record = epoch(1, None, Vec::new(), Vec::new());
        let record_bytes = record.canonical_bytes().unwrap();
        assert_eq!(
            hex(&record_bytes),
            "09010101020101030101040a030101100201000301000525070104808080200204808080080301400403ffff030503c0843d0603c0843d07048080804006010007010008020000090100"
        );
        let preimage = bootstrap_preimage(&record_bytes).unwrap();
        assert_eq!(
            hex(&preimage),
            "534c455945503031014a09010101020101030101040a030101100201000301000525070104808080200204808080080301400403ffff030503c0843d0603c0843d07048080804006010007010008020000090100"
        );
        let epoch_id = record.schema_epoch_id().unwrap();
        assert_eq!(
            hex(epoch_id.as_bytes()),
            "ae5b235713b46c04f73c1decd0fb0bb57c5557d0fe89dae7ddac4a7dba25564e"
        );
        assert_eq!(
            import_bootstrap_preimage(&preimage).unwrap(),
            (epoch_id, record)
        );
    }

    #[test]
    fn record_changes_alter_schema_epoch_id() {
        let one = epoch(1, None, Vec::new(), Vec::new())
            .schema_epoch_id()
            .unwrap();
        let two = epoch(1, None, vec![descriptor(1)], Vec::new())
            .schema_epoch_id()
            .unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn import_rejects_non_minimal_length_and_trailing_data() {
        let record = epoch(1, None, Vec::new(), Vec::new());
        let record_bytes = record.canonical_bytes().unwrap();
        let mut non_minimal = Vec::new();
        non_minimal.extend_from_slice(BOOTSTRAP_MAGIC);
        non_minimal.push(1);
        non_minimal.extend_from_slice(&[0xae, 0x00]);
        non_minimal.extend_from_slice(&record_bytes);
        assert_eq!(
            import_bootstrap_preimage(&non_minimal).unwrap_err().code(),
            SchemaErrorCode::RecordInvalid
        );

        let mut trailing = bootstrap_preimage(&record_bytes).unwrap();
        trailing.push(0);
        assert_eq!(
            import_bootstrap_preimage(&trailing).unwrap_err().code(),
            SchemaErrorCode::RecordInvalid
        );
    }

    #[test]
    fn bounded_schema_bootstrap_import_fuzz_smoke() {
        const CASES: usize = 512;
        const MAX_INPUT_BYTES: usize = 2_048;

        fn next(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }

        fn bounded_index(state: &mut u64, upper: usize) -> usize {
            let upper = u64::try_from(upper).unwrap();
            usize::try_from(next(state) % upper).unwrap()
        }

        let canonical = bootstrap_preimage(
            &epoch(1, None, vec![descriptor(1)], Vec::new())
                .canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        let mut state = 0x5c20_7001_40d3_c0de_u64;

        for case in 0..CASES {
            let mut input = match case % 5 {
                0 => canonical[..case % canonical.len()].to_vec(),
                1 => {
                    let mut value = canonical.clone();
                    value.push(u8::try_from(next(&mut state) & 0xff).unwrap());
                    value
                }
                2 => {
                    let mut value = canonical.clone();
                    let index = bounded_index(&mut state, value.len());
                    value[index] ^= 1_u8 << (next(&mut state) & 7);
                    value
                }
                3 => {
                    let mut value = canonical.clone();
                    let mutations = 1 + usize::try_from(next(&mut state) % 16).unwrap();
                    for _ in 0..mutations {
                        let index = bounded_index(&mut state, value.len());
                        value[index] = u8::try_from(next(&mut state) & 0xff).unwrap();
                    }
                    value
                }
                _ => {
                    let len = bounded_index(&mut state, MAX_INPUT_BYTES);
                    (0..len)
                        .map(|_| u8::try_from(next(&mut state) & 0xff).unwrap())
                        .collect()
                }
            };
            input.truncate(MAX_INPUT_BYTES);

            match import_bootstrap_preimage(&input) {
                Ok((epoch_id, record)) => {
                    assert_eq!(epoch_id, SchemaEpochId::derive(&input));
                    assert_eq!(
                        bootstrap_preimage(&record.canonical_bytes().unwrap()).unwrap(),
                        input
                    );
                }
                Err(error) => assert_eq!(error.code(), SchemaErrorCode::RecordInvalid),
            }
        }
    }

    #[test]
    fn registry_rejects_unsorted_duplicate_mismatched_and_decoder_mismatch() {
        let first = epoch(1, None, Vec::new(), Vec::new());
        let second = epoch(1, None, vec![descriptor(1)], Vec::new());
        let first_entry = entry(first.clone());
        let second_entry = entry(second);
        let mut reversed = vec![first_entry.clone(), second_entry.clone()];
        reversed.sort_by_key(RegistryEntry::epoch_id);
        reversed.reverse();
        assert_eq!(
            SchemaEpochRegistry::new(reversed).unwrap_err().code(),
            SchemaErrorCode::EpochMismatch
        );
        assert_eq!(
            SchemaEpochRegistry::new(vec![first_entry.clone(), first_entry])
                .unwrap_err()
                .code(),
            SchemaErrorCode::EpochMismatch
        );
        let first_id = first.schema_epoch_id().unwrap();
        let bad_decoder = TestDecoder {
            epoch_id: SchemaEpochId::from_bytes([99; ID_LEN]),
            schema: Schema::Bool,
        };
        assert_eq!(
            RegistryEntry::new(first_id, first, bad_decoder)
                .unwrap_err()
                .code(),
            SchemaErrorCode::EpochMismatch
        );
    }

    #[test]
    fn lookup_is_exact_no_fallback_and_downgrade_fails_closed() {
        let record = epoch(1, None, vec![descriptor(1)], Vec::new());
        let id = record.schema_epoch_id().unwrap();
        let registry = SchemaEpochRegistry::new(vec![entry(record)]).unwrap();
        assert!(registry.lookup(id).is_ok());
        assert_eq!(
            registry
                .lookup(SchemaEpochId::from_bytes([42; ID_LEN]))
                .unwrap_err()
                .code(),
            SchemaErrorCode::EpochMismatch
        );
        assert_eq!(
            registry.lookup_equal_or_newer(id, 2).unwrap_err().code(),
            SchemaErrorCode::Downgrade
        );
        assert_eq!(
            registry.lookup_contract(id, 99).unwrap_err().code(),
            SchemaErrorCode::ContractUnknown
        );
    }

    #[test]
    fn preserved_decoders_are_selected_by_exact_id() {
        let (registry, old_id, new_id, _plan) = registry_pair();
        assert_eq!(
            registry.lookup(old_id).unwrap().decoder().epoch_id(),
            old_id
        );
        assert_eq!(
            registry.lookup(new_id).unwrap().decoder().epoch_id(),
            new_id
        );
        assert!(registry.decode_contract(old_id, 1, &[1]).is_ok());
        assert!(registry.decode_contract(new_id, 1, &[2]).is_ok());
        assert_eq!(
            registry.decode_contract(old_id, 1, &[2]).unwrap_err(),
            EpochDecodeError::Scb(ScbError::new(ScbErrorCode::BoolInvalid))
        );
        assert_eq!(
            registry.decode_contract(new_id, 99, &[1]).unwrap_err(),
            EpochDecodeError::Schema(SchemaError::new(SchemaErrorCode::ContractUnknown))
        );
    }

    #[test]
    fn registry_decode_never_falls_back_across_epoch_or_contract() {
        use std::cell::Cell;

        #[derive(Clone, Debug)]
        struct ProbeDecoder {
            calls: Cell<u32>,
            epoch_id: SchemaEpochId,
            schema: Schema,
        }

        impl EpochDecoder for ProbeDecoder {
            fn epoch_id(&self) -> SchemaEpochId {
                self.epoch_id
            }

            fn decode_contract(
                &self,
                contract_tag: u32,
                input: &[u8],
            ) -> core::result::Result<(), ScbError> {
                self.calls.set(self.calls.get() + 1);
                if contract_tag != 1 {
                    return Err(ScbError::new(ScbErrorCode::ContractUnknown));
                }
                decode_payload_exact(&self.schema, input)
            }
        }

        let old = epoch(1, None, vec![descriptor(1)], Vec::new());
        let old_id = old.schema_epoch_id().unwrap();
        let new = epoch(2, Some(old_id), vec![descriptor(1)], Vec::new());
        let new_id = new.schema_epoch_id().unwrap();
        let old_entry = RegistryEntry::new(
            old_id,
            old,
            ProbeDecoder {
                calls: Cell::new(0),
                epoch_id: old_id,
                schema: Schema::Bool,
            },
        )
        .unwrap();
        let new_entry = RegistryEntry::new(
            new_id,
            new,
            ProbeDecoder {
                calls: Cell::new(0),
                epoch_id: new_id,
                schema: Schema::UInt(8),
            },
        )
        .unwrap();
        let mut entries = vec![old_entry, new_entry];
        entries.sort_by_key(RegistryEntry::epoch_id);
        let registry = SchemaEpochRegistry::new(entries).unwrap();

        assert_eq!(
            registry
                .decode_contract(SchemaEpochId::from_bytes([0xa5; ID_LEN]), 1, &[1])
                .unwrap_err(),
            EpochDecodeError::Schema(SchemaError::new(SchemaErrorCode::EpochMismatch))
        );
        assert_eq!(
            registry.decode_contract(old_id, 99, &[1]).unwrap_err(),
            EpochDecodeError::Schema(SchemaError::new(SchemaErrorCode::ContractUnknown))
        );
        assert_eq!(registry.lookup(old_id).unwrap().decoder().calls.get(), 0);
        assert_eq!(registry.lookup(new_id).unwrap().decoder().calls.get(), 0);

        assert_eq!(
            registry.decode_contract(old_id, 1, &[2]).unwrap_err(),
            EpochDecodeError::Scb(ScbError::new(ScbErrorCode::BoolInvalid))
        );
        assert_eq!(registry.lookup(old_id).unwrap().decoder().calls.get(), 1);
        assert_eq!(registry.lookup(new_id).unwrap().decoder().calls.get(), 0);

        registry.decode_contract(new_id, 1, &[2]).unwrap();
        assert_eq!(registry.lookup(old_id).unwrap().decoder().calls.get(), 1);
        assert_eq!(registry.lookup(new_id).unwrap().decoder().calls.get(), 1);
    }

    #[test]
    fn migration_validation_accepts_exact_evidence_only_draft() {
        let (registry, old_id, new_id, plan) = registry_pair();
        let draft = MigrationTransactionDraft {
            old_root: root(1),
            new_root: root(2),
            old_epoch: old_id,
            new_epoch: new_id,
            plan_id: digest(10),
            equivalence_evidence_digest: digest(11),
        };
        registry
            .validate_and_verify_migration(
                &plan,
                &draft,
                &MigrationVerification {
                    approved_plan_id: draft.plan_id,
                    target_slot: TargetRootSlot::Empty,
                    verifier: &TestVerifier {
                        verifier_id: plan.verifier_id,
                        evidence: Some(draft.equivalence_evidence_digest),
                    },
                    old_state: b"old",
                    new_state: b"new",
                },
            )
            .unwrap();
    }

    #[test]
    fn migration_validation_rejects_negative_cases() {
        let (registry, old_id, new_id, plan) = registry_pair();
        let draft = MigrationTransactionDraft {
            old_root: root(1),
            new_root: root(2),
            old_epoch: old_id,
            new_epoch: new_id,
            plan_id: digest(10),
            equivalence_evidence_digest: digest(11),
        };
        let mut missing_descriptor = plan.clone();
        missing_descriptor.contract_id = digest(99);
        assert_eq!(
            registry
                .validate_migration_draft(
                    &missing_descriptor,
                    &draft,
                    draft.plan_id,
                    TargetRootSlot::Empty,
                )
                .unwrap_err()
                .code(),
            SchemaErrorCode::MigrationUnsupported
        );
        let same_epoch_plan = MigrationPlan {
            old_epoch: old_id,
            new_epoch: old_id,
            ..plan.clone()
        };
        assert_eq!(
            registry
                .validate_migration_draft(
                    &same_epoch_plan,
                    &draft,
                    draft.plan_id,
                    TargetRootSlot::Empty,
                )
                .unwrap_err()
                .code(),
            SchemaErrorCode::MigrationUnsupported
        );
        let mut same_root = draft.clone();
        same_root.new_root = same_root.old_root;
        assert_eq!(
            registry
                .validate_migration_draft(
                    &plan,
                    &same_root,
                    same_root.plan_id,
                    TargetRootSlot::Empty,
                )
                .unwrap_err()
                .code(),
            SchemaErrorCode::RootOverwriteForbidden
        );
        assert_eq!(
            registry
                .validate_migration_draft(&plan, &draft, draft.plan_id, TargetRootSlot::Occupied,)
                .unwrap_err()
                .code(),
            SchemaErrorCode::RootOverwriteForbidden
        );
        let mut verifier_mismatch = plan.clone();
        verifier_mismatch.verifier_id = digest(98);
        assert_eq!(
            registry
                .validate_migration_draft(
                    &verifier_mismatch,
                    &draft,
                    draft.plan_id,
                    TargetRootSlot::Empty,
                )
                .unwrap_err()
                .code(),
            SchemaErrorCode::MigrationUnsupported
        );
    }

    #[test]
    fn migration_rejects_unapproved_plan_or_equivalence_evidence() {
        let (registry, old_id, new_id, plan) = registry_pair();
        let draft = MigrationTransactionDraft {
            old_root: root(1),
            new_root: root(2),
            old_epoch: old_id,
            new_epoch: new_id,
            plan_id: digest(10),
            equivalence_evidence_digest: digest(11),
        };
        let mut wrong_plan_id = draft.clone();
        wrong_plan_id.plan_id = digest(97);
        assert_eq!(
            registry
                .validate_migration_draft(
                    &plan,
                    &wrong_plan_id,
                    draft.plan_id,
                    TargetRootSlot::Empty,
                )
                .unwrap_err()
                .code(),
            SchemaErrorCode::MigrationUnsupported
        );
        assert_eq!(
            registry
                .validate_and_verify_migration(
                    &plan,
                    &draft,
                    &MigrationVerification {
                        approved_plan_id: draft.plan_id,
                        target_slot: TargetRootSlot::Empty,
                        verifier: &TestVerifier {
                            verifier_id: digest(96),
                            evidence: Some(draft.equivalence_evidence_digest),
                        },
                        old_state: b"old",
                        new_state: b"new",
                    },
                )
                .unwrap_err()
                .code(),
            SchemaErrorCode::MigrationUnsupported
        );
        assert_eq!(
            registry
                .validate_and_verify_migration(
                    &plan,
                    &draft,
                    &MigrationVerification {
                        approved_plan_id: draft.plan_id,
                        target_slot: TargetRootSlot::Empty,
                        verifier: &TestVerifier {
                            verifier_id: plan.verifier_id,
                            evidence: Some(digest(95)),
                        },
                        old_state: b"old",
                        new_state: b"new",
                    },
                )
                .unwrap_err()
                .code(),
            SchemaErrorCode::EquivalenceFailed
        );
    }

    #[test]
    fn migration_rejects_non_increasing_epoch_numbers() {
        let genesis_id = epoch(1, None, Vec::new(), Vec::new())
            .schema_epoch_id()
            .unwrap();
        let old = epoch(2, Some(genesis_id), vec![descriptor(1)], Vec::new());
        let old_id = old.schema_epoch_id().unwrap();
        let plan_seed = MigrationPlan {
            old_epoch: old_id,
            new_epoch: SchemaEpochId::from_bytes([0; ID_LEN]),
            contract_id: digest(7),
            verifier_id: digest(8),
            scope_hash: digest(9),
        };
        let migration = MigrationContractDescriptor {
            predecessor_epoch: old_id,
            contract_id: plan_seed.contract_id,
            verifier_id: plan_seed.verifier_id,
            scope_hash: plan_seed.scope_hash,
        };
        let new = epoch(2, Some(old_id), vec![descriptor(1)], vec![migration]);
        let new_id = new.schema_epoch_id().unwrap();
        let plan = MigrationPlan {
            new_epoch: new_id,
            ..plan_seed
        };
        let draft = MigrationTransactionDraft {
            old_root: root(1),
            new_root: root(2),
            old_epoch: old_id,
            new_epoch: new_id,
            plan_id: digest(10),
            equivalence_evidence_digest: digest(11),
        };
        let mut entries = vec![entry(old), entry(new)];
        entries.sort_by_key(RegistryEntry::epoch_id);
        let registry = SchemaEpochRegistry::new(entries).unwrap();
        assert_eq!(
            registry
                .validate_migration_draft(&plan, &draft, draft.plan_id, TargetRootSlot::Empty,)
                .unwrap_err()
                .code(),
            SchemaErrorCode::Downgrade
        );
    }

    #[test]
    fn malformed_counts_fail_before_capacity_allocation() {
        let encoded_count = encode_uvar(MAX_COLLECTION_ELEMENTS);
        assert_eq!(
            decode_descriptor_set(&encoded_count, decode_contract)
                .unwrap_err()
                .code(),
            SchemaErrorCode::RecordInvalid
        );
        assert_eq!(
            decode_u32_set(&encoded_count).unwrap_err().code(),
            SchemaErrorCode::RecordInvalid
        );
    }

    #[test]
    fn descriptor_validation_rejects_unsorted_sets_and_duplicate_contract_tags() {
        let mut unsorted = descriptor(1);
        unsorted.required_fields = vec![3, 1];
        assert_eq!(
            unsorted.validate().unwrap_err().code(),
            SchemaErrorCode::RecordInvalid
        );
        let duplicate = epoch(1, None, vec![descriptor(1), descriptor(1)], Vec::new());
        assert_eq!(
            duplicate.validate().unwrap_err().code(),
            SchemaErrorCode::RecordInvalid
        );
    }

    #[test]
    fn stable_schema_error_strings_are_frozen() {
        let codes = [
            SchemaErrorCode::EpochMismatch,
            SchemaErrorCode::Downgrade,
            SchemaErrorCode::ContractUnknown,
            SchemaErrorCode::MigrationUnsupported,
            SchemaErrorCode::EquivalenceFailed,
            SchemaErrorCode::SelfModification,
            SchemaErrorCode::RootOverwriteForbidden,
            SchemaErrorCode::RecordInvalid,
        ];
        assert_eq!(
            codes.map(SchemaErrorCode::as_str),
            [
                "SCHEMA_EPOCH_MISMATCH",
                "SCHEMA_DOWNGRADE",
                "SCHEMA_CONTRACT_UNKNOWN",
                "SCHEMA_MIGRATION_UNSUPPORTED",
                "SCHEMA_EQUIVALENCE_FAILED",
                "SCHEMA_SELF_MODIFICATION",
                "SCHEMA_ROOT_OVERWRITE_FORBIDDEN",
                "SCHEMA_RECORD_INVALID",
            ]
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, byte| {
            write!(&mut out, "{byte:02x}").unwrap();
            out
        })
    }

    #[test]
    fn scb_failure_codes_remain_distinct_from_schema_codes() {
        assert_eq!(
            ScbError::new(ScbErrorCode::VarintNonMinimal)
                .code()
                .as_str(),
            "SCB_VARINT_NON_MINIMAL"
        );
    }

    #[test]
    fn limit_constants_match_epoch_record() {
        assert_eq!(
            EpochLimits::EPOCH_1,
            EpochLimits {
                standalone_stored_bytes: MAX_STANDALONE_BYTES as u64,
                payload_bytes: MAX_BYTE_PAYLOAD as u64,
                nesting_depth: 64,
                fields_per_record: MAX_RECORD_FIELDS,
                collection_elements: MAX_COLLECTION_ELEMENTS,
                decoded_standalone_values_per_request: 1_000_000,
                decoder_allocation_per_standalone_value: MAX_TOTAL_ALLOCATION as u64,
            }
        );
    }

    #[test]
    fn ssmc1_descriptor_inputs_do_not_drift() {
        const LIMITS: &[u8] = b"sley2.ssmc1.v1.decoder-limits:scb1-epoch1;label_bytes=1024;type_depth=64;type_args=1024;tuple_items=65535;fields_or_cases=65535;function_params=65535;block_params=65535;blocks_per_function=1000000;operations_per_block=1000000;operands_per_operation=65535;results_per_operation=65535;switch_cases=65535;constant_depth=64;constant_elements=1000000;constant_payload_bytes=16777216";

        assert_eq!(
            hex(blake3::hash(SSMC1_EPOCH1_MANIFEST).as_bytes()),
            "1983bc8d6ad9ac3cb5390853f43959cf2c3dc0ae8e0ca18ca8264ca4960133ae"
        );
        assert_eq!(
            *blake3::hash(SSMC1_EPOCH1_MANIFEST).as_bytes(),
            SSMC1_EPOCH1_MANIFEST_BLAKE3
        );
        assert_eq!(
            hex(blake3::hash(LIMITS).as_bytes()),
            "389791b170bc9d8575f7e6f338e4f9e9f2b75f35d7a2e52c7cb106cb2cd6136a"
        );
    }
}
