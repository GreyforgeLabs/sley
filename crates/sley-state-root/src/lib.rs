#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;

use sley_id::{EntityId, ObjectId, PolicyRootId, SchemaEpochId, StateRoot, WorkspaceId};
use sley_scb1::{
    MAX_COLLECTION_ELEMENTS, MAX_RECORD_FIELDS, MAX_STANDALONE_BYTES, ScbError, ScbErrorCode,
    encode_list, encode_map, encode_record, encode_uvar,
};
use sley_schema::{
    ContractDescriptor, EpochDecodeError, EpochDecoder, EpochLimits, RegistryEntry,
    SchemaEpochRecordV1, SchemaEpochRegistry, SchemaError, SchemaErrorCode, UnicodeVersion,
};

const MAGIC: &[u8; 8] = b"SLEYSCB1";
const FORMAT_VERSION: u64 = 1;
const CONTRACT_TAG: u32 = 160;
const DIGEST_DOMAIN_TAG: u32 = 4;
const KIND_TAG: u32 = 160;
const ID_LEN: usize = 32;
const FIELD_COUNT: u64 = 9;
const FIELD_SCHEMA_HASH: [u8; ID_LEN] = [
    0x93, 0x58, 0x3a, 0x07, 0x96, 0xc6, 0xaa, 0x11, 0x4d, 0xe0, 0x85, 0x00, 0x14, 0xb2, 0xe6, 0xce,
    0x70, 0x05, 0x47, 0x9e, 0xb0, 0xe3, 0x0a, 0x5a, 0x68, 0xda, 0x0a, 0x3e, 0xb0, 0x23, 0xee, 0x53,
];
const DECODER_LIMITS_HASH: [u8; ID_LEN] = [
    0xc4, 0x83, 0x1b, 0xde, 0x69, 0x13, 0x62, 0x09, 0x94, 0xab, 0x5a, 0x22, 0x6f, 0xc2, 0x86, 0x8e,
    0x62, 0x6e, 0x0d, 0xd0, 0x7b, 0x95, 0x24, 0xbd, 0x3d, 0x72, 0x93, 0xfb, 0xd8, 0xae, 0x06, 0x23,
];

/// Synthetic all-zero-epoch `StateRoot` from S20-160.
pub const SYNTHETIC_ZERO_EPOCH_ROOT: StateRoot = StateRoot::from_bytes([
    0x8c, 0x8b, 0xf5, 0xf5, 0xab, 0xa5, 0x9d, 0x68, 0x16, 0xe1, 0xae, 0x3d, 0x7f, 0xfd, 0x4b, 0x79,
    0xee, 0x04, 0x34, 0xb7, 0xc5, 0xd7, 0x27, 0x82, 0xc9, 0x29, 0xe4, 0xe9, 0x7d, 0xb5, 0x0f, 0xc2,
]);

/// Stable `StateRoot` failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateRootErrorCode {
    /// `STATE_ROOT_DUPLICATE_INPUT`
    DuplicateInput,
    /// `STATE_ROOT_ENTRY_UNBOUND`
    EntryUnbound,
    /// `STATE_ROOT_FLAG_UNKNOWN`
    FlagUnknown,
    /// `STATE_ROOT_EXCLUDED_FACT`
    ExcludedFact,
}

impl StateRootErrorCode {
    /// Returns the exact stable error string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateInput => "STATE_ROOT_DUPLICATE_INPUT",
            Self::EntryUnbound => "STATE_ROOT_ENTRY_UNBOUND",
            Self::FlagUnknown => "STATE_ROOT_FLAG_UNKNOWN",
            Self::ExcludedFact => "STATE_ROOT_EXCLUDED_FACT",
        }
    }
}

impl fmt::Display for StateRootErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Exact `StateRoot` failure preserving schema and SCB errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateRootError {
    /// `StateRoot` semantic validation failed.
    StateRoot(StateRootErrorCode),
    /// Registry or descriptor authorization failed.
    Schema(SchemaError),
    /// Canonical byte decoding failed.
    Scb(ScbError),
}

impl StateRootError {
    /// Returns the stable failure string without collapsing its source.
    #[must_use]
    pub fn code_str(&self) -> &'static str {
        match self {
            Self::StateRoot(code) => code.as_str(),
            Self::Schema(error) => error.code().as_str(),
            Self::Scb(error) => error.code().as_str(),
        }
    }
}

impl fmt::Display for StateRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code_str())
    }
}

impl std::error::Error for StateRootError {}

impl From<ScbError> for StateRootError {
    fn from(value: ScbError) -> Self {
        Self::Scb(value)
    }
}

impl From<SchemaError> for StateRootError {
    fn from(value: SchemaError) -> Self {
        Self::Schema(value)
    }
}

impl From<EpochDecodeError> for StateRootError {
    fn from(value: EpochDecodeError) -> Self {
        match value {
            EpochDecodeError::Schema(error) => Self::Schema(error),
            EpochDecodeError::Scb(error) => Self::Scb(error),
        }
    }
}

/// Typed nine-field `StateRoot` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRootRecord {
    /// Exact workspace identifier.
    pub workspace_id: WorkspaceId,
    /// Exact schema epoch identifier.
    pub schema_epoch_id: SchemaEpochId,
    /// Canonically ordered entity-to-object bindings.
    pub entity_bindings: Vec<(EntityId, ObjectId)>,
    /// Canonically ordered entry points.
    pub entry_points: Vec<EntityId>,
    /// Canonically ordered dependency roots.
    pub dependency_roots: Vec<StateRoot>,
    /// Contract root object identifier.
    pub contract_root: ObjectId,
    /// Test root object identifier.
    pub test_root: ObjectId,
    /// Policy root identifier.
    pub policy_root: PolicyRootId,
    /// Canonically ordered interpretation flags. Epoch 1 accepts none.
    pub interpretation_flags: Vec<u32>,
}

/// Registry-authorized `StateRoot` with its exact stored bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedStateRoot {
    /// Derived root digest.
    pub root: StateRoot,
    /// Exact standalone bytes including digest trailer.
    pub stored_bytes: Vec<u8>,
    /// Strictly decoded typed record.
    pub record: StateRootRecord,
}

/// Builder for unordered semantic `StateRoot` inputs.
#[derive(Clone, Debug)]
pub struct StateRootBuilder {
    workspace_id: WorkspaceId,
    entity_bindings: Vec<(EntityId, ObjectId)>,
    entry_points: Vec<EntityId>,
    dependency_roots: Vec<StateRoot>,
    contract_root: ObjectId,
    test_root: ObjectId,
    policy_root: PolicyRootId,
    interpretation_flags: Vec<u32>,
}

impl StateRootBuilder {
    /// Creates a builder from the eight caller-supplied semantic fields.
    #[must_use]
    pub fn new(
        workspace_id: WorkspaceId,
        contract_root: ObjectId,
        test_root: ObjectId,
        policy_root: PolicyRootId,
    ) -> Self {
        Self {
            workspace_id,
            entity_bindings: Vec::new(),
            entry_points: Vec::new(),
            dependency_roots: Vec::new(),
            contract_root,
            test_root,
            policy_root,
            interpretation_flags: Vec::new(),
        }
    }

    /// Adds an entity binding.
    #[must_use]
    pub fn entity_binding(mut self, entity_id: EntityId, object_id: ObjectId) -> Self {
        self.entity_bindings.push((entity_id, object_id));
        self
    }

    /// Adds an entry point.
    #[must_use]
    pub fn entry_point(mut self, entity_id: EntityId) -> Self {
        self.entry_points.push(entity_id);
        self
    }

    /// Adds a dependency root.
    #[must_use]
    pub fn dependency_root(mut self, root: StateRoot) -> Self {
        self.dependency_roots.push(root);
        self
    }

    /// Adds an interpretation flag.
    #[must_use]
    pub fn interpretation_flag(mut self, flag: u32) -> Self {
        self.interpretation_flags.push(flag);
        self
    }

    /// Builds and authorizes a `StateRoot` under the exact registered conformance epoch.
    ///
    /// # Errors
    ///
    /// Returns stable schema, SCB, or `StateRoot` validation failures.
    pub fn build(
        mut self,
        registry: &SchemaEpochRegistry<StateRootEpoch1Decoder>,
    ) -> Result<AcceptedStateRoot, StateRootError> {
        check_builder_count(self.entity_bindings.len())?;
        check_builder_count(self.entry_points.len())?;
        check_builder_count(self.dependency_roots.len())?;
        check_builder_count(self.interpretation_flags.len())?;
        reject_unknown_flags(&self.interpretation_flags)?;
        sort_bindings(&mut self.entity_bindings)?;
        sort_unique(&mut self.entry_points)?;
        sort_unique(&mut self.dependency_roots)?;
        sort_unique(&mut self.interpretation_flags)?;
        for entry in &self.entry_points {
            if self
                .entity_bindings
                .binary_search_by_key(entry, |(entity_id, _)| *entity_id)
                .is_err()
            {
                return Err(StateRootError::StateRoot(StateRootErrorCode::EntryUnbound));
            }
        }
        let epoch_id = conformance_epoch_id()?;
        let record = StateRootRecord {
            workspace_id: self.workspace_id,
            schema_epoch_id: epoch_id,
            entity_bindings: self.entity_bindings,
            entry_points: self.entry_points,
            dependency_roots: self.dependency_roots,
            contract_root: self.contract_root,
            test_root: self.test_root,
            policy_root: self.policy_root,
            interpretation_flags: self.interpretation_flags,
        };
        let payload = encode_payload(&record)?;
        authorize(registry, epoch_id, &payload)?;
        let (stored_bytes, root) = stored_bytes(epoch_id, &payload)?;
        Ok(AcceptedStateRoot {
            root,
            stored_bytes,
            record,
        })
    }
}

/// Preserved epoch-1 decoder for the registered `StateRoot` conformance epoch.
#[derive(Clone, Debug)]
pub struct StateRootEpoch1Decoder {
    epoch_id: SchemaEpochId,
}

impl StateRootEpoch1Decoder {
    fn new(epoch_id: SchemaEpochId) -> Self {
        Self { epoch_id }
    }
}

impl EpochDecoder for StateRootEpoch1Decoder {
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
        let record = decode_payload(input, true)?;
        if record.schema_epoch_id != self.epoch_id {
            return Err(ScbError::new(ScbErrorCode::EpochMismatch));
        }
        Ok(())
    }
}

/// Builds the frozen nonzero conformance epoch registry for `StateRoot` v1.
///
/// # Errors
///
/// Returns a stable schema failure if the frozen row no longer validates.
pub fn conformance_registry() -> Result<SchemaEpochRegistry<StateRootEpoch1Decoder>, SchemaError> {
    let record = conformance_epoch_record();
    let epoch_id = record.schema_epoch_id()?;
    let entry = RegistryEntry::new(epoch_id, record, StateRootEpoch1Decoder::new(epoch_id))?;
    SchemaEpochRegistry::new(vec![entry])
}

/// Returns the frozen nonzero conformance epoch ID.
///
/// # Errors
///
/// Returns a stable schema failure if the frozen row no longer validates.
pub fn conformance_epoch_id() -> Result<SchemaEpochId, SchemaError> {
    conformance_epoch_record().schema_epoch_id()
}

/// Returns the frozen conformance epoch record containing the exact tag-160 descriptor.
#[must_use]
pub fn conformance_epoch_record() -> SchemaEpochRecordV1 {
    SchemaEpochRecordV1 {
        epoch_number: 1,
        scb_format_version: 1,
        hash_algorithm_tag: 1,
        unicode_nfc_version: UnicodeVersion::EPOCH_1,
        limits: EpochLimits::EPOCH_1,
        contracts: vec![expected_descriptor()],
        extensions: Vec::new(),
        predecessor: None,
        migration_contracts: Vec::new(),
    }
}

/// Imports exact stored `StateRoot` bytes through the selected preserved decoder.
///
/// # Errors
///
/// Returns stable schema, SCB, or `StateRoot` validation failures.
pub fn import_state_root(
    registry: &SchemaEpochRegistry<StateRootEpoch1Decoder>,
    input: &[u8],
) -> Result<AcceptedStateRoot, StateRootError> {
    let (epoch_id, payload, root) = decode_envelope(input)?;
    let record = decode_payload(payload, false)?;
    if record.schema_epoch_id != epoch_id {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::EpochMismatch,
        )));
    }
    validate_record_semantics(&record).map_err(StateRootError::StateRoot)?;
    authorize(registry, epoch_id, payload)?;
    Ok(AcceptedStateRoot {
        root,
        stored_bytes: input.to_vec(),
        record,
    })
}

fn expected_descriptor() -> ContractDescriptor {
    ContractDescriptor {
        contract_tag: CONTRACT_TAG,
        digest_domain_tag: DIGEST_DOMAIN_TAG,
        kind_tag: KIND_TAG,
        field_schema_hash: FIELD_SCHEMA_HASH,
        required_fields: (1..=9).collect(),
        optional_fields: Vec::new(),
        variant_tags: Vec::new(),
        decoder_limits_hash: DECODER_LIMITS_HASH,
    }
}

fn authorize(
    registry: &SchemaEpochRegistry<StateRootEpoch1Decoder>,
    epoch_id: SchemaEpochId,
    payload: &[u8],
) -> Result<(), StateRootError> {
    let descriptor = registry.lookup_contract(epoch_id, CONTRACT_TAG)?;
    if descriptor != &expected_descriptor() {
        return Err(StateRootError::Schema(SchemaError::new(
            SchemaErrorCode::ContractUnknown,
        )));
    }
    registry.decode_contract(epoch_id, CONTRACT_TAG, payload)?;
    Ok(())
}

fn encode_payload(record: &StateRootRecord) -> Result<Vec<u8>, StateRootError> {
    let bindings = record
        .entity_bindings
        .iter()
        .map(|(entity_id, object_id)| {
            (entity_id.as_bytes().to_vec(), object_id.as_bytes().to_vec())
        })
        .collect::<Vec<_>>();
    encode_record(&[
        (1, record.workspace_id.as_bytes().to_vec()),
        (2, record.schema_epoch_id.as_bytes().to_vec()),
        (3, encode_map(&bindings)?),
        (4, encode_id_set(&record.entry_points)?),
        (5, encode_id_set(&record.dependency_roots)?),
        (6, record.contract_root.as_bytes().to_vec()),
        (7, record.test_root.as_bytes().to_vec()),
        (8, record.policy_root.as_bytes().to_vec()),
        (9, encode_u32_set(&record.interpretation_flags)?),
    ])
    .map_err(Into::into)
}

fn encode_id_set<T>(values: &[T]) -> Result<Vec<u8>, ScbError>
where
    T: IdBytes,
{
    let elements = values
        .iter()
        .map(|value| value.id_bytes().to_vec())
        .collect::<Vec<_>>();
    encode_list(&elements)
}

fn encode_u32_set(values: &[u32]) -> Result<Vec<u8>, ScbError> {
    let elements = values
        .iter()
        .map(|value| encode_uvar(u64::from(*value)))
        .collect::<Vec<_>>();
    encode_list(&elements)
}

fn stored_bytes(
    epoch_id: SchemaEpochId,
    payload: &[u8],
) -> Result<(Vec<u8>, StateRoot), StateRootError> {
    let mut preimage = Vec::with_capacity(8 + 10 + 10 + ID_LEN + 10 + payload.len());
    preimage.extend_from_slice(MAGIC);
    preimage.extend_from_slice(&encode_uvar(FORMAT_VERSION));
    preimage.extend_from_slice(&encode_uvar(u64::from(CONTRACT_TAG)));
    preimage.extend_from_slice(epoch_id.as_bytes());
    preimage.extend_from_slice(&encode_uvar(payload.len() as u64));
    preimage.extend_from_slice(payload);
    let root = StateRoot::derive(&preimage);
    preimage.extend_from_slice(root.as_bytes());
    if preimage.len() > MAX_STANDALONE_BYTES {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    Ok((preimage, root))
}

fn decode_envelope(input: &[u8]) -> Result<(SchemaEpochId, &[u8], StateRoot), StateRootError> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    let mut reader = Reader::new(input);
    if reader.take_exact(MAGIC.len())? != MAGIC {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::MagicInvalid,
        )));
    }
    if reader.read_uvar_width(64)? != FORMAT_VERSION {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::VersionUnsupported,
        )));
    }
    if reader.read_uvar_width(32)? != u64::from(CONTRACT_TAG) {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::ContractUnknown,
        )));
    }
    let epoch_id = SchemaEpochId::from_bytes(reader.take_array()?);
    let payload_len = reader.read_len(MAX_STANDALONE_BYTES)?;
    let payload = reader.take_exact(payload_len)?;
    let digest = reader.take_exact(ID_LEN)?;
    if !reader.is_finished() {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::TrailingBytes,
        )));
    }
    let root = StateRoot::derive(&input[..input.len() - ID_LEN]);
    if digest != root.as_bytes() {
        return Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::DigestMismatch,
        )));
    }
    Ok((epoch_id, payload, root))
}

fn decode_payload(input: &[u8], enforce_semantics: bool) -> Result<StateRootRecord, ScbError> {
    let mut record = RecordReader::new(input)?;
    let out = StateRootRecord {
        workspace_id: WorkspaceId::from_bytes(record.required_array(1)?),
        schema_epoch_id: SchemaEpochId::from_bytes(record.required_array(2)?),
        entity_bindings: decode_bindings(record.required(3)?)?,
        entry_points: decode_id_set(record.required(4)?)?,
        dependency_roots: decode_root_set(record.required(5)?)?,
        contract_root: ObjectId::from_bytes(record.required_array(6)?),
        test_root: ObjectId::from_bytes(record.required_array(7)?),
        policy_root: PolicyRootId::from_bytes(record.required_array(8)?),
        interpretation_flags: decode_u32_set_payload(record.required(9)?)?,
    };
    record.finish()?;
    if enforce_semantics {
        validate_record_semantics(&out).map_err(|code| match code {
            StateRootErrorCode::EntryUnbound | StateRootErrorCode::FlagUnknown => {
                ScbError::new(ScbErrorCode::FieldUnknown)
            }
            StateRootErrorCode::DuplicateInput | StateRootErrorCode::ExcludedFact => {
                ScbError::new(ScbErrorCode::FieldDuplicate)
            }
        })?;
    }
    Ok(out)
}

fn decode_bindings(input: &[u8]) -> Result<Vec<(EntityId, ObjectId)>, ScbError> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count = usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > reader.remaining() / (ID_LEN + 2) {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut previous: Option<[u8; ID_LEN]> = None;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let key = reader.read_sized(MAX_STANDALONE_BYTES)?;
        let key = exact_array(key)?;
        if previous.is_some_and(|prev| prev > key) {
            return Err(ScbError::new(ScbErrorCode::MapOrder));
        }
        if previous == Some(key) {
            return Err(ScbError::new(ScbErrorCode::MapDuplicate));
        }
        let value = exact_array(reader.read_sized(MAX_STANDALONE_BYTES)?)?;
        out.push((EntityId::from_bytes(key), ObjectId::from_bytes(value)));
        previous = Some(key);
    }
    if reader.is_finished() {
        Ok(out)
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn decode_id_set(input: &[u8]) -> Result<Vec<EntityId>, ScbError> {
    decode_fixed_set(input).map(|values| values.into_iter().map(EntityId::from_bytes).collect())
}

fn decode_root_set(input: &[u8]) -> Result<Vec<StateRoot>, ScbError> {
    decode_fixed_set(input).map(|values| values.into_iter().map(StateRoot::from_bytes).collect())
}

fn decode_fixed_set(input: &[u8]) -> Result<Vec<[u8; ID_LEN]>, ScbError> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count = usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > reader.remaining() / (ID_LEN + 1) {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut previous: Option<[u8; ID_LEN]> = None;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let value = exact_array(reader.read_sized(MAX_STANDALONE_BYTES)?)?;
        if previous.is_some_and(|prev| prev >= value) {
            return Err(if previous == Some(value) {
                ScbError::new(ScbErrorCode::MapDuplicate)
            } else {
                ScbError::new(ScbErrorCode::MapOrder)
            });
        }
        previous = Some(value);
        out.push(value);
    }
    if reader.is_finished() {
        Ok(out)
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn decode_u32_set_payload(input: &[u8]) -> Result<Vec<u32>, ScbError> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let count = usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > reader.remaining() {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut previous: Option<Vec<u8>> = None;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let element = reader.read_sized(MAX_STANDALONE_BYTES)?;
        if previous.as_deref().is_some_and(|prev| prev >= element) {
            return Err(if previous.as_deref() == Some(element) {
                ScbError::new(ScbErrorCode::MapDuplicate)
            } else {
                ScbError::new(ScbErrorCode::MapOrder)
            });
        }
        let mut nested = Reader::new(element);
        let value = nested.read_uvar_width(32)?;
        if !nested.is_finished() {
            return Err(ScbError::new(ScbErrorCode::TrailingBytes));
        }
        out.push(u32::try_from(value).map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))?);
        previous = Some(element.to_vec());
    }
    if reader.is_finished() {
        Ok(out)
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn validate_record_semantics(record: &StateRootRecord) -> Result<(), StateRootErrorCode> {
    if record.interpretation_flags.is_empty() {
        for entry in &record.entry_points {
            if record
                .entity_bindings
                .binary_search_by_key(entry, |(entity_id, _)| *entity_id)
                .is_err()
            {
                return Err(StateRootErrorCode::EntryUnbound);
            }
        }
        Ok(())
    } else {
        Err(StateRootErrorCode::FlagUnknown)
    }
}

fn reject_unknown_flags(flags: &[u32]) -> Result<(), StateRootError> {
    if flags.is_empty() {
        Ok(())
    } else {
        Err(StateRootError::StateRoot(StateRootErrorCode::FlagUnknown))
    }
}

fn check_builder_count(count: usize) -> Result<(), StateRootError> {
    if u64::try_from(count).map_or(true, |count| count > MAX_COLLECTION_ELEMENTS) {
        Err(StateRootError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )))
    } else {
        Ok(())
    }
}

fn sort_bindings(bindings: &mut [(EntityId, ObjectId)]) -> Result<(), StateRootError> {
    bindings.sort_by_key(|(entity_id, _)| *entity_id);
    if bindings.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(StateRootError::StateRoot(
            StateRootErrorCode::DuplicateInput,
        ));
    }
    Ok(())
}

fn sort_unique<T: Ord>(values: &mut [T]) -> Result<(), StateRootError> {
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StateRootError::StateRoot(
            StateRootErrorCode::DuplicateInput,
        ));
    }
    Ok(())
}

trait IdBytes {
    fn id_bytes(&self) -> &[u8; ID_LEN];
}

impl IdBytes for EntityId {
    fn id_bytes(&self) -> &[u8; ID_LEN] {
        self.as_bytes()
    }
}

impl IdBytes for StateRoot {
    fn id_bytes(&self) -> &[u8; ID_LEN] {
        self.as_bytes()
    }
}

fn exact_array(input: &[u8]) -> Result<[u8; ID_LEN], ScbError> {
    input
        .try_into()
        .map_err(|_| ScbError::new(ScbErrorCode::LengthOverflow))
}

#[derive(Clone)]
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

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8], ScbError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| ScbError::new(ScbErrorCode::LengthOverflow))?;
        if end > self.input.len() {
            return Err(ScbError::new(ScbErrorCode::LengthOverflow));
        }
        let slice = &self.input[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ScbError> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take_exact(N)?);
        Ok(out)
    }

    fn read_u8(&mut self) -> Result<u8, ScbError> {
        self.take_exact(1)?
            .first()
            .copied()
            .ok_or_else(|| ScbError::new(ScbErrorCode::LengthOverflow))
    }

    fn read_uvar_width(&mut self, width: u8) -> Result<u64, ScbError> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        let mut bytes_read = 0_u8;
        loop {
            let byte = self.read_u8()?;
            bytes_read += 1;
            let payload = u64::from(byte & 0x7f);
            if shift >= 64 && payload != 0 {
                return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
            }
            if shift < 64 {
                if shift == 63 && payload > 1 {
                    return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
                }
                value |= payload
                    .checked_shl(shift)
                    .ok_or_else(|| ScbError::new(ScbErrorCode::IntegerOverflow))?;
            }
            if byte & 0x80 == 0 {
                if bytes_read > 1 && payload == 0 {
                    return Err(ScbError::new(ScbErrorCode::VarintNonMinimal));
                }
                if width < 64 && value >= (1_u64 << width) {
                    return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
                }
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 + 7 {
                return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
            }
        }
    }

    fn read_len(&mut self, max: usize) -> Result<usize, ScbError> {
        let len = self.read_uvar_width(64)?;
        let len = usize::try_from(len).map_err(|_| ScbError::new(ScbErrorCode::LengthOverflow))?;
        if len > max {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(len)
    }

    fn read_sized(&mut self, max: usize) -> Result<&'a [u8], ScbError> {
        let len = self.read_len(max)?;
        self.take_exact(len)
    }

    fn read_count(&mut self) -> Result<u64, ScbError> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_COLLECTION_ELEMENTS {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(count)
    }

    fn read_record_field_count(&mut self) -> Result<u64, ScbError> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_RECORD_FIELDS {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(count)
    }
}

struct RecordReader<'a> {
    fields: Vec<(u32, &'a [u8])>,
}

impl<'a> RecordReader<'a> {
    fn new(input: &'a [u8]) -> Result<Self, ScbError> {
        let mut reader = Reader::new(input);
        let field_count = reader.read_record_field_count()?;
        if field_count < FIELD_COUNT {
            return Err(ScbError::new(ScbErrorCode::FieldMissing));
        }
        let count =
            usize::try_from(field_count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
        if count > reader.remaining() / 2 {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        let mut fields = Vec::with_capacity(count);
        let mut previous_tag = None;
        for _ in 0..count {
            let tag = reader.read_uvar_width(32)?;
            let tag =
                u32::try_from(tag).map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))?;
            if previous_tag.is_some_and(|previous| previous == tag) {
                return Err(ScbError::new(ScbErrorCode::FieldDuplicate));
            }
            if previous_tag.is_some_and(|previous| previous > tag) {
                return Err(ScbError::new(ScbErrorCode::FieldOrder));
            }
            let value = reader.read_sized(MAX_STANDALONE_BYTES)?;
            fields.push((tag, value));
            previous_tag = Some(tag);
        }
        if !reader.is_finished() {
            return Err(ScbError::new(ScbErrorCode::TrailingBytes));
        }
        Ok(Self { fields })
    }

    fn required(&mut self, tag: u32) -> Result<&'a [u8], ScbError> {
        self.fields
            .binary_search_by_key(&tag, |(field_tag, _)| *field_tag)
            .map(|index| self.fields.remove(index).1)
            .map_err(|_| ScbError::new(ScbErrorCode::FieldMissing))
    }

    fn required_array<const N: usize>(&mut self, tag: u32) -> Result<[u8; N], ScbError> {
        self.required(tag)?
            .try_into()
            .map_err(|_| ScbError::new(ScbErrorCode::LengthOverflow))
    }

    fn finish(self) -> Result<(), ScbError> {
        if self.fields.is_empty() {
            Ok(())
        } else {
            Err(ScbError::new(ScbErrorCode::FieldUnknown))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;

    fn id(byte: u8) -> [u8; ID_LEN] {
        [byte; ID_LEN]
    }

    fn workspace(byte: u8) -> WorkspaceId {
        WorkspaceId::from_bytes(id(byte))
    }

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes(id(byte))
    }

    fn object(byte: u8) -> ObjectId {
        ObjectId::from_bytes(id(byte))
    }

    fn policy(byte: u8) -> PolicyRootId {
        PolicyRootId::from_bytes(id(byte))
    }

    fn root(byte: u8) -> StateRoot {
        StateRoot::from_bytes(id(byte))
    }

    fn registry() -> SchemaEpochRegistry<StateRootEpoch1Decoder> {
        conformance_registry().unwrap()
    }

    fn builder() -> StateRootBuilder {
        StateRootBuilder::new(workspace(1), object(20), object(21), policy(22))
            .entity_binding(entity(3), object(30))
            .entity_binding(entity(2), object(31))
            .entry_point(entity(2))
            .dependency_root(root(41))
            .dependency_root(root(40))
    }

    fn hex(bytes: impl AsRef<[u8]>) -> String {
        let mut out = String::new();
        for byte in bytes.as_ref() {
            write!(&mut out, "{byte:02x}").unwrap();
        }
        out
    }

    fn from_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn synthetic_zero_epoch_vector_hashes_but_authorization_rejects() {
        let payload = from_hex(
            "090120000000000000000000000000000000000000000000000000000000000000000002200000000000000000000000000000000000000000000000000000000000000000030100040100050100062000000000000000000000000000000000000000000000000000000000000000000720000000000000000000000000000000000000000000000000000000000000000008200000000000000000000000000000000000000000000000000000000000000000090100",
        );
        assert_eq!(payload.len(), 183);
        let zero_epoch = SchemaEpochId::from_bytes([0; ID_LEN]);
        let (stored, root) = stored_bytes(zero_epoch, &payload).unwrap();
        assert_eq!(stored.len() - ID_LEN, 228);
        assert_eq!(stored.len(), 260);
        assert_eq!(root, SYNTHETIC_ZERO_EPOCH_ROOT);

        let error = import_state_root(&registry(), &stored).unwrap_err();
        assert_eq!(error.code_str(), "SCHEMA_EPOCH_MISMATCH");
    }

    #[test]
    fn descriptor_and_registered_epoch_are_exact() {
        let record = conformance_epoch_record();
        let descriptor = record.contracts.single().unwrap();
        assert_eq!(descriptor.contract_tag, 160);
        assert_eq!(descriptor.digest_domain_tag, 4);
        assert_eq!(descriptor.kind_tag, 160);
        assert_eq!(descriptor.required_fields, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert!(descriptor.optional_fields.is_empty());
        assert!(descriptor.variant_tags.is_empty());
        assert_ne!(conformance_epoch_id().unwrap().as_bytes(), &[0; ID_LEN]);
    }

    #[test]
    fn accepted_vector_is_frozen_and_round_trips() {
        let accepted = builder().build(&registry()).unwrap();
        assert_eq!(
            hex(accepted.root.as_bytes()),
            "d3914cbffcde449959d6a35eddb16293c3424f4980e64e687a4f47358ad2770a"
        );
        assert_eq!(
            hex(&accepted.stored_bytes),
            "534c45595343423101a001a7fcf97a85d41ef9b1c89394a324f2dc7ec875b9ded48a783104314857dc870e9f0309012001010101010101010101010101010101010101010101010101010101010101010220a7fcf97a85d41ef9b1c89394a324f2dc7ec875b9ded48a783104314857dc870e03850102200202020202020202020202020202020202020202020202020202020202020202201f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f200303030303030303030303030303030303030303030303030303030303030303201e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e042201200202020202020202020202020202020202020202020202020202020202020202054302202828282828282828282828282828282828282828282828282828282828282828202929292929292929292929292929292929292929292929292929292929292929062014141414141414141414141414141414141414141414141414141414141414140720151515151515151515151515151515151515151515151515151515151515151508201616161616161616161616161616161616161616161616161616161616161616090100d3914cbffcde449959d6a35eddb16293c3424f4980e64e687a4f47358ad2770a"
        );
        assert_eq!(
            import_state_root(&registry(), &accepted.stored_bytes).unwrap(),
            accepted
        );
    }

    #[test]
    fn unordered_inputs_have_identical_root() {
        let left = builder().build(&registry()).unwrap();
        let right = StateRootBuilder::new(workspace(1), object(20), object(21), policy(22))
            .dependency_root(root(40))
            .entry_point(entity(2))
            .dependency_root(root(41))
            .entity_binding(entity(2), object(31))
            .entity_binding(entity(3), object(30))
            .build(&registry())
            .unwrap();
        assert_eq!(left.root, right.root);
        assert_eq!(left.stored_bytes, right.stored_bytes);
    }

    #[test]
    fn every_field_perturbation_changes_root() {
        let base = builder().build(&registry()).unwrap().root;
        let variants = [
            StateRootBuilder::new(workspace(9), object(20), object(21), policy(22))
                .entity_binding(entity(3), object(30))
                .entity_binding(entity(2), object(31))
                .entry_point(entity(2))
                .dependency_root(root(41))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
            StateRootBuilder::new(workspace(1), object(20), object(21), policy(22))
                .entity_binding(entity(4), object(30))
                .entity_binding(entity(2), object(31))
                .entry_point(entity(2))
                .dependency_root(root(41))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
            StateRootBuilder::new(workspace(1), object(20), object(21), policy(22))
                .entity_binding(entity(3), object(30))
                .entity_binding(entity(2), object(32))
                .entry_point(entity(2))
                .dependency_root(root(41))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
            StateRootBuilder::new(workspace(1), object(20), object(21), policy(22))
                .entity_binding(entity(3), object(30))
                .entity_binding(entity(2), object(31))
                .entry_point(entity(3))
                .dependency_root(root(41))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
            StateRootBuilder::new(workspace(1), object(20), object(21), policy(22))
                .entity_binding(entity(3), object(30))
                .entity_binding(entity(2), object(31))
                .entry_point(entity(2))
                .dependency_root(root(42))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
            StateRootBuilder::new(workspace(1), object(23), object(21), policy(22))
                .entity_binding(entity(3), object(30))
                .entity_binding(entity(2), object(31))
                .entry_point(entity(2))
                .dependency_root(root(41))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
            StateRootBuilder::new(workspace(1), object(20), object(24), policy(22))
                .entity_binding(entity(3), object(30))
                .entity_binding(entity(2), object(31))
                .entry_point(entity(2))
                .dependency_root(root(41))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
            StateRootBuilder::new(workspace(1), object(20), object(21), policy(25))
                .entity_binding(entity(3), object(30))
                .entity_binding(entity(2), object(31))
                .entry_point(entity(2))
                .dependency_root(root(41))
                .dependency_root(root(40))
                .build(&registry())
                .unwrap()
                .root,
        ];
        for variant in variants {
            assert_ne!(base, variant);
        }
    }

    #[test]
    fn builder_rejects_duplicates_unbound_entry_and_unknown_flags() {
        assert_eq!(
            builder()
                .entity_binding(entity(2), object(31))
                .build(&registry())
                .unwrap_err()
                .code_str(),
            "STATE_ROOT_DUPLICATE_INPUT"
        );
        assert_eq!(
            builder()
                .entry_point(entity(9))
                .build(&registry())
                .unwrap_err()
                .code_str(),
            "STATE_ROOT_ENTRY_UNBOUND"
        );
        assert_eq!(
            builder()
                .interpretation_flag(1)
                .build(&registry())
                .unwrap_err()
                .code_str(),
            "STATE_ROOT_FLAG_UNKNOWN"
        );
    }

    #[test]
    fn strict_import_rejects_order_duplicates_mismatch_trailer_and_limits() {
        let accepted = builder().build(&registry()).unwrap();
        let mut digest_bad = accepted.stored_bytes.clone();
        *digest_bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            import_state_root(&registry(), &digest_bad)
                .unwrap_err()
                .code_str(),
            "SCB_DIGEST_MISMATCH"
        );

        let mut trailing = accepted.stored_bytes.clone();
        trailing.push(0);
        assert_eq!(
            import_state_root(&registry(), &trailing)
                .unwrap_err()
                .code_str(),
            "SCB_TRAILING_BYTES"
        );

        let payload = manual_record(&[
            (1, accepted.record.workspace_id.as_bytes().to_vec()),
            (2, accepted.record.schema_epoch_id.as_bytes().to_vec()),
            (3, encode_bindings(&accepted.record)),
            (5, encode_id_set(&accepted.record.dependency_roots).unwrap()),
            (6, accepted.record.contract_root.as_bytes().to_vec()),
            (7, accepted.record.test_root.as_bytes().to_vec()),
            (8, accepted.record.policy_root.as_bytes().to_vec()),
            (9, encode_u32_set(&[]).unwrap()),
        ]);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_MISSING"
        );

        let mut noncanonical = accepted.record.clone();
        noncanonical.entity_bindings.swap(0, 1);
        let payload = encode_payload_manual(&noncanonical, false, false, false);
        let (stored, _) = stored_bytes(noncanonical.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_MAP_ORDER"
        );

        let payload = encode_payload_manual(&accepted.record, false, false, true);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_MAP_DUPLICATE"
        );

        let mut duplicate_set = accepted.record.clone();
        duplicate_set.entry_points.push(entity(2));
        let payload = encode_payload_manual(&duplicate_set, true, false, false);
        let (stored, _) = stored_bytes(duplicate_set.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_MAP_DUPLICATE"
        );

        let payload = encode_payload_manual(&accepted.record, false, true, false);
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "STATE_ROOT_FLAG_UNKNOWN"
        );

        let oversized = vec![0_u8; MAX_STANDALONE_BYTES + 1];
        assert_eq!(
            import_state_root(&registry(), &oversized)
                .unwrap_err()
                .code_str(),
            "SCB_RESOURCE_LIMIT"
        );
    }

    #[test]
    fn strict_import_rejects_unknown_duplicate_and_ordered_fields() {
        let accepted = builder().build(&registry()).unwrap();
        let canonical_fields = payload_fields(&accepted.record);

        let mut unknown = canonical_fields.clone();
        unknown.push((10, Vec::new()));
        let (stored, _) =
            stored_bytes(accepted.record.schema_epoch_id, &manual_record(&unknown)).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_UNKNOWN"
        );

        let mut duplicate = canonical_fields.clone();
        duplicate.insert(1, duplicate[0].clone());
        let (stored, _) =
            stored_bytes(accepted.record.schema_epoch_id, &manual_record(&duplicate)).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_DUPLICATE"
        );

        let mut unordered = canonical_fields;
        unordered.swap(0, 1);
        let (stored, _) =
            stored_bytes(accepted.record.schema_epoch_id, &manual_record(&unordered)).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_FIELD_ORDER"
        );
    }

    #[test]
    fn strict_import_rejects_nonminimal_envelope_and_payload_epoch_mismatch() {
        let accepted = builder().build(&registry()).unwrap();
        let preimage = &accepted.stored_bytes[..accepted.stored_bytes.len() - ID_LEN];
        let mut nonminimal = Vec::with_capacity(preimage.len() + 1);
        nonminimal.extend_from_slice(MAGIC);
        nonminimal.extend_from_slice(&[0x81, 0x00]);
        nonminimal.extend_from_slice(&preimage[MAGIC.len() + 1..]);
        let stored = attach_root(nonminimal);
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_VARINT_NON_MINIMAL"
        );

        let mut mismatched = accepted.record.clone();
        mismatched.schema_epoch_id = SchemaEpochId::from_bytes(id(99));
        let payload = encode_payload(&mismatched).unwrap();
        let (stored, _) = stored_bytes(accepted.record.schema_epoch_id, &payload).unwrap();
        assert_eq!(
            import_state_root(&registry(), &stored)
                .unwrap_err()
                .code_str(),
            "SCB_EPOCH_MISMATCH"
        );
    }

    #[test]
    fn builder_collection_limit_fails_closed_before_sorting() {
        assert_eq!(
            check_builder_count(usize::try_from(MAX_COLLECTION_ELEMENTS).unwrap() + 1)
                .unwrap_err()
                .code_str(),
            "SCB_RESOURCE_LIMIT"
        );
    }

    #[test]
    fn synthetic_flag_changes_digest_but_remains_unauthorized() {
        let zero_epoch = SchemaEpochId::from_bytes([0; ID_LEN]);
        let base = StateRootRecord {
            workspace_id: workspace(0),
            schema_epoch_id: zero_epoch,
            entity_bindings: Vec::new(),
            entry_points: Vec::new(),
            dependency_roots: Vec::new(),
            contract_root: object(0),
            test_root: object(0),
            policy_root: policy(0),
            interpretation_flags: Vec::new(),
        };
        let (_, empty_root) = stored_bytes(zero_epoch, &encode_payload(&base).unwrap()).unwrap();
        let mut flagged = base;
        flagged.interpretation_flags.push(1);
        let (_, flagged_root) =
            stored_bytes(zero_epoch, &encode_payload(&flagged).unwrap()).unwrap();
        assert_ne!(empty_root, flagged_root);
    }

    #[test]
    fn epoch_descriptor_and_decoder_mismatch_fail_closed() {
        let accepted = builder().build(&registry()).unwrap();
        let empty_registry =
            SchemaEpochRegistry::new(Vec::<RegistryEntry<StateRootEpoch1Decoder>>::new()).unwrap();
        assert_eq!(
            import_state_root(&empty_registry, &accepted.stored_bytes)
                .unwrap_err()
                .code_str(),
            "SCHEMA_EPOCH_MISMATCH"
        );

        let mut record = conformance_epoch_record();
        record.contracts[0].kind_tag = 161;
        let epoch_id = record.schema_epoch_id().unwrap();
        let bad_registry = SchemaEpochRegistry::new(vec![
            RegistryEntry::new(epoch_id, record, StateRootEpoch1Decoder::new(epoch_id)).unwrap(),
        ])
        .unwrap();
        let mut bad_epoch_record = accepted.record.clone();
        bad_epoch_record.schema_epoch_id = epoch_id;
        let payload = encode_payload(&bad_epoch_record).unwrap();
        let (stored, _) = stored_bytes(epoch_id, &payload).unwrap();
        assert_eq!(
            import_state_root(&bad_registry, &stored)
                .unwrap_err()
                .code_str(),
            "SCHEMA_CONTRACT_UNKNOWN"
        );

        let mismatch_decoder = StateRootEpoch1Decoder::new(SchemaEpochId::from_bytes(id(99)));
        assert_eq!(
            RegistryEntry::new(
                conformance_epoch_id().unwrap(),
                conformance_epoch_record(),
                mismatch_decoder
            )
            .unwrap_err()
            .code()
            .as_str(),
            "SCHEMA_EPOCH_MISMATCH"
        );
    }

    fn encode_payload_manual(
        record: &StateRootRecord,
        include_duplicate_entry: bool,
        include_unknown_flag: bool,
        duplicate_binding: bool,
    ) -> Vec<u8> {
        let mut bindings = record
            .entity_bindings
            .iter()
            .map(|(entity_id, object_id)| {
                let mut out = Vec::new();
                out.extend_from_slice(&encode_uvar(ID_LEN as u64));
                out.extend_from_slice(entity_id.as_bytes());
                out.extend_from_slice(&encode_uvar(ID_LEN as u64));
                out.extend_from_slice(object_id.as_bytes());
                out
            })
            .collect::<Vec<_>>();
        if duplicate_binding {
            bindings.insert(1, bindings[0].clone());
        }
        let mut bindings_field = encode_uvar(bindings.len() as u64);
        for binding in bindings {
            bindings_field.extend_from_slice(&binding);
        }

        let mut entries = record.entry_points.clone();
        if include_duplicate_entry {
            entries.push(entries[0]);
        }
        let entry_field = encode_list(
            &entries
                .iter()
                .map(|entry| entry.as_bytes().to_vec())
                .collect::<Vec<_>>(),
        )
        .unwrap();

        let flags = if include_unknown_flag {
            vec![1]
        } else {
            Vec::new()
        };
        encode_record(&[
            (1, record.workspace_id.as_bytes().to_vec()),
            (2, record.schema_epoch_id.as_bytes().to_vec()),
            (3, bindings_field),
            (4, entry_field),
            (5, encode_id_set(&record.dependency_roots).unwrap()),
            (6, record.contract_root.as_bytes().to_vec()),
            (7, record.test_root.as_bytes().to_vec()),
            (8, record.policy_root.as_bytes().to_vec()),
            (9, encode_u32_set(&flags).unwrap()),
        ])
        .unwrap()
    }

    fn encode_bindings(record: &StateRootRecord) -> Vec<u8> {
        let bindings = record
            .entity_bindings
            .iter()
            .map(|(entity_id, object_id)| {
                (entity_id.as_bytes().to_vec(), object_id.as_bytes().to_vec())
            })
            .collect::<Vec<_>>();
        encode_map(&bindings).unwrap()
    }

    fn payload_fields(record: &StateRootRecord) -> Vec<(u32, Vec<u8>)> {
        vec![
            (1, record.workspace_id.as_bytes().to_vec()),
            (2, record.schema_epoch_id.as_bytes().to_vec()),
            (3, encode_bindings(record)),
            (4, encode_id_set(&record.entry_points).unwrap()),
            (5, encode_id_set(&record.dependency_roots).unwrap()),
            (6, record.contract_root.as_bytes().to_vec()),
            (7, record.test_root.as_bytes().to_vec()),
            (8, record.policy_root.as_bytes().to_vec()),
            (9, encode_u32_set(&record.interpretation_flags).unwrap()),
        ]
    }

    fn manual_record(fields: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = encode_uvar(fields.len() as u64);
        for (tag, value) in fields {
            out.extend_from_slice(&encode_uvar(u64::from(*tag)));
            out.extend_from_slice(&encode_uvar(value.len() as u64));
            out.extend_from_slice(value);
        }
        out
    }

    fn attach_root(mut preimage: Vec<u8>) -> Vec<u8> {
        let root = StateRoot::derive(&preimage);
        preimage.extend_from_slice(root.as_bytes());
        preimage
    }

    trait Single<T> {
        fn single(&self) -> Option<&T>;
    }

    impl<T> Single<T> for [T] {
        fn single(&self) -> Option<&T> {
            if self.len() == 1 { self.first() } else { None }
        }
    }
}
