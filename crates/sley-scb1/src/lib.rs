#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::{fmt, str};

use sley_id::ObjectId;
use unicode_normalization::UnicodeNormalization;

/// Unicode normalization data frozen by SCB1 epoch 1.
pub const UNICODE_VERSION: (u8, u8, u8) = unicode_normalization::UNICODE_VERSION;

const _: () = assert!(
    UNICODE_VERSION.0 == 16 && UNICODE_VERSION.1 == 0 && UNICODE_VERSION.2 == 0,
    "SCB1 epoch 1 requires Unicode 16.0.0"
);

/// Maximum standalone envelope size accepted by SCB1 epoch 1.
pub const MAX_STANDALONE_BYTES: usize = 67_108_864;
/// Maximum length for one bytes, text, label, or extension payload.
pub const MAX_BYTE_PAYLOAD: usize = 16_777_216;
/// Maximum nested structural depth.
pub const MAX_NESTING_DEPTH: usize = 64;
/// Maximum fields in one record.
pub const MAX_RECORD_FIELDS: u64 = 65_535;
/// Maximum elements in one list, set, or map.
pub const MAX_COLLECTION_ELEMENTS: u64 = 1_000_000;
/// Maximum decoder allocation budget per standalone value.
pub const MAX_TOTAL_ALLOCATION: usize = 134_217_728;

const MAGIC: &[u8; 8] = b"SLEYSCB1";
const VERSION: u64 = 1;
const EPOCH_ID: [u8; 32] = {
    let mut bytes = [0_u8; 32];
    bytes[31] = 1;
    bytes
};

/// Stable SCB1 decode failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScbErrorCode {
    /// `SCB_MAGIC_INVALID`
    MagicInvalid,
    /// `SCB_VERSION_UNSUPPORTED`
    VersionUnsupported,
    /// `SCB_CONTRACT_UNKNOWN`
    ContractUnknown,
    /// `SCB_EPOCH_MISMATCH`
    EpochMismatch,
    /// `SCB_DIGEST_MISMATCH`
    DigestMismatch,
    /// `SCB_TRAILING_BYTES`
    TrailingBytes,
    /// `SCB_VARINT_NON_MINIMAL`
    VarintNonMinimal,
    /// `SCB_INTEGER_OVERFLOW`
    IntegerOverflow,
    /// `SCB_LENGTH_OVERFLOW`
    LengthOverflow,
    /// `SCB_BOOL_INVALID`
    BoolInvalid,
    /// `SCB_UTF8_INVALID`
    Utf8Invalid,
    /// `SCB_LABEL_NOT_NFC`
    LabelNotNfc,
    /// `SCB_FLOAT_NON_CANONICAL`
    FloatNonCanonical,
    /// `SCB_FIELD_MISSING`
    FieldMissing,
    /// `SCB_FIELD_UNKNOWN`
    FieldUnknown,
    /// `SCB_FIELD_DUPLICATE`
    FieldDuplicate,
    /// `SCB_FIELD_ORDER`
    FieldOrder,
    /// `SCB_UNION_INVALID`
    UnionInvalid,
    /// `SCB_MAP_ORDER`
    MapOrder,
    /// `SCB_MAP_DUPLICATE`
    MapDuplicate,
    /// `SCB_EXTENSION_UNKNOWN`
    ExtensionUnknown,
    /// `SCB_RESOURCE_LIMIT`
    ResourceLimit,
}

impl ScbErrorCode {
    /// Returns the frozen registry string for this error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MagicInvalid => "SCB_MAGIC_INVALID",
            Self::VersionUnsupported => "SCB_VERSION_UNSUPPORTED",
            Self::ContractUnknown => "SCB_CONTRACT_UNKNOWN",
            Self::EpochMismatch => "SCB_EPOCH_MISMATCH",
            Self::DigestMismatch => "SCB_DIGEST_MISMATCH",
            Self::TrailingBytes => "SCB_TRAILING_BYTES",
            Self::VarintNonMinimal => "SCB_VARINT_NON_MINIMAL",
            Self::IntegerOverflow => "SCB_INTEGER_OVERFLOW",
            Self::LengthOverflow => "SCB_LENGTH_OVERFLOW",
            Self::BoolInvalid => "SCB_BOOL_INVALID",
            Self::Utf8Invalid => "SCB_UTF8_INVALID",
            Self::LabelNotNfc => "SCB_LABEL_NOT_NFC",
            Self::FloatNonCanonical => "SCB_FLOAT_NON_CANONICAL",
            Self::FieldMissing => "SCB_FIELD_MISSING",
            Self::FieldUnknown => "SCB_FIELD_UNKNOWN",
            Self::FieldDuplicate => "SCB_FIELD_DUPLICATE",
            Self::FieldOrder => "SCB_FIELD_ORDER",
            Self::UnionInvalid => "SCB_UNION_INVALID",
            Self::MapOrder => "SCB_MAP_ORDER",
            Self::MapDuplicate => "SCB_MAP_DUPLICATE",
            Self::ExtensionUnknown => "SCB_EXTENSION_UNKNOWN",
            Self::ResourceLimit => "SCB_RESOURCE_LIMIT",
        }
    }
}

impl fmt::Display for ScbErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// SCB1 decode error with a stable failure code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScbError {
    code: ScbErrorCode,
}

impl ScbError {
    /// Constructs an error from a stable code.
    #[must_use]
    pub const fn new(code: ScbErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(&self) -> ScbErrorCode {
        self.code
    }
}

impl fmt::Display for ScbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(f)
    }
}

impl std::error::Error for ScbError {}

type Result<T> = core::result::Result<T, ScbError>;

/// Synthetic SCB1 fixture contracts from S20-100 conformance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureContract {
    /// Contract tag 1: empty record.
    EmptyObject,
    /// Contract tag 2: record with required Bool field tag 1.
    RequiredBool,
}

impl FixtureContract {
    const fn tag(self) -> u32 {
        match self {
            Self::EmptyObject => 1,
            Self::RequiredBool => 2,
        }
    }
}

/// Decoded standalone fixture envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandaloneFixture {
    /// Synthetic contract decoded from the envelope.
    pub contract: FixtureContract,
    /// Canonical record payload bytes.
    pub payload: Vec<u8>,
    /// Domain-separated object digest.
    pub object_id: ObjectId,
}

/// Encodes an unsigned integer as canonical SCB1 uvarint.
#[must_use]
pub fn encode_uvar(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return out;
        }
    }
}

/// Encodes a signed 64-bit integer using SCB1 `ZigZag`.
#[must_use]
pub fn encode_sint64(value: i64) -> Vec<u8> {
    encode_uvar(((value << 1) ^ (value >> 63)).cast_unsigned())
}

/// Encodes a boolean.
#[must_use]
pub fn encode_bool(value: bool) -> Vec<u8> {
    vec![u8::from(value)]
}

/// Encodes raw bytes with an SCB1 length prefix.
///
/// # Errors
///
/// Returns `SCB_RESOURCE_LIMIT` when the epoch byte-payload maximum is exceeded.
pub fn encode_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_BYTE_PAYLOAD {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    encode_sized(bytes)
}

/// Encodes text after Rust has guaranteed UTF-8 validity.
///
/// # Errors
///
/// Returns `SCB_RESOURCE_LIMIT` when the epoch text-payload maximum is exceeded.
pub fn encode_text(text: &str) -> Result<Vec<u8>> {
    encode_bytes(text.as_bytes())
}

/// Encodes a normalized label.
///
/// # Errors
///
/// Returns `SCB_LABEL_NOT_NFC` if input is not NFC.
pub fn encode_normalized_label(label: &str) -> Result<Vec<u8>> {
    if label.nfc().eq(label.chars()) {
        encode_text(label)
    } else {
        Err(ScbError::new(ScbErrorCode::LabelNotNfc))
    }
}

/// Encodes a canonical f32 bit pattern.
///
/// # Errors
///
/// Returns `SCB_FLOAT_NON_CANONICAL` for negative zero or non-canonical NaN
/// encodings.
pub fn encode_f32_bits(bits: u32) -> Result<Vec<u8>> {
    validate_f32_bits(bits)?;
    Ok(bits.to_be_bytes().to_vec())
}

/// Encodes a canonical f64 bit pattern.
///
/// # Errors
///
/// Returns `SCB_FLOAT_NON_CANONICAL` for negative zero or non-canonical NaN
/// encodings.
pub fn encode_f64_bits(bits: u64) -> Result<Vec<u8>> {
    validate_f64_bits(bits)?;
    Ok(bits.to_be_bytes().to_vec())
}

/// Encodes a list from already canonical element encodings.
///
/// # Errors
///
/// Returns a stable resource code when epoch collection or value limits are exceeded.
pub fn encode_list(elements: &[Vec<u8>]) -> Result<Vec<u8>> {
    let count =
        u64::try_from(elements.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count > MAX_COLLECTION_ELEMENTS {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut out = encode_uvar(count);
    for element in elements {
        out.extend_from_slice(&encode_sized(element)?);
    }
    Ok(out)
}

/// Encodes a record in canonical tag order.
///
/// # Errors
///
/// Returns a stable code if the record exceeds epoch limits or repeats a tag.
pub fn encode_record(fields: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
    let field_count =
        u64::try_from(fields.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if field_count > MAX_RECORD_FIELDS {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut ordered = fields.to_vec();
    ordered.sort_by_key(|(tag, _)| *tag);
    if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ScbError::new(ScbErrorCode::FieldDuplicate));
    }
    let mut out = encode_uvar(field_count);
    for (tag, value) in ordered {
        out.extend_from_slice(&encode_uvar(u64::from(tag)));
        out.extend_from_slice(&encode_sized(&value)?);
    }
    Ok(out)
}

/// Encodes a map in canonical encoded-key order.
///
/// # Errors
///
/// Returns a stable code if the map exceeds epoch limits or repeats a key.
pub fn encode_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>> {
    let entry_count =
        u64::try_from(entries.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if entry_count > MAX_COLLECTION_ELEMENTS {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut ordered = entries.to_vec();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    if ordered.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(ScbError::new(ScbErrorCode::MapDuplicate));
    }
    let mut out = encode_uvar(entry_count);
    for (key, value) in ordered {
        out.extend_from_slice(&encode_sized(&key)?);
        out.extend_from_slice(&encode_sized(&value)?);
    }
    Ok(out)
}

/// Encodes a union payload.
///
/// # Errors
///
/// Returns `SCB_RESOURCE_LIMIT` when the encoded payload exceeds epoch limits.
pub fn encode_union(tag: u32, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = encode_uvar(u64::from(tag));
    out.extend_from_slice(&encode_sized(payload)?);
    Ok(out)
}

/// Encodes `Option<UInt64>`.
///
/// # Errors
///
/// Returns a stable resource code if an encoded value exceeds epoch limits.
pub fn encode_option_uvar(value: Option<u64>) -> Result<Vec<u8>> {
    match value {
        None => encode_union(0, &[]),
        Some(value) => encode_union(1, &encode_uvar(value)),
    }
}

fn encode_sized(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let len = u64::try_from(bytes.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    let mut out = encode_uvar(len);
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Encodes a synthetic standalone fixture envelope and returns bytes plus `ObjectId`.
///
/// # Errors
///
/// Returns a stable SCB1 code if the supplied payload is not canonical for the
/// selected fixture contract.
pub fn encode_standalone_fixture(
    contract: FixtureContract,
    payload: &[u8],
) -> Result<(Vec<u8>, ObjectId)> {
    let schema = contract_schema(contract);
    decode_payload_exact(&schema, payload)?;

    let mut preimage = Vec::with_capacity(8 + 1 + 1 + 32 + 5 + payload.len());
    preimage.extend_from_slice(MAGIC);
    preimage.extend_from_slice(&encode_uvar(VERSION));
    preimage.extend_from_slice(&encode_uvar(u64::from(contract.tag())));
    preimage.extend_from_slice(&EPOCH_ID);
    preimage.extend_from_slice(&encode_uvar(payload.len() as u64));
    preimage.extend_from_slice(payload);

    let object_id = ObjectId::derive(&preimage);
    let mut stored = preimage;
    stored.extend_from_slice(object_id.as_bytes());
    if stored.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    Ok((stored, object_id))
}

/// Decodes and verifies a synthetic standalone fixture envelope.
///
/// # Errors
///
/// Returns the first stable SCB1 failure code encountered while decoding the
/// envelope, verifying its digest, or decoding its contract payload.
pub fn decode_standalone_fixture(
    input: &[u8],
    declared: FixtureContract,
) -> Result<StandaloneFixture> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }

    if input.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(ScbError::new(ScbErrorCode::MagicInvalid));
    }
    let mut reader = Reader::new(input);
    reader.take_exact(MAGIC.len())?;

    let version = reader.read_uvar_width(64)?;
    if version != VERSION {
        return Err(ScbError::new(ScbErrorCode::VersionUnsupported));
    }

    let contract_tag = reader.read_uvar_width(32)?;
    let contract = match contract_tag {
        1 => FixtureContract::EmptyObject,
        2 => FixtureContract::RequiredBool,
        _ => return Err(ScbError::new(ScbErrorCode::ContractUnknown)),
    };
    if contract != declared {
        return Err(ScbError::new(ScbErrorCode::ContractUnknown));
    }

    let epoch = reader.take_exact(32)?;
    if epoch != EPOCH_ID {
        return Err(ScbError::new(ScbErrorCode::EpochMismatch));
    }

    let payload_len = reader.read_len(MAX_STANDALONE_BYTES)?;
    let payload = reader.take_exact(payload_len)?;
    let digest = reader.take_exact(32)?;
    if !reader.is_finished() {
        return Err(ScbError::new(ScbErrorCode::TrailingBytes));
    }

    let preimage_len = input.len() - 32;
    let object_id = ObjectId::derive(&input[..preimage_len]);
    if digest != object_id.as_bytes() {
        return Err(ScbError::new(ScbErrorCode::DigestMismatch));
    }

    let schema = contract_schema(contract);
    decode_payload_exact(&schema, payload)?;
    Ok(StandaloneFixture {
        contract,
        payload: payload.to_vec(),
        object_id,
    })
}

/// Schema-directed decoding types for SCB1 fixture and primitive validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Schema {
    /// Unsigned integer with bit width.
    UInt(u8),
    /// Signed integer with bit width.
    SInt(u8),
    /// Boolean.
    Bool,
    /// Byte string.
    Bytes,
    /// Text string.
    Text,
    /// NFC-normalized label.
    NormalizedLabel,
    /// 32-bit float bits.
    F32,
    /// 64-bit float bits.
    F64,
    /// `List<UInt64>`.
    ListUInt64,
    /// `Map<UInt8, UInt8>`.
    MapUInt8UInt8,
    /// Accepted-fixture `Map<UInt64, Text>`.
    MapUInt64Text,
    /// `Option<UInt64>`.
    OptionUInt64,
    /// Accepted-fixture union containing Bool at one declared tag.
    UnionBool(u32),
    /// Fixture record with optional bool fields 1 and 2.
    FixtureRecord,
    /// Accepted-fixture record with Bool field 1 and `UInt64` field 3.
    FixtureAcceptedRecord,
    /// Empty fixture object.
    FixtureEmptyObject,
    /// Required fixture bool object.
    FixtureRequiredBool,
    /// Extensible fixture record.
    FixtureExtensibleRecord,
    /// 65-deep nested list resource fixture.
    NestedListFixture,
}

/// Decodes a complete value under a schema, rejecting trailing bytes.
///
/// # Errors
///
/// Returns the first stable SCB1 failure code encountered while decoding the
/// value or checking for trailing bytes.
pub fn decode_payload_exact(schema: &Schema, input: &[u8]) -> Result<()> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let mut reader = Reader::new(input);
    decode_schema(*schema, &mut reader, 0)?;
    if reader.is_finished() {
        Ok(())
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn contract_schema(contract: FixtureContract) -> Schema {
    match contract {
        FixtureContract::EmptyObject => Schema::FixtureEmptyObject,
        FixtureContract::RequiredBool => Schema::FixtureRequiredBool,
    }
}

fn decode_schema<'a>(schema: Schema, reader: &mut Reader<'a>, depth: usize) -> Result<&'a [u8]> {
    if depth > MAX_NESTING_DEPTH {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let start = reader.position();
    match schema {
        Schema::UInt(width) => {
            reader.read_uvar_width(width)?;
        }
        Schema::SInt(width) => {
            let encoded = reader.read_uvar_width(width)?;
            if width < 64 && encoded >= (1_u64 << width) {
                return Err(ScbError::new(ScbErrorCode::IntegerOverflow));
            }
        }
        Schema::Bool => {
            let value = reader.read_u8()?;
            if value > 1 {
                return Err(ScbError::new(ScbErrorCode::BoolInvalid));
            }
        }
        Schema::Bytes => {
            let len = reader.read_len(MAX_BYTE_PAYLOAD)?;
            reader.take_exact(len)?;
        }
        Schema::Text => {
            read_text(reader, false)?;
        }
        Schema::NormalizedLabel => {
            read_text(reader, true)?;
        }
        Schema::F32 => {
            let bits = u32::from_be_bytes(reader.take_array()?);
            validate_f32_bits(bits)?;
        }
        Schema::F64 => {
            let bits = u64::from_be_bytes(reader.take_array()?);
            validate_f64_bits(bits)?;
        }
        Schema::ListUInt64 => {
            decode_list(Schema::UInt(64), reader, depth)?;
        }
        Schema::MapUInt8UInt8 => {
            decode_map(Schema::UInt(8), Schema::UInt(8), reader, depth)?;
        }
        Schema::MapUInt64Text => {
            decode_map(Schema::UInt(64), Schema::Text, reader, depth)?;
        }
        Schema::OptionUInt64 => {
            decode_option_uvar(reader, depth)?;
        }
        Schema::UnionBool(tag) => {
            decode_union_bool(tag, reader, depth)?;
        }
        Schema::FixtureRecord => {
            decode_fixture_record(reader, depth)?;
        }
        Schema::FixtureAcceptedRecord => {
            decode_accepted_record(reader, depth)?;
        }
        Schema::FixtureEmptyObject => {
            decode_empty_record(reader)?;
        }
        Schema::FixtureRequiredBool => {
            decode_required_bool_record(reader, depth)?;
        }
        Schema::FixtureExtensibleRecord => {
            decode_extensible_record(reader, depth)?;
        }
        Schema::NestedListFixture => {
            decode_nested_list(reader, depth)?;
        }
    }
    Ok(reader.slice_from(start))
}

fn read_text(reader: &mut Reader<'_>, require_nfc: bool) -> Result<()> {
    let len = reader.read_len(MAX_BYTE_PAYLOAD)?;
    let bytes = reader.take_exact(len)?;
    let value = str::from_utf8(bytes).map_err(|_| ScbError::new(ScbErrorCode::Utf8Invalid))?;
    if require_nfc && !value.nfc().eq(value.chars()) {
        return Err(ScbError::new(ScbErrorCode::LabelNotNfc));
    }
    Ok(())
}

fn validate_f32_bits(bits: u32) -> Result<()> {
    if bits == 0x8000_0000
        || (bits & 0x7f80_0000 == 0x7f80_0000 && bits & 0x007f_ffff != 0 && bits != 0x7fc0_0000)
    {
        Err(ScbError::new(ScbErrorCode::FloatNonCanonical))
    } else {
        Ok(())
    }
}

fn validate_f64_bits(bits: u64) -> Result<()> {
    if bits == 0x8000_0000_0000_0000
        || (bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000
            && bits & 0x000f_ffff_ffff_ffff != 0
            && bits != 0x7ff8_0000_0000_0000)
    {
        Err(ScbError::new(ScbErrorCode::FloatNonCanonical))
    } else {
        Ok(())
    }
}

fn decode_list(element_schema: Schema, reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    let count = reader.read_count()?;
    for _ in 0..count {
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let element = reader.take_exact(len)?;
        let mut nested = Reader::new(element);
        decode_schema(element_schema, &mut nested, depth + 1)?;
        if !nested.is_finished() {
            return Err(ScbError::new(ScbErrorCode::TrailingBytes));
        }
    }
    Ok(())
}

fn decode_map(
    key_schema: Schema,
    value_schema: Schema,
    reader: &mut Reader<'_>,
    depth: usize,
) -> Result<()> {
    let count = reader.read_count()?;
    let mut previous_key: Option<&[u8]> = None;
    for _ in 0..count {
        let key_len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let key = reader.take_exact(key_len)?;
        let mut key_reader = Reader::new(key);
        let decoded_key = decode_schema(key_schema, &mut key_reader, depth + 1)?;
        if !key_reader.is_finished() {
            return Err(ScbError::new(ScbErrorCode::TrailingBytes));
        }
        if let Some(previous) = &previous_key {
            match previous.cmp(&decoded_key) {
                core::cmp::Ordering::Greater => return Err(ScbError::new(ScbErrorCode::MapOrder)),
                core::cmp::Ordering::Equal => {
                    return Err(ScbError::new(ScbErrorCode::MapDuplicate));
                }
                core::cmp::Ordering::Less => {}
            }
        }
        previous_key = Some(decoded_key);

        let value_len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let value = reader.take_exact(value_len)?;
        let mut value_reader = Reader::new(value);
        decode_schema(value_schema, &mut value_reader, depth + 1)?;
        if !value_reader.is_finished() {
            return Err(ScbError::new(ScbErrorCode::TrailingBytes));
        }
    }
    Ok(())
}

fn decode_option_uvar(reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    let tag = reader.read_uvar_width(32)?;
    let len = reader.read_len(MAX_STANDALONE_BYTES)?;
    let payload = reader.take_exact(len)?;
    match tag {
        0 if payload.is_empty() => Ok(()),
        1 => {
            let mut nested = Reader::new(payload);
            decode_schema(Schema::UInt(64), &mut nested, depth + 1)?;
            if nested.is_finished() {
                Ok(())
            } else {
                Err(ScbError::new(ScbErrorCode::TrailingBytes))
            }
        }
        _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
    }
}

fn decode_union_bool(expected_tag: u32, reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    let tag = reader.read_uvar_width(32)?;
    if tag != u64::from(expected_tag) {
        return Err(ScbError::new(ScbErrorCode::UnionInvalid));
    }
    let len = reader.read_len(MAX_STANDALONE_BYTES)?;
    let payload = reader.take_exact(len)?;
    decode_nested_exact(Schema::Bool, payload, depth)
}

fn decode_empty_record(reader: &mut Reader<'_>) -> Result<()> {
    let count = reader.read_record_field_count()?;
    if count == 0 {
        Ok(())
    } else {
        Err(ScbError::new(ScbErrorCode::FieldUnknown))
    }
}

fn decode_required_bool_record(reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    let count = reader.read_record_field_count()?;
    let mut saw_required = false;
    let mut previous_tag = None;
    for _ in 0..count {
        let tag = read_ordered_field_tag(reader, &mut previous_tag)?;
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let value = reader.take_exact(len)?;
        if tag != 1 {
            return Err(ScbError::new(ScbErrorCode::FieldUnknown));
        }
        saw_required = true;
        decode_nested_exact(Schema::Bool, value, depth)?;
    }
    if saw_required {
        Ok(())
    } else {
        Err(ScbError::new(ScbErrorCode::FieldMissing))
    }
}

fn decode_fixture_record(reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    let count = reader.read_record_field_count()?;
    let mut previous_tag = None;
    for _ in 0..count {
        let tag = read_ordered_field_tag(reader, &mut previous_tag)?;
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let value = reader.take_exact(len)?;
        if tag != 1 && tag != 2 {
            return Err(ScbError::new(ScbErrorCode::FieldUnknown));
        }
        decode_nested_exact(Schema::Bool, value, depth)?;
    }
    Ok(())
}

fn decode_accepted_record(reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    let count = reader.read_record_field_count()?;
    if count != 2 {
        return Err(ScbError::new(ScbErrorCode::FieldMissing));
    }
    let mut previous_tag = None;
    for expected_tag in [1, 3] {
        let tag = read_ordered_field_tag(reader, &mut previous_tag)?;
        if tag != expected_tag {
            return Err(ScbError::new(ScbErrorCode::FieldUnknown));
        }
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let value = reader.take_exact(len)?;
        let schema = if tag == 1 {
            Schema::Bool
        } else {
            Schema::UInt(64)
        };
        decode_nested_exact(schema, value, depth)?;
    }
    Ok(())
}

fn decode_extensible_record(reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    let count = reader.read_record_field_count()?;
    let mut previous_tag = None;
    for _ in 0..count {
        let tag = read_ordered_field_tag(reader, &mut previous_tag)?;
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let value = reader.take_exact(len)?;
        if tag != 1 {
            return Err(ScbError::new(ScbErrorCode::FieldUnknown));
        }
        decode_extension_set(value, depth)?;
    }
    Ok(())
}

fn decode_extension_set(input: &[u8], depth: usize) -> Result<()> {
    let mut reader = Reader::new(input);
    let count = reader.read_count()?;
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let extension = reader.take_exact(len)?;
        if let Some(previous_bytes) = &previous {
            match previous_bytes.cmp(&extension) {
                core::cmp::Ordering::Greater => return Err(ScbError::new(ScbErrorCode::MapOrder)),
                core::cmp::Ordering::Equal => {
                    return Err(ScbError::new(ScbErrorCode::MapDuplicate));
                }
                core::cmp::Ordering::Less => {}
            }
        }
        previous = Some(extension);
        decode_extension_record(extension, depth + 1)?;
    }
    if reader.is_finished() {
        Ok(())
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
}

fn decode_extension_record(input: &[u8], depth: usize) -> Result<()> {
    let mut reader = Reader::new(input);
    let count = reader.read_record_field_count()?;
    if count < 4 {
        return Err(ScbError::new(ScbErrorCode::FieldMissing));
    }
    if count > 4 {
        return Err(ScbError::new(ScbErrorCode::FieldUnknown));
    }
    let mut previous_tag = None;
    let mut fields = 0_u8;
    for expected_tag in 1..=4 {
        let tag = read_ordered_field_tag(&mut reader, &mut previous_tag)?;
        if tag != expected_tag {
            return Err(ScbError::new(ScbErrorCode::FieldMissing));
        }
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let value = reader.take_exact(len)?;
        match tag {
            1 => {
                if len != 16 {
                    return Err(ScbError::new(ScbErrorCode::LengthOverflow));
                }
            }
            2 | 3 => decode_nested_exact(Schema::UInt(32), value, depth)?,
            4 => decode_nested_exact(Schema::Bytes, value, depth)?,
            _ => unreachable!(),
        }
        fields += 1;
    }
    if count != u64::from(fields) {
        return Err(ScbError::new(ScbErrorCode::FieldUnknown));
    }
    if !reader.is_finished() {
        return Err(ScbError::new(ScbErrorCode::TrailingBytes));
    }
    Err(ScbError::new(ScbErrorCode::ExtensionUnknown))
}

fn decode_nested_list(reader: &mut Reader<'_>, depth: usize) -> Result<()> {
    if depth >= MAX_NESTING_DEPTH {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    let count = reader.read_count()?;
    for _ in 0..count {
        let len = reader.read_len(MAX_STANDALONE_BYTES)?;
        let value = reader.take_exact(len)?;
        let mut nested = Reader::new(value);
        decode_nested_list(&mut nested, depth + 1)?;
        if !nested.is_finished() {
            return Err(ScbError::new(ScbErrorCode::TrailingBytes));
        }
    }
    Ok(())
}

fn read_ordered_field_tag(reader: &mut Reader<'_>, previous_tag: &mut Option<u64>) -> Result<u64> {
    let tag = reader.read_uvar_width(32)?;
    if let Some(previous) = *previous_tag {
        if tag == previous {
            return Err(ScbError::new(ScbErrorCode::FieldDuplicate));
        }
        if tag < previous {
            return Err(ScbError::new(ScbErrorCode::FieldOrder));
        }
    }
    *previous_tag = Some(tag);
    Ok(tag)
}

fn decode_nested_exact(schema: Schema, input: &[u8], depth: usize) -> Result<()> {
    let mut nested = Reader::new(input);
    decode_schema(schema, &mut nested, depth + 1)?;
    if nested.is_finished() {
        Ok(())
    } else {
        Err(ScbError::new(ScbErrorCode::TrailingBytes))
    }
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

    const fn position(&self) -> usize {
        self.position
    }

    fn slice_from(&self, start: usize) -> &'a [u8] {
        &self.input[start..self.position]
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(*self
            .take_exact(1)?
            .first()
            .ok_or_else(|| ScbError::new(ScbErrorCode::LengthOverflow))?)
    }

    fn take_exact(&mut self, len: usize) -> Result<&'a [u8]> {
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

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take_exact(N)?);
        Ok(out)
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

    fn read_len(&mut self, max: usize) -> Result<usize> {
        let len = self.read_uvar_width(64)?;
        let len = usize::try_from(len).map_err(|_| ScbError::new(ScbErrorCode::LengthOverflow))?;
        if len > max {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(len)
    }

    fn read_count(&mut self) -> Result<u64> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_COLLECTION_ELEMENTS {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(count)
    }

    fn read_record_field_count(&mut self) -> Result<u64> {
        let count = self.read_uvar_width(64)?;
        if count > MAX_RECORD_FIELDS {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(count)
    }
}
