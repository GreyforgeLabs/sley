//! Exact SSMC1 entity-object bytes used by S20-360 in-memory validation.
//!
//! This module proves canonical object bytes and `ObjectId` derivation for one
//! explicit schema epoch. It does not authorize that epoch, read an object
//! store, establish accepted state, validate semantics, or mutate a root.

use sley_id::{EntityId, ObjectId, SchemaEpochId, SemanticFingerprint};
use sley_scb1::{
    MAX_STANDALONE_BYTES, ScbError, ScbErrorCode, ScbValueCursor, encode_normalized_label,
    encode_record, encode_uvar,
};

use crate::codec::{decode_exact, encode_exact};
use crate::value::EntityBodyValue;

/// Exact SCB1 standalone magic used by SSMC1 entity objects.
pub const ENTITY_OBJECT_MAGIC: &[u8; 8] = b"SLEYSCB1";
/// Exact SCB1 standalone format version used by SSMC1 entity objects.
pub const ENTITY_OBJECT_FORMAT_VERSION: u64 = 1;
/// Exact SSMC1 entity-object contract tag.
pub const ENTITY_OBJECT_CONTRACT_TAG: u32 = 200;
/// Maximum UTF-8 bytes in optional normalized label metadata.
pub const MAX_ENTITY_OBJECT_LABEL_BYTES: usize = 1_024;

/// Typed SSMC1 entity-object payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityObjectRecord {
    /// Stable logical identity bound by the containing state root.
    pub entity_id: EntityId,
    /// Exact closed epoch-1 entity body.
    pub body: EntityBodyValue,
    /// Optional NFC metadata; never an identity input for `EntityId`.
    pub label: Option<String>,
    /// Optional reserved semantic fingerprint projection.
    pub semantic_fingerprint: Option<SemanticFingerprint>,
}

/// Canonical entity-object bytes with a verified digest trailer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityObject {
    schema_epoch_id: SchemaEpochId,
    record: EntityObjectRecord,
    object_id: ObjectId,
    preimage: Vec<u8>,
    stored_bytes: Vec<u8>,
}

impl EntityObject {
    /// Returns the explicit schema epoch encoded in the object envelope.
    #[must_use]
    pub const fn schema_epoch_id(&self) -> SchemaEpochId {
        self.schema_epoch_id
    }

    /// Returns the strictly decoded immutable object payload.
    #[must_use]
    pub const fn record(&self) -> &EntityObjectRecord {
        &self.record
    }

    /// Returns the exact domain-separated immutable object identity.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Returns the exact digest preimage, excluding the trailer.
    #[must_use]
    pub fn preimage(&self) -> &[u8] {
        &self.preimage
    }

    /// Returns the complete standalone bytes including the digest trailer.
    #[must_use]
    pub fn stored_bytes(&self) -> &[u8] {
        &self.stored_bytes
    }
}

/// Builds one canonical SSMC1 entity object for an explicit schema epoch.
///
/// The caller must separately establish that the epoch is accepted. This
/// function performs no registry lookup and grants no root or commit authority.
///
/// # Errors
///
/// Returns an exact SCB1 error for invalid metadata or a resource violation.
pub fn build_entity_object(
    schema_epoch_id: SchemaEpochId,
    record: &EntityObjectRecord,
) -> Result<EntityObject, ScbError> {
    let payload = encode_object_record(record)?;
    let preimage = build_preimage(schema_epoch_id, &payload)?;
    let object_id = ObjectId::derive(&preimage);
    let mut stored_bytes = preimage.clone();
    stored_bytes.extend_from_slice(object_id.as_bytes());
    if stored_bytes.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    Ok(EntityObject {
        schema_epoch_id,
        record: record.clone(),
        object_id,
        preimage,
        stored_bytes,
    })
}

/// Imports one canonical SSMC1 entity object under an exact expected epoch.
///
/// The expected epoch is a trusted comparison input, not a registry selected
/// by object bytes. Registry authority remains an S20-140/production-epoch
/// obligation outside this codec.
///
/// # Errors
///
/// Returns an exact SCB1 framing, epoch, digest, payload, or resource error.
pub fn import_entity_object(
    expected_schema_epoch_id: SchemaEpochId,
    input: &[u8],
) -> Result<EntityObject, ScbError> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    if input.len() < 32 {
        return Err(ScbError::new(ScbErrorCode::LengthOverflow));
    }
    let (preimage, digest) = input.split_at(input.len() - 32);
    let mut cursor = ScbValueCursor::new(preimage)?;
    if cursor.read_exact_bytes(ENTITY_OBJECT_MAGIC.len())? != ENTITY_OBJECT_MAGIC {
        return Err(ScbError::new(ScbErrorCode::MagicInvalid));
    }
    if cursor.read_uvar(64)? != ENTITY_OBJECT_FORMAT_VERSION {
        return Err(ScbError::new(ScbErrorCode::VersionUnsupported));
    }
    if cursor.read_uvar(32)? != u64::from(ENTITY_OBJECT_CONTRACT_TAG) {
        return Err(ScbError::new(ScbErrorCode::ContractUnknown));
    }
    let schema_epoch_id = SchemaEpochId::from_bytes(cursor.read_fixed_bytes()?);
    if schema_epoch_id != expected_schema_epoch_id {
        return Err(ScbError::new(ScbErrorCode::EpochMismatch));
    }
    let payload = cursor.read_sized_payload()?;
    cursor.check_finished()?;

    let object_id = ObjectId::derive(preimage);
    if digest != object_id.as_bytes() {
        return Err(ScbError::new(ScbErrorCode::DigestMismatch));
    }
    let record = decode_object_record(payload)?;
    Ok(EntityObject {
        schema_epoch_id,
        record,
        object_id,
        preimage: preimage.to_vec(),
        stored_bytes: input.to_vec(),
    })
}

fn encode_object_record(record: &EntityObjectRecord) -> Result<Vec<u8>, ScbError> {
    let mut fields = vec![
        (1, record.entity_id.as_bytes().to_vec()),
        (2, encode_exact(&record.body)?),
    ];
    if let Some(label) = &record.label {
        if label.len() > MAX_ENTITY_OBJECT_LABEL_BYTES {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        fields.push((3, encode_normalized_label(label)?));
    }
    if let Some(fingerprint) = record.semantic_fingerprint {
        fields.push((4, fingerprint.as_bytes().to_vec()));
    }
    encode_record(&fields)
}

fn decode_object_record(input: &[u8]) -> Result<EntityObjectRecord, ScbError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let count = cursor.read_record_field_count()?;
    if !(2..=4).contains(&count) {
        return Err(ScbError::new(if count < 2 {
            ScbErrorCode::FieldMissing
        } else {
            ScbErrorCode::FieldUnknown
        }));
    }

    let mut entity_id = None;
    let mut body = None;
    let mut label = None;
    let mut semantic_fingerprint = None;
    let mut previous = None;
    for _ in 0..count {
        let tag = u32::try_from(cursor.read_uvar(32)?)
            .map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))?;
        if previous == Some(tag) {
            return Err(ScbError::new(ScbErrorCode::FieldDuplicate));
        }
        if previous.is_some_and(|prior| prior > tag) {
            return Err(ScbError::new(ScbErrorCode::FieldOrder));
        }
        previous = Some(tag);
        let payload = cursor.read_sized_payload()?;
        match tag {
            1 => entity_id = Some(decode_fixed(payload, EntityId::from_bytes)?),
            2 => body = Some(decode_exact(payload)?),
            3 => label = Some(decode_label(payload)?),
            4 => {
                semantic_fingerprint =
                    Some(decode_fixed(payload, SemanticFingerprint::from_bytes)?);
            }
            _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
        }
    }
    cursor.check_finished()?;
    Ok(EntityObjectRecord {
        entity_id: entity_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        body: body.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        label,
        semantic_fingerprint,
    })
}

fn decode_label(input: &[u8]) -> Result<String, ScbError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let label = cursor.read_text()?;
    cursor.check_finished()?;
    if label.len() > MAX_ENTITY_OBJECT_LABEL_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    if encode_normalized_label(label)? != input {
        return Err(ScbError::new(ScbErrorCode::LabelNotNfc));
    }
    Ok(label.to_owned())
}

fn decode_fixed<T>(input: &[u8], constructor: fn([u8; 32]) -> T) -> Result<T, ScbError> {
    let mut cursor = ScbValueCursor::new(input)?;
    let bytes = cursor.read_fixed_bytes()?;
    cursor.check_finished()?;
    Ok(constructor(bytes))
}

fn build_preimage(schema_epoch_id: SchemaEpochId, payload: &[u8]) -> Result<Vec<u8>, ScbError> {
    let mut preimage = Vec::with_capacity(ENTITY_OBJECT_MAGIC.len() + 12 + 32 + payload.len());
    preimage.extend_from_slice(ENTITY_OBJECT_MAGIC);
    preimage.extend_from_slice(&encode_uvar(ENTITY_OBJECT_FORMAT_VERSION));
    preimage.extend_from_slice(&encode_uvar(u64::from(ENTITY_OBJECT_CONTRACT_TAG)));
    preimage.extend_from_slice(schema_epoch_id.as_bytes());
    preimage.extend_from_slice(&encode_uvar(
        u64::try_from(payload.len()).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?,
    ));
    preimage.extend_from_slice(payload);
    if preimage
        .len()
        .checked_add(32)
        .is_none_or(|stored_len| stored_len > MAX_STANDALONE_BYTES)
    {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    Ok(preimage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::{EntityIdSet, WorkspaceBody};

    fn entity(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn fixture() -> EntityObjectRecord {
        EntityObjectRecord {
            entity_id: entity(1),
            body: EntityBodyValue::Workspace(WorkspaceBody {
                packages: EntityIdSet::from_unsorted(vec![entity(3), entity(2)]).unwrap(),
                root_namespace: entity(4),
                capability_requirements: EntityIdSet::from_unsorted(vec![]).unwrap(),
                contracts: EntityIdSet::from_unsorted(vec![entity(5)]).unwrap(),
                tests: EntityIdSet::from_unsorted(vec![entity(6)]).unwrap(),
            }),
            label: Some("Café".to_owned()),
            semantic_fingerprint: Some(SemanticFingerprint::from_bytes([7; 32])),
        }
    }

    #[test]
    fn entity_object_build_import_and_digest_are_exact() {
        let epoch = SchemaEpochId::from_bytes([9; 32]);
        let built = build_entity_object(epoch, &fixture()).unwrap();
        let imported = import_entity_object(epoch, built.stored_bytes()).unwrap();
        assert_eq!(imported, built);
        assert_eq!(built.object_id(), ObjectId::derive(built.preimage()));
        assert!(built.stored_bytes().starts_with(ENTITY_OBJECT_MAGIC));
        assert_eq!(built.record().body.kind_tag(), 1);
    }

    #[test]
    fn entity_object_rejects_epoch_digest_and_trailing_substitution() {
        let epoch = SchemaEpochId::from_bytes([9; 32]);
        let built = build_entity_object(epoch, &fixture()).unwrap();
        assert_eq!(
            import_entity_object(SchemaEpochId::from_bytes([8; 32]), built.stored_bytes(),)
                .unwrap_err()
                .code(),
            ScbErrorCode::EpochMismatch
        );

        let mut digest_tamper = built.stored_bytes().to_vec();
        *digest_tamper.last_mut().unwrap() ^= 1;
        assert_eq!(
            import_entity_object(epoch, &digest_tamper)
                .unwrap_err()
                .code(),
            ScbErrorCode::DigestMismatch
        );

        let mut trailing = built.stored_bytes().to_vec();
        trailing.insert(trailing.len() - 32, 0);
        assert_eq!(
            import_entity_object(epoch, &trailing).unwrap_err().code(),
            ScbErrorCode::TrailingBytes
        );
    }

    #[test]
    fn entity_object_metadata_is_bounded_and_nfc() {
        let epoch = SchemaEpochId::from_bytes([9; 32]);
        let mut record = fixture();
        record.label = Some("e\u{301}".to_owned());
        assert_eq!(
            build_entity_object(epoch, &record).unwrap_err().code(),
            ScbErrorCode::LabelNotNfc
        );
        record.label = Some("x".repeat(MAX_ENTITY_OBJECT_LABEL_BYTES + 1));
        assert_eq!(
            build_entity_object(epoch, &record).unwrap_err().code(),
            ScbErrorCode::ResourceLimit
        );
    }
}
