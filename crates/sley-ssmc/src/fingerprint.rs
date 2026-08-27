//! S20-250 restricted epoch-1 semantic fingerprint encoding.

use core::fmt;
use std::collections::BTreeMap;

use sley_id::{EntityId, SchemaEpochId, SemanticFingerprint, ValueHash};

use crate::{
    Block, CaseKey, ConstData, ConstValue, FunctionGraph, FunctionRefValue, Immediate, Operation,
    Parameter, ParameterRole, ResultConst, SwitchArgument, SwitchEdge, TargetEdge, Terminator,
    TypeDefForm, TypeDefinition, TypeExpr, ValueRef,
};

/// Exact SSMC1 field-schema hash frozen by S20-200.
pub const SSMC1_FIELD_SCHEMA_HASH: [u8; 32] = [
    0x04, 0x4d, 0x21, 0xd3, 0x28, 0xe4, 0x0d, 0x51, 0x7f, 0xd0, 0x9f, 0xd0, 0x99, 0xc9, 0x69, 0x7f,
    0xbb, 0xa2, 0xc9, 0x5d, 0x0a, 0x51, 0x9e, 0xad, 0xe3, 0x33, 0xc1, 0x14, 0x0d, 0x64, 0x8e, 0x73,
];

/// Maximum encoded S20-250 preimage size.
pub const MAX_FINGERPRINT_PREIMAGE_BYTES: usize = 67_108_864;
/// Maximum Function-owned graph entities in one fingerprint request.
pub const MAX_FINGERPRINT_GRAPH_ENTITIES: usize = 2_000_000;
/// Maximum Operations in one Function fingerprint request.
pub const MAX_FINGERPRINT_OPERATIONS: usize = 1_000_000;
/// Maximum charged canonical-encoding work.
pub const MAX_FINGERPRINT_WORK: u64 = 100_000_000;

/// Stable S20-250 fingerprint/value-hash error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FingerprintErrorCode {
    /// `FINGERPRINT_ENTITY_UNSUPPORTED`.
    EntityUnsupported,
    /// `FINGERPRINT_INVENTORY_INVALID`.
    InventoryInvalid,
    /// `FINGERPRINT_LOCAL_REFERENCE_INVALID`.
    LocalReferenceInvalid,
    /// `FINGERPRINT_CLAIM_MISSING`.
    ClaimMissing,
    /// `FINGERPRINT_MISMATCH`.
    Mismatch,
    /// `FINGERPRINT_RESOURCE_LIMIT`.
    ResourceLimit,
    /// `VALUE_HASH_TYPE_UNSUPPORTED`.
    ValueHashTypeUnsupported,
    /// `VALUE_HASH_VALUE_INVALID`.
    ValueHashValueInvalid,
}

impl FingerprintErrorCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntityUnsupported => "FINGERPRINT_ENTITY_UNSUPPORTED",
            Self::InventoryInvalid => "FINGERPRINT_INVENTORY_INVALID",
            Self::LocalReferenceInvalid => "FINGERPRINT_LOCAL_REFERENCE_INVALID",
            Self::ClaimMissing => "FINGERPRINT_CLAIM_MISSING",
            Self::Mismatch => "FINGERPRINT_MISMATCH",
            Self::ResourceLimit => "FINGERPRINT_RESOURCE_LIMIT",
            Self::ValueHashTypeUnsupported => "VALUE_HASH_TYPE_UNSUPPORTED",
            Self::ValueHashValueInvalid => "VALUE_HASH_VALUE_INVALID",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::EntityUnsupported => 25_000,
            Self::InventoryInvalid => 25_001,
            Self::LocalReferenceInvalid => 25_002,
            Self::ClaimMissing => 25_003,
            Self::Mismatch => 25_004,
            Self::ResourceLimit => 25_005,
            Self::ValueHashTypeUnsupported => 25_006,
            Self::ValueHashValueInvalid => 25_007,
        }
    }
}

impl fmt::Display for FingerprintErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable fingerprint failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FingerprintError(FingerprintErrorCode);

impl FingerprintError {
    /// Constructs a failure.
    #[must_use]
    pub const fn new(code: FingerprintErrorCode) -> Self {
        Self(code)
    }

    /// Returns the stable code.
    #[must_use]
    pub const fn code(&self) -> FingerprintErrorCode {
        self.0
    }
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for FingerprintError {}

/// S20-250 fingerprint result.
pub type Result<T> = core::result::Result<T, FingerprintError>;

/// Complete Function-owned inventory for one fingerprint.
#[derive(Clone, Copy, Debug)]
pub struct FunctionFingerprintInput<'a> {
    /// Function body.
    pub function: &'a FunctionGraph,
    /// Complete Function and Block Parameter inventory in arbitrary slice order.
    pub parameters: &'a [Parameter],
    /// Complete Block inventory in arbitrary slice order.
    pub blocks: &'a [Block],
    /// Complete Operation inventory in arbitrary slice order.
    pub operations: &'a [Operation],
}

/// Computes a `TypeDef` semantic fingerprint.
///
/// # Errors
///
/// Returns a resource failure if the canonical projection exceeds the bound.
pub fn fingerprint_type_definition(
    schema_epoch: SchemaEpochId,
    definition: &TypeDefinition,
) -> Result<SemanticFingerprint> {
    let mut body = Encoder::new();
    body.list_len(definition.type_parameters.len())?;
    for parameter in &definition.type_parameters {
        body.u32(parameter.ordinal)?;
    }
    body.u32(definition.form.tag())?;
    match &definition.form {
        TypeDefForm::Record(fields) => {
            body.list_len(fields.len())?;
            for field in fields {
                body.fixed(field.member_id.as_bytes())?;
                encode_type(&mut body, &field.value_type, None, 1)?;
                body.u32(field.visibility.tag())?;
            }
        }
        TypeDefForm::Variant(cases) => {
            body.list_len(cases.len())?;
            for case in cases {
                body.fixed(case.member_id.as_bytes())?;
                encode_option(&mut body, case.payload_type.as_ref(), |encoder, value| {
                    encode_type(encoder, value, None, 1)
                })?;
            }
        }
    }
    body.list_len(definition.invariants.len())?;
    for invariant in &definition.invariants {
        encode_entity_ref(&mut body, *invariant, None)?;
    }
    body.u32(definition.visibility.tag())?;
    finish_fingerprint(schema_epoch, 4, &body, 0)
}

/// Computes a complete Function semantic fingerprint using canonical local slots.
///
/// # Errors
///
/// Returns an inventory/local-reference/resource failure for malformed input.
pub fn fingerprint_function(
    schema_epoch: SchemaEpochId,
    input: FunctionFingerprintInput<'_>,
) -> Result<SemanticFingerprint> {
    let maps = FunctionMaps::build(input)?;
    let function = input.function;
    let self_id = Some(function.entity_id);
    let mut body = Encoder::new();

    body.list_len(function.type_parameters.len())?;
    for parameter in &function.type_parameters {
        body.u32(parameter.ordinal)?;
    }
    body.list_len(function.parameters.len())?;
    for id in &function.parameters {
        let parameter = maps.parameter(*id)?;
        encode_type(&mut body, &parameter.value_type, self_id, 1)?;
    }
    encode_type(&mut body, &function.result_type, self_id, 1)?;
    body.list_len(function.effects.len())?;
    for effect in &function.effects {
        encode_entity_ref(&mut body, *effect, self_id)?;
    }
    body.u32(maps.block_slot(function.entry_block)?)?;
    body.list_len(function.blocks.len())?;
    for block_id in &function.blocks {
        let block = maps.block(*block_id)?;
        body.u32(block.reachability.tag())?;
        body.list_len(block.parameters.len())?;
        for parameter_id in &block.parameters {
            let parameter = maps.parameter(*parameter_id)?;
            encode_type(&mut body, &parameter.value_type, self_id, 1)?;
        }
        body.list_len(block.operations.len())?;
        for operation_id in &block.operations {
            let operation = maps.operation(*operation_id)?;
            body.u32(operation.opcode.tag())?;
            body.list_len(operation.operands.len())?;
            for operand in &operation.operands {
                encode_value_ref(&mut body, *operand, &maps)?;
            }
            body.list_len(operation.result_types.len())?;
            for result_type in &operation.result_types {
                encode_type(&mut body, result_type, self_id, 1)?;
            }
            encode_immediate(&mut body, &operation.immediate, self_id)?;
        }
        encode_terminator(&mut body, &block.terminator, &maps)?;
    }
    body.list_len(function.contracts.len())?;
    for contract in &function.contracts {
        encode_entity_ref(&mut body, *contract, self_id)?;
    }
    body.u32(function.visibility.tag())?;
    let inventory_work = input
        .parameters
        .len()
        .checked_add(input.blocks.len())
        .and_then(|value| value.checked_add(input.operations.len()))
        .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
    finish_fingerprint(
        schema_epoch,
        5,
        &body,
        u64::try_from(inventory_work)
            .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?,
    )
}

/// Verifies a required caller-supplied fingerprint claim.
///
/// # Errors
///
/// Returns missing or mismatch when the claim is not exact.
pub fn verify_fingerprint_claim(
    computed: SemanticFingerprint,
    claimed: Option<SemanticFingerprint>,
) -> Result<()> {
    match claimed {
        None => fail(FingerprintErrorCode::ClaimMissing),
        Some(value) if value != computed => fail(FingerprintErrorCode::Mismatch),
        Some(_) => Ok(()),
    }
}

/// Enforces absence of field 4 on an unsupported restricted-profile kind.
///
/// # Errors
///
/// Returns `FINGERPRINT_ENTITY_UNSUPPORTED` when a claim is present.
pub fn verify_unsupported_fingerprint_claim(claimed: Option<SemanticFingerprint>) -> Result<()> {
    if claimed.is_some() {
        fail(FingerprintErrorCode::EntityUnsupported)
    } else {
        Ok(())
    }
}

/// Hashes one already S20-210-validated, canonically hashable value.
///
/// This low-level encoder does not replace the S20-210 trait/constant judgment.
///
/// # Errors
///
/// Returns a resource failure if the canonical value preimage exceeds the bound.
pub fn hash_validated_value(schema_epoch: SchemaEpochId, value: &ConstValue) -> Result<ValueHash> {
    let mut type_bytes = Encoder::new();
    encode_type(&mut type_bytes, &value.value_type, None, 1)?;
    let mut data_bytes = Encoder::new();
    encode_const_data(&mut data_bytes, &value.data, None, 1)?;

    let mut preimage = Encoder::new();
    preimage.fixed(b"SLEYVHS1")?;
    preimage.u32(1)?;
    preimage.fixed(schema_epoch.as_bytes())?;
    preimage.fixed(&SSMC1_FIELD_SCHEMA_HASH)?;
    let appended = 8_usize
        .checked_add(type_bytes.out.len())
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(data_bytes.out.len()))
        .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
    preimage.ensure_append(appended)?;
    require_work(
        type_bytes
            .work
            .checked_add(data_bytes.work)
            .and_then(|value| value.checked_add(preimage.work))
            .and_then(|value| value.checked_add(u64::try_from(appended).ok()?)),
    )?;
    preimage.bytes(&type_bytes.out)?;
    preimage.bytes(&data_bytes.out)?;
    Ok(ValueHash::derive(preimage.out))
}

fn finish_fingerprint(
    schema_epoch: SchemaEpochId,
    kind: u32,
    body: &Encoder,
    extra_work: u64,
) -> Result<SemanticFingerprint> {
    let mut preimage = Encoder::new();
    preimage.fixed(b"SLEYSFP1")?;
    preimage.u32(1)?;
    preimage.fixed(schema_epoch.as_bytes())?;
    preimage.fixed(&SSMC1_FIELD_SCHEMA_HASH)?;
    preimage.u32(kind)?;
    let appended = 8_usize
        .checked_add(body.out.len())
        .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
    preimage.ensure_append(appended)?;
    require_work(
        body.work
            .checked_add(preimage.work)
            .and_then(|value| value.checked_add(u64::try_from(appended).ok()?))
            .and_then(|value| value.checked_add(extra_work)),
    )?;
    preimage.bytes(&body.out)?;
    Ok(SemanticFingerprint::derive(preimage.out))
}

struct Encoder {
    out: Vec<u8>,
    work: u64,
}

impl Encoder {
    const fn new() -> Self {
        Self {
            out: Vec::new(),
            work: 0,
        }
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<()> {
        self.ensure_append(bytes.len())?;
        self.work = self
            .work
            .checked_add(
                u64::try_from(bytes.len())
                    .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?,
            )
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
        if self.work > MAX_FINGERPRINT_WORK {
            return fail(FingerprintErrorCode::ResourceLimit);
        }
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    fn ensure_append(&self, length: usize) -> Result<()> {
        let next = self
            .out
            .len()
            .checked_add(length)
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
        let work = self
            .work
            .checked_add(
                u64::try_from(length)
                    .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?,
            )
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
        if next > MAX_FINGERPRINT_PREIMAGE_BYTES || work > MAX_FINGERPRINT_WORK {
            fail(FingerprintErrorCode::ResourceLimit)
        } else {
            Ok(())
        }
    }

    fn fixed(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend(bytes)
    }

    fn u16(&mut self, value: u16) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    fn u128(&mut self, value: u128) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    fn i128(&mut self, value: i128) -> Result<()> {
        self.extend(&value.to_be_bytes())
    }

    fn boolean(&mut self, value: bool) -> Result<()> {
        self.extend(&[u8::from(value)])
    }

    fn list_len(&mut self, length: usize) -> Result<()> {
        self.u64(
            u64::try_from(length)
                .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?,
        )
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.ensure_append(
            8_usize
                .checked_add(bytes.len())
                .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?,
        )?;
        self.list_len(bytes.len())?;
        self.extend(bytes)
    }
}

fn encode_entity_ref(
    encoder: &mut Encoder,
    entity: EntityId,
    enclosing_function: Option<EntityId>,
) -> Result<()> {
    if enclosing_function == Some(entity) {
        encoder.u32(2)
    } else {
        encoder.u32(1)?;
        encoder.fixed(entity.as_bytes())
    }
}

fn encode_option<T>(
    encoder: &mut Encoder,
    value: Option<&T>,
    encode: impl FnOnce(&mut Encoder, &T) -> Result<()>,
) -> Result<()> {
    match value {
        None => encoder.u32(1),
        Some(value) => {
            encoder.u32(2)?;
            encode(encoder, value)
        }
    }
}

fn encode_type(
    encoder: &mut Encoder,
    value: &TypeExpr,
    enclosing_function: Option<EntityId>,
    depth: usize,
) -> Result<()> {
    if depth > crate::MAX_TYPE_DEPTH {
        return fail(FingerprintErrorCode::ResourceLimit);
    }
    encoder.u32(value.tag())?;
    match value {
        TypeExpr::Unit
        | TypeExpr::Bool
        | TypeExpr::F32
        | TypeExpr::F64
        | TypeExpr::Bytes
        | TypeExpr::Text => Ok(()),
        TypeExpr::SInt(width) | TypeExpr::UInt(width) => encoder.u16(width.bits()),
        TypeExpr::Tuple(elements) => {
            encoder.list_len(elements.len())?;
            for element in elements {
                encode_type(encoder, element, enclosing_function, depth + 1)?;
            }
            Ok(())
        }
        TypeExpr::Named(named) => {
            encode_entity_ref(encoder, named.definition, enclosing_function)?;
            encoder.list_len(named.arguments.len())?;
            for argument in &named.arguments {
                encode_type(encoder, argument, enclosing_function, depth + 1)?;
            }
            Ok(())
        }
        TypeExpr::Vector(element) | TypeExpr::Option(element) | TypeExpr::LocalCell(element) => {
            encode_type(encoder, element, enclosing_function, depth + 1)
        }
        TypeExpr::OrderedMap { key, value } => {
            encode_type(encoder, key, enclosing_function, depth + 1)?;
            encode_type(encoder, value, enclosing_function, depth + 1)
        }
        TypeExpr::Result { ok, error } => {
            encode_type(encoder, ok, enclosing_function, depth + 1)?;
            encode_type(encoder, error, enclosing_function, depth + 1)
        }
        TypeExpr::FunctionRef(function) => {
            encoder.list_len(function.parameters.len())?;
            for parameter in &function.parameters {
                encode_type(encoder, parameter, enclosing_function, depth + 1)?;
            }
            encode_type(encoder, &function.result, enclosing_function, depth + 1)?;
            encoder.list_len(function.effects.len())?;
            for effect in &function.effects {
                encode_entity_ref(encoder, *effect, enclosing_function)?;
            }
            Ok(())
        }
        TypeExpr::AdapterHandle(entity) | TypeExpr::CapabilityToken(entity) => {
            encode_entity_ref(encoder, *entity, enclosing_function)
        }
        TypeExpr::TypeParameter(ordinal) => encoder.u32(*ordinal),
        TypeExpr::BuiltinFailure(kind) => encoder.u16(kind.tag()),
    }
}

fn encode_function_ref(
    encoder: &mut Encoder,
    value: &FunctionRefValue,
    enclosing_function: Option<EntityId>,
    depth: usize,
) -> Result<()> {
    encode_entity_ref(encoder, value.function, enclosing_function)?;
    encoder.list_len(value.type_arguments.len())?;
    for argument in &value.type_arguments {
        encode_type(encoder, argument, enclosing_function, depth + 1)?;
    }
    Ok(())
}

fn encode_const_value(
    encoder: &mut Encoder,
    value: &ConstValue,
    enclosing_function: Option<EntityId>,
    depth: usize,
) -> Result<()> {
    encode_type(encoder, &value.value_type, enclosing_function, depth)?;
    encode_const_data(encoder, &value.data, enclosing_function, depth)
}

fn encode_const_data(
    encoder: &mut Encoder,
    value: &ConstData,
    enclosing_function: Option<EntityId>,
    depth: usize,
) -> Result<()> {
    if depth > crate::MAX_TYPE_DEPTH {
        return fail(FingerprintErrorCode::ResourceLimit);
    }
    encoder.u32(value.tag())?;
    match value {
        ConstData::Unit => Ok(()),
        ConstData::Bool(value) => encoder.boolean(*value),
        ConstData::SInt(value) => encoder.i128(*value),
        ConstData::UInt(value) => encoder.u128(*value),
        ConstData::F32Bits(value) => encoder.u32(*value),
        ConstData::F64Bits(value) => encoder.u64(*value),
        ConstData::Bytes(value) => encoder.bytes(value),
        ConstData::Text(value) => encoder.bytes(value.as_bytes()),
        ConstData::Sequence(values) => {
            encoder.list_len(values.len())?;
            for value in values {
                encode_const_value(encoder, value, enclosing_function, depth + 1)?;
            }
            Ok(())
        }
        ConstData::Record(record) => {
            encode_entity_ref(encoder, record.definition, enclosing_function)?;
            encoder.list_len(record.fields.len())?;
            for field in &record.fields {
                encoder.fixed(field.member_id.as_bytes())?;
                encode_const_value(encoder, &field.value, enclosing_function, depth + 1)?;
            }
            Ok(())
        }
        ConstData::Variant(variant) => {
            encode_entity_ref(encoder, variant.definition, enclosing_function)?;
            encoder.fixed(variant.member_id.as_bytes())?;
            encode_option(encoder, variant.payload.as_deref(), |encoder, value| {
                encode_const_value(encoder, value, enclosing_function, depth + 1)
            })
        }
        ConstData::Map(entries) => {
            encoder.list_len(entries.len())?;
            for entry in entries {
                encode_const_value(encoder, &entry.key, enclosing_function, depth + 1)?;
                encode_const_value(encoder, &entry.value, enclosing_function, depth + 1)?;
            }
            Ok(())
        }
        ConstData::Option(value) => encode_option(encoder, value.as_deref(), |encoder, value| {
            encode_const_value(encoder, value, enclosing_function, depth + 1)
        }),
        ConstData::Result(ResultConst::Ok(value)) => {
            encoder.u32(1)?;
            encode_const_value(encoder, value, enclosing_function, depth + 1)
        }
        ConstData::Result(ResultConst::Err(value)) => {
            encoder.u32(2)?;
            encode_const_value(encoder, value, enclosing_function, depth + 1)
        }
        ConstData::FunctionRef(value) => {
            encode_function_ref(encoder, value, enclosing_function, depth + 1)
        }
        ConstData::BuiltinFailure(value) => {
            encoder.u16(value.kind.tag())?;
            encoder.u16(value.code)
        }
    }
}

#[derive(Clone, Copy)]
struct ParameterSlot {
    owner_class: u32,
    block: u32,
    parameter: u32,
}

#[derive(Clone, Copy)]
struct OperationSlot {
    block: u32,
    operation: u32,
}

struct FunctionMaps<'a> {
    parameters: BTreeMap<EntityId, (&'a Parameter, ParameterSlot)>,
    blocks: BTreeMap<EntityId, (&'a Block, u32)>,
    operations: BTreeMap<EntityId, (&'a Operation, OperationSlot)>,
}

impl<'a> FunctionMaps<'a> {
    #[allow(clippy::too_many_lines)]
    fn build(input: FunctionFingerprintInput<'a>) -> Result<Self> {
        if input.operations.len() > MAX_FINGERPRINT_OPERATIONS {
            return fail(FingerprintErrorCode::ResourceLimit);
        }
        let graph_entities = input
            .parameters
            .len()
            .checked_add(input.blocks.len())
            .and_then(|value| value.checked_add(input.operations.len()))
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
        if graph_entities > MAX_FINGERPRINT_GRAPH_ENTITIES {
            return fail(FingerprintErrorCode::ResourceLimit);
        }
        let function = input.function;
        let mut parameter_input = BTreeMap::new();
        for parameter in input.parameters {
            if parameter_input
                .insert(parameter.entity_id, parameter)
                .is_some()
            {
                return fail(FingerprintErrorCode::InventoryInvalid);
            }
        }
        let mut block_input = BTreeMap::new();
        for block in input.blocks {
            if block_input.insert(block.entity_id, block).is_some() {
                return fail(FingerprintErrorCode::InventoryInvalid);
            }
        }
        let mut operation_input = BTreeMap::new();
        for operation in input.operations {
            if operation_input
                .insert(operation.entity_id, operation)
                .is_some()
            {
                return fail(FingerprintErrorCode::InventoryInvalid);
            }
        }

        let mut parameters = BTreeMap::new();
        for (index, id) in function.parameters.iter().copied().enumerate() {
            let parameter = parameter_input
                .get(&id)
                .copied()
                .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::InventoryInvalid))?;
            let ordinal = u32::try_from(index)
                .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
            if parameter.owner != function.entity_id
                || parameter.role != ParameterRole::Function
                || parameter.ordinal != ordinal
                || parameters
                    .insert(
                        id,
                        (
                            parameter,
                            ParameterSlot {
                                owner_class: 1,
                                block: 0,
                                parameter: ordinal,
                            },
                        ),
                    )
                    .is_some()
            {
                return fail(FingerprintErrorCode::InventoryInvalid);
            }
        }

        let mut blocks = BTreeMap::new();
        let mut operations = BTreeMap::new();
        for (block_index, id) in function.blocks.iter().copied().enumerate() {
            let block = block_input
                .get(&id)
                .copied()
                .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::InventoryInvalid))?;
            if block.function != function.entity_id {
                return fail(FingerprintErrorCode::InventoryInvalid);
            }
            let block_slot = u32::try_from(block_index)
                .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
            if blocks.insert(id, (block, block_slot)).is_some() {
                return fail(FingerprintErrorCode::InventoryInvalid);
            }
            for (parameter_index, parameter_id) in block.parameters.iter().copied().enumerate() {
                let parameter = parameter_input
                    .get(&parameter_id)
                    .copied()
                    .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::InventoryInvalid))?;
                let parameter_slot = u32::try_from(parameter_index)
                    .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
                if parameter.owner != id
                    || parameter.role != ParameterRole::Block
                    || parameter.ordinal != parameter_slot
                    || parameters
                        .insert(
                            parameter_id,
                            (
                                parameter,
                                ParameterSlot {
                                    owner_class: 2,
                                    block: block_slot,
                                    parameter: parameter_slot,
                                },
                            ),
                        )
                        .is_some()
                {
                    return fail(FingerprintErrorCode::InventoryInvalid);
                }
            }
            for (operation_index, operation_id) in block.operations.iter().copied().enumerate() {
                let operation = operation_input
                    .get(&operation_id)
                    .copied()
                    .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::InventoryInvalid))?;
                let operation_slot = u32::try_from(operation_index)
                    .map_err(|_| FingerprintError::new(FingerprintErrorCode::ResourceLimit))?;
                if operation.block != id
                    || operation.ordinal != operation_slot
                    || operations
                        .insert(
                            operation_id,
                            (
                                operation,
                                OperationSlot {
                                    block: block_slot,
                                    operation: operation_slot,
                                },
                            ),
                        )
                        .is_some()
                {
                    return fail(FingerprintErrorCode::InventoryInvalid);
                }
            }
        }
        if parameters.len() != parameter_input.len()
            || blocks.len() != block_input.len()
            || operations.len() != operation_input.len()
        {
            return fail(FingerprintErrorCode::InventoryInvalid);
        }
        Ok(Self {
            parameters,
            blocks,
            operations,
        })
    }

    fn parameter(&self, id: EntityId) -> Result<&'a Parameter> {
        self.parameters
            .get(&id)
            .map(|(value, _)| *value)
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::LocalReferenceInvalid))
    }

    fn block(&self, id: EntityId) -> Result<&'a Block> {
        self.blocks
            .get(&id)
            .map(|(value, _)| *value)
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::LocalReferenceInvalid))
    }

    fn operation(&self, id: EntityId) -> Result<&'a Operation> {
        self.operations
            .get(&id)
            .map(|(value, _)| *value)
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::LocalReferenceInvalid))
    }

    fn block_slot(&self, id: EntityId) -> Result<u32> {
        self.blocks
            .get(&id)
            .map(|(_, slot)| *slot)
            .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::LocalReferenceInvalid))
    }
}

fn encode_value_ref(encoder: &mut Encoder, value: ValueRef, maps: &FunctionMaps<'_>) -> Result<()> {
    encoder.u32(value.tag())?;
    match value {
        ValueRef::Parameter(id) => {
            let (_, slot) = maps.parameters.get(&id).ok_or_else(|| {
                FingerprintError::new(FingerprintErrorCode::LocalReferenceInvalid)
            })?;
            encoder.u32(slot.owner_class)?;
            encoder.u32(slot.block)?;
            encoder.u32(slot.parameter)
        }
        ValueRef::OperationResult(result) => {
            let (operation, slot) = maps.operations.get(&result.operation).ok_or_else(|| {
                FingerprintError::new(FingerprintErrorCode::LocalReferenceInvalid)
            })?;
            let result_index = usize::try_from(result.result_index)
                .map_err(|_| FingerprintError::new(FingerprintErrorCode::LocalReferenceInvalid))?;
            if result_index >= operation.result_types.len() {
                return fail(FingerprintErrorCode::LocalReferenceInvalid);
            }
            encoder.u32(slot.block)?;
            encoder.u32(slot.operation)?;
            encoder.u32(result.result_index)
        }
    }
}

fn encode_immediate(
    encoder: &mut Encoder,
    immediate: &Immediate,
    enclosing_function: Option<EntityId>,
) -> Result<()> {
    encoder.u32(immediate.tag())?;
    match immediate {
        Immediate::None => Ok(()),
        Immediate::Entity(entity) => encode_entity_ref(encoder, *entity, enclosing_function),
        Immediate::Index(index) => encoder.u32(*index),
        Immediate::Field(member) => encoder.fixed(member.as_bytes()),
        Immediate::Variant(value) => {
            encode_entity_ref(encoder, value.definition, enclosing_function)?;
            encoder.fixed(value.member_id.as_bytes())
        }
        Immediate::Observation(value) => encoder.fixed(value),
        Immediate::Function(value) => encode_function_ref(encoder, value, enclosing_function, 1),
    }
}

fn encode_target_edge(
    encoder: &mut Encoder,
    edge: &TargetEdge,
    maps: &FunctionMaps<'_>,
) -> Result<()> {
    encoder.u32(maps.block_slot(edge.target)?)?;
    encoder.list_len(edge.arguments.len())?;
    for argument in &edge.arguments {
        encode_value_ref(encoder, *argument, maps)?;
    }
    Ok(())
}

fn encode_switch_edge(
    encoder: &mut Encoder,
    edge: &SwitchEdge,
    maps: &FunctionMaps<'_>,
) -> Result<()> {
    encoder.u32(maps.block_slot(edge.target)?)?;
    encoder.list_len(edge.arguments.len())?;
    for argument in &edge.arguments {
        encoder.u32(argument.tag())?;
        if let SwitchArgument::Value(value) = argument {
            encode_value_ref(encoder, *value, maps)?;
        }
    }
    Ok(())
}

fn encode_case_key(encoder: &mut Encoder, key: CaseKey) -> Result<()> {
    encoder.u32(key.tag())?;
    match key {
        CaseKey::Member(member) => encoder.fixed(member.as_bytes()),
        CaseKey::Builtin(value) => encoder.u32(value.tag()),
    }
}

fn encode_terminator(
    encoder: &mut Encoder,
    terminator: &Terminator,
    maps: &FunctionMaps<'_>,
) -> Result<()> {
    encoder.u32(terminator.tag())?;
    match terminator {
        Terminator::Return(value) => encode_value_ref(encoder, value.value, maps),
        Terminator::Branch(value) => encode_target_edge(encoder, &value.edge, maps),
        Terminator::CondBranch(value) => {
            encode_value_ref(encoder, value.condition, maps)?;
            encode_target_edge(encoder, &value.if_true, maps)?;
            encode_target_edge(encoder, &value.if_false, maps)
        }
        Terminator::VariantSwitch(value) => {
            encode_value_ref(encoder, value.value, maps)?;
            encoder.list_len(value.cases.len())?;
            for case in &value.cases {
                encode_case_key(encoder, case.case_key)?;
                encode_switch_edge(encoder, &case.edge, maps)?;
            }
            Ok(())
        }
        Terminator::Trap(value) => {
            encoder.u32(value.code.tag())?;
            encode_option(encoder, value.payload.as_ref(), |encoder, value| {
                encode_value_ref(encoder, *value, maps)
            })
        }
    }
}

fn fail<T>(code: FingerprintErrorCode) -> Result<T> {
    Err(FingerprintError::new(code))
}

fn require_work(work: Option<u64>) -> Result<()> {
    if work.is_none_or(|value| value > MAX_FINGERPRINT_WORK) {
        fail(FingerprintErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sley_id::SchemaEpochId;

    use super::*;
    use crate::{Reachability, ReturnTerminator, TypeParameterDef, Visibility};

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn hex_32(value: &str) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        bytes
    }

    #[test]
    fn type_definition_ignores_own_identity_but_not_semantics() {
        let mut first = TypeDefinition {
            entity_id: id(1),
            type_parameters: vec![TypeParameterDef { ordinal: 0 }],
            form: TypeDefForm::Variant(vec![crate::VariantCase {
                member_id: crate::MemberId::from_bytes([7; 32]),
                payload_type: Some(TypeExpr::TypeParameter(0)),
            }]),
            invariants: Vec::new(),
            visibility: Visibility::Exported,
        };
        let epoch = SchemaEpochId::from_bytes([9; 32]);
        let fingerprint = fingerprint_type_definition(epoch, &first).unwrap();
        assert_eq!(
            fingerprint.as_bytes(),
            &hex_32("2577617e0a4c3ae7872bbcdeae98510e6173f2ef51aea32f5be25acbb3189abe")
        );
        first.entity_id = id(2);
        assert_eq!(
            fingerprint,
            fingerprint_type_definition(epoch, &first).unwrap()
        );
        first.visibility = Visibility::Private;
        assert_ne!(
            fingerprint,
            fingerprint_type_definition(epoch, &first).unwrap()
        );
    }

    #[test]
    fn function_child_id_and_slice_order_do_not_change_fingerprint() {
        let function_id = id(1);
        let parameter = Parameter {
            entity_id: id(2),
            owner: function_id,
            role: ParameterRole::Function,
            ordinal: 0,
            value_type: TypeExpr::Bool,
        };
        let operation = Operation {
            entity_id: id(4),
            block: id(3),
            ordinal: 0,
            opcode: crate::Opcode::BoolNot,
            operands: vec![ValueRef::Parameter(parameter.entity_id)],
            result_types: vec![TypeExpr::Bool],
            immediate: Immediate::None,
        };
        let block = Block {
            entity_id: id(3),
            function: function_id,
            parameters: Vec::new(),
            operations: vec![operation.entity_id],
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::OperationResult(crate::OperationResultRef {
                    operation: operation.entity_id,
                    result_index: 0,
                }),
            }),
            reachability: Reachability::Required,
        };
        let function = FunctionGraph {
            entity_id: function_id,
            type_parameters: Vec::new(),
            parameters: vec![parameter.entity_id],
            result_type: TypeExpr::Bool,
            effects: Vec::new(),
            entry_block: block.entity_id,
            blocks: vec![block.entity_id],
            contracts: Vec::new(),
            visibility: Visibility::Private,
        };
        let epoch = SchemaEpochId::from_bytes([9; 32]);
        let first = fingerprint_function(
            epoch,
            FunctionFingerprintInput {
                function: &function,
                parameters: core::slice::from_ref(&parameter),
                blocks: core::slice::from_ref(&block),
                operations: core::slice::from_ref(&operation),
            },
        )
        .unwrap();
        assert_eq!(
            first.as_bytes(),
            &hex_32("da0c8dbd242a663affc56afea576f30ecbbcfe7c2dd3a69c03ab47940c2e470f")
        );

        let mut second_parameter = parameter.clone();
        second_parameter.entity_id = id(12);
        second_parameter.owner = id(11);
        let mut second_operation = operation.clone();
        second_operation.entity_id = id(14);
        second_operation.block = id(13);
        second_operation.operands = vec![ValueRef::Parameter(second_parameter.entity_id)];
        let mut second_block = block.clone();
        second_block.entity_id = id(13);
        second_block.function = id(11);
        second_block.operations = vec![second_operation.entity_id];
        second_block.terminator = Terminator::Return(ReturnTerminator {
            value: ValueRef::OperationResult(crate::OperationResultRef {
                operation: second_operation.entity_id,
                result_index: 0,
            }),
        });
        let mut second_function = function.clone();
        second_function.entity_id = id(11);
        second_function.parameters = vec![second_parameter.entity_id];
        second_function.entry_block = second_block.entity_id;
        second_function.blocks = vec![second_block.entity_id];
        assert_eq!(
            first,
            fingerprint_function(
                epoch,
                FunctionFingerprintInput {
                    function: &second_function,
                    parameters: &[second_parameter],
                    blocks: &[second_block],
                    operations: &[second_operation],
                },
            )
            .unwrap()
        );
    }

    #[test]
    fn value_hash_is_domain_separated_and_deterministic() {
        let epoch = SchemaEpochId::from_bytes([3; 32]);
        let value = ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(true),
        };
        let hash = hash_validated_value(epoch, &value).unwrap();
        assert_eq!(
            hash.as_bytes(),
            &hex_32("7b41b6b9bdb3da41140423a8653a95bba432877657c3e86ffcb31345d41fa159")
        );
        assert_eq!(hash, hash_validated_value(epoch, &value).unwrap());
        assert_ne!(hash.as_bytes(), SemanticFingerprint::derive([]).as_bytes());
    }

    #[test]
    fn all_fingerprint_codes_are_stable() {
        let codes = [
            FingerprintErrorCode::EntityUnsupported,
            FingerprintErrorCode::InventoryInvalid,
            FingerprintErrorCode::LocalReferenceInvalid,
            FingerprintErrorCode::ClaimMissing,
            FingerprintErrorCode::Mismatch,
            FingerprintErrorCode::ResourceLimit,
            FingerprintErrorCode::ValueHashTypeUnsupported,
            FingerprintErrorCode::ValueHashValueInvalid,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 25_000 + u32::try_from(offset).unwrap());
        }
    }
}
