//! Crate-private staged foundation for `MUTATION_VALUE_CODEC_V1`.
//!
//! These helpers intentionally stay private until the candidate/precondition
//! layers own descriptor-selected admission and exact mutation-body wiring.

#![allow(dead_code)]

use sley_id::{EntityId, StateRoot};
use sley_scb1::{
    MAX_NESTING_DEPTH, MAX_STANDALONE_BYTES, MAX_TOTAL_ALLOCATION, ScbError, ScbErrorCode,
    ScbValueCursor, encode_bool, encode_bytes, encode_f32_bits, encode_f64_bits, encode_list,
    encode_record, encode_sint64, encode_text, encode_union, encode_uvar,
};
use sley_ssmc::{
    BuiltinFailureKind, ContractKind, EffectKind, FunctionType, IntegerWidth, NamedType,
    ParameterRole, Reachability, TypeExpr, Visibility,
};

use crate::value::{EntityIdSet, EntryExposure};

type Result<T> = core::result::Result<T, ScbError>;

trait MutationValueCodec: Sized {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>>;
    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self>;
}

trait SimpleEnumCodec: Copy + Eq {
    fn tag(self) -> u32;
    fn from_tag(tag: u32) -> Option<Self>;
}

fn encode_exact<T: MutationValueCodec>(value: &T) -> Result<Vec<u8>> {
    encode_at_depth(value, 0)
}

fn decode_exact<T: MutationValueCodec>(input: &[u8]) -> Result<T> {
    let mut cursor = ScbValueCursor::new(input)?;
    let mut budget = DecodeBudget::default();
    let value = decode_at_depth(&mut cursor, 0, &mut budget)?;
    cursor.check_finished()?;
    Ok(value)
}

fn encode_at_depth<T: MutationValueCodec>(value: &T, depth: usize) -> Result<Vec<u8>> {
    check_depth(depth)?;
    let encoded = value.encode_value(depth)?;
    if encoded.len() > MAX_STANDALONE_BYTES {
        return Err(ScbError::new(ScbErrorCode::ResourceLimit));
    }
    Ok(encoded)
}

fn decode_at_depth<T: MutationValueCodec>(
    cursor: &mut ScbValueCursor<'_>,
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<T> {
    check_depth(depth)?;
    T::decode_value(cursor, depth, budget)
}

fn decode_nested_exact<T: MutationValueCodec>(
    input: &[u8],
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<T> {
    let mut cursor = ScbValueCursor::new(input)?;
    let value = decode_at_depth(&mut cursor, depth, budget)?;
    cursor.check_finished()?;
    Ok(value)
}

fn decode_record_fields<F>(
    cursor: &mut ScbValueCursor<'_>,
    expected_tags: &[u32],
    mut decode_field: F,
) -> Result<()>
where
    F: FnMut(u32, &[u8]) -> Result<()>,
{
    let count = cursor.read_record_field_count()?;
    let expected_count = u64::try_from(expected_tags.len())
        .map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    if count != expected_count {
        return if count < expected_count {
            Err(ScbError::new(ScbErrorCode::FieldMissing))
        } else {
            Err(ScbError::new(ScbErrorCode::FieldUnknown))
        };
    }
    let mut previous = None;
    for expected_tag in expected_tags {
        let tag = decode_u32(cursor)?;
        if let Some(previous) = previous {
            if tag == previous {
                return Err(ScbError::new(ScbErrorCode::FieldDuplicate));
            }
            if tag < previous {
                return Err(ScbError::new(ScbErrorCode::FieldOrder));
            }
        }
        previous = Some(tag);
        if tag != *expected_tag {
            return if expected_tags.contains(&tag) {
                Err(ScbError::new(ScbErrorCode::FieldOrder))
            } else {
                Err(ScbError::new(ScbErrorCode::FieldUnknown))
            };
        }
        decode_field(tag, cursor.read_sized_payload()?)?;
    }
    Ok(())
}

fn check_depth(depth: usize) -> Result<()> {
    if depth > MAX_NESTING_DEPTH {
        Err(ScbError::new(ScbErrorCode::ResourceLimit))
    } else {
        Ok(())
    }
}

fn check_container_depth(depth: usize) -> Result<()> {
    if depth >= MAX_NESTING_DEPTH {
        Err(ScbError::new(ScbErrorCode::ResourceLimit))
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct DecodeBudget {
    allocated: usize,
}

impl DecodeBudget {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.allocated = self
            .allocated
            .checked_add(bytes)
            .ok_or_else(|| ScbError::new(ScbErrorCode::ResourceLimit))?;
        if self.allocated > MAX_TOTAL_ALLOCATION {
            return Err(ScbError::new(ScbErrorCode::ResourceLimit));
        }
        Ok(())
    }
}

fn encode_u16(value: u16) -> Vec<u8> {
    encode_uvar(u64::from(value))
}

fn decode_u16(cursor: &mut ScbValueCursor<'_>) -> Result<u16> {
    let value = cursor.read_uvar(16)?;
    u16::try_from(value).map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))
}

fn encode_u32(value: u32) -> Vec<u8> {
    encode_uvar(u64::from(value))
}

fn decode_u32(cursor: &mut ScbValueCursor<'_>) -> Result<u32> {
    let value = cursor.read_uvar(32)?;
    u32::try_from(value).map_err(|_| ScbError::new(ScbErrorCode::IntegerOverflow))
}

fn encode_u64(value: u64) -> Vec<u8> {
    encode_uvar(value)
}

fn decode_u64(cursor: &mut ScbValueCursor<'_>) -> Result<u64> {
    cursor.read_uvar(64)
}

fn encode_simple_enum<T: SimpleEnumCodec>(value: T) -> Vec<u8> {
    encode_u32(value.tag())
}

fn decode_simple_enum<T: SimpleEnumCodec>(cursor: &mut ScbValueCursor<'_>) -> Result<T> {
    let tag = decode_u32(cursor)?;
    T::from_tag(tag).ok_or_else(|| ScbError::new(ScbErrorCode::UnionInvalid))
}

macro_rules! impl_uint_codec {
    ($ty:ty, $encode:ident, $decode:ident) => {
        impl MutationValueCodec for $ty {
            fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
                Ok($encode(*self))
            }

            fn decode_value(
                cursor: &mut ScbValueCursor<'_>,
                _depth: usize,
                _budget: &mut DecodeBudget,
            ) -> Result<Self> {
                $decode(cursor)
            }
        }
    };
}

impl MutationValueCodec for bool {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_bool(*self))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        cursor.read_bool()
    }
}

impl_uint_codec!(u16, encode_u16, decode_u16);
impl_uint_codec!(u32, encode_u32, decode_u32);
impl_uint_codec!(u64, encode_u64, decode_u64);

impl MutationValueCodec for i64 {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_sint64(*self))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        cursor.read_sint64()
    }
}

impl MutationValueCodec for [u8; 32] {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(self.to_vec())
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        cursor.read_fixed_bytes::<32>()
    }
}

impl MutationValueCodec for Vec<u8> {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        encode_bytes(self)
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        let value = cursor.read_bytes()?;
        budget.charge(value.len())?;
        Ok(value.to_vec())
    }
}

impl MutationValueCodec for String {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        encode_text(self)
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        let value = cursor.read_text()?;
        budget.charge(value.len())?;
        Ok(value.to_owned())
    }
}

impl MutationValueCodec for EntityId {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        Ok(Self::from_bytes(cursor.read_fixed_bytes::<32>()?))
    }
}

impl MutationValueCodec for StateRoot {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        Ok(Self::from_bytes(cursor.read_fixed_bytes::<32>()?))
    }
}

impl<T: MutationValueCodec> MutationValueCodec for Vec<T> {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        let elements = self
            .iter()
            .map(|value| encode_at_depth(value, depth + 1))
            .collect::<Result<Vec<_>>>()?;
        encode_list(&elements)
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let count = cursor.read_list_count()?;
        let capacity =
            usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
        budget.charge(
            capacity
                .checked_mul(core::mem::size_of::<T>())
                .ok_or_else(|| ScbError::new(ScbErrorCode::ResourceLimit))?,
        )?;
        let mut values = Vec::with_capacity(capacity);
        for _ in 0..count {
            values.push(decode_nested_exact(
                cursor.read_sized_payload()?,
                depth + 1,
                budget,
            )?);
        }
        Ok(values)
    }
}

impl<T: MutationValueCodec> MutationValueCodec for Option<T> {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            None => encode_union(0, &[]),
            Some(value) => encode_union(1, &encode_at_depth(value, depth + 1)?),
        }
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let (tag, payload) = cursor.read_union()?;
        match tag {
            0 if payload.is_empty() => Ok(None),
            1 => Ok(Some(decode_nested_exact(payload, depth + 1, budget)?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl<T: MutationValueCodec> MutationValueCodec for Box<T> {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        (**self).encode_value(depth)
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        budget.charge(core::mem::size_of::<T>())?;
        Ok(Box::new(T::decode_value(cursor, depth, budget)?))
    }
}

impl MutationValueCodec for EntityIdSet {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        let elements = self
            .as_slice()
            .iter()
            .map(|value| encode_at_depth(value, depth + 1))
            .collect::<Result<Vec<_>>>()?;
        encode_list(&elements)
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let count = cursor.read_list_count()?;
        let capacity =
            usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
        budget.charge(
            capacity
                .checked_mul(core::mem::size_of::<EntityId>())
                .ok_or_else(|| ScbError::new(ScbErrorCode::ResourceLimit))?,
        )?;
        let mut values = Vec::with_capacity(capacity);
        let mut previous: Option<EntityId> = None;
        for _ in 0..count {
            let value =
                decode_nested_exact::<EntityId>(cursor.read_sized_payload()?, depth + 1, budget)?;
            if let Some(previous) = previous {
                match previous.cmp(&value) {
                    core::cmp::Ordering::Less => {}
                    core::cmp::Ordering::Equal => {
                        return Err(ScbError::new(ScbErrorCode::MapDuplicate));
                    }
                    core::cmp::Ordering::Greater => {
                        return Err(ScbError::new(ScbErrorCode::MapOrder));
                    }
                }
            }
            previous = Some(value);
            values.push(value);
        }
        EntityIdSet::from_unsorted(values).map_err(|_| ScbError::new(ScbErrorCode::MapDuplicate))
    }
}

fn encode_f32_value_bits(bits: u32) -> Result<Vec<u8>> {
    encode_f32_bits(bits)
}

fn decode_f32_value_bits(cursor: &mut ScbValueCursor<'_>) -> Result<u32> {
    cursor.read_f32_bits()
}

fn encode_f64_value_bits(bits: u64) -> Result<Vec<u8>> {
    encode_f64_bits(bits)
}

fn decode_f64_value_bits(cursor: &mut ScbValueCursor<'_>) -> Result<u64> {
    cursor.read_f64_bits()
}

impl SimpleEnumCodec for Visibility {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Private),
            2 => Some(Self::Package),
            3 => Some(Self::Workspace),
            4 => Some(Self::Exported),
            _ => None,
        }
    }
}

impl SimpleEnumCodec for ParameterRole {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Function),
            2 => Some(Self::Block),
            _ => None,
        }
    }
}

impl SimpleEnumCodec for Reachability {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Required),
            2 => Some(Self::ExplicitlyUnreachable),
            _ => None,
        }
    }
}

impl SimpleEnumCodec for EffectKind {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::StdoutWrite),
            2 => Some(Self::StderrWrite),
            3 => Some(Self::FileRead),
            4 => Some(Self::FileWrite),
            5 => Some(Self::ClockRead),
            6 => Some(Self::RandomRead),
            7 => Some(Self::EnvironmentRead),
            8 => Some(Self::AdapterCall),
            _ => None,
        }
    }
}

impl SimpleEnumCodec for ContractKind {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Precondition),
            2 => Some(Self::Postcondition),
            3 => Some(Self::Invariant),
            4 => Some(Self::EffectBound),
            5 => Some(Self::CapabilityBound),
            6 => Some(Self::ResultPredicate),
            7 => Some(Self::ResourceCeiling),
            _ => None,
        }
    }
}

impl SimpleEnumCodec for EntryExposure {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Local),
            2 => Some(Self::Protocol),
            _ => None,
        }
    }
}

macro_rules! impl_simple_enum_codec {
    ($ty:ty) => {
        impl MutationValueCodec for $ty {
            fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
                Ok(encode_simple_enum(*self))
            }

            fn decode_value(
                cursor: &mut ScbValueCursor<'_>,
                _depth: usize,
                _budget: &mut DecodeBudget,
            ) -> Result<Self> {
                decode_simple_enum(cursor)
            }
        }
    };
}

impl_simple_enum_codec!(Visibility);
impl_simple_enum_codec!(ParameterRole);
impl_simple_enum_codec!(Reachability);
impl_simple_enum_codec!(EffectKind);
impl_simple_enum_codec!(ContractKind);
impl_simple_enum_codec!(EntryExposure);

impl MutationValueCodec for IntegerWidth {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_u16(self.bits()))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        Ok(Self::from_bits(decode_u16(cursor)?))
    }
}

impl SimpleEnumCodec for BuiltinFailureKind {
    fn tag(self) -> u32 {
        u32::from(self.tag())
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Arithmetic),
            2 => Some(Self::Index),
            3 => Some(Self::DuplicateKey),
            4 => Some(Self::ContractViolation),
            5 => Some(Self::Capability),
            _ => None,
        }
    }
}

impl MutationValueCodec for BuiltinFailureKind {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_u16(self.tag()))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        Self::from_tag(u32::from(decode_u16(cursor)?))
            .ok_or_else(|| ScbError::new(ScbErrorCode::UnionInvalid))
    }
}

impl MutationValueCodec for NamedType {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.definition, depth + 1)?),
            (2, encode_at_depth(&self.arguments, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut definition = None;
        let mut arguments = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => definition = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => arguments = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            definition: definition.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            arguments: arguments.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

struct MapType {
    key: Box<TypeExpr>,
    value: Box<TypeExpr>,
}

impl MutationValueCodec for MapType {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.key, depth + 1)?),
            (2, encode_at_depth(&self.value, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut key = None;
        let mut value = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => key = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => value = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            key: key.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            value: value.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

fn encode_map_type(key: &TypeExpr, value: &TypeExpr, depth: usize) -> Result<Vec<u8>> {
    check_container_depth(depth)?;
    encode_record(&[
        (1, encode_at_depth(key, depth + 1)?),
        (2, encode_at_depth(value, depth + 1)?),
    ])
}

struct ResultType {
    ok: Box<TypeExpr>,
    error: Box<TypeExpr>,
}

impl MutationValueCodec for ResultType {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.ok, depth + 1)?),
            (2, encode_at_depth(&self.error, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut ok = None;
        let mut error = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => ok = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => error = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            ok: ok.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            error: error.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

fn encode_result_type(ok: &TypeExpr, error: &TypeExpr, depth: usize) -> Result<Vec<u8>> {
    check_container_depth(depth)?;
    encode_record(&[
        (1, encode_at_depth(ok, depth + 1)?),
        (2, encode_at_depth(error, depth + 1)?),
    ])
}

fn validate_entity_id_set_order(values: &[EntityId]) -> Result<()> {
    let mut previous: Option<&EntityId> = None;
    for value in values {
        if let Some(previous) = previous {
            match previous.as_bytes().cmp(value.as_bytes()) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => {
                    return Err(ScbError::new(ScbErrorCode::MapDuplicate));
                }
                core::cmp::Ordering::Greater => {
                    return Err(ScbError::new(ScbErrorCode::MapOrder));
                }
            }
        }
        previous = Some(value);
    }
    Ok(())
}

fn encode_entity_id_set_vec(values: &[EntityId], depth: usize) -> Result<Vec<u8>> {
    check_container_depth(depth)?;
    validate_entity_id_set_order(values)?;
    let elements = values
        .iter()
        .map(|value| encode_at_depth(value, depth + 1))
        .collect::<Result<Vec<_>>>()?;
    encode_list(&elements)
}

fn decode_entity_id_set_vec(
    cursor: &mut ScbValueCursor<'_>,
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<Vec<EntityId>> {
    check_container_depth(depth)?;
    let count = cursor.read_list_count()?;
    let capacity =
        usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    budget.charge(
        capacity
            .checked_mul(core::mem::size_of::<EntityId>())
            .ok_or_else(|| ScbError::new(ScbErrorCode::ResourceLimit))?,
    )?;
    let mut values = Vec::with_capacity(capacity);
    let mut previous_payload: Option<&[u8]> = None;
    for _ in 0..count {
        let payload = cursor.read_sized_payload()?;
        let value = decode_nested_exact::<EntityId>(payload, depth + 1, budget)?;
        if let Some(previous) = previous_payload {
            match previous.cmp(payload) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => {
                    return Err(ScbError::new(ScbErrorCode::MapDuplicate));
                }
                core::cmp::Ordering::Greater => {
                    return Err(ScbError::new(ScbErrorCode::MapOrder));
                }
            }
        }
        previous_payload = Some(payload);
        values.push(value);
    }
    Ok(values)
}

impl MutationValueCodec for FunctionType {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.parameters, depth + 1)?),
            (2, encode_at_depth(&self.result, depth + 1)?),
            (3, encode_entity_id_set_vec(&self.effects, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut parameters = None;
        let mut result = None;
        let mut effects = None;
        decode_record_fields(cursor, &[1, 2, 3], |tag, payload| {
            match tag {
                1 => parameters = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => result = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => {
                    let mut nested = ScbValueCursor::new(payload)?;
                    effects = Some(decode_entity_id_set_vec(&mut nested, depth + 1, budget)?);
                    nested.check_finished()?;
                }
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            parameters: parameters.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            result: result.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            effects: effects.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for TypeExpr {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Unit | Self::Bool | Self::F32 | Self::F64 | Self::Bytes | Self::Text => {
                encode_union(self.tag(), &[])
            }
            Self::SInt(value) | Self::UInt(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::Tuple(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Named(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Vector(value) | Self::Option(value) | Self::LocalCell(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::OrderedMap { key, value } => {
                encode_union(self.tag(), &encode_map_type(key, value, depth + 1)?)
            }
            Self::Result { ok, error } => {
                encode_union(self.tag(), &encode_result_type(ok, error, depth + 1)?)
            }
            Self::FunctionRef(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::AdapterHandle(value) | Self::CapabilityToken(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::TypeParameter(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::BuiltinFailure(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
        }
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let (tag, payload) = cursor.read_union()?;
        match tag {
            1 if payload.is_empty() => Ok(Self::Unit),
            2 if payload.is_empty() => Ok(Self::Bool),
            3 => Ok(Self::SInt(decode_nested_exact(payload, depth + 1, budget)?)),
            4 => Ok(Self::UInt(decode_nested_exact(payload, depth + 1, budget)?)),
            5 if payload.is_empty() => Ok(Self::F32),
            6 if payload.is_empty() => Ok(Self::F64),
            7 if payload.is_empty() => Ok(Self::Bytes),
            8 if payload.is_empty() => Ok(Self::Text),
            9 => Ok(Self::Tuple(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            10 => Ok(Self::Named(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            11 => Ok(Self::Vector(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            12 => {
                let value: MapType = decode_nested_exact(payload, depth + 1, budget)?;
                Ok(Self::OrderedMap {
                    key: value.key,
                    value: value.value,
                })
            }
            13 => Ok(Self::Option(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            14 => {
                let value: ResultType = decode_nested_exact(payload, depth + 1, budget)?;
                Ok(Self::Result {
                    ok: value.ok,
                    error: value.error,
                })
            }
            15 => Ok(Self::FunctionRef(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            16 => Ok(Self::AdapterHandle(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            17 => Ok(Self::CapabilityToken(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            18 => Ok(Self::LocalCell(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            19 => Ok(Self::TypeParameter(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            20 => Ok(Self::BuiltinFailure(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn sized(payload: &[u8]) -> Vec<u8> {
        let mut encoded = encode_uvar(payload.len() as u64);
        encoded.extend_from_slice(payload);
        encoded
    }

    fn raw_record(fields: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut encoded = encode_uvar(fields.len() as u64);
        for (tag, payload) in fields {
            encoded.extend_from_slice(&encode_u32(*tag));
            encoded.extend_from_slice(&sized(payload));
        }
        encoded
    }

    fn option_chain(depth: usize) -> TypeExpr {
        let mut value = TypeExpr::Unit;
        for _ in 0..depth {
            value = TypeExpr::Option(Box::new(value));
        }
        value
    }

    fn assert_round_trip<T>(value: &T)
    where
        T: MutationValueCodec + Eq + core::fmt::Debug,
    {
        let encoded = encode_exact(value).unwrap();
        assert_eq!(&decode_exact::<T>(&encoded).unwrap(), value);
    }

    #[test]
    fn primitives_round_trip_extremes_exactly() {
        for value in [false, true] {
            assert_round_trip(&value);
        }
        for value in [u16::MIN, u16::MAX] {
            assert_round_trip(&value);
        }
        for value in [u32::MIN, u32::MAX] {
            assert_round_trip(&value);
        }
        for value in [u64::MIN, u64::MAX] {
            assert_round_trip(&value);
        }
        for value in [i64::MIN, -1, 0, i64::MAX] {
            assert_round_trip(&value);
        }
        assert_eq!(
            decode_f32_value_bits(
                &mut ScbValueCursor::new(&encode_f32_value_bits(0x7fc0_0000).unwrap()).unwrap()
            )
            .unwrap(),
            0x7fc0_0000
        );
        assert_eq!(
            decode_f64_value_bits(
                &mut ScbValueCursor::new(&encode_f64_value_bits(0x7ff8_0000_0000_0000).unwrap())
                    .unwrap()
            )
            .unwrap(),
            0x7ff8_0000_0000_0000
        );
        assert_round_trip(&Vec::<u8>::from([0, 1, 255]));
        assert_round_trip(&String::from("mutation codec"));
        assert_round_trip(&[7_u8; 32]);
        assert_round_trip(&id(8));
        assert_round_trip(&StateRoot::from_bytes([9_u8; 32]));
    }

    #[test]
    fn all_direct_body_enum_tags_round_trip_and_reject_unknown_tags() {
        for value in [
            Visibility::Private,
            Visibility::Package,
            Visibility::Workspace,
            Visibility::Exported,
        ] {
            assert_round_trip(&value);
        }
        for value in [ParameterRole::Function, ParameterRole::Block] {
            assert_round_trip(&value);
        }
        for value in [Reachability::Required, Reachability::ExplicitlyUnreachable] {
            assert_round_trip(&value);
        }
        for value in [
            EffectKind::StdoutWrite,
            EffectKind::StderrWrite,
            EffectKind::FileRead,
            EffectKind::FileWrite,
            EffectKind::ClockRead,
            EffectKind::RandomRead,
            EffectKind::EnvironmentRead,
            EffectKind::AdapterCall,
        ] {
            assert_round_trip(&value);
        }
        for value in [
            ContractKind::Precondition,
            ContractKind::Postcondition,
            ContractKind::Invariant,
            ContractKind::EffectBound,
            ContractKind::CapabilityBound,
            ContractKind::ResultPredicate,
            ContractKind::ResourceCeiling,
        ] {
            assert_round_trip(&value);
        }
        for value in [EntryExposure::Local, EntryExposure::Protocol] {
            assert_round_trip(&value);
        }

        assert_eq!(
            decode_exact::<Visibility>(&encode_uvar(99))
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
    }

    #[test]
    fn option_and_list_nesting_preserve_order_and_reject_inner_trailing_bytes() {
        let value = vec![Some(vec![id(1), id(2)]), None, Some(vec![id(3)])];
        assert_round_trip(&value);

        let malformed_some = encode_union(1, &[1, 2]).unwrap();
        assert_eq!(
            decode_exact::<Option<bool>>(&malformed_some)
                .unwrap_err()
                .code(),
            ScbErrorCode::TrailingBytes
        );

        let malformed_list = encode_list(&[vec![1, 2]]).unwrap();
        assert_eq!(
            decode_exact::<Vec<bool>>(&malformed_list)
                .unwrap_err()
                .code(),
            ScbErrorCode::TrailingBytes
        );
    }

    #[test]
    fn entity_id_set_uses_canonical_encoding_and_rejects_duplicate_or_unordered_bytes() {
        let set = EntityIdSet::from_unsorted(vec![id(3), id(1), id(2)]).unwrap();
        assert_eq!(
            decode_exact::<EntityIdSet>(&encode_exact(&set).unwrap()).unwrap(),
            EntityIdSet::from_unsorted(vec![id(1), id(2), id(3)]).unwrap()
        );

        let duplicate =
            encode_list(&[encode_exact(&id(1)).unwrap(), encode_exact(&id(1)).unwrap()]).unwrap();
        assert_eq!(
            decode_exact::<EntityIdSet>(&duplicate).unwrap_err().code(),
            ScbErrorCode::MapDuplicate
        );

        let unordered =
            encode_list(&[encode_exact(&id(2)).unwrap(), encode_exact(&id(1)).unwrap()]).unwrap();
        assert_eq!(
            decode_exact::<EntityIdSet>(&unordered).unwrap_err().code(),
            ScbErrorCode::MapOrder
        );
    }

    #[test]
    fn type_expr_all_twenty_tags_round_trip_exactly() {
        let values = [
            TypeExpr::Unit,
            TypeExpr::Bool,
            TypeExpr::SInt(IntegerWidth::from_bits(8)),
            TypeExpr::UInt(IntegerWidth::from_bits(24)),
            TypeExpr::F32,
            TypeExpr::F64,
            TypeExpr::Bytes,
            TypeExpr::Text,
            TypeExpr::Tuple(vec![TypeExpr::Bool, TypeExpr::Bytes]),
            TypeExpr::Named(NamedType {
                definition: id(10),
                arguments: vec![TypeExpr::Text],
            }),
            TypeExpr::Vector(Box::new(TypeExpr::UInt(IntegerWidth::from_bits(16)))),
            TypeExpr::OrderedMap {
                key: Box::new(TypeExpr::Text),
                value: Box::new(TypeExpr::Bool),
            },
            TypeExpr::Option(Box::new(TypeExpr::Bytes)),
            TypeExpr::Result {
                ok: Box::new(TypeExpr::Unit),
                error: Box::new(TypeExpr::BuiltinFailure(BuiltinFailureKind::Capability)),
            },
            TypeExpr::FunctionRef(FunctionType {
                parameters: vec![TypeExpr::Bool],
                result: Box::new(TypeExpr::Unit),
                effects: vec![id(1), id(2)],
            }),
            TypeExpr::AdapterHandle(id(16)),
            TypeExpr::CapabilityToken(id(17)),
            TypeExpr::LocalCell(Box::new(TypeExpr::Text)),
            TypeExpr::TypeParameter(3),
            TypeExpr::BuiltinFailure(BuiltinFailureKind::DuplicateKey),
        ];
        for (index, value) in values.iter().enumerate() {
            assert_eq!(value.tag(), u32::try_from(index + 1).unwrap());
            assert_round_trip(value);
        }
    }

    #[test]
    fn type_expr_rejects_unknown_tags_and_non_empty_direct_payloads() {
        assert_eq!(
            decode_exact::<TypeExpr>(&encode_union(99, &[]).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
        assert_eq!(
            decode_exact::<TypeExpr>(&encode_union(20, &encode_uvar(65_536)).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::IntegerOverflow
        );
        assert_eq!(
            decode_exact::<TypeExpr>(&encode_union(1, &encode_bool(false)).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
    }

    #[test]
    fn type_expr_preserves_raw_invalid_integer_width_payload() {
        let value = TypeExpr::UInt(IntegerWidth::from_bits(24));
        assert_eq!(
            decode_exact::<TypeExpr>(&encode_exact(&value).unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn type_expr_records_fail_closed_for_missing_unknown_order_and_inner_trailing() {
        let missing = encode_union(
            10,
            &encode_record(&[(1, encode_exact(&id(1)).unwrap())]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_exact::<TypeExpr>(&missing).unwrap_err().code(),
            ScbErrorCode::FieldMissing
        );

        let unknown = encode_union(
            10,
            &encode_record(&[
                (1, encode_exact(&id(1)).unwrap()),
                (2, encode_exact(&Vec::<TypeExpr>::new()).unwrap()),
                (3, encode_exact(&TypeExpr::Unit).unwrap()),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_exact::<TypeExpr>(&unknown).unwrap_err().code(),
            ScbErrorCode::FieldUnknown
        );

        let ordered_map = encode_union(
            12,
            &raw_record(&[
                (2, encode_exact(&TypeExpr::Bool).unwrap()),
                (1, encode_exact(&TypeExpr::Text).unwrap()),
            ]),
        )
        .unwrap();
        assert_eq!(
            decode_exact::<TypeExpr>(&ordered_map).unwrap_err().code(),
            ScbErrorCode::FieldOrder
        );

        let mut trailing_definition = encode_exact(&id(1)).unwrap();
        trailing_definition.push(0);
        let inner_trailing = encode_union(
            10,
            &encode_record(&[
                (1, trailing_definition),
                (2, encode_exact(&Vec::<TypeExpr>::new()).unwrap()),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_exact::<TypeExpr>(&inner_trailing)
                .unwrap_err()
                .code(),
            ScbErrorCode::TrailingBytes
        );
    }

    #[test]
    fn function_type_effects_reject_unordered_and_duplicate_on_encode_and_decode() {
        let duplicate = FunctionType {
            parameters: vec![],
            result: Box::new(TypeExpr::Unit),
            effects: vec![id(1), id(1)],
        };
        assert_eq!(
            encode_exact(&duplicate).unwrap_err().code(),
            ScbErrorCode::MapDuplicate
        );

        let unordered = FunctionType {
            parameters: vec![],
            result: Box::new(TypeExpr::Unit),
            effects: vec![id(2), id(1)],
        };
        assert_eq!(
            encode_exact(&unordered).unwrap_err().code(),
            ScbErrorCode::MapOrder
        );

        let duplicate_effects =
            encode_list(&[encode_exact(&id(1)).unwrap(), encode_exact(&id(1)).unwrap()]).unwrap();
        let function = encode_record(&[
            (1, encode_exact(&Vec::<TypeExpr>::new()).unwrap()),
            (2, encode_exact(&TypeExpr::Unit).unwrap()),
            (3, duplicate_effects),
        ])
        .unwrap();
        assert_eq!(
            decode_exact::<FunctionType>(&function).unwrap_err().code(),
            ScbErrorCode::MapDuplicate
        );

        let unordered_effects =
            encode_list(&[encode_exact(&id(2)).unwrap(), encode_exact(&id(1)).unwrap()]).unwrap();
        let function = encode_record(&[
            (1, encode_exact(&Vec::<TypeExpr>::new()).unwrap()),
            (2, encode_exact(&TypeExpr::Unit).unwrap()),
            (3, unordered_effects),
        ])
        .unwrap();
        assert_eq!(
            decode_exact::<FunctionType>(&function).unwrap_err().code(),
            ScbErrorCode::MapOrder
        );

        let malformed_effects = encode_list(&[encode_exact(&id(2)).unwrap(), vec![1; 31]]).unwrap();
        let function = encode_record(&[
            (1, encode_exact(&Vec::<TypeExpr>::new()).unwrap()),
            (2, encode_exact(&TypeExpr::Unit).unwrap()),
            (3, malformed_effects),
        ])
        .unwrap();
        assert_eq!(
            decode_exact::<FunctionType>(&function).unwrap_err().code(),
            ScbErrorCode::LengthOverflow
        );
    }

    #[test]
    fn type_expr_recursive_round_trip_and_depth_boundary_are_exact() {
        assert_round_trip(&option_chain(8));

        let allowed = option_chain(MAX_NESTING_DEPTH - 1);
        assert!(encode_exact(&allowed).is_ok());

        let rejected = option_chain(MAX_NESTING_DEPTH);
        assert_eq!(
            encode_exact(&rejected).unwrap_err().code(),
            ScbErrorCode::ResourceLimit
        );
    }

    #[test]
    fn exact_decoders_reject_outer_trailing_bytes_and_resource_failures() {
        assert_eq!(
            decode_exact::<bool>(&[1, 0]).unwrap_err().code(),
            ScbErrorCode::TrailingBytes
        );
        assert_eq!(
            decode_exact::<Vec<u64>>(&encode_uvar(1_000_001))
                .unwrap_err()
                .code(),
            ScbErrorCode::ResourceLimit
        );

        let malformed_none = encode_union(0, &encode_bool(false)).unwrap();
        assert_eq!(
            decode_exact::<Option<bool>>(&malformed_none)
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );

        assert_eq!(
            encode_at_depth(&true, MAX_NESTING_DEPTH + 1)
                .unwrap_err()
                .code(),
            ScbErrorCode::ResourceLimit
        );
        assert!(encode_at_depth(&true, MAX_NESTING_DEPTH).is_ok());
        assert_eq!(
            encode_at_depth(&Vec::<bool>::new(), MAX_NESTING_DEPTH)
                .unwrap_err()
                .code(),
            ScbErrorCode::ResourceLimit
        );
        let mut cursor = ScbValueCursor::new(&[1]).unwrap();
        let mut budget = DecodeBudget::default();
        assert_eq!(
            decode_at_depth::<bool>(&mut cursor, MAX_NESTING_DEPTH + 1, &mut budget)
                .unwrap_err()
                .code(),
            ScbErrorCode::ResourceLimit
        );
        let mut leaf_cursor = ScbValueCursor::new(&[1]).unwrap();
        assert!(decode_at_depth::<bool>(&mut leaf_cursor, MAX_NESTING_DEPTH, &mut budget).is_ok());
        let mut container_cursor = ScbValueCursor::new(&[0]).unwrap();
        assert_eq!(
            decode_at_depth::<Vec<bool>>(&mut container_cursor, MAX_NESTING_DEPTH, &mut budget,)
                .unwrap_err()
                .code(),
            ScbErrorCode::ResourceLimit
        );
        budget.charge(MAX_TOTAL_ALLOCATION).unwrap();
        assert_eq!(
            budget.charge(1).unwrap_err().code(),
            ScbErrorCode::ResourceLimit
        );
    }
}
