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
    BranchTerminator, BuiltinCase, BuiltinFailureKind, BuiltinFailureValue, CaseKey,
    CondBranchTerminator, ContractBinding, ContractKind, ContractSource, EffectKind,
    FunctionRefValue, FunctionType, Immediate, IntegerWidth, MemberId, NamedType,
    OperationResultRef, ParameterRole, Reachability, RecordField, ResourceLimits, ReturnTerminator,
    SwitchArgument, SwitchCase, SwitchEdge, TargetEdge, TrapCode, TypeExpr, TypeParameterDef,
    ValueRef, VariantImmediate, VariantSwitchTerminator, Visibility,
};

use crate::value::{
    AdapterImportBody, DependencyBindingBody, EffectDefBody, EntityIdSet, EntryExposure,
    EntryPointBody, FunctionBody, GlobalValueBody, OperationBody, PackageBody, ParameterBody,
    PolicyBindingBody, WorkspaceBody,
};

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

macro_rules! impl_required_record_codec {
    ($type:ident, $($tag:literal => $field:ident),+ $(,)?) => {
        impl MutationValueCodec for $type {
            fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
                check_container_depth(depth)?;
                encode_record(&[
                    $(($tag, encode_at_depth(&self.$field, depth + 1)?),)+
                ])
            }

            fn decode_value(
                cursor: &mut ScbValueCursor<'_>,
                depth: usize,
                budget: &mut DecodeBudget,
            ) -> Result<Self> {
                check_container_depth(depth)?;
                $(let mut $field = None;)+
                decode_record_fields(cursor, &[$($tag),+], |tag, payload| {
                    match tag {
                        $($tag => {
                            $field = Some(decode_nested_exact(payload, depth + 1, budget)?)
                        },)+
                        _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
                    }
                    Ok(())
                })?;
                Ok(Self {
                    $($field: $field
                        .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,)+
                })
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

impl MutationValueCodec for MemberId {
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

impl MutationValueCodec for OperationResultRef {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.operation, depth + 1)?),
            (2, encode_at_depth(&self.result_index, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut operation = None;
        let mut result_index = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => operation = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => result_index = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            operation: operation.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            result_index: result_index.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for ValueRef {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Parameter(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::OperationResult(value) => {
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
            1 => Ok(Self::Parameter(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::OperationResult(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for FunctionRefValue {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.function, depth + 1)?),
            (2, encode_at_depth(&self.type_arguments, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut function = None;
        let mut type_arguments = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => function = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => type_arguments = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            function: function.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            type_arguments: type_arguments
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for VariantImmediate {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.definition, depth + 1)?),
            (2, encode_at_depth(&self.member_id, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut definition = None;
        let mut member_id = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => definition = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => member_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            definition: definition.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            member_id: member_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for Immediate {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::None => encode_union(self.tag(), &[]),
            Self::Entity(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Index(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Field(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Variant(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Observation(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::Function(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
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
            1 if payload.is_empty() => Ok(Self::None),
            2 => Ok(Self::Entity(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            3 => Ok(Self::Index(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            4 => Ok(Self::Field(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            5 => Ok(Self::Variant(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            6 => Ok(Self::Observation(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            7 => Ok(Self::Function(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for TargetEdge {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.target, depth + 1)?),
            (2, encode_at_depth(&self.arguments, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut target = None;
        let mut arguments = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => target = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => arguments = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            target: target.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            arguments: arguments.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl SimpleEnumCodec for BuiltinCase {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::None),
            2 => Some(Self::Some),
            3 => Some(Self::Ok),
            4 => Some(Self::Err),
            _ => None,
        }
    }
}

impl_simple_enum_codec!(BuiltinCase);

impl MutationValueCodec for CaseKey {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Member(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Builtin(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
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
            1 => Ok(Self::Member(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::Builtin(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for SwitchArgument {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Value(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::CasePayload => encode_union(self.tag(), &[]),
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
            1 => Ok(Self::Value(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 if payload.is_empty() => Ok(Self::CasePayload),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for SwitchEdge {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.target, depth + 1)?),
            (2, encode_at_depth(&self.arguments, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut target = None;
        let mut arguments = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => target = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => arguments = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            target: target.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            arguments: arguments.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for SwitchCase {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.case_key, depth + 1)?),
            (2, encode_at_depth(&self.edge, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut case_key = None;
        let mut edge = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => case_key = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => edge = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            case_key: case_key.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            edge: edge.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl SimpleEnumCodec for TrapCode {
    fn tag(self) -> u32 {
        self.tag()
    }

    fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::Unreachable),
            2 => Some(Self::ResourceExhausted),
            3 => Some(Self::AdapterContractViolation),
            4 => Some(Self::InternalInvariant),
            _ => None,
        }
    }
}

impl_simple_enum_codec!(TrapCode);

impl MutationValueCodec for ReturnTerminator {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[(1, encode_at_depth(&self.value, depth + 1)?)])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut value = None;
        decode_record_fields(cursor, &[1], |tag, payload| {
            match tag {
                1 => value = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            value: value.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for BranchTerminator {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[(1, encode_at_depth(&self.edge, depth + 1)?)])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut edge = None;
        decode_record_fields(cursor, &[1], |tag, payload| {
            match tag {
                1 => edge = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            edge: edge.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for CondBranchTerminator {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.condition, depth + 1)?),
            (2, encode_at_depth(&self.if_true, depth + 1)?),
            (3, encode_at_depth(&self.if_false, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut condition = None;
        let mut if_true = None;
        let mut if_false = None;
        decode_record_fields(cursor, &[1, 2, 3], |tag, payload| {
            match tag {
                1 => condition = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => if_true = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => if_false = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            condition: condition.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            if_true: if_true.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            if_false: if_false.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for VariantSwitchTerminator {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.value, depth + 1)?),
            (2, encode_at_depth(&self.cases, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut value = None;
        let mut cases = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => value = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => cases = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            value: value.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            cases: cases.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for TypeParameterDef {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[(1, encode_at_depth(&self.ordinal, depth + 1)?)])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut ordinal = None;
        decode_record_fields(cursor, &[1], |tag, payload| {
            match tag {
                1 => ordinal = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            ordinal: ordinal.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for RecordField {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.member_id, depth + 1)?),
            (2, encode_at_depth(&self.value_type, depth + 1)?),
            (3, encode_at_depth(&self.visibility, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut member_id = None;
        let mut value_type = None;
        let mut visibility = None;
        decode_record_fields(cursor, &[1, 2, 3], |tag, payload| {
            match tag {
                1 => member_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => value_type = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => visibility = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            member_id: member_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            value_type: value_type.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            visibility: visibility.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for BuiltinFailureValue {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.kind, depth + 1)?),
            (2, encode_at_depth(&self.code, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut kind = None;
        let mut code = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => kind = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => code = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            kind: kind.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            code: code.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for ContractSource {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Parameter(value) | Self::Global(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::Result | Self::Error => encode_union(self.tag(), &[]),
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
            1 => Ok(Self::Parameter(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 if payload.is_empty() => Ok(Self::Result),
            3 if payload.is_empty() => Ok(Self::Error),
            4 => Ok(Self::Global(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for ContractBinding {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.predicate_parameter, depth + 1)?),
            (2, encode_at_depth(&self.source, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut predicate_parameter = None;
        let mut source = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => predicate_parameter = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => source = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            predicate_parameter: predicate_parameter
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            source: source.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for ResourceLimits {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.fuel, depth + 1)?),
            (2, encode_at_depth(&self.memory_bytes, depth + 1)?),
            (3, encode_at_depth(&self.output_bytes, depth + 1)?),
            (4, encode_at_depth(&self.effect_count, depth + 1)?),
            (5, encode_at_depth(&self.call_depth, depth + 1)?),
            (6, encode_at_depth(&self.wall_timeout_millis, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut fuel = None;
        let mut memory_bytes = None;
        let mut output_bytes = None;
        let mut effect_count = None;
        let mut call_depth = None;
        let mut wall_timeout_millis = None;
        decode_record_fields(cursor, &[1, 2, 3, 4, 5, 6], |tag, payload| {
            match tag {
                1 => fuel = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => memory_bytes = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => output_bytes = Some(decode_nested_exact(payload, depth + 1, budget)?),
                4 => effect_count = Some(decode_nested_exact(payload, depth + 1, budget)?),
                5 => call_depth = Some(decode_nested_exact(payload, depth + 1, budget)?),
                6 => wall_timeout_millis = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            fuel: fuel.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            memory_bytes: memory_bytes.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            output_bytes: output_bytes.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            effect_count: effect_count.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            call_depth: call_depth.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            wall_timeout_millis: wall_timeout_millis
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl_required_record_codec!(
    WorkspaceBody,
    1 => packages,
    2 => root_namespace,
    3 => capability_requirements,
    4 => contracts,
    5 => tests,
);

impl_required_record_codec!(
    PackageBody,
    1 => workspace,
    2 => root_namespace,
    3 => dependencies,
    4 => exports,
);

impl_required_record_codec!(
    FunctionBody,
    1 => type_parameters,
    2 => parameters,
    3 => result_type,
    4 => effects,
    5 => entry_block,
    6 => blocks,
    7 => contracts,
    8 => visibility,
);

impl_required_record_codec!(
    ParameterBody,
    1 => owner,
    2 => role,
    3 => ordinal,
    4 => value_type,
);

impl_required_record_codec!(
    GlobalValueBody,
    1 => value_type,
    2 => initializer,
    3 => visibility,
);

impl_required_record_codec!(
    EffectDefBody,
    1 => effect_kind,
    2 => scope_type,
    3 => request_type,
    4 => response_type,
    5 => failure_type,
    6 => visibility,
);

impl_required_record_codec!(
    AdapterImportBody,
    1 => adapter_id,
    2 => abi_version,
    3 => request_type,
    4 => response_type,
    5 => failure_type,
    6 => effects,
);

impl_required_record_codec!(EntryPointBody, 1 => function, 2 => exposure,);

impl_required_record_codec!(
    PolicyBindingBody,
    1 => subject,
    2 => requirements,
);

impl_required_record_codec!(
    DependencyBindingBody,
    1 => dependency_root,
    2 => external_package,
    3 => local_namespace,
);

impl MutationValueCodec for OperationBody {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.block, depth + 1)?),
            (2, encode_at_depth(&self.ordinal, depth + 1)?),
            (3, encode_at_depth(&self.opcode, depth + 1)?),
            (4, encode_at_depth(&self.operands, depth + 1)?),
            (5, encode_at_depth(&self.result_types, depth + 1)?),
            (6, encode_at_depth(&self.immediate, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut block = None;
        let mut ordinal = None;
        let mut opcode = None;
        let mut operands = None;
        let mut result_types = None;
        let mut immediate = None;
        decode_record_fields(cursor, &[1, 2, 3, 4, 5, 6], |tag, payload| {
            match tag {
                1 => block = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => ordinal = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => opcode = Some(decode_nested_exact(payload, depth + 1, budget)?),
                4 => operands = Some(decode_nested_exact(payload, depth + 1, budget)?),
                5 => result_types = Some(decode_nested_exact(payload, depth + 1, budget)?),
                6 => immediate = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            block: block.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            ordinal: ordinal.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            opcode: opcode.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            operands: operands.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            result_types: result_types.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            immediate: immediate.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn member(byte: u8) -> MemberId {
        MemberId::from_bytes([byte; 32])
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

        assert_eq!(
            encode_exact(&Option::<bool>::None).unwrap(),
            encode_union(0, &[]).unwrap()
        );
        assert_eq!(
            encode_exact(&Some(true)).unwrap(),
            encode_union(1, &encode_bool(true)).unwrap()
        );

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

    #[test]
    fn cfg_member_id_and_reference_records_round_trip_exactly() {
        assert_round_trip(&member(9));
        assert_eq!(encode_exact(&member(9)).unwrap(), vec![9_u8; 32]);

        assert_round_trip(&OperationResultRef {
            operation: id(1),
            result_index: 7,
        });
        assert_round_trip(&ValueRef::Parameter(id(2)));
        assert_round_trip(&ValueRef::OperationResult(OperationResultRef {
            operation: id(3),
            result_index: u32::MAX,
        }));
        assert_round_trip(&FunctionRefValue {
            function: id(4),
            type_arguments: vec![TypeExpr::Option(Box::new(TypeExpr::FunctionRef(
                FunctionType {
                    parameters: vec![TypeExpr::Bool],
                    result: Box::new(TypeExpr::Unit),
                    effects: vec![],
                },
            )))],
        });
    }

    #[test]
    fn cfg_immediate_all_seven_tags_round_trip_exactly() {
        let values = [
            Immediate::None,
            Immediate::Entity(id(1)),
            Immediate::Index(2),
            Immediate::Field(member(3)),
            Immediate::Variant(VariantImmediate {
                definition: id(4),
                member_id: member(5),
            }),
            Immediate::Observation([6; 32]),
            Immediate::Function(FunctionRefValue {
                function: id(7),
                type_arguments: vec![TypeExpr::Text],
            }),
        ];
        for (index, value) in values.iter().enumerate() {
            assert_eq!(value.tag(), u32::try_from(index + 1).unwrap());
            assert_round_trip(value);
        }
    }

    #[test]
    fn cfg_cases_edges_traps_and_non_option_terminators_round_trip() {
        for value in [
            BuiltinCase::None,
            BuiltinCase::Some,
            BuiltinCase::Ok,
            BuiltinCase::Err,
        ] {
            assert_round_trip(&value);
        }
        for value in [
            TrapCode::Unreachable,
            TrapCode::ResourceExhausted,
            TrapCode::AdapterContractViolation,
            TrapCode::InternalInvariant,
        ] {
            assert_round_trip(&value);
        }

        let result_ref = ValueRef::OperationResult(OperationResultRef {
            operation: id(9),
            result_index: 1,
        });
        let target_edge = TargetEdge {
            target: id(10),
            arguments: vec![ValueRef::Parameter(id(11)), result_ref],
        };
        let switch_edge = SwitchEdge {
            target: id(12),
            arguments: vec![
                SwitchArgument::CasePayload,
                SwitchArgument::Value(result_ref),
            ],
        };
        let switch_case = SwitchCase {
            case_key: CaseKey::Builtin(BuiltinCase::Some),
            edge: switch_edge.clone(),
        };

        assert_round_trip(&target_edge);
        assert_round_trip(&CaseKey::Member(member(13)));
        assert_round_trip(&CaseKey::Builtin(BuiltinCase::Ok));
        assert_round_trip(&SwitchArgument::Value(ValueRef::Parameter(id(14))));
        assert_round_trip(&SwitchArgument::CasePayload);
        assert_round_trip(&switch_edge);
        assert_round_trip(&switch_case);

        assert_round_trip(&ReturnTerminator {
            value: ValueRef::Parameter(id(15)),
        });
        assert_round_trip(&BranchTerminator {
            edge: target_edge.clone(),
        });
        assert_round_trip(&CondBranchTerminator {
            condition: ValueRef::Parameter(id(16)),
            if_true: target_edge,
            if_false: TargetEdge {
                target: id(17),
                arguments: vec![],
            },
        });
        assert_round_trip(&VariantSwitchTerminator {
            value: result_ref,
            cases: vec![switch_case],
        });
    }

    #[test]
    fn cfg_unions_reject_unknown_nonempty_payload_free_and_inner_trailing() {
        assert_eq!(
            decode_exact::<Immediate>(&encode_union(99, &[]).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
        assert_eq!(
            decode_exact::<Immediate>(&encode_union(1, &[0]).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
        assert_eq!(
            decode_exact::<SwitchArgument>(&encode_union(2, &[0]).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
        assert_eq!(
            decode_exact::<BuiltinCase>(&encode_u32(5))
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
        assert_eq!(
            decode_exact::<TrapCode>(&encode_u32(5)).unwrap_err().code(),
            ScbErrorCode::UnionInvalid
        );

        let mut trailing_target = encode_exact(&id(1)).unwrap();
        trailing_target.push(0);
        let malformed_edge = encode_record(&[
            (1, trailing_target),
            (2, encode_exact(&Vec::<ValueRef>::new()).unwrap()),
        ])
        .unwrap();
        assert_eq!(
            decode_exact::<TargetEdge>(&malformed_edge)
                .unwrap_err()
                .code(),
            ScbErrorCode::TrailingBytes
        );

        let malformed_value_ref = encode_union(1, &[1; 31]).unwrap();
        assert_eq!(
            decode_exact::<ValueRef>(&malformed_value_ref)
                .unwrap_err()
                .code(),
            ScbErrorCode::LengthOverflow
        );
    }

    #[test]
    fn cfg_records_fail_closed_for_missing_unknown_duplicate_order_and_inner_trailing() {
        assert_eq!(
            decode_exact::<OperationResultRef>(
                &encode_record(&[(1, encode_exact(&id(1)).unwrap())]).unwrap()
            )
            .unwrap_err()
            .code(),
            ScbErrorCode::FieldMissing
        );

        assert_eq!(
            decode_exact::<OperationResultRef>(
                &encode_record(&[
                    (1, encode_exact(&id(1)).unwrap()),
                    (2, encode_exact(&0_u32).unwrap()),
                    (3, encode_exact(&1_u32).unwrap()),
                ])
                .unwrap()
            )
            .unwrap_err()
            .code(),
            ScbErrorCode::FieldUnknown
        );

        assert_eq!(
            decode_exact::<OperationResultRef>(&raw_record(&[
                (1, encode_exact(&id(1)).unwrap()),
                (1, encode_exact(&id(2)).unwrap()),
            ]))
            .unwrap_err()
            .code(),
            ScbErrorCode::FieldDuplicate
        );

        assert_eq!(
            decode_exact::<OperationResultRef>(&raw_record(&[
                (2, encode_exact(&0_u32).unwrap()),
                (1, encode_exact(&id(1)).unwrap()),
            ]))
            .unwrap_err()
            .code(),
            ScbErrorCode::FieldOrder
        );

        let mut trailing_index = encode_exact(&0_u32).unwrap();
        trailing_index.push(0);
        assert_eq!(
            decode_exact::<OperationResultRef>(
                &encode_record(&[(1, encode_exact(&id(1)).unwrap()), (2, trailing_index)]).unwrap()
            )
            .unwrap_err()
            .code(),
            ScbErrorCode::TrailingBytes
        );
    }

    #[test]
    fn cfg_variant_switch_preserves_noncanonical_duplicate_case_list_order() {
        let case_a = SwitchCase {
            case_key: CaseKey::Builtin(BuiltinCase::Err),
            edge: SwitchEdge {
                target: id(21),
                arguments: vec![SwitchArgument::CasePayload],
            },
        };
        let case_b = SwitchCase {
            case_key: CaseKey::Builtin(BuiltinCase::Ok),
            edge: SwitchEdge {
                target: id(22),
                arguments: vec![SwitchArgument::Value(ValueRef::Parameter(id(23)))],
            },
        };
        let value = VariantSwitchTerminator {
            value: ValueRef::Parameter(id(24)),
            cases: vec![case_a.clone(), case_b, case_a],
        };
        let encoded = encode_exact(&value).unwrap();
        assert_eq!(
            decode_exact::<VariantSwitchTerminator>(&encoded).unwrap(),
            value
        );
    }

    #[test]
    fn independent_manifest_helpers_round_trip_exact_records_and_unions() {
        assert_round_trip(&TypeParameterDef { ordinal: u32::MAX });
        assert_round_trip(&RecordField {
            member_id: member(31),
            value_type: TypeExpr::Named(NamedType {
                definition: id(32),
                arguments: vec![TypeExpr::UInt(IntegerWidth::from_bits(128))],
            }),
            visibility: Visibility::Exported,
        });
        assert_round_trip(&BuiltinFailureValue {
            kind: BuiltinFailureKind::Capability,
            code: u16::MAX,
        });

        let sources = [
            ContractSource::Parameter(id(33)),
            ContractSource::Result,
            ContractSource::Error,
            ContractSource::Global(id(34)),
        ];
        for (index, source) in sources.iter().enumerate() {
            assert_eq!(source.tag(), u32::try_from(index + 1).unwrap());
            assert_round_trip(source);
        }
        assert_round_trip(&ContractBinding {
            predicate_parameter: u32::MAX,
            source: ContractSource::Global(id(35)),
        });
        assert_round_trip(&ResourceLimits {
            fuel: 0,
            memory_bytes: 1,
            output_bytes: 127,
            effect_count: 128,
            call_depth: u64::MAX - 1,
            wall_timeout_millis: u64::MAX,
        });
    }

    #[test]
    fn independent_manifest_helpers_reject_payload_and_record_failures() {
        for tag in [2, 3] {
            assert_eq!(
                decode_exact::<ContractSource>(&encode_union(tag, &[0]).unwrap())
                    .unwrap_err()
                    .code(),
                ScbErrorCode::UnionInvalid
            );
        }
        assert_eq!(
            decode_exact::<ContractSource>(&encode_union(5, &[]).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
        assert_eq!(
            decode_exact::<ResourceLimits>(
                &encode_record(&[
                    (1, encode_exact(&0_u64).unwrap()),
                    (2, encode_exact(&0_u64).unwrap()),
                    (3, encode_exact(&0_u64).unwrap()),
                    (4, encode_exact(&0_u64).unwrap()),
                    (5, encode_exact(&0_u64).unwrap()),
                ])
                .unwrap()
            )
            .unwrap_err()
            .code(),
            ScbErrorCode::FieldMissing
        );

        let mut trailing_kind = encode_exact(&BuiltinFailureKind::Arithmetic).unwrap();
        trailing_kind.push(0);
        assert_eq!(
            decode_exact::<BuiltinFailureValue>(
                &encode_record(&[(1, trailing_kind), (2, encode_exact(&0_u16).unwrap())]).unwrap()
            )
            .unwrap_err()
            .code(),
            ScbErrorCode::TrailingBytes
        );
    }

    fn operation_body_fixture() -> OperationBody {
        OperationBody {
            block: id(40),
            ordinal: u32::MAX,
            opcode: 55,
            operands: vec![
                ValueRef::Parameter(id(41)),
                ValueRef::OperationResult(OperationResultRef {
                    operation: id(42),
                    result_index: 3,
                }),
            ],
            result_types: vec![
                TypeExpr::Bool,
                TypeExpr::Named(NamedType {
                    definition: id(43),
                    arguments: vec![TypeExpr::UInt(IntegerWidth::from_bits(64))],
                }),
            ],
            immediate: Immediate::Function(FunctionRefValue {
                function: id(44),
                type_arguments: vec![TypeExpr::Text],
            }),
        }
    }

    fn operation_body_fields(value: &OperationBody) -> Vec<(u32, Vec<u8>)> {
        vec![
            (1, encode_exact(&value.block).unwrap()),
            (2, encode_exact(&value.ordinal).unwrap()),
            (3, encode_exact(&value.opcode).unwrap()),
            (4, encode_exact(&value.operands).unwrap()),
            (5, encode_exact(&value.result_types).unwrap()),
            (6, encode_exact(&value.immediate).unwrap()),
        ]
    }

    #[test]
    fn operation_body_round_trips_the_exact_six_field_record() {
        let value = operation_body_fixture();
        let expected = encode_record(&operation_body_fields(&value)).unwrap();
        assert_eq!(encode_exact(&value).unwrap(), expected);
        assert_eq!(decode_exact::<OperationBody>(&expected).unwrap(), value);
    }

    #[test]
    fn operation_body_rejects_record_shape_and_nested_trailing_failures() {
        let value = operation_body_fixture();

        let mut missing = operation_body_fields(&value);
        missing.pop();
        assert_eq!(
            decode_exact::<OperationBody>(&encode_record(&missing).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::FieldMissing
        );

        let mut unknown = operation_body_fields(&value);
        unknown.push((7, encode_exact(&0_u32).unwrap()));
        assert_eq!(
            decode_exact::<OperationBody>(&encode_record(&unknown).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::FieldUnknown
        );

        let mut unordered = operation_body_fields(&value);
        unordered.swap(2, 3);
        assert_eq!(
            decode_exact::<OperationBody>(&raw_record(&unordered))
                .unwrap_err()
                .code(),
            ScbErrorCode::FieldOrder
        );

        for field_index in [3, 4, 5] {
            let mut trailing = operation_body_fields(&value);
            trailing[field_index].1.push(0);
            assert_eq!(
                decode_exact::<OperationBody>(&encode_record(&trailing).unwrap())
                    .unwrap_err()
                    .code(),
                ScbErrorCode::TrailingBytes
            );
        }
    }

    fn entity_set(bytes: &[u8]) -> EntityIdSet {
        EntityIdSet::from_unsorted(bytes.iter().copied().map(id).collect()).unwrap()
    }

    fn assert_exact_manifest_record<T>(value: &T, fields: &[(u32, Vec<u8>)])
    where
        T: MutationValueCodec + Eq + core::fmt::Debug,
    {
        let expected = encode_record(fields).unwrap();
        assert_eq!(encode_exact(value).unwrap(), expected);
        assert_eq!(&decode_exact::<T>(&expected).unwrap(), value);
    }

    #[test]
    fn workspace_and_package_bodies_use_exact_manifest_fields() {
        let workspace = WorkspaceBody {
            packages: entity_set(&[1]),
            root_namespace: id(2),
            capability_requirements: entity_set(&[3]),
            contracts: entity_set(&[4]),
            tests: entity_set(&[5]),
        };
        assert_exact_manifest_record(
            &workspace,
            &[
                (1, encode_exact(&workspace.packages).unwrap()),
                (2, encode_exact(&workspace.root_namespace).unwrap()),
                (3, encode_exact(&workspace.capability_requirements).unwrap()),
                (4, encode_exact(&workspace.contracts).unwrap()),
                (5, encode_exact(&workspace.tests).unwrap()),
            ],
        );

        let package = PackageBody {
            workspace: id(6),
            root_namespace: id(7),
            dependencies: entity_set(&[8]),
            exports: entity_set(&[9]),
        };
        assert_exact_manifest_record(
            &package,
            &[
                (1, encode_exact(&package.workspace).unwrap()),
                (2, encode_exact(&package.root_namespace).unwrap()),
                (3, encode_exact(&package.dependencies).unwrap()),
                (4, encode_exact(&package.exports).unwrap()),
            ],
        );
    }

    #[test]
    fn function_parameter_and_global_bodies_use_exact_manifest_fields() {
        let function = FunctionBody {
            type_parameters: vec![TypeParameterDef { ordinal: 1 }],
            parameters: vec![id(10), id(11)],
            result_type: TypeExpr::Bool,
            effects: entity_set(&[12]),
            entry_block: id(13),
            blocks: vec![id(15), id(14)],
            contracts: entity_set(&[16]),
            visibility: Visibility::Workspace,
        };
        assert_exact_manifest_record(
            &function,
            &[
                (1, encode_exact(&function.type_parameters).unwrap()),
                (2, encode_exact(&function.parameters).unwrap()),
                (3, encode_exact(&function.result_type).unwrap()),
                (4, encode_exact(&function.effects).unwrap()),
                (5, encode_exact(&function.entry_block).unwrap()),
                (6, encode_exact(&function.blocks).unwrap()),
                (7, encode_exact(&function.contracts).unwrap()),
                (8, encode_exact(&function.visibility).unwrap()),
            ],
        );

        let parameter = ParameterBody {
            owner: id(17),
            role: ParameterRole::Block,
            ordinal: u32::MAX,
            value_type: TypeExpr::TypeParameter(2),
        };
        assert_exact_manifest_record(
            &parameter,
            &[
                (1, encode_exact(&parameter.owner).unwrap()),
                (2, encode_exact(&parameter.role).unwrap()),
                (3, encode_exact(&parameter.ordinal).unwrap()),
                (4, encode_exact(&parameter.value_type).unwrap()),
            ],
        );

        let global = GlobalValueBody {
            value_type: TypeExpr::Text,
            initializer: id(18),
            visibility: Visibility::Exported,
        };
        assert_exact_manifest_record(
            &global,
            &[
                (1, encode_exact(&global.value_type).unwrap()),
                (2, encode_exact(&global.initializer).unwrap()),
                (3, encode_exact(&global.visibility).unwrap()),
            ],
        );
    }

    #[test]
    fn effect_and_adapter_bodies_use_exact_manifest_fields() {
        let effect = EffectDefBody {
            effect_kind: EffectKind::AdapterCall,
            scope_type: TypeExpr::Bytes,
            request_type: TypeExpr::Text,
            response_type: TypeExpr::Bool,
            failure_type: TypeExpr::BuiltinFailure(BuiltinFailureKind::Capability),
            visibility: Visibility::Package,
        };
        assert_exact_manifest_record(
            &effect,
            &[
                (1, encode_exact(&effect.effect_kind).unwrap()),
                (2, encode_exact(&effect.scope_type).unwrap()),
                (3, encode_exact(&effect.request_type).unwrap()),
                (4, encode_exact(&effect.response_type).unwrap()),
                (5, encode_exact(&effect.failure_type).unwrap()),
                (6, encode_exact(&effect.visibility).unwrap()),
            ],
        );

        let adapter = AdapterImportBody {
            adapter_id: [19; 32],
            abi_version: u32::MAX,
            request_type: TypeExpr::Bytes,
            response_type: TypeExpr::Text,
            failure_type: TypeExpr::BuiltinFailure(BuiltinFailureKind::ContractViolation),
            effects: entity_set(&[20, 21]),
        };
        assert_exact_manifest_record(
            &adapter,
            &[
                (1, encode_exact(&adapter.adapter_id).unwrap()),
                (2, encode_exact(&adapter.abi_version).unwrap()),
                (3, encode_exact(&adapter.request_type).unwrap()),
                (4, encode_exact(&adapter.response_type).unwrap()),
                (5, encode_exact(&adapter.failure_type).unwrap()),
                (6, encode_exact(&adapter.effects).unwrap()),
            ],
        );
    }

    #[test]
    fn entry_policy_and_dependency_bodies_use_exact_manifest_fields() {
        let entry_point = EntryPointBody {
            function: id(22),
            exposure: EntryExposure::Protocol,
        };
        assert_exact_manifest_record(
            &entry_point,
            &[
                (1, encode_exact(&entry_point.function).unwrap()),
                (2, encode_exact(&entry_point.exposure).unwrap()),
            ],
        );

        let policy = PolicyBindingBody {
            subject: id(23),
            requirements: entity_set(&[24, 25]),
        };
        assert_exact_manifest_record(
            &policy,
            &[
                (1, encode_exact(&policy.subject).unwrap()),
                (2, encode_exact(&policy.requirements).unwrap()),
            ],
        );

        let dependency = DependencyBindingBody {
            dependency_root: StateRoot::from_bytes([26; 32]),
            external_package: id(27),
            local_namespace: id(28),
        };
        assert_exact_manifest_record(
            &dependency,
            &[
                (1, encode_exact(&dependency.dependency_root).unwrap()),
                (2, encode_exact(&dependency.external_package).unwrap()),
                (3, encode_exact(&dependency.local_namespace).unwrap()),
            ],
        );
    }

    #[test]
    fn dependency_closed_body_records_reject_nested_trailing_bytes() {
        let function = FunctionBody {
            type_parameters: vec![TypeParameterDef { ordinal: 0 }],
            parameters: vec![id(1)],
            result_type: TypeExpr::Bool,
            effects: entity_set(&[2]),
            entry_block: id(3),
            blocks: vec![id(4)],
            contracts: entity_set(&[5]),
            visibility: Visibility::Private,
        };
        let fields = [
            (1, encode_exact(&function.type_parameters).unwrap()),
            (2, encode_exact(&function.parameters).unwrap()),
            (3, encode_exact(&function.result_type).unwrap()),
            (4, encode_exact(&function.effects).unwrap()),
            (5, encode_exact(&function.entry_block).unwrap()),
            (6, encode_exact(&function.blocks).unwrap()),
            (7, encode_exact(&function.contracts).unwrap()),
            (8, encode_exact(&function.visibility).unwrap()),
        ];
        for field_index in 0..fields.len() {
            let mut trailing = fields.clone();
            trailing[field_index].1.push(0);
            assert_eq!(
                decode_exact::<FunctionBody>(&encode_record(&trailing).unwrap())
                    .unwrap_err()
                    .code(),
                ScbErrorCode::TrailingBytes
            );
        }
    }
}
