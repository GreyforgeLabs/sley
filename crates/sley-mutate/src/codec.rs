//! Crate-private staged foundation for `MUTATION_VALUE_CODEC_V1`.
//!
//! These helpers intentionally stay private until the candidate/precondition
//! layers own descriptor-selected admission and exact mutation-body wiring.

#![allow(dead_code)]

use sley_id::{
    CandidateId, CandidateNonce, CapabilitySummaryDigest, EntityId, ObjectId, PolicyRootId,
    PrincipalId, SchemaEpochId, StateRoot, TransactionId, ValidationProfileId, WorkspaceId,
};
use sley_scb1::{
    MAX_NESTING_DEPTH, MAX_STANDALONE_BYTES, MAX_TOTAL_ALLOCATION, ScbError, ScbErrorCode,
    ScbValueCursor, encode_bool, encode_bytes, encode_f32_bits, encode_f64_bits, encode_list,
    encode_record, encode_sint64, encode_sint128, encode_text, encode_union, encode_uvar,
    encode_uvar128,
};
use sley_ssmc::{
    AdapterConfig, BranchTerminator, BuiltinCase, BuiltinFailureKind, BuiltinFailureValue, CaseKey,
    CondBranchTerminator, ConstData, ConstValue, ContractBinding, ContractKind, ContractSource,
    EffectEnvironment, EffectKind, ExpectedObservation, ExpectedOutcome, FieldConst,
    FunctionRefValue, FunctionType, Immediate, IntegerWidth, MapEntryConst, MemberId, NamedType,
    OperationResultRef, ParameterRole, Reachability, RecordConst, RecordField, ReplayBinding,
    ResourceLimits, ResultConst, ReturnTerminator, SwitchArgument, SwitchCase, SwitchEdge,
    TargetEdge, Terminator, TrapCode, TrapTerminator, TypeDefForm, TypeExpr, TypeParameterDef,
    ValueRef, VariantCase, VariantConst, VariantImmediate, VariantSwitchTerminator, Visibility,
};

use crate::candidate::{
    BoundPrecondition, CANDIDATE_ENVELOPE_VERSION, CANDIDATE_MAGIC, CandidateError,
    CandidateExpiry, CandidateRecord, ExactContainerVersion, ExactEntityVersion,
    ExpectedIdentityAbsent, ImportedCandidate, MutationOperation, MutationPayload, OrderedInsert,
    OrderedMove, OrderedRemove, PreconditionPayload, ReferenceTarget, ValidationProfileRecord,
    descriptor_field_tag, scb_invalid,
};
use crate::value::{
    AdapterImportBody, BlockBody, CapabilityRequirementBody, ConstantBody, ContractBody,
    DependencyBindingBody, EffectDefBody, EntityBodyValue, EntityIdSet, EntryExposure,
    EntryPointBody, FieldValue, FunctionBody, GlobalValueBody, NamespaceBody, OperationBody,
    PackageBody, ParameterBody, PolicyBindingBody, TestCaseBody, TypeDefBody, WorkspaceBody,
};
use crate::{MutationClass, PreimageRequirement, mutation_operation_descriptor};

type Result<T> = core::result::Result<T, ScbError>;

pub(crate) trait MutationValueCodec: Sized {
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

pub(crate) fn encode_exact<T: MutationValueCodec>(value: &T) -> Result<Vec<u8>> {
    encode_at_depth(value, 0)
}

pub(crate) fn decode_exact<T: MutationValueCodec>(input: &[u8]) -> Result<T> {
    let mut cursor = ScbValueCursor::new(input)?;
    let mut budget = DecodeBudget::default();
    let value = decode_at_depth(&mut cursor, 0, &mut budget)?;
    cursor.check_finished()?;
    Ok(value)
}

pub(crate) fn encode_at_depth<T: MutationValueCodec>(value: &T, depth: usize) -> Result<Vec<u8>> {
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
pub(crate) struct DecodeBudget {
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

impl MutationValueCodec for i128 {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_sint128(*self))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        cursor.read_sint128()
    }
}

impl MutationValueCodec for u128 {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_uvar128(*self))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        cursor.read_uvar128(128)
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

macro_rules! impl_fixed_id_codec {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl MutationValueCodec for $ty {
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
        )+
    };
}

impl_fixed_id_codec!(
    CandidateId,
    CandidateNonce,
    CapabilitySummaryDigest,
    ObjectId,
    PolicyRootId,
    PrincipalId,
    SchemaEpochId,
    TransactionId,
    ValidationProfileId,
    WorkspaceId,
);

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

impl MutationValueCodec for TrapTerminator {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.code, depth + 1)?),
            (2, encode_at_depth(&self.payload, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut code = None;
        let mut payload = None;
        decode_record_fields(cursor, &[1, 2], |tag, field_payload| {
            match tag {
                1 => code = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                2 => payload = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            code: code.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            payload: payload.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for Terminator {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Return(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Branch(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::CondBranch(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::VariantSwitch(value) => {
                encode_union(self.tag(), &encode_at_depth(value, depth + 1)?)
            }
            Self::Trap(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
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
            1 => Ok(Self::Return(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::Branch(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            3 => Ok(Self::CondBranch(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            4 => Ok(Self::VariantSwitch(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            5 => Ok(Self::Trap(decode_nested_exact(payload, depth + 1, budget)?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
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

impl MutationValueCodec for VariantCase {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.member_id, depth + 1)?),
            (2, encode_at_depth(&self.payload_type, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut member_id = None;
        let mut payload_type = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => member_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => payload_type = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            member_id: member_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            payload_type: payload_type.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for TypeDefForm {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Record(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Variant(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
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
            1 => Ok(Self::Record(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::Variant(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
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

impl MutationValueCodec for FieldConst {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.member_id, depth + 1)?),
            (2, encode_at_depth(&self.value, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut member_id = None;
        let mut value = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => member_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => value = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            member_id: member_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            value: value.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for RecordConst {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.definition, depth + 1)?),
            (2, encode_at_depth(&self.fields, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut definition = None;
        let mut fields = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => definition = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => fields = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            definition: definition.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            fields: fields.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for VariantConst {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.definition, depth + 1)?),
            (2, encode_at_depth(&self.member_id, depth + 1)?),
            (3, encode_at_depth(&self.payload, depth + 1)?),
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
        let mut payload = None;
        decode_record_fields(cursor, &[1, 2, 3], |tag, field_payload| {
            match tag {
                1 => definition = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                2 => member_id = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                3 => payload = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            definition: definition.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            member_id: member_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            payload: payload.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for MapEntryConst {
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

impl MutationValueCodec for ResultConst {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Ok(value) | Self::Err(value) => {
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
            1 => Ok(Self::Ok(decode_nested_exact(payload, depth + 1, budget)?)),
            2 => Ok(Self::Err(decode_nested_exact(payload, depth + 1, budget)?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

fn encode_map_entries(values: &[MapEntryConst], depth: usize) -> Result<Vec<u8>> {
    check_container_depth(depth)?;
    let mut previous_key: Option<Vec<u8>> = None;
    let mut elements = Vec::with_capacity(values.len());
    for value in values {
        let key = encode_at_depth(&value.key, depth + 2)?;
        if let Some(previous) = &previous_key {
            match previous.cmp(&key) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => {
                    return Err(ScbError::new(ScbErrorCode::MapDuplicate));
                }
                core::cmp::Ordering::Greater => {
                    return Err(ScbError::new(ScbErrorCode::MapOrder));
                }
            }
        }
        previous_key = Some(key);
        elements.push(encode_at_depth(value, depth + 1)?);
    }
    encode_list(&elements)
}

fn decode_map_entries(
    cursor: &mut ScbValueCursor<'_>,
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<Vec<MapEntryConst>> {
    check_container_depth(depth)?;
    let count = cursor.read_list_count()?;
    let capacity =
        usize::try_from(count).map_err(|_| ScbError::new(ScbErrorCode::ResourceLimit))?;
    budget.charge(
        capacity
            .checked_mul(core::mem::size_of::<MapEntryConst>())
            .ok_or_else(|| ScbError::new(ScbErrorCode::ResourceLimit))?,
    )?;
    let mut values = Vec::with_capacity(capacity);
    let mut previous_key: Option<Vec<u8>> = None;
    for _ in 0..count {
        let value =
            decode_nested_exact::<MapEntryConst>(cursor.read_sized_payload()?, depth + 1, budget)?;
        let key = encode_at_depth(&value.key, depth + 2)?;
        if let Some(previous) = &previous_key {
            match previous.cmp(&key) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => {
                    return Err(ScbError::new(ScbErrorCode::MapDuplicate));
                }
                core::cmp::Ordering::Greater => {
                    return Err(ScbError::new(ScbErrorCode::MapOrder));
                }
            }
        }
        previous_key = Some(key);
        values.push(value);
    }
    Ok(values)
}

impl MutationValueCodec for ConstData {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Unit => encode_union(self.tag(), &[]),
            Self::Bool(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::SInt(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::UInt(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::F32Bits(value) => encode_union(self.tag(), &encode_f32_value_bits(*value)?),
            Self::F64Bits(value) => encode_union(self.tag(), &encode_f64_value_bits(*value)?),
            Self::Bytes(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Text(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Sequence(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Record(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Variant(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Map(value) => encode_union(self.tag(), &encode_map_entries(value, depth + 1)?),
            Self::Option(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::Result(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::FunctionRef(value) => {
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
            2 => Ok(Self::Bool(decode_nested_exact(payload, depth + 1, budget)?)),
            3 => Ok(Self::SInt(decode_nested_exact(payload, depth + 1, budget)?)),
            4 => Ok(Self::UInt(decode_nested_exact(payload, depth + 1, budget)?)),
            5 => {
                let mut nested = ScbValueCursor::new(payload)?;
                let value = decode_f32_value_bits(&mut nested)?;
                nested.check_finished()?;
                Ok(Self::F32Bits(value))
            }
            6 => {
                let mut nested = ScbValueCursor::new(payload)?;
                let value = decode_f64_value_bits(&mut nested)?;
                nested.check_finished()?;
                Ok(Self::F64Bits(value))
            }
            7 => Ok(Self::Bytes(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            8 => Ok(Self::Text(decode_nested_exact(payload, depth + 1, budget)?)),
            9 => Ok(Self::Sequence(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            10 => Ok(Self::Record(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            11 => Ok(Self::Variant(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            12 => {
                let mut nested = ScbValueCursor::new(payload)?;
                let value = decode_map_entries(&mut nested, depth + 1, budget)?;
                nested.check_finished()?;
                Ok(Self::Map(value))
            }
            13 => Ok(Self::Option(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            14 => Ok(Self::Result(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            15 => Ok(Self::FunctionRef(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            16 => Ok(Self::BuiltinFailure(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for ConstValue {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.value_type, depth + 1)?),
            (2, encode_at_depth(&self.data, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut value_type = None;
        let mut data = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => value_type = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => data = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            value_type: value_type.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            data: data.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
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

impl MutationValueCodec for ReplayBinding {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.adapter_import, depth + 1)?),
            (2, encode_at_depth(&self.request, depth + 1)?),
            (3, encode_at_depth(&self.response, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut adapter_import = None;
        let mut request = None;
        let mut response = None;
        decode_record_fields(cursor, &[1, 2, 3], |tag, payload| {
            match tag {
                1 => adapter_import = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => request = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => response = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            adapter_import: adapter_import
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            request: request.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            response: response.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for AdapterConfig {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.adapter_import, depth + 1)?),
            (2, encode_at_depth(&self.configuration, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut adapter_import = None;
        let mut configuration = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => adapter_import = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => configuration = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            adapter_import: adapter_import
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            configuration: configuration
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for EffectEnvironment {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Replay(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::DeterministicAdapters(value) => {
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
            1 => Ok(Self::Replay(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::DeterministicAdapters(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for ExpectedOutcome {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::Value(value) => encode_union(self.tag(), &encode_at_depth(value, depth + 1)?),
            Self::FailureCode(value) => {
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
            1 => Ok(Self::Value(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::FailureCode(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for ExpectedObservation {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.observation_id, depth + 1)?),
            (2, encode_at_depth(&self.value, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut observation_id = None;
        let mut value = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => observation_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => value = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            observation_id: observation_id
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            value: value.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl_required_record_codec!(NamespaceBody, 1 => parent, 2 => members,);

impl_required_record_codec!(
    TypeDefBody,
    1 => type_parameters,
    2 => form,
    3 => invariants,
    4 => visibility,
);

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
    BlockBody,
    1 => function,
    2 => parameters,
    3 => operations,
    4 => terminator,
    5 => reachability,
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

impl_required_record_codec!(ConstantBody, 1 => value,);

impl_required_record_codec!(
    CapabilityRequirementBody,
    1 => effect,
    2 => allowed_scopes,
    3 => constraint_contracts,
);

impl MutationValueCodec for ContractBody {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        let mut fields = vec![
            (1, encode_at_depth(&self.target, depth + 1)?),
            (2, encode_at_depth(&self.contract_kind, depth + 1)?),
            (3, encode_at_depth(&self.predicate, depth + 1)?),
            (4, encode_at_depth(&self.bindings, depth + 1)?),
        ];
        if let Some(resource_limits) = &self.resource_limits {
            fields.push((5, encode_at_depth(resource_limits, depth + 1)?));
        }
        encode_record(&fields)
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let count = cursor.read_record_field_count()?;
        if !(4..=5).contains(&count) {
            return if count < 4 {
                Err(ScbError::new(ScbErrorCode::FieldMissing))
            } else {
                Err(ScbError::new(ScbErrorCode::FieldUnknown))
            };
        }
        let mut target = None;
        let mut contract_kind = None;
        let mut predicate = None;
        let mut bindings = None;
        let mut resource_limits = None;
        let mut previous = None;
        for _ in 0..count {
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
            let payload = cursor.read_sized_payload()?;
            match tag {
                1 => target = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => contract_kind = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => predicate = Some(decode_nested_exact(payload, depth + 1, budget)?),
                4 => bindings = Some(decode_nested_exact(payload, depth + 1, budget)?),
                5 => resource_limits = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
        }
        Ok(Self {
            target: target.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            contract_kind: contract_kind
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            predicate: predicate.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            bindings: bindings.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            resource_limits,
        })
    }
}

impl_required_record_codec!(
    TestCaseBody,
    1 => target,
    2 => inputs,
    3 => effect_environment,
    4 => expected,
    5 => observations,
    6 => resource_limits,
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

impl MutationValueCodec for EntityBodyValue {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            EntityBodyValue::Workspace(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Package(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Namespace(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::TypeDef(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Function(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Parameter(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Block(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Operation(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Constant(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::GlobalValue(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::EffectDef(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::CapabilityRequirement(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::Contract(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::TestCase(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::AdapterImport(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::EntryPoint(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::PolicyBinding(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
            }
            EntityBodyValue::DependencyBinding(value) => {
                encode_union(self.kind_tag().into(), &encode_at_depth(value, depth + 1)?)
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
            1 => Ok(Self::Workspace(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::Package(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            3 => Ok(Self::Namespace(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            4 => Ok(Self::TypeDef(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            5 => Ok(Self::Function(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            6 => Ok(Self::Parameter(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            7 => Ok(Self::Block(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            8 => Ok(Self::Operation(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            9 => Ok(Self::Constant(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            10 => Ok(Self::GlobalValue(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            11 => Ok(Self::EffectDef(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            12 => Ok(Self::CapabilityRequirement(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            13 => Ok(Self::Contract(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            14 => Ok(Self::TestCase(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            15 => Ok(Self::AdapterImport(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            16 => Ok(Self::EntryPoint(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            17 => Ok(Self::PolicyBinding(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            18 => Ok(Self::DependencyBinding(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

#[allow(clippy::match_same_arms)]
fn encode_selected_field_value(value: &FieldValue, depth: usize) -> Result<Vec<u8>> {
    match value {
        FieldValue::WorkspacePackages(value) => encode_at_depth(value, depth + 1),
        FieldValue::WorkspaceRootNamespace(value) => encode_at_depth(value, depth + 1),
        FieldValue::WorkspaceCapabilityRequirements(value) => encode_at_depth(value, depth + 1),
        FieldValue::WorkspaceContracts(value) => encode_at_depth(value, depth + 1),
        FieldValue::WorkspaceTests(value) => encode_at_depth(value, depth + 1),
        FieldValue::PackageWorkspace(value) => encode_at_depth(value, depth + 1),
        FieldValue::PackageRootNamespace(value) => encode_at_depth(value, depth + 1),
        FieldValue::PackageDependencies(value) => encode_at_depth(value, depth + 1),
        FieldValue::PackageExports(value) => encode_at_depth(value, depth + 1),
        FieldValue::NamespaceParent(value) => encode_at_depth(value, depth + 1),
        FieldValue::NamespaceMembers(value) => encode_at_depth(value, depth + 1),
        FieldValue::TypeDefTypeParameters(value) => encode_at_depth(value, depth + 1),
        FieldValue::TypeDefForm(value) => encode_at_depth(value, depth + 1),
        FieldValue::TypeDefInvariants(value) => encode_at_depth(value, depth + 1),
        FieldValue::TypeDefVisibility(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionTypeParameters(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionParameters(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionResultType(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionEffects(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionEntryBlock(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionBlocks(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionContracts(value) => encode_at_depth(value, depth + 1),
        FieldValue::FunctionVisibility(value) => encode_at_depth(value, depth + 1),
        FieldValue::ParameterOwner(value) => encode_at_depth(value, depth + 1),
        FieldValue::ParameterRole(value) => encode_at_depth(value, depth + 1),
        FieldValue::ParameterOrdinal(value) => encode_at_depth(value, depth + 1),
        FieldValue::ParameterValueType(value) => encode_at_depth(value, depth + 1),
        FieldValue::BlockFunction(value) => encode_at_depth(value, depth + 1),
        FieldValue::BlockParameters(value) => encode_at_depth(value, depth + 1),
        FieldValue::BlockOperations(value) => encode_at_depth(value, depth + 1),
        FieldValue::BlockTerminator(value) => encode_at_depth(value, depth + 1),
        FieldValue::BlockReachability(value) => encode_at_depth(value, depth + 1),
        FieldValue::OperationBlock(value) => encode_at_depth(value, depth + 1),
        FieldValue::OperationOrdinal(value) => encode_at_depth(value, depth + 1),
        FieldValue::OperationOpcode(value) => encode_at_depth(value, depth + 1),
        FieldValue::OperationOperands(value) => encode_at_depth(value, depth + 1),
        FieldValue::OperationResultTypes(value) => encode_at_depth(value, depth + 1),
        FieldValue::OperationImmediate(value) => encode_at_depth(value, depth + 1),
        FieldValue::ConstantValue(value) => encode_at_depth(value, depth + 1),
        FieldValue::GlobalValueValueType(value) => encode_at_depth(value, depth + 1),
        FieldValue::GlobalValueInitializer(value) => encode_at_depth(value, depth + 1),
        FieldValue::GlobalValueVisibility(value) => encode_at_depth(value, depth + 1),
        FieldValue::EffectDefEffectKind(value) => encode_at_depth(value, depth + 1),
        FieldValue::EffectDefScopeType(value) => encode_at_depth(value, depth + 1),
        FieldValue::EffectDefRequestType(value) => encode_at_depth(value, depth + 1),
        FieldValue::EffectDefResponseType(value) => encode_at_depth(value, depth + 1),
        FieldValue::EffectDefFailureType(value) => encode_at_depth(value, depth + 1),
        FieldValue::EffectDefVisibility(value) => encode_at_depth(value, depth + 1),
        FieldValue::CapabilityRequirementEffect(value) => encode_at_depth(value, depth + 1),
        FieldValue::CapabilityRequirementAllowedScopes(value) => encode_at_depth(value, depth + 1),
        FieldValue::CapabilityRequirementConstraintContracts(value) => {
            encode_at_depth(value, depth + 1)
        }
        FieldValue::ContractTarget(value) => encode_at_depth(value, depth + 1),
        FieldValue::ContractContractKind(value) => encode_at_depth(value, depth + 1),
        FieldValue::ContractPredicate(value) => encode_at_depth(value, depth + 1),
        FieldValue::ContractBindings(value) => encode_at_depth(value, depth + 1),
        FieldValue::ContractResourceLimits(value) => encode_at_depth(value, depth + 1),
        FieldValue::TestCaseTarget(value) => encode_at_depth(value, depth + 1),
        FieldValue::TestCaseInputs(value) => encode_at_depth(value, depth + 1),
        FieldValue::TestCaseEffectEnvironment(value) => encode_at_depth(value, depth + 1),
        FieldValue::TestCaseExpected(value) => encode_at_depth(value, depth + 1),
        FieldValue::TestCaseObservations(value) => encode_at_depth(value, depth + 1),
        FieldValue::TestCaseResourceLimits(value) => encode_at_depth(value, depth + 1),
        FieldValue::AdapterImportAdapterId(value) => encode_at_depth(value, depth + 1),
        FieldValue::AdapterImportAbiVersion(value) => encode_at_depth(value, depth + 1),
        FieldValue::AdapterImportRequestType(value) => encode_at_depth(value, depth + 1),
        FieldValue::AdapterImportResponseType(value) => encode_at_depth(value, depth + 1),
        FieldValue::AdapterImportFailureType(value) => encode_at_depth(value, depth + 1),
        FieldValue::AdapterImportEffects(value) => encode_at_depth(value, depth + 1),
        FieldValue::EntryPointFunction(value) => encode_at_depth(value, depth + 1),
        FieldValue::EntryPointExposure(value) => encode_at_depth(value, depth + 1),
        FieldValue::PolicyBindingSubject(value) => encode_at_depth(value, depth + 1),
        FieldValue::PolicyBindingRequirements(value) => encode_at_depth(value, depth + 1),
        FieldValue::DependencyBindingDependencyRoot(value) => encode_at_depth(value, depth + 1),
        FieldValue::DependencyBindingExternalPackage(value) => encode_at_depth(value, depth + 1),
        FieldValue::DependencyBindingLocalNamespace(value) => encode_at_depth(value, depth + 1),
    }
}

#[allow(clippy::too_many_lines)]
fn decode_selected_field_value(
    target_kind: u16,
    field_tag: u16,
    payload: &[u8],
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<FieldValue> {
    match (target_kind, field_tag) {
        (1, 1) => Ok(FieldValue::WorkspacePackages(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (1, 2) => Ok(FieldValue::WorkspaceRootNamespace(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (1, 3) => Ok(FieldValue::WorkspaceCapabilityRequirements(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        (1, 4) => Ok(FieldValue::WorkspaceContracts(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (1, 5) => Ok(FieldValue::WorkspaceTests(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (2, 1) => Ok(FieldValue::PackageWorkspace(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (2, 2) => Ok(FieldValue::PackageRootNamespace(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (2, 3) => Ok(FieldValue::PackageDependencies(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (2, 4) => Ok(FieldValue::PackageExports(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (3, 1) => Ok(FieldValue::NamespaceParent(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (3, 2) => Ok(FieldValue::NamespaceMembers(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (4, 1) => Ok(FieldValue::TypeDefTypeParameters(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (4, 2) => Ok(FieldValue::TypeDefForm(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (4, 3) => Ok(FieldValue::TypeDefInvariants(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (4, 4) => Ok(FieldValue::TypeDefVisibility(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 1) => Ok(FieldValue::FunctionTypeParameters(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 2) => Ok(FieldValue::FunctionParameters(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 3) => Ok(FieldValue::FunctionResultType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 4) => Ok(FieldValue::FunctionEffects(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 5) => Ok(FieldValue::FunctionEntryBlock(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 6) => Ok(FieldValue::FunctionBlocks(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 7) => Ok(FieldValue::FunctionContracts(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (5, 8) => Ok(FieldValue::FunctionVisibility(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (6, 1) => Ok(FieldValue::ParameterOwner(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (6, 2) => Ok(FieldValue::ParameterRole(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (6, 3) => Ok(FieldValue::ParameterOrdinal(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (6, 4) => Ok(FieldValue::ParameterValueType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (7, 1) => Ok(FieldValue::BlockFunction(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (7, 2) => Ok(FieldValue::BlockParameters(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (7, 3) => Ok(FieldValue::BlockOperations(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (7, 4) => Ok(FieldValue::BlockTerminator(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (7, 5) => Ok(FieldValue::BlockReachability(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (8, 1) => Ok(FieldValue::OperationBlock(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (8, 2) => Ok(FieldValue::OperationOrdinal(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (8, 3) => Ok(FieldValue::OperationOpcode(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (8, 4) => Ok(FieldValue::OperationOperands(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (8, 5) => Ok(FieldValue::OperationResultTypes(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (8, 6) => Ok(FieldValue::OperationImmediate(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (9, 1) => Ok(FieldValue::ConstantValue(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (10, 1) => Ok(FieldValue::GlobalValueValueType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (10, 2) => Ok(FieldValue::GlobalValueInitializer(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (10, 3) => Ok(FieldValue::GlobalValueVisibility(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (11, 1) => Ok(FieldValue::EffectDefEffectKind(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (11, 2) => Ok(FieldValue::EffectDefScopeType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (11, 3) => Ok(FieldValue::EffectDefRequestType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (11, 4) => Ok(FieldValue::EffectDefResponseType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (11, 5) => Ok(FieldValue::EffectDefFailureType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (11, 6) => Ok(FieldValue::EffectDefVisibility(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (12, 1) => Ok(FieldValue::CapabilityRequirementEffect(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        (12, 2) => Ok(FieldValue::CapabilityRequirementAllowedScopes(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        (12, 3) => Ok(FieldValue::CapabilityRequirementConstraintContracts(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        (13, 1) => Ok(FieldValue::ContractTarget(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (13, 2) => Ok(FieldValue::ContractContractKind(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (13, 3) => Ok(FieldValue::ContractPredicate(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (13, 4) => Ok(FieldValue::ContractBindings(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (13, 5) => Ok(FieldValue::ContractResourceLimits(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (14, 1) => Ok(FieldValue::TestCaseTarget(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (14, 2) => Ok(FieldValue::TestCaseInputs(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (14, 3) => Ok(FieldValue::TestCaseEffectEnvironment(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (14, 4) => Ok(FieldValue::TestCaseExpected(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (14, 5) => Ok(FieldValue::TestCaseObservations(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (14, 6) => Ok(FieldValue::TestCaseResourceLimits(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (15, 1) => Ok(FieldValue::AdapterImportAdapterId(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (15, 2) => Ok(FieldValue::AdapterImportAbiVersion(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (15, 3) => Ok(FieldValue::AdapterImportRequestType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (15, 4) => Ok(FieldValue::AdapterImportResponseType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (15, 5) => Ok(FieldValue::AdapterImportFailureType(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (15, 6) => Ok(FieldValue::AdapterImportEffects(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (16, 1) => Ok(FieldValue::EntryPointFunction(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (16, 2) => Ok(FieldValue::EntryPointExposure(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (17, 1) => Ok(FieldValue::PolicyBindingSubject(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (17, 2) => Ok(FieldValue::PolicyBindingRequirements(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        (18, 1) => Ok(FieldValue::DependencyBindingDependencyRoot(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        (18, 2) => Ok(FieldValue::DependencyBindingExternalPackage(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        (18, 3) => Ok(FieldValue::DependencyBindingLocalNamespace(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
    }
}

impl MutationValueCodec for MutationClass {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_u32(u32::from(self.tag())))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        let tag = decode_u32(cursor)?;
        let tag = u16::try_from(tag).map_err(|_| ScbError::new(ScbErrorCode::UnionInvalid))?;
        Self::from_tag(tag).ok_or_else(|| ScbError::new(ScbErrorCode::UnionInvalid))
    }
}

impl MutationValueCodec for PreimageRequirement {
    fn encode_value(&self, _depth: usize) -> Result<Vec<u8>> {
        Ok(encode_u32(u32::from(self.tag())))
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        _depth: usize,
        _budget: &mut DecodeBudget,
    ) -> Result<Self> {
        let tag = decode_u32(cursor)?;
        let tag = u16::try_from(tag).map_err(|_| ScbError::new(ScbErrorCode::UnionInvalid))?;
        Self::from_tag(tag).ok_or_else(|| ScbError::new(ScbErrorCode::UnionInvalid))
    }
}

impl MutationValueCodec for CandidateExpiry {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        encode_record(&[
            (1, encode_at_depth(&self.clock, depth + 1)?),
            (2, encode_at_depth(&self.not_after, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut clock = None;
        let mut not_after = None;
        decode_record_fields(cursor, &[1, 2], |tag, payload| {
            match tag {
                1 => clock = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => not_after = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            clock: clock.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            not_after: not_after.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl_required_record_codec!(OrderedInsert, 1 => index, 2 => child,);
impl_required_record_codec!(OrderedRemove, 1 => index, 2 => expected_child,);
impl_required_record_codec!(OrderedMove, 1 => from, 2 => to, 3 => expected_child,);
impl_required_record_codec!(ExpectedIdentityAbsent, 1 => entity_id,);
impl_required_record_codec!(ExactEntityVersion, 1 => entity_id, 2 => object_id,);
impl_required_record_codec!(
    ExactContainerVersion,
    1 => container_id,
    2 => object_id,
    3 => field_tag,
);

impl MutationValueCodec for PreconditionPayload {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        match self {
            Self::ExpectedIdentityAbsent(value) => {
                encode_union(1, &encode_at_depth(value, depth + 1)?)
            }
            Self::ExactEntityVersion(value) => encode_union(2, &encode_at_depth(value, depth + 1)?),
            Self::ExactContainerVersion(value) => {
                encode_union(3, &encode_at_depth(value, depth + 1)?)
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
            1 => Ok(Self::ExpectedIdentityAbsent(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            2 => Ok(Self::ExactEntityVersion(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            3 => Ok(Self::ExactContainerVersion(decode_nested_exact(
                payload,
                depth + 1,
                budget,
            )?)),
            _ => Err(ScbError::new(ScbErrorCode::UnionInvalid)),
        }
    }
}

impl MutationValueCodec for BoundPrecondition {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        if self.payload.requirement() != self.requirement {
            return Err(scb_invalid());
        }
        encode_record(&[
            (1, encode_at_depth(&self.operation_ordinal, depth + 1)?),
            (2, encode_at_depth(&self.requirement, depth + 1)?),
            (3, encode_at_depth(&self.payload, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut operation_ordinal = None;
        let mut requirement = None;
        let mut payload = None;
        decode_record_fields(cursor, &[1, 2, 3], |tag, field_payload| {
            match tag {
                1 => {
                    operation_ordinal =
                        Some(decode_nested_exact(field_payload, depth + 1, budget)?);
                }
                2 => requirement = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                3 => payload = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        let value = Self {
            operation_ordinal: operation_ordinal
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            requirement: requirement.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            payload: payload.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        };
        if value.payload.requirement() != value.requirement {
            return Err(scb_invalid());
        }
        Ok(value)
    }
}

impl MutationValueCodec for ValidationProfileRecord {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        self.validate_full_v1().map_err(|_| scb_invalid())?;
        encode_record(&[
            (1, encode_at_depth(&self.format_version, depth + 1)?),
            (2, encode_at_depth(&self.phase_tags, depth + 1)?),
            (3, encode_at_depth(&self.max_operations, depth + 1)?),
            (4, encode_at_depth(&self.max_preconditions, depth + 1)?),
            (5, encode_at_depth(&self.max_candidate_bytes, depth + 1)?),
            (
                6,
                encode_at_depth(&self.max_decoded_value_bytes, depth + 1)?,
            ),
            (7, encode_at_depth(&self.max_graph_work, depth + 1)?),
            (8, encode_at_depth(&self.max_selected_tests, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut format_version = None;
        let mut phase_tags = None;
        let mut max_operations = None;
        let mut max_preconditions = None;
        let mut max_candidate_bytes = None;
        let mut max_decoded_value_bytes = None;
        let mut max_graph_work = None;
        let mut max_selected_tests = None;
        decode_record_fields(cursor, &[1, 2, 3, 4, 5, 6, 7, 8], |tag, payload| {
            match tag {
                1 => format_version = Some(decode_nested_exact(payload, depth + 1, budget)?),
                2 => phase_tags = Some(decode_nested_exact(payload, depth + 1, budget)?),
                3 => max_operations = Some(decode_nested_exact(payload, depth + 1, budget)?),
                4 => max_preconditions = Some(decode_nested_exact(payload, depth + 1, budget)?),
                5 => max_candidate_bytes = Some(decode_nested_exact(payload, depth + 1, budget)?),
                6 => {
                    max_decoded_value_bytes =
                        Some(decode_nested_exact(payload, depth + 1, budget)?);
                }
                7 => max_graph_work = Some(decode_nested_exact(payload, depth + 1, budget)?),
                8 => max_selected_tests = Some(decode_nested_exact(payload, depth + 1, budget)?),
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        let value = Self {
            format_version: format_version
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            phase_tags: phase_tags.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            max_operations: max_operations
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            max_preconditions: max_preconditions
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            max_candidate_bytes: max_candidate_bytes
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            max_decoded_value_bytes: max_decoded_value_bytes
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            max_graph_work: max_graph_work
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            max_selected_tests: max_selected_tests
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        };
        value.validate_full_v1().map_err(|_| scb_invalid())?;
        Ok(value)
    }
}

impl MutationValueCodec for MutationOperation {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        let payload = encode_mutation_payload(
            self.class,
            self.target_kind,
            self.field_tag,
            &self.payload,
            depth + 1,
        )?;
        encode_record(&[
            (1, encode_at_depth(&self.ordinal, depth + 1)?),
            (2, encode_at_depth(&self.class, depth + 1)?),
            (3, encode_at_depth(&u32::from(self.target_kind), depth + 1)?),
            (4, encode_at_depth(&self.target_entity, depth + 1)?),
            (5, encode_at_depth(&self.field_tag, depth + 1)?),
            (6, payload),
            (7, encode_at_depth(&self.precondition_ordinal, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut ordinal = None;
        let mut class = None;
        let mut target_kind = None;
        let mut target_entity = None;
        let mut field_tag = None;
        let mut payload = None;
        let mut precondition_ordinal = None;
        decode_record_fields(cursor, &[1, 2, 3, 4, 5, 6, 7], |tag, field_payload| {
            match tag {
                1 => ordinal = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                2 => class = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                3 => {
                    let raw: u32 = decode_nested_exact(field_payload, depth + 1, budget)?;
                    target_kind = Some(
                        u16::try_from(raw)
                            .map_err(|_| ScbError::new(ScbErrorCode::UnionInvalid))?,
                    );
                }
                4 => target_entity = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                5 => field_tag = Some(decode_nested_exact(field_payload, depth + 1, budget)?),
                6 => {
                    let class = class.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?;
                    let target_kind =
                        target_kind.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?;
                    let field_tag =
                        field_tag.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?;
                    payload = Some(decode_mutation_payload(
                        class,
                        target_kind,
                        field_tag,
                        field_payload,
                        depth + 1,
                        budget,
                    )?);
                }
                7 => {
                    precondition_ordinal =
                        Some(decode_nested_exact(field_payload, depth + 1, budget)?);
                }
                _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
            }
            Ok(())
        })?;
        Ok(Self {
            ordinal: ordinal.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            class: class.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            target_kind: target_kind.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            target_entity: target_entity
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            field_tag: field_tag.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            payload: payload.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            precondition_ordinal: precondition_ordinal
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

impl MutationValueCodec for CandidateRecord {
    fn encode_value(&self, depth: usize) -> Result<Vec<u8>> {
        check_container_depth(depth)?;
        self.validate().map_err(|_| scb_invalid())?;
        encode_record(&[
            (1, encode_at_depth(&self.format_version, depth + 1)?),
            (2, encode_at_depth(&self.workspace_id, depth + 1)?),
            (3, encode_at_depth(&self.base_transaction_id, depth + 1)?),
            (4, encode_at_depth(&self.base_root, depth + 1)?),
            (5, encode_at_depth(&self.schema_epoch_id, depth + 1)?),
            (6, encode_at_depth(&self.policy_root_id, depth + 1)?),
            (7, encode_at_depth(&self.principal_id, depth + 1)?),
            (
                8,
                encode_at_depth(&self.capability_summary_digest, depth + 1)?,
            ),
            (9, encode_at_depth(&self.operations, depth + 1)?),
            (10, encode_at_depth(&self.preconditions, depth + 1)?),
            (11, encode_at_depth(&self.validation_profile_id, depth + 1)?),
            (12, encode_at_depth(&self.candidate_nonce, depth + 1)?),
            (13, encode_at_depth(&self.expiry, depth + 1)?),
        ])
    }

    fn decode_value(
        cursor: &mut ScbValueCursor<'_>,
        depth: usize,
        budget: &mut DecodeBudget,
    ) -> Result<Self> {
        check_container_depth(depth)?;
        let mut format_version = None;
        let mut workspace_id = None;
        let mut base_transaction_id = None;
        let mut base_root = None;
        let mut schema_epoch_id = None;
        let mut policy_root_id = None;
        let mut principal_id = None;
        let mut capability_summary_digest = None;
        let mut operations = None;
        let mut preconditions = None;
        let mut validation_profile_id = None;
        let mut candidate_nonce = None;
        let mut expiry = None;
        decode_record_fields(
            cursor,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
            |tag, payload| {
                match tag {
                    1 => format_version = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    2 => workspace_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    3 => {
                        base_transaction_id =
                            Some(decode_nested_exact(payload, depth + 1, budget)?);
                    }
                    4 => base_root = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    5 => schema_epoch_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    6 => policy_root_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    7 => principal_id = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    8 => {
                        capability_summary_digest =
                            Some(decode_nested_exact(payload, depth + 1, budget)?);
                    }
                    9 => operations = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    10 => preconditions = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    11 => {
                        validation_profile_id =
                            Some(decode_nested_exact(payload, depth + 1, budget)?);
                    }
                    12 => candidate_nonce = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    13 => expiry = Some(decode_nested_exact(payload, depth + 1, budget)?),
                    _ => return Err(ScbError::new(ScbErrorCode::FieldUnknown)),
                }
                Ok(())
            },
        )?;
        Ok(Self {
            format_version: format_version
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            workspace_id: workspace_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            base_transaction_id: base_transaction_id
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            base_root: base_root.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            schema_epoch_id: schema_epoch_id
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            policy_root_id: policy_root_id
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            principal_id: principal_id.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            capability_summary_digest: capability_summary_digest
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            operations: operations.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            preconditions: preconditions
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            validation_profile_id: validation_profile_id
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            candidate_nonce: candidate_nonce
                .ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
            expiry: expiry.ok_or_else(|| ScbError::new(ScbErrorCode::FieldMissing))?,
        })
    }
}

fn encode_mutation_payload(
    class: MutationClass,
    target_kind: u16,
    field_tag: Option<u32>,
    payload: &MutationPayload,
    depth: usize,
) -> Result<Vec<u8>> {
    check_container_depth(depth)?;
    let descriptor_field = descriptor_field_tag(field_tag).map_err(|_| scb_invalid())?;
    let descriptor = mutation_operation_descriptor(class, target_kind, descriptor_field)
        .ok_or_else(scb_invalid)?;
    if !payload.matches_descriptor(class, target_kind, descriptor_field, descriptor.value_type) {
        return Err(scb_invalid());
    }
    let payload_bytes = match payload {
        MutationPayload::CreateEntity(value) | MutationPayload::ReplaceEntityVersion(value) => {
            encode_at_depth(value, depth + 1)?
        }
        MutationPayload::DeleteEntityBinding | MutationPayload::RemoveEntryPoint => Vec::new(),
        MutationPayload::SetScalarField(value) | MutationPayload::ReplaceTypedField(value) => {
            encode_selected_field_value(value, depth + 1)?
        }
        MutationPayload::RetargetReference(ReferenceTarget::Entity(value)) => {
            encode_at_depth(value, depth + 1)?
        }
        MutationPayload::RetargetReference(ReferenceTarget::Optional(value)) => {
            encode_at_depth(value, depth + 1)?
        }
        MutationPayload::InsertOrderedChild(value) => encode_at_depth(value, depth + 1)?,
        MutationPayload::RemoveOrderedChild(value) => encode_at_depth(value, depth + 1)?,
        MutationPayload::MoveOrderedChild(value) => encode_at_depth(value, depth + 1)?,
        MutationPayload::AddEntryPoint(value) => encode_at_depth(value, depth + 1)?,
        MutationPayload::AddTest(value) | MutationPayload::ReplaceTest(value) => {
            encode_at_depth(value, depth + 1)?
        }
        MutationPayload::AddContract(value) | MutationPayload::ReplaceContract(value) => {
            encode_at_depth(value, depth + 1)?
        }
        MutationPayload::UpdateDependencyBinding(value) => encode_at_depth(value, depth + 1)?,
    };
    encode_union(u32::from(class.tag()), &payload_bytes)
}

#[allow(clippy::too_many_lines)]
fn decode_mutation_payload(
    class: MutationClass,
    target_kind: u16,
    field_tag: Option<u32>,
    input: &[u8],
    depth: usize,
    budget: &mut DecodeBudget,
) -> Result<MutationPayload> {
    check_container_depth(depth)?;
    let descriptor_field = descriptor_field_tag(field_tag).map_err(|_| scb_invalid())?;
    let descriptor = mutation_operation_descriptor(class, target_kind, descriptor_field)
        .ok_or_else(scb_invalid)?;
    let mut cursor = ScbValueCursor::new(input)?;
    let (tag, payload) = cursor.read_union()?;
    cursor.check_finished()?;
    if tag != u32::from(class.tag()) {
        return Err(scb_invalid());
    }
    match class {
        MutationClass::CreateEntity => {
            let value = decode_nested_exact::<EntityBodyValue>(payload, depth + 1, budget)?;
            if !MutationPayload::CreateEntity(value.clone()).matches_descriptor(
                class,
                target_kind,
                descriptor_field,
                descriptor.value_type,
            ) {
                return Err(scb_invalid());
            }
            Ok(MutationPayload::CreateEntity(value))
        }
        MutationClass::ReplaceEntityVersion => {
            let value = decode_nested_exact::<EntityBodyValue>(payload, depth + 1, budget)?;
            if !MutationPayload::ReplaceEntityVersion(value.clone()).matches_descriptor(
                class,
                target_kind,
                descriptor_field,
                descriptor.value_type,
            ) {
                return Err(scb_invalid());
            }
            Ok(MutationPayload::ReplaceEntityVersion(value))
        }
        MutationClass::DeleteEntityBinding => {
            if payload.is_empty() {
                Ok(MutationPayload::DeleteEntityBinding)
            } else {
                Err(scb_invalid())
            }
        }
        MutationClass::SetScalarField => {
            let field = descriptor_field.ok_or_else(scb_invalid)?;
            Ok(MutationPayload::SetScalarField(
                decode_selected_field_value(target_kind, field, payload, depth + 1, budget)?,
            ))
        }
        MutationClass::ReplaceTypedField => {
            let field = descriptor_field.ok_or_else(scb_invalid)?;
            Ok(MutationPayload::ReplaceTypedField(
                decode_selected_field_value(target_kind, field, payload, depth + 1, budget)?,
            ))
        }
        MutationClass::RetargetReference => match descriptor.value_type {
            "EntityId" => Ok(MutationPayload::RetargetReference(ReferenceTarget::Entity(
                decode_nested_exact(payload, depth + 1, budget)?,
            ))),
            "Option<EntityId>" => Ok(MutationPayload::RetargetReference(
                ReferenceTarget::Optional(decode_nested_exact(payload, depth + 1, budget)?),
            )),
            _ => Err(scb_invalid()),
        },
        MutationClass::InsertOrderedChild => Ok(MutationPayload::InsertOrderedChild(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        MutationClass::RemoveOrderedChild => Ok(MutationPayload::RemoveOrderedChild(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        MutationClass::MoveOrderedChild => Ok(MutationPayload::MoveOrderedChild(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        MutationClass::AddEntryPoint => Ok(MutationPayload::AddEntryPoint(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        MutationClass::RemoveEntryPoint => {
            if payload.is_empty() {
                Ok(MutationPayload::RemoveEntryPoint)
            } else {
                Err(scb_invalid())
            }
        }
        MutationClass::AddTest => Ok(MutationPayload::AddTest(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        MutationClass::ReplaceTest => Ok(MutationPayload::ReplaceTest(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        MutationClass::AddContract => Ok(MutationPayload::AddContract(decode_nested_exact(
            payload,
            depth + 1,
            budget,
        )?)),
        MutationClass::ReplaceContract => Ok(MutationPayload::ReplaceContract(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
        MutationClass::UpdateDependencyBinding => Ok(MutationPayload::UpdateDependencyBinding(
            decode_nested_exact(payload, depth + 1, budget)?,
        )),
    }
}

pub(crate) fn encode_candidate_record(
    record: &CandidateRecord,
) -> core::result::Result<Vec<u8>, CandidateError> {
    record.validate()?;
    encode_exact(record).map_err(CandidateError::from)
}

pub(crate) fn decode_candidate_record(
    input: &[u8],
) -> core::result::Result<CandidateRecord, CandidateError> {
    let record = decode_exact::<CandidateRecord>(input)?;
    record.validate()?;
    Ok(record)
}

pub(crate) fn build_candidate(
    record: &CandidateRecord,
) -> core::result::Result<ImportedCandidate, CandidateError> {
    let record_bytes = encode_candidate_record(record)?;
    let preimage = candidate_preimage(&record_bytes)?;
    let candidate_id = CandidateId::derive(&preimage);
    let mut stored_bytes = preimage.clone();
    stored_bytes.extend_from_slice(candidate_id.as_bytes());
    if stored_bytes.len() > MAX_STANDALONE_BYTES {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    Ok(ImportedCandidate {
        record: record.clone(),
        candidate_id,
        preimage,
        stored_bytes,
    })
}

pub(crate) fn import_candidate(
    input: &[u8],
) -> core::result::Result<ImportedCandidate, CandidateError> {
    if input.len() > MAX_STANDALONE_BYTES {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    if input.len() < 32 {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::LengthOverflow,
        )));
    }
    let (preimage, digest) = input.split_at(input.len() - 32);
    let mut cursor = ScbValueCursor::new(preimage)?;
    if cursor.read_exact_bytes(CANDIDATE_MAGIC.len())? != CANDIDATE_MAGIC {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::MagicInvalid,
        )));
    }
    if cursor.read_uvar(64)? != CANDIDATE_ENVELOPE_VERSION {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::VersionUnsupported,
        )));
    }
    let record_bytes = cursor.read_sized_payload()?;
    cursor.check_finished()?;
    let candidate_id = CandidateId::derive(preimage);
    if digest != candidate_id.as_bytes() {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::DigestMismatch,
        )));
    }
    let record = decode_candidate_record(record_bytes)?;
    Ok(ImportedCandidate {
        record,
        candidate_id,
        preimage: preimage.to_vec(),
        stored_bytes: input.to_vec(),
    })
}

pub(crate) fn full_validation_profile_id()
-> core::result::Result<ValidationProfileId, CandidateError> {
    let profile = ValidationProfileRecord::full_v1();
    let record = encode_exact(&profile)?;
    let mut preimage = Vec::with_capacity(8 + 1 + record.len());
    preimage.extend_from_slice(b"SLEYVAP1");
    preimage.extend_from_slice(&encode_uvar(1));
    preimage.extend_from_slice(&encode_uvar(record.len() as u64));
    preimage.extend_from_slice(&record);
    Ok(ValidationProfileId::derive(preimage))
}

fn candidate_preimage(record: &[u8]) -> core::result::Result<Vec<u8>, CandidateError> {
    if record.len() > MAX_STANDALONE_BYTES {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    let mut preimage = Vec::with_capacity(CANDIDATE_MAGIC.len() + 1 + record.len());
    preimage.extend_from_slice(CANDIDATE_MAGIC);
    preimage.extend_from_slice(&encode_uvar(CANDIDATE_ENVELOPE_VERSION));
    preimage.extend_from_slice(&encode_uvar(record.len() as u64));
    preimage.extend_from_slice(record);
    if preimage.len() > MAX_STANDALONE_BYTES {
        return Err(CandidateError::Scb(ScbError::new(
            ScbErrorCode::ResourceLimit,
        )));
    }
    Ok(preimage)
}

#[cfg(test)]
mod adversarial_tests;
#[cfg(test)]
mod fixture_tests;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::value::{ENTITY_BODY_VALUE_COUNT, FIELD_VALUE_COUNT};

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
        for value in [i128::MIN, -1, 0, i128::MAX] {
            assert_round_trip(&value);
        }
        for value in [u128::MIN, u128::MAX] {
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
        assert_round_trip(&TrapTerminator {
            code: TrapCode::InternalInvariant,
            payload: Some(ValueRef::Parameter(id(18))),
        });

        let terminators = [
            Terminator::Return(ReturnTerminator {
                value: ValueRef::Parameter(id(19)),
            }),
            Terminator::Branch(BranchTerminator {
                edge: TargetEdge {
                    target: id(20),
                    arguments: vec![],
                },
            }),
            Terminator::CondBranch(CondBranchTerminator {
                condition: ValueRef::Parameter(id(21)),
                if_true: TargetEdge {
                    target: id(22),
                    arguments: vec![],
                },
                if_false: TargetEdge {
                    target: id(23),
                    arguments: vec![],
                },
            }),
            Terminator::VariantSwitch(VariantSwitchTerminator {
                value: ValueRef::Parameter(id(24)),
                cases: vec![],
            }),
            Terminator::Trap(TrapTerminator {
                code: TrapCode::Unreachable,
                payload: None,
            }),
        ];
        for (index, value) in terminators.iter().enumerate() {
            assert_eq!(value.tag(), u32::try_from(index + 1).unwrap());
            assert_round_trip(value);
        }
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
        assert_round_trip(&VariantCase {
            member_id: member(36),
            payload_type: Some(TypeExpr::Text),
        });
        assert_round_trip(&TypeDefForm::Record(vec![RecordField {
            member_id: member(37),
            value_type: TypeExpr::Bytes,
            visibility: Visibility::Workspace,
        }]));
        assert_round_trip(&TypeDefForm::Variant(vec![VariantCase {
            member_id: member(38),
            payload_type: None,
        }]));
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

    fn resource_limits_fixture() -> ResourceLimits {
        ResourceLimits {
            fuel: 1,
            memory_bytes: 2,
            output_bytes: 3,
            effect_count: 4,
            call_depth: 5,
            wall_timeout_millis: 6,
        }
    }

    fn const_unit() -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Unit,
            data: ConstData::Unit,
        }
    }

    fn const_bool(value: bool) -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Bool,
            data: ConstData::Bool(value),
        }
    }

    fn const_text(value: &str) -> ConstValue {
        ConstValue {
            value_type: TypeExpr::Text,
            data: ConstData::Text(value.to_owned()),
        }
    }

    fn result_const_fixture() -> ResultConst {
        ResultConst::Ok(Box::new(const_bool(true)))
    }

    fn effect_environment_fixture() -> EffectEnvironment {
        EffectEnvironment::Replay(vec![ReplayBinding {
            adapter_import: id(81),
            request: vec![const_unit()],
            response: result_const_fixture(),
        }])
    }

    fn expected_outcome_fixture() -> ExpectedOutcome {
        ExpectedOutcome::Value(const_text("ok"))
    }

    fn expected_observation_fixture() -> ExpectedObservation {
        ExpectedObservation {
            observation_id: [82; 32],
            value: const_bool(false),
        }
    }

    fn type_def_form_fixture() -> TypeDefForm {
        TypeDefForm::Variant(vec![VariantCase {
            member_id: member(83),
            payload_type: Some(TypeExpr::Text),
        }])
    }

    fn terminator_fixture() -> Terminator {
        Terminator::Trap(TrapTerminator {
            code: TrapCode::AdapterContractViolation,
            payload: Some(ValueRef::Parameter(id(84))),
        })
    }

    fn contract_binding_fixture() -> ContractBinding {
        ContractBinding {
            predicate_parameter: 1,
            source: ContractSource::Global(id(85)),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn all_entity_body_values() -> Vec<EntityBodyValue> {
        vec![
            EntityBodyValue::Workspace(WorkspaceBody {
                packages: entity_set(&[1]),
                root_namespace: id(2),
                capability_requirements: entity_set(&[3]),
                contracts: entity_set(&[4]),
                tests: entity_set(&[5]),
            }),
            EntityBodyValue::Package(PackageBody {
                workspace: id(6),
                root_namespace: id(7),
                dependencies: entity_set(&[8]),
                exports: entity_set(&[9]),
            }),
            EntityBodyValue::Namespace(NamespaceBody {
                parent: Some(id(10)),
                members: entity_set(&[11]),
            }),
            EntityBodyValue::TypeDef(TypeDefBody {
                type_parameters: vec![TypeParameterDef { ordinal: 0 }],
                form: type_def_form_fixture(),
                invariants: entity_set(&[12]),
                visibility: Visibility::Exported,
            }),
            EntityBodyValue::Function(FunctionBody {
                type_parameters: vec![TypeParameterDef { ordinal: 1 }],
                parameters: vec![id(13), id(14)],
                result_type: TypeExpr::Bool,
                effects: entity_set(&[15]),
                entry_block: id(16),
                blocks: vec![id(17), id(18)],
                contracts: entity_set(&[19]),
                visibility: Visibility::Workspace,
            }),
            EntityBodyValue::Parameter(ParameterBody {
                owner: id(20),
                role: ParameterRole::Function,
                ordinal: 2,
                value_type: TypeExpr::Text,
            }),
            EntityBodyValue::Block(BlockBody {
                function: id(21),
                parameters: vec![id(22)],
                operations: vec![id(23)],
                terminator: terminator_fixture(),
                reachability: Reachability::Required,
            }),
            EntityBodyValue::Operation(operation_body_fixture()),
            EntityBodyValue::Constant(ConstantBody {
                value: const_text("constant"),
            }),
            EntityBodyValue::GlobalValue(GlobalValueBody {
                value_type: TypeExpr::Bytes,
                initializer: id(24),
                visibility: Visibility::Package,
            }),
            EntityBodyValue::EffectDef(EffectDefBody {
                effect_kind: EffectKind::AdapterCall,
                scope_type: TypeExpr::Bytes,
                request_type: TypeExpr::Text,
                response_type: TypeExpr::Bool,
                failure_type: TypeExpr::BuiltinFailure(BuiltinFailureKind::Capability),
                visibility: Visibility::Private,
            }),
            EntityBodyValue::CapabilityRequirement(CapabilityRequirementBody {
                effect: id(25),
                allowed_scopes: vec![const_unit(), const_text("scope")],
                constraint_contracts: entity_set(&[26]),
            }),
            EntityBodyValue::Contract(ContractBody {
                target: id(27),
                contract_kind: ContractKind::Precondition,
                predicate: id(28),
                bindings: vec![contract_binding_fixture()],
                resource_limits: Some(resource_limits_fixture()),
            }),
            EntityBodyValue::TestCase(TestCaseBody {
                target: id(29),
                inputs: vec![const_bool(true)],
                effect_environment: effect_environment_fixture(),
                expected: expected_outcome_fixture(),
                observations: vec![expected_observation_fixture()],
                resource_limits: resource_limits_fixture(),
            }),
            EntityBodyValue::AdapterImport(AdapterImportBody {
                adapter_id: [30; 32],
                abi_version: 1,
                request_type: TypeExpr::Bytes,
                response_type: TypeExpr::Text,
                failure_type: TypeExpr::BuiltinFailure(BuiltinFailureKind::ContractViolation),
                effects: entity_set(&[31]),
            }),
            EntityBodyValue::EntryPoint(EntryPointBody {
                function: id(32),
                exposure: EntryExposure::Protocol,
            }),
            EntityBodyValue::PolicyBinding(PolicyBindingBody {
                subject: id(33),
                requirements: entity_set(&[34]),
            }),
            EntityBodyValue::DependencyBinding(DependencyBindingBody {
                dependency_root: StateRoot::from_bytes([35; 32]),
                external_package: id(36),
                local_namespace: id(37),
            }),
        ]
    }

    fn all_field_values() -> Vec<FieldValue> {
        vec![
            FieldValue::WorkspacePackages(entity_set(&[1])),
            FieldValue::WorkspaceRootNamespace(id(2)),
            FieldValue::WorkspaceCapabilityRequirements(entity_set(&[3])),
            FieldValue::WorkspaceContracts(entity_set(&[4])),
            FieldValue::WorkspaceTests(entity_set(&[5])),
            FieldValue::PackageWorkspace(id(6)),
            FieldValue::PackageRootNamespace(id(7)),
            FieldValue::PackageDependencies(entity_set(&[8])),
            FieldValue::PackageExports(entity_set(&[9])),
            FieldValue::NamespaceParent(Some(id(10))),
            FieldValue::NamespaceMembers(entity_set(&[11])),
            FieldValue::TypeDefTypeParameters(vec![TypeParameterDef { ordinal: 0 }]),
            FieldValue::TypeDefForm(type_def_form_fixture()),
            FieldValue::TypeDefInvariants(entity_set(&[12])),
            FieldValue::TypeDefVisibility(Visibility::Exported),
            FieldValue::FunctionTypeParameters(vec![TypeParameterDef { ordinal: 1 }]),
            FieldValue::FunctionParameters(vec![id(13), id(14)]),
            FieldValue::FunctionResultType(TypeExpr::Bool),
            FieldValue::FunctionEffects(entity_set(&[15])),
            FieldValue::FunctionEntryBlock(id(16)),
            FieldValue::FunctionBlocks(vec![id(17), id(18)]),
            FieldValue::FunctionContracts(entity_set(&[19])),
            FieldValue::FunctionVisibility(Visibility::Workspace),
            FieldValue::ParameterOwner(id(20)),
            FieldValue::ParameterRole(ParameterRole::Block),
            FieldValue::ParameterOrdinal(u32::MAX),
            FieldValue::ParameterValueType(TypeExpr::Text),
            FieldValue::BlockFunction(id(21)),
            FieldValue::BlockParameters(vec![id(22)]),
            FieldValue::BlockOperations(vec![id(23)]),
            FieldValue::BlockTerminator(terminator_fixture()),
            FieldValue::BlockReachability(Reachability::ExplicitlyUnreachable),
            FieldValue::OperationBlock(id(24)),
            FieldValue::OperationOrdinal(4),
            FieldValue::OperationOpcode(5),
            FieldValue::OperationOperands(vec![ValueRef::Parameter(id(25))]),
            FieldValue::OperationResultTypes(vec![TypeExpr::Bytes]),
            FieldValue::OperationImmediate(Immediate::Index(6)),
            FieldValue::ConstantValue(const_text("field-constant")),
            FieldValue::GlobalValueValueType(TypeExpr::Text),
            FieldValue::GlobalValueInitializer(id(26)),
            FieldValue::GlobalValueVisibility(Visibility::Package),
            FieldValue::EffectDefEffectKind(EffectKind::ClockRead),
            FieldValue::EffectDefScopeType(TypeExpr::Bytes),
            FieldValue::EffectDefRequestType(TypeExpr::Text),
            FieldValue::EffectDefResponseType(TypeExpr::Bool),
            FieldValue::EffectDefFailureType(TypeExpr::BuiltinFailure(
                BuiltinFailureKind::Capability,
            )),
            FieldValue::EffectDefVisibility(Visibility::Private),
            FieldValue::CapabilityRequirementEffect(id(27)),
            FieldValue::CapabilityRequirementAllowedScopes(vec![const_unit()]),
            FieldValue::CapabilityRequirementConstraintContracts(entity_set(&[28])),
            FieldValue::ContractTarget(id(29)),
            FieldValue::ContractContractKind(ContractKind::Invariant),
            FieldValue::ContractPredicate(id(30)),
            FieldValue::ContractBindings(vec![contract_binding_fixture()]),
            FieldValue::ContractResourceLimits(Some(resource_limits_fixture())),
            FieldValue::TestCaseTarget(id(31)),
            FieldValue::TestCaseInputs(vec![const_bool(true)]),
            FieldValue::TestCaseEffectEnvironment(effect_environment_fixture()),
            FieldValue::TestCaseExpected(ExpectedOutcome::FailureCode(7)),
            FieldValue::TestCaseObservations(vec![expected_observation_fixture()]),
            FieldValue::TestCaseResourceLimits(resource_limits_fixture()),
            FieldValue::AdapterImportAdapterId([32; 32]),
            FieldValue::AdapterImportAbiVersion(8),
            FieldValue::AdapterImportRequestType(TypeExpr::Bytes),
            FieldValue::AdapterImportResponseType(TypeExpr::Text),
            FieldValue::AdapterImportFailureType(TypeExpr::BuiltinFailure(
                BuiltinFailureKind::ContractViolation,
            )),
            FieldValue::AdapterImportEffects(entity_set(&[33])),
            FieldValue::EntryPointFunction(id(34)),
            FieldValue::EntryPointExposure(EntryExposure::Local),
            FieldValue::PolicyBindingSubject(id(35)),
            FieldValue::PolicyBindingRequirements(entity_set(&[36])),
            FieldValue::DependencyBindingDependencyRoot(StateRoot::from_bytes([37; 32])),
            FieldValue::DependencyBindingExternalPackage(id(38)),
            FieldValue::DependencyBindingLocalNamespace(id(39)),
        ]
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

    #[test]
    fn const_value_family_covers_all_sixteen_data_tags_and_ordered_maps() {
        let values = vec![
            ConstData::Unit,
            ConstData::Bool(true),
            ConstData::SInt(i128::MIN + 1),
            ConstData::UInt(u128::MAX),
            ConstData::F32Bits(0x7fc0_0000),
            ConstData::F64Bits(0x7ff8_0000_0000_0000),
            ConstData::Bytes(vec![0, 1, 255]),
            ConstData::Text("text".to_owned()),
            ConstData::Sequence(vec![const_unit(), const_bool(false)]),
            ConstData::Record(RecordConst {
                definition: id(90),
                fields: vec![FieldConst {
                    member_id: member(91),
                    value: const_unit(),
                }],
            }),
            ConstData::Variant(VariantConst {
                definition: id(92),
                member_id: member(93),
                payload: Some(Box::new(const_text("payload"))),
            }),
            ConstData::Map(vec![MapEntryConst {
                key: const_unit(),
                value: const_bool(true),
            }]),
            ConstData::Option(Some(Box::new(const_bool(false)))),
            ConstData::Result(ResultConst::Err(Box::new(const_text("err")))),
            ConstData::FunctionRef(FunctionRefValue {
                function: id(94),
                type_arguments: vec![TypeExpr::Text],
            }),
            ConstData::BuiltinFailure(BuiltinFailureValue {
                kind: BuiltinFailureKind::DuplicateKey,
                code: 9,
            }),
        ];
        for (index, value) in values.iter().enumerate() {
            assert_eq!(value.tag(), u32::try_from(index + 1).unwrap());
            assert_round_trip(value);
            assert_round_trip(&ConstValue {
                value_type: TypeExpr::Unit,
                data: value.clone(),
            });
        }

        let mut entries = vec![
            MapEntryConst {
                key: const_text("b"),
                value: const_bool(true),
            },
            MapEntryConst {
                key: const_text("a"),
                value: const_bool(false),
            },
        ];
        entries.sort_by_key(|entry| encode_exact(&entry.key).unwrap());
        assert_round_trip(&ConstData::Map(entries.clone()));

        let duplicate = ConstData::Map(vec![entries[0].clone(), entries[0].clone()]);
        assert_eq!(
            encode_exact(&duplicate).unwrap_err().code(),
            ScbErrorCode::MapDuplicate
        );

        let mut reversed = entries.clone();
        reversed.reverse();
        assert_eq!(
            encode_exact(&ConstData::Map(reversed.clone()))
                .unwrap_err()
                .code(),
            ScbErrorCode::MapOrder
        );
        let malformed = encode_union(
            12,
            &encode_list(
                &reversed
                    .iter()
                    .map(|entry| encode_exact(entry).unwrap())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            decode_exact::<ConstData>(&malformed).unwrap_err().code(),
            ScbErrorCode::MapOrder
        );

        assert_eq!(
            decode_exact::<ConstData>(&encode_union(1, &[0]).unwrap())
                .unwrap_err()
                .code(),
            ScbErrorCode::UnionInvalid
        );
    }

    #[test]
    fn all_eighteen_entity_body_union_tags_are_descriptor_selected() {
        let bodies = all_entity_body_values();
        assert_eq!(bodies.len(), ENTITY_BODY_VALUE_COUNT);
        let mut seen = BTreeSet::new();
        for body in bodies {
            let encoded = encode_exact(&body).unwrap();
            let mut cursor = ScbValueCursor::new(&encoded).unwrap();
            let (tag, payload) = cursor.read_union().unwrap();
            cursor.check_finished().unwrap();
            assert_eq!(tag, u32::from(body.kind_tag()));
            assert!(!payload.is_empty());
            assert!(seen.insert(body.kind_tag()));
            assert_eq!(decode_exact::<EntityBodyValue>(&encoded).unwrap(), body);
        }
        assert_eq!(seen.len(), ENTITY_BODY_VALUE_COUNT);
    }

    #[test]
    fn all_seventy_five_field_values_round_trip_without_self_tags() {
        let fields = all_field_values();
        assert_eq!(fields.len(), FIELD_VALUE_COUNT);
        let mut seen = BTreeSet::new();
        for field_value in fields {
            let (kind, field_tag) = field_value.field_key();
            let encoded = encode_selected_field_value(&field_value, 0).unwrap();
            let mut budget = DecodeBudget::default();
            let decoded =
                decode_selected_field_value(kind, field_tag, &encoded, 0, &mut budget).unwrap();
            assert_eq!(decoded, field_value);
            assert!(seen.insert((kind, field_tag)));
            assert!(
                mutation_operation_descriptor(
                    MutationClass::ReplaceTypedField,
                    kind,
                    Some(field_tag)
                )
                .is_some()
            );
        }
        assert_eq!(seen.len(), FIELD_VALUE_COUNT);
    }

    fn precondition_for(operation: &MutationOperation, object_seed: u8) -> BoundPrecondition {
        let descriptor = mutation_operation_descriptor(
            operation.class,
            operation.target_kind,
            descriptor_field_tag(operation.field_tag).unwrap(),
        )
        .unwrap();
        match descriptor.preimage {
            PreimageRequirement::ExpectedIdentityAbsent => BoundPrecondition {
                operation_ordinal: operation.ordinal,
                requirement: PreimageRequirement::ExpectedIdentityAbsent,
                payload: PreconditionPayload::ExpectedIdentityAbsent(ExpectedIdentityAbsent {
                    entity_id: operation.target_entity,
                }),
            },
            PreimageRequirement::ExactEntityVersion => BoundPrecondition {
                operation_ordinal: operation.ordinal,
                requirement: PreimageRequirement::ExactEntityVersion,
                payload: PreconditionPayload::ExactEntityVersion(ExactEntityVersion {
                    entity_id: operation.target_entity,
                    object_id: ObjectId::from_bytes([object_seed; 32]),
                }),
            },
            PreimageRequirement::ExactContainerVersion => BoundPrecondition {
                operation_ordinal: operation.ordinal,
                requirement: PreimageRequirement::ExactContainerVersion,
                payload: PreconditionPayload::ExactContainerVersion(ExactContainerVersion {
                    container_id: operation.target_entity,
                    object_id: ObjectId::from_bytes([object_seed; 32]),
                    field_tag: operation.field_tag.unwrap(),
                }),
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    fn full_candidate_record() -> CandidateRecord {
        let workspace_id = WorkspaceId::from_bytes([201; 32]);
        let candidate_nonce = CandidateNonce::from_bytes([202; 32]);
        let create_entity = EntityId::derive(workspace_id, candidate_nonce, 1, 0);
        let mut operations = vec![
            MutationOperation {
                ordinal: 0,
                class: MutationClass::CreateEntity,
                target_kind: 1,
                target_entity: create_entity,
                field_tag: None,
                payload: MutationPayload::CreateEntity(all_entity_body_values()[0].clone()),
                precondition_ordinal: 0,
            },
            MutationOperation {
                ordinal: 1,
                class: MutationClass::ReplaceEntityVersion,
                target_kind: 2,
                target_entity: id(41),
                field_tag: None,
                payload: MutationPayload::ReplaceEntityVersion(all_entity_body_values()[1].clone()),
                precondition_ordinal: 1,
            },
            MutationOperation {
                ordinal: 2,
                class: MutationClass::DeleteEntityBinding,
                target_kind: 2,
                target_entity: id(42),
                field_tag: None,
                payload: MutationPayload::DeleteEntityBinding,
                precondition_ordinal: 2,
            },
            MutationOperation {
                ordinal: 3,
                class: MutationClass::SetScalarField,
                target_kind: 6,
                target_entity: id(43),
                field_tag: Some(3),
                payload: MutationPayload::SetScalarField(FieldValue::ParameterOrdinal(3)),
                precondition_ordinal: 3,
            },
            MutationOperation {
                ordinal: 4,
                class: MutationClass::ReplaceTypedField,
                target_kind: 4,
                target_entity: id(44),
                field_tag: Some(2),
                payload: MutationPayload::ReplaceTypedField(FieldValue::TypeDefForm(
                    type_def_form_fixture(),
                )),
                precondition_ordinal: 4,
            },
            MutationOperation {
                ordinal: 5,
                class: MutationClass::RetargetReference,
                target_kind: 3,
                target_entity: id(45),
                field_tag: Some(1),
                payload: MutationPayload::RetargetReference(ReferenceTarget::Optional(Some(id(
                    46,
                )))),
                precondition_ordinal: 5,
            },
            MutationOperation {
                ordinal: 6,
                class: MutationClass::InsertOrderedChild,
                target_kind: 5,
                target_entity: id(47),
                field_tag: Some(2),
                payload: MutationPayload::InsertOrderedChild(OrderedInsert {
                    index: 0,
                    child: id(48),
                }),
                precondition_ordinal: 6,
            },
            MutationOperation {
                ordinal: 7,
                class: MutationClass::RemoveOrderedChild,
                target_kind: 5,
                target_entity: id(49),
                field_tag: Some(2),
                payload: MutationPayload::RemoveOrderedChild(OrderedRemove {
                    index: 1,
                    expected_child: id(50),
                }),
                precondition_ordinal: 7,
            },
            MutationOperation {
                ordinal: 8,
                class: MutationClass::MoveOrderedChild,
                target_kind: 5,
                target_entity: id(51),
                field_tag: Some(2),
                payload: MutationPayload::MoveOrderedChild(OrderedMove {
                    from: 2,
                    to: 0,
                    expected_child: id(52),
                }),
                precondition_ordinal: 8,
            },
            MutationOperation {
                ordinal: 9,
                class: MutationClass::AddEntryPoint,
                target_kind: 16,
                target_entity: id(53),
                field_tag: None,
                payload: MutationPayload::AddEntryPoint(EntryPointBody {
                    function: id(54),
                    exposure: EntryExposure::Protocol,
                }),
                precondition_ordinal: 9,
            },
            MutationOperation {
                ordinal: 10,
                class: MutationClass::RemoveEntryPoint,
                target_kind: 16,
                target_entity: id(55),
                field_tag: None,
                payload: MutationPayload::RemoveEntryPoint,
                precondition_ordinal: 10,
            },
            MutationOperation {
                ordinal: 11,
                class: MutationClass::AddTest,
                target_kind: 14,
                target_entity: id(56),
                field_tag: None,
                payload: MutationPayload::AddTest(match all_entity_body_values()[13].clone() {
                    EntityBodyValue::TestCase(value) => value,
                    _ => unreachable!(),
                }),
                precondition_ordinal: 11,
            },
            MutationOperation {
                ordinal: 12,
                class: MutationClass::ReplaceTest,
                target_kind: 14,
                target_entity: id(57),
                field_tag: None,
                payload: MutationPayload::ReplaceTest(match all_entity_body_values()[13].clone() {
                    EntityBodyValue::TestCase(value) => value,
                    _ => unreachable!(),
                }),
                precondition_ordinal: 12,
            },
            MutationOperation {
                ordinal: 13,
                class: MutationClass::AddContract,
                target_kind: 13,
                target_entity: id(58),
                field_tag: None,
                payload: MutationPayload::AddContract(match all_entity_body_values()[12].clone() {
                    EntityBodyValue::Contract(value) => value,
                    _ => unreachable!(),
                }),
                precondition_ordinal: 13,
            },
            MutationOperation {
                ordinal: 14,
                class: MutationClass::ReplaceContract,
                target_kind: 13,
                target_entity: id(59),
                field_tag: None,
                payload: MutationPayload::ReplaceContract(
                    match all_entity_body_values()[12].clone() {
                        EntityBodyValue::Contract(value) => value,
                        _ => unreachable!(),
                    },
                ),
                precondition_ordinal: 14,
            },
            MutationOperation {
                ordinal: 15,
                class: MutationClass::UpdateDependencyBinding,
                target_kind: 18,
                target_entity: id(60),
                field_tag: None,
                payload: MutationPayload::UpdateDependencyBinding(
                    match all_entity_body_values()[17].clone() {
                        EntityBodyValue::DependencyBinding(value) => value,
                        _ => unreachable!(),
                    },
                ),
                precondition_ordinal: 15,
            },
        ];
        for (index, operation) in operations.iter_mut().enumerate() {
            operation.ordinal = u32::try_from(index).unwrap();
            operation.precondition_ordinal = operation.ordinal;
        }
        let preconditions = operations
            .iter()
            .enumerate()
            .map(|(index, operation)| precondition_for(operation, u8::try_from(index + 1).unwrap()))
            .collect();
        CandidateRecord {
            format_version: crate::candidate::CANDIDATE_FORMAT_VERSION,
            workspace_id,
            base_transaction_id: TransactionId::from_bytes([203; 32]),
            base_root: StateRoot::from_bytes([204; 32]),
            schema_epoch_id: SchemaEpochId::from_bytes([205; 32]),
            policy_root_id: PolicyRootId::from_bytes([206; 32]),
            principal_id: PrincipalId::from_bytes([207; 32]),
            capability_summary_digest: CapabilitySummaryDigest::from_bytes([208; 32]),
            operations,
            preconditions,
            validation_profile_id: full_validation_profile_id().unwrap(),
            candidate_nonce,
            expiry: CandidateExpiry::unix_millis(1),
        }
    }

    #[test]
    fn candidate_record_build_import_digest_and_stale_preimage_are_bound() {
        let record = full_candidate_record();
        assert_eq!(record.operations.len(), 16);
        assert_eq!(record.preconditions.len(), 16);

        let encoded_record = encode_candidate_record(&record).unwrap();
        assert_eq!(decode_candidate_record(&encoded_record).unwrap(), record);
        let imported = build_candidate(&record).unwrap();
        assert!(
            imported
                .preimage
                .starts_with(crate::candidate::CANDIDATE_MAGIC)
        );
        assert_eq!(
            imported.candidate_id,
            CandidateId::derive(&imported.preimage)
        );
        assert_eq!(imported.stored_bytes.len(), imported.preimage.len() + 32);
        assert_eq!(import_candidate(&imported.stored_bytes).unwrap(), imported);

        let mut changed_precondition = record.clone();
        changed_precondition.preconditions[1] =
            precondition_for(&changed_precondition.operations[1], 250);
        let changed = build_candidate(&changed_precondition).unwrap();
        assert_ne!(changed.candidate_id, imported.candidate_id);

        let mut corrupted = imported.stored_bytes.clone();
        let last_preimage_byte = imported.preimage.len() - 1;
        corrupted[last_preimage_byte] ^= 1;
        assert_eq!(
            import_candidate(&corrupted).unwrap_err().code(),
            ScbErrorCode::DigestMismatch.as_str()
        );

        let mut wrong_identity = record.clone();
        wrong_identity.operations[0].target_entity = id(250);
        assert_eq!(
            build_candidate(&wrong_identity).unwrap_err(),
            CandidateError::TargetEntityMismatch
        );

        let mut wrong_precondition = record;
        if let PreconditionPayload::ExactContainerVersion(payload) =
            &mut wrong_precondition.preconditions[6].payload
        {
            payload.field_tag = 3;
        }
        assert_eq!(
            build_candidate(&wrong_precondition).unwrap_err(),
            CandidateError::PreconditionMismatch
        );
    }

    #[test]
    fn validation_profile_full_v1_is_exact_and_digest_bound() {
        let profile = ValidationProfileRecord::full_v1();
        assert_eq!(
            profile.phase_tags,
            crate::candidate::FULL_VALIDATION_PHASE_TAGS
        );
        assert_round_trip(&profile);
        assert_eq!(
            full_validation_profile_id().unwrap(),
            crate::full_validation_profile_id().unwrap()
        );

        let mut invalid = profile;
        invalid.max_operations = 1;
        assert_eq!(
            invalid.validate_full_v1().unwrap_err(),
            CandidateError::ValidationProfileInvalid
        );
    }
}
