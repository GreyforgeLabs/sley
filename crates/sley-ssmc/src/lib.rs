#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use sley_id::EntityId;

/// Exact epoch-1 structural type depth.
pub const MAX_TYPE_DEPTH: usize = 64;
/// Maximum explicit type arguments.
pub const MAX_TYPE_ARGUMENTS: usize = 1_024;
/// Maximum tuple elements.
pub const MAX_TUPLE_ITEMS: usize = 65_535;
/// Maximum definition fields or cases.
pub const MAX_MEMBERS: usize = 65_535;
/// Maximum constant collection elements.
pub const MAX_CONSTANT_ELEMENTS: usize = 1_000_000;
/// Maximum byte or text payload.
pub const MAX_CONSTANT_PAYLOAD_BYTES: usize = 16_777_216;

/// Raw declared integer width; the checker admits only the five epoch-1 widths.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntegerWidth(u16);

impl IntegerWidth {
    /// Constructs a raw decoded width for later semantic validation.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw width.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether this is one of 8, 16, 32, 64, or 128.
    #[must_use]
    pub const fn is_epoch_1(self) -> bool {
        matches!(self.0, 8 | 16 | 32 | 64 | 128)
    }
}

/// Definition-local stable field or case identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemberId([u8; 32]);

impl MemberId {
    /// Constructs an identity from exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Closed epoch-1 built-in operation failure type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BuiltinFailureKind {
    /// Checked integer arithmetic failure.
    Arithmetic,
    /// Collection index failure.
    Index,
    /// Ordered-map duplicate key.
    DuplicateKey,
    /// Contract predicate failure.
    ContractViolation,
    /// Capability narrowing failure.
    Capability,
}

impl BuiltinFailureKind {
    /// Returns the exact SSMC1 tag.
    #[must_use]
    pub const fn tag(self) -> u16 {
        match self {
            Self::Arithmetic => 1,
            Self::Index => 2,
            Self::DuplicateKey => 3,
            Self::ContractViolation => 4,
            Self::Capability => 5,
        }
    }
}

/// Named type instantiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedType {
    /// Stable type-definition identity.
    pub definition: EntityId,
    /// Explicit invariant type arguments.
    pub arguments: Vec<TypeExpr>,
}

/// First-class function-reference type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionType {
    /// Ordered parameter types.
    pub parameters: Vec<TypeExpr>,
    /// Exact result type.
    pub result: Box<TypeExpr>,
    /// Raw-ID-sorted declared effect identities.
    pub effects: Vec<EntityId>,
}

/// Closed SSMC1 epoch-1 structural type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypeExpr {
    /// Unit.
    Unit,
    /// Boolean.
    Bool,
    /// Explicit-width signed integer.
    SInt(IntegerWidth),
    /// Explicit-width unsigned integer.
    UInt(IntegerWidth),
    /// Deterministic IEEE-754 binary32.
    F32,
    /// Deterministic IEEE-754 binary64.
    F64,
    /// Byte sequence.
    Bytes,
    /// Exact Unicode scalar sequence.
    Text,
    /// Fixed ordered tuple.
    Tuple(Vec<Self>),
    /// Named record or variant instantiation.
    Named(NamedType),
    /// Immutable vector.
    Vector(Box<Self>),
    /// Canonical ordered map.
    OrderedMap {
        /// Key type.
        key: Box<Self>,
        /// Value type.
        value: Box<Self>,
    },
    /// Optional value.
    Option(Box<Self>),
    /// Explicit success or failure value.
    Result {
        /// Success type.
        ok: Box<Self>,
        /// Failure type.
        error: Box<Self>,
    },
    /// Stable function reference.
    FunctionRef(FunctionType),
    /// Opaque execution-scoped adapter handle.
    AdapterHandle(EntityId),
    /// Root/session-scoped capability token.
    CapabilityToken(EntityId),
    /// Function-local mutable cell.
    LocalCell(Box<Self>),
    /// Zero-based declaration parameter.
    TypeParameter(u32),
    /// Closed built-in failure type.
    BuiltinFailure(BuiltinFailureKind),
}

impl TypeExpr {
    /// Returns the exact frozen SSMC1 type tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Unit => 1,
            Self::Bool => 2,
            Self::SInt(_) => 3,
            Self::UInt(_) => 4,
            Self::F32 => 5,
            Self::F64 => 6,
            Self::Bytes => 7,
            Self::Text => 8,
            Self::Tuple(_) => 9,
            Self::Named(_) => 10,
            Self::Vector(_) => 11,
            Self::OrderedMap { .. } => 12,
            Self::Option(_) => 13,
            Self::Result { .. } => 14,
            Self::FunctionRef(_) => 15,
            Self::AdapterHandle(_) => 16,
            Self::CapabilityToken(_) => 17,
            Self::LocalCell(_) => 18,
            Self::TypeParameter(_) => 19,
            Self::BuiltinFailure(_) => 20,
        }
    }
}

/// Type-definition visibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Visibility {
    /// Visible only within the definition owner.
    Private,
    /// Visible within its package.
    Package,
    /// Visible within its workspace.
    Workspace,
    /// Exported through package/dependency boundaries.
    Exported,
}

impl Visibility {
    /// Returns the exact frozen SSMC1 visibility tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Private => 1,
            Self::Package => 2,
            Self::Workspace => 3,
            Self::Exported => 4,
        }
    }
}

/// One declaration parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeParameterDef {
    /// Required zero-based ordinal.
    pub ordinal: u32,
}

/// Record field definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordField {
    /// Stable definition-local member identity.
    pub member_id: MemberId,
    /// Field type, possibly using declaration parameters.
    pub value_type: TypeExpr,
    /// Field visibility.
    pub visibility: Visibility,
}

/// Tagged-variant case definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariantCase {
    /// Stable definition-local member identity.
    pub member_id: MemberId,
    /// Optional case payload type.
    pub payload_type: Option<TypeExpr>,
}

/// Closed type-definition form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypeDefForm {
    /// Ordered record fields.
    Record(Vec<RecordField>),
    /// Ordered tagged-variant cases.
    Variant(Vec<VariantCase>),
}

impl TypeDefForm {
    /// Returns the exact frozen SSMC1 form tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Record(_) => 1,
            Self::Variant(_) => 2,
        }
    }
}

/// One immutable type-definition semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeDefinition {
    /// Stable logical definition identity.
    pub entity_id: EntityId,
    /// Ordered declaration parameters.
    pub type_parameters: Vec<TypeParameterDef>,
    /// Record or tagged-variant body.
    pub form: TypeDefForm,
    /// Raw-ID-sorted invariant contract identities.
    pub invariants: Vec<EntityId>,
    /// Definition visibility.
    pub visibility: Visibility,
}

/// Persistable function-reference value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionRefValue {
    /// Stable function identity.
    pub function: EntityId,
    /// Explicit invariant type arguments.
    pub type_arguments: Vec<TypeExpr>,
}

/// Record constant field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldConst {
    /// Exact defining member identity.
    pub member_id: MemberId,
    /// Field value.
    pub value: ConstValue,
}

/// Record constant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordConst {
    /// Exact named definition.
    pub definition: EntityId,
    /// Fields in definition order.
    pub fields: Vec<FieldConst>,
}

/// Variant constant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariantConst {
    /// Exact named definition.
    pub definition: EntityId,
    /// Exact case identity.
    pub member_id: MemberId,
    /// Case payload.
    pub payload: Option<Box<ConstValue>>,
}

/// Ordered-map constant entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapEntryConst {
    /// Key.
    pub key: ConstValue,
    /// Value.
    pub value: ConstValue,
}

/// Result constant arm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultConst {
    /// Success value.
    Ok(Box<ConstValue>),
    /// Failure value.
    Err(Box<ConstValue>),
}

impl ResultConst {
    /// Returns the exact frozen SSMC1 result-arm tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Ok(_) => 1,
            Self::Err(_) => 2,
        }
    }
}

/// Built-in failure constant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinFailureValue {
    /// Failure family.
    pub kind: BuiltinFailureKind,
    /// Closed family-specific code.
    pub code: u16,
}

/// Closed constant data variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstData {
    /// Unit.
    Unit,
    /// Boolean.
    Bool(bool),
    /// Signed integer.
    SInt(i128),
    /// Unsigned integer.
    UInt(u128),
    /// Raw canonical binary32 bits.
    F32Bits(u32),
    /// Raw canonical binary64 bits.
    F64Bits(u64),
    /// Bytes.
    Bytes(Vec<u8>),
    /// Exact runtime text.
    Text(String),
    /// Tuple or vector elements.
    Sequence(Vec<ConstValue>),
    /// Named record.
    Record(RecordConst),
    /// Named variant.
    Variant(VariantConst),
    /// Ordered-map entries.
    Map(Vec<MapEntryConst>),
    /// Optional value.
    Option(Option<Box<ConstValue>>),
    /// Result value.
    Result(ResultConst),
    /// Function reference.
    FunctionRef(FunctionRefValue),
    /// Closed built-in failure.
    BuiltinFailure(BuiltinFailureValue),
}

impl ConstData {
    /// Returns the exact frozen SSMC1 constant-data tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Unit => 1,
            Self::Bool(_) => 2,
            Self::SInt(_) => 3,
            Self::UInt(_) => 4,
            Self::F32Bits(_) => 5,
            Self::F64Bits(_) => 6,
            Self::Bytes(_) => 7,
            Self::Text(_) => 8,
            Self::Sequence(_) => 9,
            Self::Record(_) => 10,
            Self::Variant(_) => 11,
            Self::Map(_) => 12,
            Self::Option(_) => 13,
            Self::Result(_) => 14,
            Self::FunctionRef(_) => 15,
            Self::BuiltinFailure(_) => 16,
        }
    }
}

/// One typed persistable constant candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstValue {
    /// Declared exact type.
    pub value_type: TypeExpr,
    /// Closed data body.
    pub data: ConstData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_type_tags_are_exact_and_unique() {
        let id = EntityId::from_bytes([1; 32]);
        let width = IntegerWidth::from_bits(8);
        let types = [
            TypeExpr::Unit,
            TypeExpr::Bool,
            TypeExpr::SInt(width),
            TypeExpr::UInt(width),
            TypeExpr::F32,
            TypeExpr::F64,
            TypeExpr::Bytes,
            TypeExpr::Text,
            TypeExpr::Tuple(Vec::new()),
            TypeExpr::Named(NamedType {
                definition: id,
                arguments: Vec::new(),
            }),
            TypeExpr::Vector(Box::new(TypeExpr::Unit)),
            TypeExpr::OrderedMap {
                key: Box::new(TypeExpr::Bool),
                value: Box::new(TypeExpr::Unit),
            },
            TypeExpr::Option(Box::new(TypeExpr::Unit)),
            TypeExpr::Result {
                ok: Box::new(TypeExpr::Unit),
                error: Box::new(TypeExpr::Unit),
            },
            TypeExpr::FunctionRef(FunctionType {
                parameters: Vec::new(),
                result: Box::new(TypeExpr::Unit),
                effects: Vec::new(),
            }),
            TypeExpr::AdapterHandle(id),
            TypeExpr::CapabilityToken(id),
            TypeExpr::LocalCell(Box::new(TypeExpr::Unit)),
            TypeExpr::TypeParameter(0),
            TypeExpr::BuiltinFailure(BuiltinFailureKind::Arithmetic),
        ];
        assert_eq!(
            types.map(|value| value.tag()),
            std::array::from_fn(|i| u32::try_from(i).expect("array index fits u32") + 1)
        );
    }

    #[test]
    fn raw_integer_width_preserves_invalid_candidates_for_checker() {
        assert!(IntegerWidth::from_bits(128).is_epoch_1());
        assert!(!IntegerWidth::from_bits(24).is_epoch_1());
    }

    #[test]
    fn built_in_failure_tags_are_frozen() {
        assert_eq!(
            [
                BuiltinFailureKind::Arithmetic,
                BuiltinFailureKind::Index,
                BuiltinFailureKind::DuplicateKey,
                BuiltinFailureKind::ContractViolation,
                BuiltinFailureKind::Capability,
            ]
            .map(BuiltinFailureKind::tag),
            [1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn supporting_enum_tags_do_not_depend_on_rust_layout() {
        assert_eq!(
            [
                Visibility::Private,
                Visibility::Package,
                Visibility::Workspace,
                Visibility::Exported,
            ]
            .map(Visibility::tag),
            [1, 2, 3, 4]
        );
        assert_eq!(TypeDefForm::Record(Vec::new()).tag(), 1);
        assert_eq!(TypeDefForm::Variant(Vec::new()).tag(), 2);
        assert_eq!(ConstData::Unit.tag(), 1);
        assert_eq!(
            ConstData::BuiltinFailure(BuiltinFailureValue {
                kind: BuiltinFailureKind::Index,
                code: 1,
            })
            .tag(),
            16
        );
        let value = ConstValue {
            value_type: TypeExpr::Unit,
            data: ConstData::Unit,
        };
        assert_eq!(ResultConst::Ok(Box::new(value.clone())).tag(), 1);
        assert_eq!(ResultConst::Err(Box::new(value)).tag(), 2);
    }
}
