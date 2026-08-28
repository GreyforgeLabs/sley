#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use sley_id::EntityId;

pub mod fingerprint;

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

/// Closed epoch-1 effect kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EffectKind {
    /// Captured standard output write.
    StdoutWrite,
    /// Captured standard error write.
    StderrWrite,
    /// Confined file read.
    FileRead,
    /// Confined file write.
    FileWrite,
    /// Deterministic or replayed clock read.
    ClockRead,
    /// Deterministic or replayed random read.
    RandomRead,
    /// Explicit environment lookup.
    EnvironmentRead,
    /// Typed replayable adapter call.
    AdapterCall,
}

impl EffectKind {
    /// Returns the exact frozen SSMC1 effect-kind tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::StdoutWrite => 1,
            Self::StderrWrite => 2,
            Self::FileRead => 3,
            Self::FileWrite => 4,
            Self::ClockRead => 5,
            Self::RandomRead => 6,
            Self::EnvironmentRead => 7,
            Self::AdapterCall => 8,
        }
    }

    /// Resolves one exact frozen SSMC1 effect-kind tag.
    #[must_use]
    pub const fn from_tag(tag: u32) -> Option<Self> {
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

/// One immutable effect-definition semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectDefinition {
    /// Stable effect identity.
    pub entity_id: EntityId,
    /// Closed effect kind.
    pub effect_kind: EffectKind,
    /// Exact resource-scope type.
    pub scope_type: TypeExpr,
    /// Exact request type.
    pub request_type: TypeExpr,
    /// Exact response type.
    pub response_type: TypeExpr,
    /// Exact failure type.
    pub failure_type: TypeExpr,
    /// Definition visibility.
    pub visibility: Visibility,
}

/// One static capability requirement semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRequirement {
    /// Stable requirement identity.
    pub entity_id: EntityId,
    /// Required effect definition.
    pub effect: EntityId,
    /// Canonically ordered exact allowed scope constants.
    pub allowed_scopes: Vec<ConstValue>,
    /// Raw-ID-sorted constraint contract identities.
    pub constraint_contracts: Vec<EntityId>,
}

/// One typed adapter-import semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterImport {
    /// Stable import entity identity.
    pub entity_id: EntityId,
    /// Stable external adapter identity bytes.
    pub adapter_id: [u8; 32],
    /// Exact adapter ABI version.
    pub abi_version: u32,
    /// Exact request type.
    pub request_type: TypeExpr,
    /// Exact response type.
    pub response_type: TypeExpr,
    /// Exact failure type.
    pub failure_type: TypeExpr,
    /// Raw-ID-sorted effect identities.
    pub effects: Vec<EntityId>,
}

/// Closed epoch-1 contract kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractKind {
    /// Function precondition.
    Precondition,
    /// Function postcondition.
    Postcondition,
    /// Type invariant; unsupported by the restricted epoch-1 profile.
    Invariant,
    /// Effect bound; unsupported by the restricted epoch-1 profile.
    EffectBound,
    /// Capability bound; unsupported by the restricted epoch-1 profile.
    CapabilityBound,
    /// Function result predicate.
    ResultPredicate,
    /// Resource ceiling; unsupported by the restricted epoch-1 profile.
    ResourceCeiling,
}

impl ContractKind {
    /// Returns the exact frozen SSMC1 contract-kind tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Precondition => 1,
            Self::Postcondition => 2,
            Self::Invariant => 3,
            Self::EffectBound => 4,
            Self::CapabilityBound => 5,
            Self::ResultPredicate => 6,
            Self::ResourceCeiling => 7,
        }
    }
}

/// Closed source for one predicate parameter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractSource {
    /// Target function parameter.
    Parameter(EntityId),
    /// Complete target function result.
    Result,
    /// Error arm of an explicit Result target type.
    Error,
    /// Immutable global value.
    Global(EntityId),
}

impl ContractSource {
    /// Returns the exact frozen SSMC1 contract-source tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Parameter(_) => 1,
            Self::Result => 2,
            Self::Error => 3,
            Self::Global(_) => 4,
        }
    }
}

/// One ordered predicate-parameter binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractBinding {
    /// Zero-based predicate parameter ordinal.
    pub predicate_parameter: u32,
    /// Exact semantic source.
    pub source: ContractSource,
}

/// Exact execution/test resource ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    /// VM fuel.
    pub fuel: u64,
    /// Memory bytes.
    pub memory_bytes: u64,
    /// Output bytes.
    pub output_bytes: u64,
    /// Effect operation count.
    pub effect_count: u64,
    /// Call depth.
    pub call_depth: u64,
    /// Wall-time ceiling in milliseconds.
    pub wall_timeout_millis: u64,
}

/// One canonical contract semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDefinition {
    /// Stable contract identity.
    pub entity_id: EntityId,
    /// Exact target entity.
    pub target: EntityId,
    /// Closed contract kind.
    pub contract_kind: ContractKind,
    /// Predicate function identity.
    pub predicate: EntityId,
    /// Ordered predicate bindings.
    pub bindings: Vec<ContractBinding>,
    /// Optional resource ceilings.
    pub resource_limits: Option<ResourceLimits>,
}

/// One canonical Constant entity body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstantDefinition {
    /// Stable constant identity.
    pub entity_id: EntityId,
    /// Exact persistable value.
    pub value: ConstValue,
}

/// One immutable `GlobalValue` entity body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GlobalValueDefinition {
    /// Stable global identity.
    pub entity_id: EntityId,
    /// Exact value type.
    pub value_type: TypeExpr,
    /// Initializer Constant identity.
    pub initializer: EntityId,
    /// Global visibility.
    pub visibility: Visibility,
}

/// One structurally frozen adapter replay binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBinding {
    /// Adapter import identity.
    pub adapter_import: EntityId,
    /// Ordered request constants.
    pub request: Vec<ConstValue>,
    /// Frozen response arm.
    pub response: ResultConst,
}

/// One structurally frozen deterministic-adapter configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterConfig {
    /// Adapter import identity.
    pub adapter_import: EntityId,
    /// Opaque canonical configuration candidate.
    pub configuration: ConstValue,
}

/// Closed test effect environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectEnvironment {
    /// Ordered replay bindings.
    Replay(Vec<ReplayBinding>),
    /// Ordered deterministic adapter configurations.
    DeterministicAdapters(Vec<AdapterConfig>),
}

impl EffectEnvironment {
    /// Returns the exact frozen SSMC1 environment tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Replay(_) => 1,
            Self::DeterministicAdapters(_) => 2,
        }
    }
}

/// Closed expected test outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpectedOutcome {
    /// Exact persistable value.
    Value(ConstValue),
    /// Closed failure code candidate.
    FailureCode(u32),
}

impl ExpectedOutcome {
    /// Returns the exact frozen SSMC1 outcome tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Value(_) => 1,
            Self::FailureCode(_) => 2,
        }
    }
}

/// One structurally frozen expected observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedObservation {
    /// Stable observation identity.
    pub observation_id: [u8; 32],
    /// Exact expected value.
    pub value: ConstValue,
}

/// One canonical test-case semantic body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestCaseDefinition {
    /// Stable test identity.
    pub entity_id: EntityId,
    /// Exact target entity.
    pub target: EntityId,
    /// Ordered input constants.
    pub inputs: Vec<ConstValue>,
    /// Explicit effect environment.
    pub effect_environment: EffectEnvironment,
    /// Expected outcome.
    pub expected: ExpectedOutcome,
    /// Ordered expected observations.
    pub observations: Vec<ExpectedObservation>,
    /// Exact required resource limits.
    pub resource_limits: ResourceLimits,
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

/// Function or block parameter role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterRole {
    /// Ordered function parameter.
    Function,
    /// Ordered block parameter.
    Block,
}

impl ParameterRole {
    /// Returns the exact frozen role tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Function => 1,
            Self::Block => 2,
        }
    }
}

/// Declared block reachability policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reachability {
    /// Must be reachable from the entry block.
    Required,
    /// Must not be reachable from the entry block.
    ExplicitlyUnreachable,
}

impl Reachability {
    /// Returns the exact frozen reachability tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Required => 1,
            Self::ExplicitlyUnreachable => 2,
        }
    }
}

/// Operation-result value identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationResultRef {
    /// Defining operation.
    pub operation: EntityId,
    /// Zero-based result index.
    pub result_index: u32,
}

/// Closed SSMC1 value reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueRef {
    /// Parameter identity.
    Parameter(EntityId),
    /// Operation result.
    OperationResult(OperationResultRef),
}

impl ValueRef {
    /// Returns the exact frozen value-reference tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Parameter(_) => 1,
            Self::OperationResult(_) => 2,
        }
    }
}

/// Named-variant immediate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VariantImmediate {
    /// Exact variant definition.
    pub definition: EntityId,
    /// Exact case identity.
    pub member_id: MemberId,
}

/// Closed operation immediate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Immediate {
    /// No immediate.
    None,
    /// Entity identity.
    Entity(EntityId),
    /// Zero-based index.
    Index(u32),
    /// Stable field identity.
    Field(MemberId),
    /// Named variant and case.
    Variant(VariantImmediate),
    /// Stable observation identity.
    Observation([u8; 32]),
    /// Function identity plus explicit type arguments.
    Function(FunctionRefValue),
}

impl Immediate {
    /// Returns the exact frozen immediate tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::None => 1,
            Self::Entity(_) => 2,
            Self::Index(_) => 3,
            Self::Field(_) => 4,
            Self::Variant(_) => 5,
            Self::Observation(_) => 6,
            Self::Function(_) => 7,
        }
    }
}

/// Closed SSMC1 epoch-1 opcode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    /// Constant reference.
    ConstantRef,
    /// Tuple construction.
    TupleNew,
    /// Tuple projection.
    TupleGet,
    /// Record construction.
    RecordNew,
    /// Record projection.
    RecordGet,
    /// Variant construction.
    VariantNew,
    /// Variant projection with explicit absence.
    VariantGet,
    /// Vector construction.
    VectorNew,
    /// Vector length.
    VectorLen,
    /// Vector access.
    VectorGet,
    /// Persistent vector update.
    VectorSet,
    /// Ordered-map construction.
    MapNew,
    /// Ordered-map access.
    MapGet,
    /// Ordered-map membership.
    MapContains,
    /// Persistent ordered-map insertion.
    MapInsert,
    /// Persistent ordered-map removal.
    MapRemove,
    /// Checked integer addition.
    IntAddChecked,
    /// Checked integer subtraction.
    IntSubChecked,
    /// Checked integer multiplication.
    IntMulChecked,
    /// Checked integer division.
    IntDivChecked,
    /// Checked integer remainder.
    IntRemChecked,
    /// Checked signed negation.
    IntNegChecked,
    /// Checked left shift.
    IntShlChecked,
    /// Checked right shift.
    IntShrChecked,
    /// Floating addition.
    FloatAdd,
    /// Floating subtraction.
    FloatSub,
    /// Floating multiplication.
    FloatMul,
    /// Floating division.
    FloatDiv,
    /// Floating negation.
    FloatNeg,
    /// Explicit fused multiply-add.
    FloatFma,
    /// Equality.
    Equal,
    /// Inequality.
    NotEqual,
    /// Less than.
    LessThan,
    /// Less than or equal.
    LessEqual,
    /// Greater than.
    GreaterThan,
    /// Greater than or equal.
    GreaterEqual,
    /// Boolean not.
    BoolNot,
    /// Boolean and.
    BoolAnd,
    /// Boolean or.
    BoolOr,
    /// Direct typed function call.
    CallDirect,
    /// Option some.
    OptionSome,
    /// Option none.
    OptionNone,
    /// Result success.
    ResultOk,
    /// Result failure.
    ResultErr,
    /// Contract assertion.
    ContractAssert,
    /// Test observation.
    TestObserve,
    /// Typed effect request.
    EffectRequest,
    /// Typed adapter invocation.
    AdapterInvoke,
    /// Capability narrowing.
    CapabilityNarrow,
    /// Local-cell construction.
    CellNew,
    /// Local-cell read.
    CellGet,
    /// Local-cell write.
    CellSet,
    /// Defined value hash.
    ValueHash,
    /// Immutable global read.
    GlobalGet,
    /// Function-reference construction.
    FunctionRef,
}

impl Opcode {
    /// Returns the exact frozen opcode tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::ConstantRef => 1,
            Self::TupleNew => 16,
            Self::TupleGet => 17,
            Self::RecordNew => 18,
            Self::RecordGet => 19,
            Self::VariantNew => 20,
            Self::VariantGet => 21,
            Self::VectorNew => 32,
            Self::VectorLen => 33,
            Self::VectorGet => 34,
            Self::VectorSet => 35,
            Self::MapNew => 36,
            Self::MapGet => 37,
            Self::MapContains => 38,
            Self::MapInsert => 39,
            Self::MapRemove => 40,
            Self::IntAddChecked => 64,
            Self::IntSubChecked => 65,
            Self::IntMulChecked => 66,
            Self::IntDivChecked => 67,
            Self::IntRemChecked => 68,
            Self::IntNegChecked => 69,
            Self::IntShlChecked => 70,
            Self::IntShrChecked => 71,
            Self::FloatAdd => 80,
            Self::FloatSub => 81,
            Self::FloatMul => 82,
            Self::FloatDiv => 83,
            Self::FloatNeg => 84,
            Self::FloatFma => 85,
            Self::Equal => 96,
            Self::NotEqual => 97,
            Self::LessThan => 98,
            Self::LessEqual => 99,
            Self::GreaterThan => 100,
            Self::GreaterEqual => 101,
            Self::BoolNot => 102,
            Self::BoolAnd => 103,
            Self::BoolOr => 104,
            Self::CallDirect => 112,
            Self::OptionSome => 128,
            Self::OptionNone => 129,
            Self::ResultOk => 130,
            Self::ResultErr => 131,
            Self::ContractAssert => 144,
            Self::TestObserve => 145,
            Self::EffectRequest => 160,
            Self::AdapterInvoke => 161,
            Self::CapabilityNarrow => 162,
            Self::CellNew => 176,
            Self::CellGet => 177,
            Self::CellSet => 178,
            Self::ValueHash => 192,
            Self::GlobalGet => 193,
            Self::FunctionRef => 194,
        }
    }

    /// Resolves one exact frozen SSMC1 opcode tag.
    #[must_use]
    pub const fn from_tag(tag: u32) -> Option<Self> {
        match tag {
            1 => Some(Self::ConstantRef),
            16 => Some(Self::TupleNew),
            17 => Some(Self::TupleGet),
            18 => Some(Self::RecordNew),
            19 => Some(Self::RecordGet),
            20 => Some(Self::VariantNew),
            21 => Some(Self::VariantGet),
            32 => Some(Self::VectorNew),
            33 => Some(Self::VectorLen),
            34 => Some(Self::VectorGet),
            35 => Some(Self::VectorSet),
            36 => Some(Self::MapNew),
            37 => Some(Self::MapGet),
            38 => Some(Self::MapContains),
            39 => Some(Self::MapInsert),
            40 => Some(Self::MapRemove),
            64 => Some(Self::IntAddChecked),
            65 => Some(Self::IntSubChecked),
            66 => Some(Self::IntMulChecked),
            67 => Some(Self::IntDivChecked),
            68 => Some(Self::IntRemChecked),
            69 => Some(Self::IntNegChecked),
            70 => Some(Self::IntShlChecked),
            71 => Some(Self::IntShrChecked),
            80 => Some(Self::FloatAdd),
            81 => Some(Self::FloatSub),
            82 => Some(Self::FloatMul),
            83 => Some(Self::FloatDiv),
            84 => Some(Self::FloatNeg),
            85 => Some(Self::FloatFma),
            96 => Some(Self::Equal),
            97 => Some(Self::NotEqual),
            98 => Some(Self::LessThan),
            99 => Some(Self::LessEqual),
            100 => Some(Self::GreaterThan),
            101 => Some(Self::GreaterEqual),
            102 => Some(Self::BoolNot),
            103 => Some(Self::BoolAnd),
            104 => Some(Self::BoolOr),
            112 => Some(Self::CallDirect),
            128 => Some(Self::OptionSome),
            129 => Some(Self::OptionNone),
            130 => Some(Self::ResultOk),
            131 => Some(Self::ResultErr),
            144 => Some(Self::ContractAssert),
            145 => Some(Self::TestObserve),
            160 => Some(Self::EffectRequest),
            161 => Some(Self::AdapterInvoke),
            162 => Some(Self::CapabilityNarrow),
            176 => Some(Self::CellNew),
            177 => Some(Self::CellGet),
            178 => Some(Self::CellSet),
            192 => Some(Self::ValueHash),
            193 => Some(Self::GlobalGet),
            194 => Some(Self::FunctionRef),
            _ => None,
        }
    }
}

/// One SSMC1 operation entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    /// Stable operation identity.
    pub entity_id: EntityId,
    /// Owning block.
    pub block: EntityId,
    /// Zero-based position in the block.
    pub ordinal: u32,
    /// Frozen closed opcode.
    pub opcode: Opcode,
    /// Ordered input values.
    pub operands: Vec<ValueRef>,
    /// Ordered declared result types.
    pub result_types: Vec<TypeExpr>,
    /// Frozen opcode immediate.
    pub immediate: Immediate,
}

/// Ordinary CFG target edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetEdge {
    /// Target block.
    pub target: EntityId,
    /// Ordered target arguments.
    pub arguments: Vec<ValueRef>,
}

/// Built-in Option/Result switch case.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BuiltinCase {
    /// Option none.
    None,
    /// Option some.
    Some,
    /// Result success.
    Ok,
    /// Result failure.
    Err,
}

impl BuiltinCase {
    /// Returns the exact frozen built-in case tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::None => 1,
            Self::Some => 2,
            Self::Ok => 3,
            Self::Err => 4,
        }
    }
}

/// Named or built-in switch case key.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CaseKey {
    /// Named variant member.
    Member(MemberId),
    /// Option/Result built-in case.
    Builtin(BuiltinCase),
}

impl CaseKey {
    /// Returns the exact frozen case-key union tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Member(_) => 1,
            Self::Builtin(_) => 2,
        }
    }
}

/// One switch-edge argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchArgument {
    /// Ordinary source-block value.
    Value(ValueRef),
    /// Selected case payload.
    CasePayload,
}

impl SwitchArgument {
    /// Returns the exact frozen switch-argument tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Value(_) => 1,
            Self::CasePayload => 2,
        }
    }
}

/// Variant-switch target edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchEdge {
    /// Target block.
    pub target: EntityId,
    /// Ordinary values or selected payload.
    pub arguments: Vec<SwitchArgument>,
}

/// One exhaustive variant-switch case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwitchCase {
    /// Named or built-in case key.
    pub case_key: CaseKey,
    /// Case target edge.
    pub edge: SwitchEdge,
}

/// Closed trap code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapCode {
    /// Statically unreachable path.
    Unreachable,
    /// Declared resource exhaustion.
    ResourceExhausted,
    /// Adapter violated its typed contract.
    AdapterContractViolation,
    /// Validated internal invariant failed.
    InternalInvariant,
}

impl TrapCode {
    /// Returns the exact frozen trap tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Unreachable => 1,
            Self::ResourceExhausted => 2,
            Self::AdapterContractViolation => 3,
            Self::InternalInvariant => 4,
        }
    }
}

/// Return terminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnTerminator {
    /// Returned value.
    pub value: ValueRef,
}

/// Unconditional branch terminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchTerminator {
    /// Only target edge.
    pub edge: TargetEdge,
}

/// Conditional branch terminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CondBranchTerminator {
    /// Boolean condition.
    pub condition: ValueRef,
    /// True edge.
    pub if_true: TargetEdge,
    /// False edge.
    pub if_false: TargetEdge,
}

/// Exhaustive variant switch terminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VariantSwitchTerminator {
    /// Selected variant value.
    pub value: ValueRef,
    /// Strictly canonical ordered cases.
    pub cases: Vec<SwitchCase>,
}

/// Explicit unrecoverable trap terminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrapTerminator {
    /// Closed trap code.
    pub code: TrapCode,
    /// Optional persistable value.
    pub payload: Option<ValueRef>,
}

/// Closed SSMC1 terminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Terminator {
    /// Function return.
    Return(ReturnTerminator),
    /// Unconditional branch.
    Branch(BranchTerminator),
    /// Conditional branch.
    CondBranch(CondBranchTerminator),
    /// Exhaustive closed-variant switch.
    VariantSwitch(VariantSwitchTerminator),
    /// Explicit trap.
    Trap(TrapTerminator),
}

impl Terminator {
    /// Returns the exact frozen terminator tag.
    #[must_use]
    pub const fn tag(&self) -> u32 {
        match self {
            Self::Return(_) => 1,
            Self::Branch(_) => 2,
            Self::CondBranch(_) => 3,
            Self::VariantSwitch(_) => 4,
            Self::Trap(_) => 5,
        }
    }
}

/// One parameter entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Parameter {
    /// Stable parameter identity.
    pub entity_id: EntityId,
    /// Function or block owner.
    pub owner: EntityId,
    /// Function or block role.
    pub role: ParameterRole,
    /// Zero-based owner-list position.
    pub ordinal: u32,
    /// Exact value type.
    pub value_type: TypeExpr,
}

/// One block entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Stable block identity.
    pub entity_id: EntityId,
    /// Owning function.
    pub function: EntityId,
    /// Ordered block parameters.
    pub parameters: Vec<EntityId>,
    /// Ordered operations.
    pub operations: Vec<EntityId>,
    /// Exactly one terminator.
    pub terminator: Terminator,
    /// Exact reachability policy.
    pub reachability: Reachability,
}

/// Function graph fields required by S20-220.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionGraph {
    /// Stable function identity.
    pub entity_id: EntityId,
    /// Ordered declaration parameters.
    pub type_parameters: Vec<TypeParameterDef>,
    /// Ordered function parameters.
    pub parameters: Vec<EntityId>,
    /// Exact result type.
    pub result_type: TypeExpr,
    /// Raw-ID-sorted effect identities.
    pub effects: Vec<EntityId>,
    /// Entry block.
    pub entry_block: EntityId,
    /// Ordered function blocks.
    pub blocks: Vec<EntityId>,
    /// Raw-ID-sorted contract identities.
    pub contracts: Vec<EntityId>,
    /// Function visibility.
    pub visibility: Visibility,
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
        let effects = [
            EffectKind::StdoutWrite,
            EffectKind::StderrWrite,
            EffectKind::FileRead,
            EffectKind::FileWrite,
            EffectKind::ClockRead,
            EffectKind::RandomRead,
            EffectKind::EnvironmentRead,
            EffectKind::AdapterCall,
        ];
        let effect_tags = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(effects.map(EffectKind::tag), effect_tags);
        for (effect, tag) in effects.into_iter().zip(effect_tags) {
            assert_eq!(EffectKind::from_tag(tag), Some(effect));
        }
        assert_eq!(EffectKind::from_tag(0), None);
        assert_eq!(EffectKind::from_tag(9), None);
        assert_eq!(
            [
                ContractKind::Precondition,
                ContractKind::Postcondition,
                ContractKind::Invariant,
                ContractKind::EffectBound,
                ContractKind::CapabilityBound,
                ContractKind::ResultPredicate,
                ContractKind::ResourceCeiling,
            ]
            .map(ContractKind::tag),
            [1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            ContractSource::Parameter(EntityId::from_bytes([1; 32])).tag(),
            1
        );
        assert_eq!(ContractSource::Result.tag(), 2);
        assert_eq!(ContractSource::Error.tag(), 3);
        assert_eq!(
            ContractSource::Global(EntityId::from_bytes([2; 32])).tag(),
            4
        );
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
        assert_eq!(EffectEnvironment::Replay(Vec::new()).tag(), 1);
        assert_eq!(
            EffectEnvironment::DeterministicAdapters(Vec::new()).tag(),
            2
        );
        assert_eq!(
            ExpectedOutcome::Value(ConstValue {
                value_type: TypeExpr::Unit,
                data: ConstData::Unit,
            })
            .tag(),
            1
        );
        assert_eq!(ExpectedOutcome::FailureCode(1).tag(), 2);
    }

    #[test]
    fn cfg_enum_tags_do_not_depend_on_rust_layout() {
        let id = EntityId::from_bytes([1; 32]);
        assert_eq!(ParameterRole::Function.tag(), 1);
        assert_eq!(ParameterRole::Block.tag(), 2);
        assert_eq!(Reachability::Required.tag(), 1);
        assert_eq!(Reachability::ExplicitlyUnreachable.tag(), 2);
        assert_eq!(ValueRef::Parameter(id).tag(), 1);
        assert_eq!(
            ValueRef::OperationResult(OperationResultRef {
                operation: id,
                result_index: 0,
            })
            .tag(),
            2
        );
        assert_eq!(BuiltinCase::None.tag(), 1);
        assert_eq!(BuiltinCase::Err.tag(), 4);
        assert_eq!(CaseKey::Member(MemberId::from_bytes([2; 32])).tag(), 1);
        assert_eq!(CaseKey::Builtin(BuiltinCase::Ok).tag(), 2);
        assert_eq!(SwitchArgument::Value(ValueRef::Parameter(id)).tag(), 1);
        assert_eq!(SwitchArgument::CasePayload.tag(), 2);
        assert_eq!(TrapCode::Unreachable.tag(), 1);
        assert_eq!(TrapCode::InternalInvariant.tag(), 4);
        assert_eq!(
            Terminator::Return(ReturnTerminator {
                value: ValueRef::Parameter(id),
            })
            .tag(),
            1
        );
        assert_eq!(
            Terminator::Trap(TrapTerminator {
                code: TrapCode::Unreachable,
                payload: None,
            })
            .tag(),
            5
        );
    }

    #[test]
    fn all_opcode_tags_are_exact_and_unique() {
        let opcodes = [
            Opcode::ConstantRef,
            Opcode::TupleNew,
            Opcode::TupleGet,
            Opcode::RecordNew,
            Opcode::RecordGet,
            Opcode::VariantNew,
            Opcode::VariantGet,
            Opcode::VectorNew,
            Opcode::VectorLen,
            Opcode::VectorGet,
            Opcode::VectorSet,
            Opcode::MapNew,
            Opcode::MapGet,
            Opcode::MapContains,
            Opcode::MapInsert,
            Opcode::MapRemove,
            Opcode::IntAddChecked,
            Opcode::IntSubChecked,
            Opcode::IntMulChecked,
            Opcode::IntDivChecked,
            Opcode::IntRemChecked,
            Opcode::IntNegChecked,
            Opcode::IntShlChecked,
            Opcode::IntShrChecked,
            Opcode::FloatAdd,
            Opcode::FloatSub,
            Opcode::FloatMul,
            Opcode::FloatDiv,
            Opcode::FloatNeg,
            Opcode::FloatFma,
            Opcode::Equal,
            Opcode::NotEqual,
            Opcode::LessThan,
            Opcode::LessEqual,
            Opcode::GreaterThan,
            Opcode::GreaterEqual,
            Opcode::BoolNot,
            Opcode::BoolAnd,
            Opcode::BoolOr,
            Opcode::CallDirect,
            Opcode::OptionSome,
            Opcode::OptionNone,
            Opcode::ResultOk,
            Opcode::ResultErr,
            Opcode::ContractAssert,
            Opcode::TestObserve,
            Opcode::EffectRequest,
            Opcode::AdapterInvoke,
            Opcode::CapabilityNarrow,
            Opcode::CellNew,
            Opcode::CellGet,
            Opcode::CellSet,
            Opcode::ValueHash,
            Opcode::GlobalGet,
            Opcode::FunctionRef,
        ];
        let expected = [
            1, 16, 17, 18, 19, 20, 21, 32, 33, 34, 35, 36, 37, 38, 39, 40, 64, 65, 66, 67, 68, 69,
            70, 71, 80, 81, 82, 83, 84, 85, 96, 97, 98, 99, 100, 101, 102, 103, 104, 112, 128, 129,
            130, 131, 144, 145, 160, 161, 162, 176, 177, 178, 192, 193, 194,
        ];
        assert_eq!(opcodes.map(Opcode::tag), expected);
        for (opcode, tag) in opcodes.into_iter().zip(expected) {
            assert_eq!(Opcode::from_tag(tag), Some(opcode));
        }
        assert_eq!(Opcode::from_tag(0), None);
        assert_eq!(Opcode::from_tag(2), None);
        assert_eq!(Opcode::from_tag(195), None);
        assert!(expected.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
