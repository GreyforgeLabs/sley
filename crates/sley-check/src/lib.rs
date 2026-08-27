#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use sley_id::EntityId;
use sley_ssmc::{
    BuiltinFailureKind, ConstData, ConstValue, IntegerWidth, MAX_CONSTANT_ELEMENTS,
    MAX_CONSTANT_PAYLOAD_BYTES, MAX_MEMBERS, MAX_TUPLE_ITEMS, MAX_TYPE_ARGUMENTS, MAX_TYPE_DEPTH,
    ResultConst, TypeDefForm, TypeDefinition, TypeExpr,
};

/// Bounded CFG and value-use validation.
pub mod cfg;
/// Deterministic static effect closure and scope validation.
pub mod effects;

const MAX_DEFINITIONS: usize = 1_000_000;
const CANONICAL_F32_NAN: u32 = 0x7fc0_0000;
const CANONICAL_F64_NAN: u64 = 0x7ff8_0000_0000_0000;

/// Stable S20-210 type-system failure code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeErrorCode {
    /// `TYPE_DEPTH_LIMIT`
    DepthLimit,
    /// `TYPE_WIDTH_INVALID`
    WidthInvalid,
    /// `TYPE_PARAMETER_OUT_OF_SCOPE`
    ParameterOutOfScope,
    /// `TYPE_ARGUMENT_LIMIT`
    ArgumentLimit,
    /// `TYPE_ARGUMENT_ARITY`
    ArgumentArity,
    /// `TYPE_DEFINITION_UNKNOWN`
    DefinitionUnknown,
    /// `TYPE_DEFINITION_DUPLICATE`
    DefinitionDuplicate,
    /// `TYPE_DEFINITION_CYCLE`
    DefinitionCycle,
    /// `TYPE_MEMBER_DUPLICATE`
    MemberDuplicate,
    /// `TYPE_MEMBER_UNKNOWN`
    MemberUnknown,
    /// `TYPE_SET_ORDER`
    SetOrder,
    /// `TYPE_NOT_ORDERABLE`
    NotOrderable,
    /// `TYPE_NOT_HASHABLE`
    NotHashable,
    /// `TYPE_NOT_PERSISTABLE`
    NotPersistable,
    /// `TYPE_CONST_SHAPE`
    ConstShape,
    /// `TYPE_CONST_RANGE`
    ConstRange,
    /// `TYPE_FLOAT_NON_CANONICAL`
    FloatNonCanonical,
    /// `TYPE_CONST_DUPLICATE_KEY`
    ConstDuplicateKey,
    /// `TYPE_RESOURCE_LIMIT`
    ResourceLimit,
    /// `TYPE_IMPLICIT_COERCION`
    ImplicitCoercion,
    /// `TYPE_BUILTIN_FAILURE_INVALID`
    BuiltinFailureInvalid,
}

impl TypeErrorCode {
    /// Returns the exact stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DepthLimit => "TYPE_DEPTH_LIMIT",
            Self::WidthInvalid => "TYPE_WIDTH_INVALID",
            Self::ParameterOutOfScope => "TYPE_PARAMETER_OUT_OF_SCOPE",
            Self::ArgumentLimit => "TYPE_ARGUMENT_LIMIT",
            Self::ArgumentArity => "TYPE_ARGUMENT_ARITY",
            Self::DefinitionUnknown => "TYPE_DEFINITION_UNKNOWN",
            Self::DefinitionDuplicate => "TYPE_DEFINITION_DUPLICATE",
            Self::DefinitionCycle => "TYPE_DEFINITION_CYCLE",
            Self::MemberDuplicate => "TYPE_MEMBER_DUPLICATE",
            Self::MemberUnknown => "TYPE_MEMBER_UNKNOWN",
            Self::SetOrder => "TYPE_SET_ORDER",
            Self::NotOrderable => "TYPE_NOT_ORDERABLE",
            Self::NotHashable => "TYPE_NOT_HASHABLE",
            Self::NotPersistable => "TYPE_NOT_PERSISTABLE",
            Self::ConstShape => "TYPE_CONST_SHAPE",
            Self::ConstRange => "TYPE_CONST_RANGE",
            Self::FloatNonCanonical => "TYPE_FLOAT_NON_CANONICAL",
            Self::ConstDuplicateKey => "TYPE_CONST_DUPLICATE_KEY",
            Self::ResourceLimit => "TYPE_RESOURCE_LIMIT",
            Self::ImplicitCoercion => "TYPE_IMPLICIT_COERCION",
            Self::BuiltinFailureInvalid => "TYPE_BUILTIN_FAILURE_INVALID",
        }
    }

    /// Returns the exact stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::DepthLimit => 21_000,
            Self::WidthInvalid => 21_001,
            Self::ParameterOutOfScope => 21_002,
            Self::ArgumentLimit => 21_003,
            Self::ArgumentArity => 21_004,
            Self::DefinitionUnknown => 21_005,
            Self::DefinitionDuplicate => 21_006,
            Self::DefinitionCycle => 21_007,
            Self::MemberDuplicate => 21_008,
            Self::MemberUnknown => 21_009,
            Self::SetOrder => 21_010,
            Self::NotOrderable => 21_011,
            Self::NotHashable => 21_012,
            Self::NotPersistable => 21_013,
            Self::ConstShape => 21_014,
            Self::ConstRange => 21_015,
            Self::FloatNonCanonical => 21_016,
            Self::ConstDuplicateKey => 21_017,
            Self::ResourceLimit => 21_018,
            Self::ImplicitCoercion => 21_019,
            Self::BuiltinFailureInvalid => 21_020,
        }
    }
}

impl fmt::Display for TypeErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Deterministic type-system error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypeError {
    code: TypeErrorCode,
}

impl TypeError {
    /// Constructs an error from a frozen code.
    #[must_use]
    pub const fn new(code: TypeErrorCode) -> Self {
        Self { code }
    }

    /// Returns the frozen error code.
    #[must_use]
    pub const fn code(&self) -> TypeErrorCode {
        self.code
    }
}

impl fmt::Display for TypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for TypeError {}

/// S20-210 result type.
pub type Result<T> = core::result::Result<T, TypeError>;

/// Structural type capabilities.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypeTraits {
    /// Supports deterministic semantic equality.
    pub equality: bool,
    /// Supports epoch-1 total order.
    pub total_order: bool,
    /// Supports canonical value hashing.
    pub canonical_hash: bool,
    /// May occur in canonical persisted values.
    pub persistable: bool,
}

impl TypeTraits {
    const ALL: Self = Self {
        equality: true,
        total_order: true,
        canonical_hash: true,
        persistable: true,
    };

    const fn combine(self, other: Self) -> Self {
        Self {
            equality: self.equality && other.equality,
            total_order: self.total_order && other.total_order,
            canonical_hash: self.canonical_hash && other.canonical_hash,
            persistable: self.persistable && other.persistable,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Visit {
    Active,
    Complete,
}

/// Immutable, exactly keyed type-definition environment.
#[derive(Clone, Debug)]
pub struct TypeEnvironment {
    definitions: BTreeMap<EntityId, TypeDefinition>,
}

impl TypeEnvironment {
    /// Constructs and fully validates an environment.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic structural, reference, cycle, trait, or
    /// resource-limit failure.
    pub fn new(definitions: Vec<TypeDefinition>) -> Result<Self> {
        if definitions.len() > MAX_DEFINITIONS {
            return fail(TypeErrorCode::ResourceLimit);
        }

        let mut by_id = BTreeMap::new();
        for definition in definitions {
            if by_id.insert(definition.entity_id, definition).is_some() {
                return fail(TypeErrorCode::DefinitionDuplicate);
            }
        }

        let environment = Self { definitions: by_id };
        for definition in environment.definitions.values() {
            environment.check_definition_shape(definition)?;
        }
        environment.reject_definition_cycles()?;
        for definition in environment.definitions.values() {
            environment.check_definition_map_keys(definition)?;
        }
        Ok(environment)
    }

    /// Returns the exact definition or `TYPE_DEFINITION_UNKNOWN`.
    ///
    /// # Errors
    ///
    /// Returns `TYPE_DEFINITION_UNKNOWN` when the identity is absent.
    pub fn definition(&self, id: EntityId) -> Result<&TypeDefinition> {
        self.definitions
            .get(&id)
            .ok_or_else(|| TypeError::new(TypeErrorCode::DefinitionUnknown))
    }

    /// Checks a type under an exact number of declaration parameters.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic well-formedness or limit failure.
    pub fn check_type(&self, value: &TypeExpr, parameter_count: u32) -> Result<()> {
        self.check_type_inner(value, parameter_count, 1)?;
        self.check_map_keys(value, 1)
    }

    /// Checks a type with no free parameters.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic closed-type failure.
    pub fn check_closed_type(&self, value: &TypeExpr) -> Result<()> {
        self.check_type(value, 0)
    }

    /// Computes traits for one closed, well-formed type.
    ///
    /// # Errors
    ///
    /// Returns a well-formedness, resolution, cycle-depth, or map-key failure.
    pub fn traits(&self, value: &TypeExpr) -> Result<TypeTraits> {
        self.check_closed_type(value)?;
        self.traits_inner(value, 1)
    }

    /// Requires epoch-1 total ordering for a closed type.
    ///
    /// # Errors
    ///
    /// Returns `TYPE_NOT_ORDERABLE` or an earlier type failure.
    pub fn require_orderable(&self, value: &TypeExpr) -> Result<()> {
        if self.traits(value)?.total_order {
            Ok(())
        } else {
            fail(TypeErrorCode::NotOrderable)
        }
    }

    /// Requires canonical value hashing for a closed type.
    ///
    /// # Errors
    ///
    /// Returns `TYPE_NOT_HASHABLE` or an earlier type failure.
    pub fn require_hashable(&self, value: &TypeExpr) -> Result<()> {
        if self.traits(value)?.canonical_hash {
            Ok(())
        } else {
            fail(TypeErrorCode::NotHashable)
        }
    }

    /// Requires persistence in a canonical constant or entity value.
    ///
    /// # Errors
    ///
    /// Returns `TYPE_NOT_PERSISTABLE` or an earlier type failure.
    pub fn require_persistable(&self, value: &TypeExpr) -> Result<()> {
        if self.traits(value)?.persistable {
            Ok(())
        } else {
            fail(TypeErrorCode::NotPersistable)
        }
    }

    /// Explicitly substitutes a complete ordered argument list.
    ///
    /// # Errors
    ///
    /// Returns an argument, substitution, well-formedness, or limit failure.
    pub fn instantiate(&self, value: &TypeExpr, arguments: &[TypeExpr]) -> Result<TypeExpr> {
        self.instantiate_in_scope(value, arguments, 0)
    }

    /// Explicitly substitutes arguments that may use a caller parameter scope.
    ///
    /// # Errors
    ///
    /// Returns an argument, substitution, well-formedness, or limit failure.
    pub fn instantiate_in_scope(
        &self,
        value: &TypeExpr,
        arguments: &[TypeExpr],
        parameter_count: u32,
    ) -> Result<TypeExpr> {
        if arguments.len() > MAX_TYPE_ARGUMENTS {
            return fail(TypeErrorCode::ArgumentLimit);
        }
        for argument in arguments {
            self.check_type(argument, parameter_count)?;
        }
        let instantiated = substitute(value, arguments, 1)?;
        self.check_type(&instantiated, parameter_count)?;
        Ok(instantiated)
    }

    /// Checks one constant and its recursively declared types.
    ///
    /// # Errors
    ///
    /// Returns the first deterministic type, shape, range, canonicality, or
    /// resource-limit failure.
    pub fn check_constant(&self, value: &ConstValue) -> Result<()> {
        self.check_closed_type(&value.value_type)?;
        if !self.traits(&value.value_type)?.persistable {
            return fail(TypeErrorCode::NotPersistable);
        }
        self.check_constant_as(value, &value.value_type, 1)
    }

    fn check_definition_shape(&self, definition: &TypeDefinition) -> Result<()> {
        if definition.type_parameters.len() > MAX_TYPE_ARGUMENTS {
            return fail(TypeErrorCode::ArgumentLimit);
        }
        for (index, parameter) in definition.type_parameters.iter().enumerate() {
            if usize::try_from(parameter.ordinal).ok() != Some(index) {
                return fail(TypeErrorCode::ParameterOutOfScope);
            }
        }
        ensure_sorted_unique(&definition.invariants)?;

        let parameter_count = u32::try_from(definition.type_parameters.len())
            .map_err(|_| TypeError::new(TypeErrorCode::ArgumentLimit))?;
        let mut members = BTreeSet::new();
        match &definition.form {
            TypeDefForm::Record(fields) => {
                if fields.len() > MAX_MEMBERS {
                    return fail(TypeErrorCode::ResourceLimit);
                }
                for field in fields {
                    if !members.insert(field.member_id) {
                        return fail(TypeErrorCode::MemberDuplicate);
                    }
                    self.check_type_inner(&field.value_type, parameter_count, 1)?;
                }
            }
            TypeDefForm::Variant(cases) => {
                if cases.len() > MAX_MEMBERS {
                    return fail(TypeErrorCode::ResourceLimit);
                }
                for case in cases {
                    if !members.insert(case.member_id) {
                        return fail(TypeErrorCode::MemberDuplicate);
                    }
                    if let Some(payload) = &case.payload_type {
                        self.check_type_inner(payload, parameter_count, 1)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn check_definition_map_keys(&self, definition: &TypeDefinition) -> Result<()> {
        match &definition.form {
            TypeDefForm::Record(fields) => {
                for field in fields {
                    self.check_map_keys(&field.value_type, 1)?;
                }
            }
            TypeDefForm::Variant(cases) => {
                for case in cases {
                    if let Some(payload) = &case.payload_type {
                        self.check_map_keys(payload, 1)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn check_type_inner(&self, value: &TypeExpr, parameter_count: u32, depth: usize) -> Result<()> {
        check_depth(depth)?;
        match value {
            TypeExpr::SInt(width) | TypeExpr::UInt(width) => check_width(*width),
            TypeExpr::Tuple(elements) => {
                if elements.len() > MAX_TUPLE_ITEMS {
                    return fail(TypeErrorCode::ResourceLimit);
                }
                for element in elements {
                    self.check_type_inner(element, parameter_count, depth + 1)?;
                }
                Ok(())
            }
            TypeExpr::Named(named) => {
                if named.arguments.len() > MAX_TYPE_ARGUMENTS {
                    return fail(TypeErrorCode::ArgumentLimit);
                }
                let definition = self.definition(named.definition)?;
                if named.arguments.len() != definition.type_parameters.len() {
                    return fail(TypeErrorCode::ArgumentArity);
                }
                for argument in &named.arguments {
                    self.check_type_inner(argument, parameter_count, depth + 1)?;
                }
                Ok(())
            }
            TypeExpr::Vector(element)
            | TypeExpr::Option(element)
            | TypeExpr::LocalCell(element) => {
                self.check_type_inner(element, parameter_count, depth + 1)
            }
            TypeExpr::OrderedMap { key, value } => {
                self.check_type_inner(key, parameter_count, depth + 1)?;
                self.check_type_inner(value, parameter_count, depth + 1)
            }
            TypeExpr::Result { ok, error } => {
                self.check_type_inner(ok, parameter_count, depth + 1)?;
                self.check_type_inner(error, parameter_count, depth + 1)
            }
            TypeExpr::FunctionRef(function) => {
                if function.parameters.len() > MAX_MEMBERS {
                    return fail(TypeErrorCode::ResourceLimit);
                }
                ensure_sorted_unique(&function.effects)?;
                for parameter in &function.parameters {
                    self.check_type_inner(parameter, parameter_count, depth + 1)?;
                }
                self.check_type_inner(&function.result, parameter_count, depth + 1)
            }
            TypeExpr::TypeParameter(index) if *index >= parameter_count => {
                fail(TypeErrorCode::ParameterOutOfScope)
            }
            TypeExpr::Unit
            | TypeExpr::Bool
            | TypeExpr::F32
            | TypeExpr::F64
            | TypeExpr::Bytes
            | TypeExpr::Text
            | TypeExpr::AdapterHandle(_)
            | TypeExpr::CapabilityToken(_)
            | TypeExpr::TypeParameter(_)
            | TypeExpr::BuiltinFailure(_) => Ok(()),
        }
    }

    fn check_map_keys(&self, value: &TypeExpr, depth: usize) -> Result<()> {
        check_depth(depth)?;
        match value {
            TypeExpr::OrderedMap { key, value } => {
                self.check_map_keys(key, depth + 1)?;
                self.check_map_keys(value, depth + 1)?;
                if contains_parameter(key) {
                    return fail(TypeErrorCode::NotOrderable);
                }
                require_map_key_traits(self.traits_inner(key, depth + 1)?)?;
                Ok(())
            }
            TypeExpr::Named(named) => {
                if named.arguments.iter().any(contains_parameter) {
                    return Ok(());
                }
                let definition = self.definition(named.definition)?;
                match &definition.form {
                    TypeDefForm::Record(fields) => {
                        for field in fields {
                            let field_type =
                                substitute(&field.value_type, &named.arguments, depth + 1)?;
                            self.check_map_keys(&field_type, depth + 1)?;
                        }
                    }
                    TypeDefForm::Variant(cases) => {
                        for case in cases {
                            if let Some(payload) = &case.payload_type {
                                let payload = substitute(payload, &named.arguments, depth + 1)?;
                                self.check_map_keys(&payload, depth + 1)?;
                            }
                        }
                    }
                }
                Ok(())
            }
            TypeExpr::Tuple(elements) => {
                for element in elements {
                    self.check_map_keys(element, depth + 1)?;
                }
                Ok(())
            }
            TypeExpr::Vector(element)
            | TypeExpr::Option(element)
            | TypeExpr::LocalCell(element) => self.check_map_keys(element, depth + 1),
            TypeExpr::Result { ok, error } => {
                self.check_map_keys(ok, depth + 1)?;
                self.check_map_keys(error, depth + 1)
            }
            TypeExpr::FunctionRef(function) => {
                for parameter in &function.parameters {
                    self.check_map_keys(parameter, depth + 1)?;
                }
                self.check_map_keys(&function.result, depth + 1)
            }
            _ => Ok(()),
        }
    }

    fn traits_inner(&self, value: &TypeExpr, depth: usize) -> Result<TypeTraits> {
        check_depth(depth)?;
        match value {
            TypeExpr::Unit
            | TypeExpr::Bool
            | TypeExpr::SInt(_)
            | TypeExpr::UInt(_)
            | TypeExpr::Bytes
            | TypeExpr::Text
            | TypeExpr::BuiltinFailure(_) => Ok(TypeTraits::ALL),
            TypeExpr::F32 | TypeExpr::F64 => Ok(TypeTraits {
                total_order: false,
                ..TypeTraits::ALL
            }),
            TypeExpr::Tuple(elements) => self.combine_traits(elements.iter(), depth + 1),
            TypeExpr::Named(named) => {
                let definition = self.definition(named.definition)?;
                let mut combined = TypeTraits::ALL;
                match &definition.form {
                    TypeDefForm::Record(fields) => {
                        for field in fields {
                            let field_type =
                                substitute(&field.value_type, &named.arguments, depth + 1)?;
                            combined = combined.combine(self.traits_inner(&field_type, depth + 1)?);
                        }
                    }
                    TypeDefForm::Variant(cases) => {
                        for case in cases {
                            if let Some(payload) = &case.payload_type {
                                let payload = substitute(payload, &named.arguments, depth + 1)?;
                                combined =
                                    combined.combine(self.traits_inner(&payload, depth + 1)?);
                            }
                        }
                    }
                }
                Ok(combined)
            }
            TypeExpr::Vector(element) => {
                let element = self.traits_inner(element, depth + 1)?;
                Ok(TypeTraits {
                    total_order: false,
                    ..element
                })
            }
            TypeExpr::OrderedMap { key, value } => {
                let key = self.traits_inner(key, depth + 1)?;
                require_map_key_traits(key)?;
                let combined = key.combine(self.traits_inner(value, depth + 1)?);
                Ok(TypeTraits {
                    total_order: false,
                    ..combined
                })
            }
            TypeExpr::Option(element) => self.traits_inner(element, depth + 1),
            TypeExpr::Result { ok, error } => Ok(self
                .traits_inner(ok, depth + 1)?
                .combine(self.traits_inner(error, depth + 1)?)),
            TypeExpr::FunctionRef(_) => Ok(TypeTraits {
                equality: true,
                total_order: false,
                canonical_hash: true,
                persistable: true,
            }),
            TypeExpr::AdapterHandle(_) | TypeExpr::CapabilityToken(_) => Ok(TypeTraits {
                equality: true,
                total_order: false,
                canonical_hash: false,
                persistable: false,
            }),
            TypeExpr::LocalCell(_) => Ok(TypeTraits {
                equality: false,
                total_order: false,
                canonical_hash: false,
                persistable: false,
            }),
            TypeExpr::TypeParameter(_) => fail(TypeErrorCode::ParameterOutOfScope),
        }
    }

    fn combine_traits<'a>(
        &self,
        values: impl Iterator<Item = &'a TypeExpr>,
        depth: usize,
    ) -> Result<TypeTraits> {
        let mut combined = TypeTraits::ALL;
        for value in values {
            combined = combined.combine(self.traits_inner(value, depth)?);
        }
        Ok(combined)
    }

    fn reject_definition_cycles(&self) -> Result<()> {
        let mut visits = BTreeMap::new();
        for id in self.definitions.keys().copied() {
            self.visit_definition(id, &mut visits, 1)?;
        }
        Ok(())
    }

    fn visit_definition(
        &self,
        id: EntityId,
        visits: &mut BTreeMap<EntityId, Visit>,
        depth: usize,
    ) -> Result<()> {
        check_depth(depth)?;
        match visits.get(&id) {
            Some(Visit::Active) => return fail(TypeErrorCode::DefinitionCycle),
            Some(Visit::Complete) => return Ok(()),
            None => {}
        }
        visits.insert(id, Visit::Active);

        let definition = self.definition(id)?;
        let mut dependencies = BTreeSet::new();
        match &definition.form {
            TypeDefForm::Record(fields) => {
                for field in fields {
                    collect_named_dependencies(&field.value_type, &mut dependencies);
                }
            }
            TypeDefForm::Variant(cases) => {
                for case in cases {
                    if let Some(payload) = &case.payload_type {
                        collect_named_dependencies(payload, &mut dependencies);
                    }
                }
            }
        }
        for dependency in dependencies {
            self.definition(dependency)?;
            self.visit_definition(dependency, visits, depth + 1)?;
        }
        visits.insert(id, Visit::Complete);
        Ok(())
    }

    fn check_constant_as(
        &self,
        value: &ConstValue,
        expected: &TypeExpr,
        depth: usize,
    ) -> Result<()> {
        check_depth(depth)?;
        if &value.value_type != expected {
            return fail(TypeErrorCode::ImplicitCoercion);
        }
        match (expected, &value.data) {
            (TypeExpr::Unit, ConstData::Unit) | (TypeExpr::Bool, ConstData::Bool(_)) => Ok(()),
            (TypeExpr::SInt(width), ConstData::SInt(number)) => check_signed_range(*width, *number),
            (TypeExpr::UInt(width), ConstData::UInt(number)) => {
                check_unsigned_range(*width, *number)
            }
            (TypeExpr::F32, ConstData::F32Bits(bits)) => check_f32(*bits),
            (TypeExpr::F64, ConstData::F64Bits(bits)) => check_f64(*bits),
            (TypeExpr::Bytes, ConstData::Bytes(bytes)) => check_payload_len(bytes.len()),
            (TypeExpr::Text, ConstData::Text(text)) => check_payload_len(text.len()),
            (TypeExpr::Tuple(types), ConstData::Sequence(values)) => {
                if values.len() != types.len() {
                    return fail(TypeErrorCode::ConstShape);
                }
                for (item, item_type) in values.iter().zip(types) {
                    self.check_constant_as(item, item_type, depth + 1)?;
                }
                Ok(())
            }
            (TypeExpr::Vector(element), ConstData::Sequence(values)) => {
                check_collection_len(values.len())?;
                for item in values {
                    self.check_constant_as(item, element, depth + 1)?;
                }
                Ok(())
            }
            (TypeExpr::Named(named), ConstData::Record(record)) => {
                self.check_record_constant(named, record, depth + 1)
            }
            (TypeExpr::Named(named), ConstData::Variant(variant)) => {
                self.check_variant_constant(named, variant, depth + 1)
            }
            (TypeExpr::OrderedMap { key, value }, ConstData::Map(entries)) => {
                self.check_map_constant(entries, key, value, depth + 1)
            }
            (TypeExpr::Option(element), ConstData::Option(item)) => {
                if let Some(item) = item {
                    self.check_constant_as(item, element, depth + 1)?;
                }
                Ok(())
            }
            (TypeExpr::Result { ok, .. }, ConstData::Result(ResultConst::Ok(value))) => {
                self.check_constant_as(value, ok, depth + 1)
            }
            (TypeExpr::Result { error, .. }, ConstData::Result(ResultConst::Err(value))) => {
                self.check_constant_as(value, error, depth + 1)
            }
            (TypeExpr::FunctionRef(_), ConstData::FunctionRef(reference)) => {
                if reference.type_arguments.len() > MAX_TYPE_ARGUMENTS {
                    return fail(TypeErrorCode::ArgumentLimit);
                }
                for argument in &reference.type_arguments {
                    self.check_closed_type(argument)?;
                }
                Ok(())
            }
            (TypeExpr::BuiltinFailure(kind), ConstData::BuiltinFailure(failure))
                if kind == &failure.kind =>
            {
                check_builtin_failure(failure.kind, failure.code)
            }
            (
                TypeExpr::AdapterHandle(_)
                | TypeExpr::CapabilityToken(_)
                | TypeExpr::LocalCell(_)
                | TypeExpr::TypeParameter(_),
                _,
            ) => fail(TypeErrorCode::NotPersistable),
            _ => fail(TypeErrorCode::ConstShape),
        }
    }

    fn check_record_constant(
        &self,
        named: &sley_ssmc::NamedType,
        record: &sley_ssmc::RecordConst,
        depth: usize,
    ) -> Result<()> {
        if named.definition != record.definition {
            return fail(TypeErrorCode::ImplicitCoercion);
        }
        let definition = self.definition(named.definition)?;
        let TypeDefForm::Record(fields) = &definition.form else {
            return fail(TypeErrorCode::ConstShape);
        };
        if fields.len() != record.fields.len() {
            return fail(TypeErrorCode::ConstShape);
        }
        for (field, value) in fields.iter().zip(&record.fields) {
            if field.member_id != value.member_id {
                return fail(TypeErrorCode::MemberUnknown);
            }
            let field_type = substitute(&field.value_type, &named.arguments, depth + 1)?;
            self.check_constant_as(&value.value, &field_type, depth + 1)?;
        }
        Ok(())
    }

    fn check_variant_constant(
        &self,
        named: &sley_ssmc::NamedType,
        variant: &sley_ssmc::VariantConst,
        depth: usize,
    ) -> Result<()> {
        if named.definition != variant.definition {
            return fail(TypeErrorCode::ImplicitCoercion);
        }
        let definition = self.definition(named.definition)?;
        let TypeDefForm::Variant(cases) = &definition.form else {
            return fail(TypeErrorCode::ConstShape);
        };
        let case = cases
            .iter()
            .find(|case| case.member_id == variant.member_id)
            .ok_or_else(|| TypeError::new(TypeErrorCode::MemberUnknown))?;
        match (&case.payload_type, &variant.payload) {
            (None, None) => Ok(()),
            (Some(expected), Some(value)) => {
                let expected = substitute(expected, &named.arguments, depth + 1)?;
                self.check_constant_as(value, &expected, depth + 1)
            }
            _ => fail(TypeErrorCode::ConstShape),
        }
    }

    fn check_map_constant(
        &self,
        entries: &[sley_ssmc::MapEntryConst],
        key_type: &TypeExpr,
        value_type: &TypeExpr,
        depth: usize,
    ) -> Result<()> {
        check_collection_len(entries.len())?;
        require_map_key_traits(self.traits(key_type)?)?;
        for (index, entry) in entries.iter().enumerate() {
            self.check_constant_as(&entry.key, key_type, depth + 1)?;
            self.check_constant_as(&entry.value, value_type, depth + 1)?;
            if entries[..index]
                .iter()
                .any(|previous| previous.key == entry.key)
            {
                return fail(TypeErrorCode::ConstDuplicateKey);
            }
        }
        Ok(())
    }
}

fn fail<T>(code: TypeErrorCode) -> Result<T> {
    Err(TypeError::new(code))
}

fn check_depth(depth: usize) -> Result<()> {
    if depth > MAX_TYPE_DEPTH {
        fail(TypeErrorCode::DepthLimit)
    } else {
        Ok(())
    }
}

fn check_width(width: IntegerWidth) -> Result<()> {
    if width.is_epoch_1() {
        Ok(())
    } else {
        fail(TypeErrorCode::WidthInvalid)
    }
}

fn ensure_sorted_unique(values: &[EntityId]) -> Result<()> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        fail(TypeErrorCode::SetOrder)
    }
}

fn require_map_key_traits(traits: TypeTraits) -> Result<()> {
    if !traits.total_order {
        return fail(TypeErrorCode::NotOrderable);
    }
    if !traits.equality {
        return fail(TypeErrorCode::NotOrderable);
    }
    if !traits.canonical_hash {
        return fail(TypeErrorCode::NotHashable);
    }
    if !traits.persistable {
        return fail(TypeErrorCode::NotPersistable);
    }
    Ok(())
}

fn contains_parameter(value: &TypeExpr) -> bool {
    match value {
        TypeExpr::TypeParameter(_) => true,
        TypeExpr::Tuple(values) => values.iter().any(contains_parameter),
        TypeExpr::Named(named) => named.arguments.iter().any(contains_parameter),
        TypeExpr::Vector(value) | TypeExpr::Option(value) | TypeExpr::LocalCell(value) => {
            contains_parameter(value)
        }
        TypeExpr::OrderedMap { key, value } => contains_parameter(key) || contains_parameter(value),
        TypeExpr::Result { ok, error } => contains_parameter(ok) || contains_parameter(error),
        TypeExpr::FunctionRef(function) => {
            function.parameters.iter().any(contains_parameter)
                || contains_parameter(&function.result)
        }
        _ => false,
    }
}

fn collect_named_dependencies(value: &TypeExpr, dependencies: &mut BTreeSet<EntityId>) {
    match value {
        TypeExpr::Named(named) => {
            dependencies.insert(named.definition);
            for argument in &named.arguments {
                collect_named_dependencies(argument, dependencies);
            }
        }
        TypeExpr::Tuple(values) => {
            for value in values {
                collect_named_dependencies(value, dependencies);
            }
        }
        TypeExpr::Vector(value) | TypeExpr::Option(value) | TypeExpr::LocalCell(value) => {
            collect_named_dependencies(value, dependencies);
        }
        TypeExpr::OrderedMap { key, value } => {
            collect_named_dependencies(key, dependencies);
            collect_named_dependencies(value, dependencies);
        }
        TypeExpr::Result { ok, error } => {
            collect_named_dependencies(ok, dependencies);
            collect_named_dependencies(error, dependencies);
        }
        TypeExpr::FunctionRef(function) => {
            for parameter in &function.parameters {
                collect_named_dependencies(parameter, dependencies);
            }
            collect_named_dependencies(&function.result, dependencies);
        }
        _ => {}
    }
}

fn substitute(value: &TypeExpr, arguments: &[TypeExpr], depth: usize) -> Result<TypeExpr> {
    check_depth(depth)?;
    let next = depth + 1;
    Ok(match value {
        TypeExpr::TypeParameter(index) => arguments
            .get(
                usize::try_from(*index)
                    .map_err(|_| TypeError::new(TypeErrorCode::ParameterOutOfScope))?,
            )
            .cloned()
            .ok_or_else(|| TypeError::new(TypeErrorCode::ParameterOutOfScope))?,
        TypeExpr::Tuple(values) => TypeExpr::Tuple(
            values
                .iter()
                .map(|value| substitute(value, arguments, next))
                .collect::<Result<_>>()?,
        ),
        TypeExpr::Named(named) => TypeExpr::Named(sley_ssmc::NamedType {
            definition: named.definition,
            arguments: named
                .arguments
                .iter()
                .map(|value| substitute(value, arguments, next))
                .collect::<Result<_>>()?,
        }),
        TypeExpr::Vector(value) => TypeExpr::Vector(Box::new(substitute(value, arguments, next)?)),
        TypeExpr::OrderedMap { key, value } => TypeExpr::OrderedMap {
            key: Box::new(substitute(key, arguments, next)?),
            value: Box::new(substitute(value, arguments, next)?),
        },
        TypeExpr::Option(value) => TypeExpr::Option(Box::new(substitute(value, arguments, next)?)),
        TypeExpr::Result { ok, error } => TypeExpr::Result {
            ok: Box::new(substitute(ok, arguments, next)?),
            error: Box::new(substitute(error, arguments, next)?),
        },
        TypeExpr::FunctionRef(function) => TypeExpr::FunctionRef(sley_ssmc::FunctionType {
            parameters: function
                .parameters
                .iter()
                .map(|value| substitute(value, arguments, next))
                .collect::<Result<_>>()?,
            result: Box::new(substitute(&function.result, arguments, next)?),
            effects: function.effects.clone(),
        }),
        TypeExpr::LocalCell(value) => {
            TypeExpr::LocalCell(Box::new(substitute(value, arguments, next)?))
        }
        other => other.clone(),
    })
}

fn check_signed_range(width: IntegerWidth, value: i128) -> Result<()> {
    check_width(width)?;
    if width.bits() == 128 {
        return Ok(());
    }
    let shift = u32::from(width.bits() - 1);
    let limit = 1_i128 << shift;
    if (-limit..limit).contains(&value) {
        Ok(())
    } else {
        fail(TypeErrorCode::ConstRange)
    }
}

fn check_unsigned_range(width: IntegerWidth, value: u128) -> Result<()> {
    check_width(width)?;
    if width.bits() == 128 {
        return Ok(());
    }
    let limit = 1_u128 << u32::from(width.bits());
    if value < limit {
        Ok(())
    } else {
        fail(TypeErrorCode::ConstRange)
    }
}

fn check_f32(bits: u32) -> Result<()> {
    if bits == 0x8000_0000 {
        return fail(TypeErrorCode::FloatNonCanonical);
    }
    let is_nan = bits & 0x7f80_0000 == 0x7f80_0000 && bits & 0x007f_ffff != 0;
    if is_nan && bits != CANONICAL_F32_NAN {
        fail(TypeErrorCode::FloatNonCanonical)
    } else {
        Ok(())
    }
}

fn check_f64(bits: u64) -> Result<()> {
    if bits == 0x8000_0000_0000_0000 {
        return fail(TypeErrorCode::FloatNonCanonical);
    }
    let is_nan =
        bits & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000 && bits & 0x000f_ffff_ffff_ffff != 0;
    if is_nan && bits != CANONICAL_F64_NAN {
        fail(TypeErrorCode::FloatNonCanonical)
    } else {
        Ok(())
    }
}

fn check_payload_len(length: usize) -> Result<()> {
    if length > MAX_CONSTANT_PAYLOAD_BYTES {
        fail(TypeErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn check_collection_len(length: usize) -> Result<()> {
    if length > MAX_CONSTANT_ELEMENTS {
        fail(TypeErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

fn check_builtin_failure(kind: BuiltinFailureKind, code: u16) -> Result<()> {
    let valid = match kind {
        BuiltinFailureKind::Arithmetic => (1..=3).contains(&code),
        BuiltinFailureKind::Index
        | BuiltinFailureKind::DuplicateKey
        | BuiltinFailureKind::ContractViolation => code == 1,
        BuiltinFailureKind::Capability => (1..=4).contains(&code),
    };
    if valid {
        Ok(())
    } else {
        fail(TypeErrorCode::BuiltinFailureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sley_ssmc::{
        BuiltinFailureValue, FieldConst, FunctionRefValue, FunctionType, MapEntryConst, MemberId,
        NamedType, RecordConst, RecordField, TypeParameterDef, VariantCase, VariantConst,
        Visibility,
    };

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn member(byte: u8) -> MemberId {
        MemberId::from_bytes([byte; 32])
    }

    fn record_definition(entity_id: EntityId, field_type: TypeExpr) -> TypeDefinition {
        TypeDefinition {
            entity_id,
            type_parameters: Vec::new(),
            form: TypeDefForm::Record(vec![RecordField {
                member_id: member(1),
                value_type: field_type,
                visibility: Visibility::Private,
            }]),
            invariants: Vec::new(),
            visibility: Visibility::Private,
        }
    }

    fn generic_record(entity_id: EntityId) -> TypeDefinition {
        TypeDefinition {
            entity_id,
            type_parameters: vec![TypeParameterDef { ordinal: 0 }],
            form: TypeDefForm::Record(vec![RecordField {
                member_id: member(1),
                value_type: TypeExpr::TypeParameter(0),
                visibility: Visibility::Private,
            }]),
            invariants: Vec::new(),
            visibility: Visibility::Private,
        }
    }

    fn uint8(value: u128) -> ConstValue {
        ConstValue {
            value_type: TypeExpr::UInt(IntegerWidth::from_bits(8)),
            data: ConstData::UInt(value),
        }
    }

    #[test]
    fn empty_environment_accepts_every_closed_primitive() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        for value in [
            TypeExpr::Unit,
            TypeExpr::Bool,
            TypeExpr::SInt(IntegerWidth::from_bits(128)),
            TypeExpr::UInt(IntegerWidth::from_bits(8)),
            TypeExpr::F32,
            TypeExpr::F64,
            TypeExpr::Bytes,
            TypeExpr::Text,
            TypeExpr::BuiltinFailure(BuiltinFailureKind::Index),
        ] {
            environment.check_closed_type(&value).unwrap();
        }
    }

    #[test]
    fn invalid_width_and_free_parameter_fail_exactly() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        assert_eq!(
            environment
                .check_closed_type(&TypeExpr::UInt(IntegerWidth::from_bits(24)))
                .unwrap_err()
                .code(),
            TypeErrorCode::WidthInvalid
        );
        assert_eq!(
            environment
                .check_closed_type(&TypeExpr::TypeParameter(0))
                .unwrap_err()
                .code(),
            TypeErrorCode::ParameterOutOfScope
        );
    }

    #[test]
    fn structural_depth_is_closed() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let mut value = TypeExpr::Unit;
        for _ in 0..MAX_TYPE_DEPTH {
            value = TypeExpr::Option(Box::new(value));
        }
        assert_eq!(
            environment.check_closed_type(&value).unwrap_err().code(),
            TypeErrorCode::DepthLimit
        );
    }

    #[test]
    fn named_definition_expansion_depth_is_closed() {
        let mut definitions = Vec::new();
        for byte in 0_u8..65 {
            let field_type = if byte == 64 {
                TypeExpr::Unit
            } else {
                TypeExpr::Named(NamedType {
                    definition: id(byte + 1),
                    arguments: Vec::new(),
                })
            };
            definitions.push(record_definition(id(byte), field_type));
        }
        assert_eq!(
            TypeEnvironment::new(definitions).unwrap_err().code(),
            TypeErrorCode::DepthLimit
        );
    }

    #[test]
    fn duplicate_definitions_and_members_fail() {
        let definition = record_definition(id(1), TypeExpr::Unit);
        assert_eq!(
            TypeEnvironment::new(vec![definition.clone(), definition])
                .unwrap_err()
                .code(),
            TypeErrorCode::DefinitionDuplicate
        );

        let duplicate_members = TypeDefinition {
            entity_id: id(2),
            type_parameters: Vec::new(),
            form: TypeDefForm::Variant(vec![
                VariantCase {
                    member_id: member(1),
                    payload_type: None,
                },
                VariantCase {
                    member_id: member(1),
                    payload_type: Some(TypeExpr::Unit),
                },
            ]),
            invariants: Vec::new(),
            visibility: Visibility::Private,
        };
        assert_eq!(
            TypeEnvironment::new(vec![duplicate_members])
                .unwrap_err()
                .code(),
            TypeErrorCode::MemberDuplicate
        );
    }

    #[test]
    fn direct_and_indirect_definition_cycles_fail() {
        let direct = record_definition(
            id(1),
            TypeExpr::Named(NamedType {
                definition: id(1),
                arguments: Vec::new(),
            }),
        );
        assert_eq!(
            TypeEnvironment::new(vec![direct]).unwrap_err().code(),
            TypeErrorCode::DefinitionCycle
        );

        let left = record_definition(
            id(2),
            TypeExpr::Option(Box::new(TypeExpr::Named(NamedType {
                definition: id(3),
                arguments: Vec::new(),
            }))),
        );
        let right = record_definition(
            id(3),
            TypeExpr::LocalCell(Box::new(TypeExpr::Named(NamedType {
                definition: id(2),
                arguments: Vec::new(),
            }))),
        );
        assert_eq!(
            TypeEnvironment::new(vec![right, left]).unwrap_err().code(),
            TypeErrorCode::DefinitionCycle
        );
    }

    #[test]
    fn exact_named_arity_and_unknown_definition_fail() {
        let environment = TypeEnvironment::new(vec![generic_record(id(1))]).unwrap();
        assert_eq!(
            environment
                .check_closed_type(&TypeExpr::Named(NamedType {
                    definition: id(1),
                    arguments: Vec::new(),
                }))
                .unwrap_err()
                .code(),
            TypeErrorCode::ArgumentArity
        );
        assert_eq!(
            environment
                .check_closed_type(&TypeExpr::Named(NamedType {
                    definition: id(9),
                    arguments: Vec::new(),
                }))
                .unwrap_err()
                .code(),
            TypeErrorCode::DefinitionUnknown
        );
    }

    #[test]
    fn explicit_substitution_is_invariant_and_input_immutable() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let input = TypeExpr::Tuple(vec![
            TypeExpr::TypeParameter(0),
            TypeExpr::Option(Box::new(TypeExpr::TypeParameter(1))),
        ]);
        let original = input.clone();
        let result = environment
            .instantiate(&input, &[TypeExpr::Bool, TypeExpr::Bytes])
            .unwrap();
        assert_eq!(input, original);
        assert_eq!(
            result,
            TypeExpr::Tuple(vec![
                TypeExpr::Bool,
                TypeExpr::Option(Box::new(TypeExpr::Bytes))
            ])
        );
    }

    #[test]
    fn effect_and_invariant_sets_must_be_strictly_sorted() {
        let function = TypeExpr::FunctionRef(FunctionType {
            parameters: Vec::new(),
            result: Box::new(TypeExpr::Unit),
            effects: vec![id(2), id(1)],
        });
        assert_eq!(
            TypeEnvironment::new(Vec::new())
                .unwrap()
                .check_closed_type(&function)
                .unwrap_err()
                .code(),
            TypeErrorCode::SetOrder
        );

        let mut definition = record_definition(id(3), TypeExpr::Unit);
        definition.invariants = vec![id(2), id(1)];
        assert_eq!(
            TypeEnvironment::new(vec![definition]).unwrap_err().code(),
            TypeErrorCode::SetOrder
        );
    }

    #[test]
    fn map_keys_require_all_closed_traits() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        for key in [
            TypeExpr::F64,
            TypeExpr::Vector(Box::new(TypeExpr::UInt(IntegerWidth::from_bits(8)))),
            TypeExpr::FunctionRef(FunctionType {
                parameters: Vec::new(),
                result: Box::new(TypeExpr::Unit),
                effects: Vec::new(),
            }),
            TypeExpr::CapabilityToken(id(1)),
        ] {
            assert_eq!(
                environment
                    .check_closed_type(&TypeExpr::OrderedMap {
                        key: Box::new(key),
                        value: Box::new(TypeExpr::Unit),
                    })
                    .unwrap_err()
                    .code(),
                TypeErrorCode::NotOrderable
            );
        }
    }

    #[test]
    fn generic_map_key_without_trait_bounds_fails_closed() {
        let definition = TypeDefinition {
            entity_id: id(1),
            type_parameters: vec![TypeParameterDef { ordinal: 0 }],
            form: TypeDefForm::Record(vec![RecordField {
                member_id: member(1),
                value_type: TypeExpr::OrderedMap {
                    key: Box::new(TypeExpr::TypeParameter(0)),
                    value: Box::new(TypeExpr::Unit),
                },
                visibility: Visibility::Private,
            }]),
            invariants: Vec::new(),
            visibility: Visibility::Private,
        };
        assert_eq!(
            TypeEnvironment::new(vec![definition]).unwrap_err().code(),
            TypeErrorCode::NotOrderable
        );
    }

    #[test]
    fn traits_resolve_instantiated_named_members() {
        let environment = TypeEnvironment::new(vec![generic_record(id(1))]).unwrap();
        let named = TypeExpr::Named(NamedType {
            definition: id(1),
            arguments: vec![TypeExpr::F32],
        });
        assert_eq!(
            environment.traits(&named).unwrap(),
            TypeTraits {
                equality: true,
                total_order: false,
                canonical_hash: true,
                persistable: true,
            }
        );
    }

    #[test]
    fn nonpersistable_traits_are_explicit() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let handle = environment.traits(&TypeExpr::AdapterHandle(id(1))).unwrap();
        assert!(handle.equality);
        assert!(!handle.total_order);
        assert!(!handle.canonical_hash);
        assert!(!handle.persistable);
        assert_eq!(
            environment
                .traits(&TypeExpr::LocalCell(Box::new(TypeExpr::Unit)))
                .unwrap(),
            TypeTraits {
                equality: false,
                total_order: false,
                canonical_hash: false,
                persistable: false,
            }
        );
        assert_eq!(
            environment
                .require_hashable(&TypeExpr::CapabilityToken(id(1)))
                .unwrap_err()
                .code(),
            TypeErrorCode::NotHashable
        );
        assert_eq!(
            environment
                .require_persistable(&TypeExpr::AdapterHandle(id(1)))
                .unwrap_err()
                .code(),
            TypeErrorCode::NotPersistable
        );
    }

    #[test]
    fn argument_and_collection_limits_fail_before_deeper_judgment() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let oversized_arguments = vec![TypeExpr::Unit; MAX_TYPE_ARGUMENTS + 1];
        assert_eq!(
            environment
                .instantiate(&TypeExpr::Unit, &oversized_arguments)
                .unwrap_err()
                .code(),
            TypeErrorCode::ArgumentLimit
        );

        let oversized_tuple = TypeExpr::Tuple(vec![TypeExpr::Unit; MAX_TUPLE_ITEMS + 1]);
        assert_eq!(
            environment
                .check_closed_type(&oversized_tuple)
                .unwrap_err()
                .code(),
            TypeErrorCode::ResourceLimit
        );
    }

    #[test]
    fn integer_constants_enforce_width_without_coercion() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        environment.check_constant(&uint8(255)).unwrap();
        assert_eq!(
            environment.check_constant(&uint8(256)).unwrap_err().code(),
            TypeErrorCode::ConstRange
        );
        let wrong = ConstValue {
            value_type: TypeExpr::UInt(IntegerWidth::from_bits(8)),
            data: ConstData::SInt(1),
        };
        assert_eq!(
            environment.check_constant(&wrong).unwrap_err().code(),
            TypeErrorCode::ConstShape
        );
    }

    #[test]
    fn floats_accept_only_canonical_nan_and_positive_zero() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        for bits in [0_u32, 1, CANONICAL_F32_NAN, 0x7f80_0000] {
            environment
                .check_constant(&ConstValue {
                    value_type: TypeExpr::F32,
                    data: ConstData::F32Bits(bits),
                })
                .unwrap();
        }
        for bits in [0x8000_0000, 0x7fc0_0001, 0xffc0_0000] {
            assert_eq!(
                environment
                    .check_constant(&ConstValue {
                        value_type: TypeExpr::F32,
                        data: ConstData::F32Bits(bits),
                    })
                    .unwrap_err()
                    .code(),
                TypeErrorCode::FloatNonCanonical
            );
        }
    }

    #[test]
    fn tuple_constant_rejects_implicit_element_coercion() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let value = ConstValue {
            value_type: TypeExpr::Tuple(vec![TypeExpr::UInt(IntegerWidth::from_bits(16))]),
            data: ConstData::Sequence(vec![uint8(1)]),
        };
        assert_eq!(
            environment.check_constant(&value).unwrap_err().code(),
            TypeErrorCode::ImplicitCoercion
        );
    }

    #[test]
    fn collection_and_sum_constants_match_exactly() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let vector_type = TypeExpr::Vector(Box::new(TypeExpr::Bool));
        environment
            .check_constant(&ConstValue {
                value_type: vector_type,
                data: ConstData::Sequence(vec![ConstValue {
                    value_type: TypeExpr::Bool,
                    data: ConstData::Bool(true),
                }]),
            })
            .unwrap();
        environment
            .check_constant(&ConstValue {
                value_type: TypeExpr::Option(Box::new(TypeExpr::Text)),
                data: ConstData::Option(Some(Box::new(ConstValue {
                    value_type: TypeExpr::Text,
                    data: ConstData::Text("e\u{301}".to_owned()),
                }))),
            })
            .unwrap();
        environment
            .check_constant(&ConstValue {
                value_type: TypeExpr::Result {
                    ok: Box::new(TypeExpr::Bytes),
                    error: Box::new(TypeExpr::Bool),
                },
                data: ConstData::Result(ResultConst::Ok(Box::new(ConstValue {
                    value_type: TypeExpr::Bytes,
                    data: ConstData::Bytes(vec![0, 1, 2]),
                }))),
            })
            .unwrap();
    }

    #[test]
    fn record_and_variant_constants_bind_exact_members() {
        let record_id = id(1);
        let variant_id = id(2);
        let record = record_definition(record_id, TypeExpr::Bool);
        let variant = TypeDefinition {
            entity_id: variant_id,
            type_parameters: Vec::new(),
            form: TypeDefForm::Variant(vec![VariantCase {
                member_id: member(2),
                payload_type: Some(TypeExpr::Text),
            }]),
            invariants: Vec::new(),
            visibility: Visibility::Private,
        };
        let environment = TypeEnvironment::new(vec![variant, record]).unwrap();

        environment
            .check_constant(&ConstValue {
                value_type: TypeExpr::Named(NamedType {
                    definition: record_id,
                    arguments: Vec::new(),
                }),
                data: ConstData::Record(RecordConst {
                    definition: record_id,
                    fields: vec![FieldConst {
                        member_id: member(1),
                        value: ConstValue {
                            value_type: TypeExpr::Bool,
                            data: ConstData::Bool(true),
                        },
                    }],
                }),
            })
            .unwrap();

        let bad_variant = ConstValue {
            value_type: TypeExpr::Named(NamedType {
                definition: variant_id,
                arguments: Vec::new(),
            }),
            data: ConstData::Variant(VariantConst {
                definition: variant_id,
                member_id: member(9),
                payload: None,
            }),
        };
        assert_eq!(
            environment.check_constant(&bad_variant).unwrap_err().code(),
            TypeErrorCode::MemberUnknown
        );
    }

    #[test]
    fn map_constants_reject_duplicate_semantic_keys() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let map_type = TypeExpr::OrderedMap {
            key: Box::new(TypeExpr::UInt(IntegerWidth::from_bits(8))),
            value: Box::new(TypeExpr::Bool),
        };
        let entry = MapEntryConst {
            key: uint8(1),
            value: ConstValue {
                value_type: TypeExpr::Bool,
                data: ConstData::Bool(true),
            },
        };
        let map = ConstValue {
            value_type: map_type,
            data: ConstData::Map(vec![entry.clone(), entry]),
        };
        assert_eq!(
            environment.check_constant(&map).unwrap_err().code(),
            TypeErrorCode::ConstDuplicateKey
        );
    }

    #[test]
    fn nonpersistable_constant_fails_before_shape() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let value = ConstValue {
            value_type: TypeExpr::CapabilityToken(id(1)),
            data: ConstData::Unit,
        };
        assert_eq!(
            environment.check_constant(&value).unwrap_err().code(),
            TypeErrorCode::NotPersistable
        );
    }

    #[test]
    fn builtin_failure_codes_are_closed() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let valid = ConstValue {
            value_type: TypeExpr::BuiltinFailure(BuiltinFailureKind::Capability),
            data: ConstData::BuiltinFailure(BuiltinFailureValue {
                kind: BuiltinFailureKind::Capability,
                code: 4,
            }),
        };
        environment.check_constant(&valid).unwrap();
        let mut invalid = valid;
        invalid.data = ConstData::BuiltinFailure(BuiltinFailureValue {
            kind: BuiltinFailureKind::Capability,
            code: 5,
        });
        assert_eq!(
            environment.check_constant(&invalid).unwrap_err().code(),
            TypeErrorCode::BuiltinFailureInvalid
        );
    }

    #[test]
    fn function_reference_constant_has_no_host_identity() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        environment
            .check_constant(&ConstValue {
                value_type: TypeExpr::FunctionRef(FunctionType {
                    parameters: vec![TypeExpr::Bool],
                    result: Box::new(TypeExpr::Unit),
                    effects: Vec::new(),
                }),
                data: ConstData::FunctionRef(FunctionRefValue {
                    function: id(7),
                    type_arguments: vec![TypeExpr::Bytes],
                }),
            })
            .unwrap();
    }

    #[test]
    fn definition_insertion_order_does_not_change_traits() {
        let left = record_definition(id(1), TypeExpr::Bool);
        let right = record_definition(
            id(2),
            TypeExpr::Named(NamedType {
                definition: id(1),
                arguments: Vec::new(),
            }),
        );
        let first = TypeEnvironment::new(vec![left.clone(), right.clone()]).unwrap();
        let second = TypeEnvironment::new(vec![right, left]).unwrap();
        let target = TypeExpr::Named(NamedType {
            definition: id(2),
            arguments: Vec::new(),
        });
        assert_eq!(
            first.traits(&target).unwrap(),
            second.traits(&target).unwrap()
        );
    }

    #[test]
    fn stable_codes_and_numeric_range_are_frozen() {
        let codes = [
            TypeErrorCode::DepthLimit,
            TypeErrorCode::WidthInvalid,
            TypeErrorCode::ParameterOutOfScope,
            TypeErrorCode::ArgumentLimit,
            TypeErrorCode::ArgumentArity,
            TypeErrorCode::DefinitionUnknown,
            TypeErrorCode::DefinitionDuplicate,
            TypeErrorCode::DefinitionCycle,
            TypeErrorCode::MemberDuplicate,
            TypeErrorCode::MemberUnknown,
            TypeErrorCode::SetOrder,
            TypeErrorCode::NotOrderable,
            TypeErrorCode::NotHashable,
            TypeErrorCode::NotPersistable,
            TypeErrorCode::ConstShape,
            TypeErrorCode::ConstRange,
            TypeErrorCode::FloatNonCanonical,
            TypeErrorCode::ConstDuplicateKey,
            TypeErrorCode::ResourceLimit,
            TypeErrorCode::ImplicitCoercion,
            TypeErrorCode::BuiltinFailureInvalid,
        ];
        assert_eq!(
            codes.map(TypeErrorCode::numeric),
            std::array::from_fn(|index| {
                21_000 + u32::try_from(index).expect("error-code index fits u32")
            })
        );
        assert!(codes.iter().all(|code| code.as_str().starts_with("TYPE_")));
    }
}
