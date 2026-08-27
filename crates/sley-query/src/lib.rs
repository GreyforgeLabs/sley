#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sley_check::{TypeEnvironment, TypeError};
use sley_id::{EntityId, SchemaEpochId, ValueHash};
use sley_ssmc::{
    AdapterImport, Block, CapabilityRequirement, ConstData, ConstValue, ConstantDefinition,
    ContractDefinition, ContractSource, EffectDefinition, EffectEnvironment, ExpectedOutcome,
    FunctionGraph, GlobalValueDefinition, Immediate, Opcode, Operation, Parameter, ParameterRole,
    ResultConst, SwitchArgument, Terminator, TestCaseDefinition, TypeDefForm, TypeDefinition,
    TypeExpr, ValueRef,
    fingerprint::{FingerprintError, hash_validated_value},
};

/// Maximum modeled entities in one restricted impact request.
pub const MAX_IMPACT_ENTITIES: usize = 65_535;
/// Maximum direct impact edges.
pub const MAX_IMPACT_EDGES: usize = 4_000_000;
/// Maximum transitive-impact seeds.
pub const MAX_IMPACT_SEEDS: usize = 65_535;
/// Maximum charged extraction or traversal work.
pub const MAX_IMPACT_WORK: u64 = 100_000_000;

/// Closed S20-250 modeled entity kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ModeledEntityKind {
    /// SSMC1 kind 4.
    TypeDef,
    /// SSMC1 kind 5.
    Function,
    /// SSMC1 kind 6.
    Parameter,
    /// SSMC1 kind 7.
    Block,
    /// SSMC1 kind 8.
    Operation,
    /// SSMC1 kind 9.
    Constant,
    /// SSMC1 kind 10.
    GlobalValue,
    /// SSMC1 kind 11.
    EffectDef,
    /// SSMC1 kind 12.
    CapabilityRequirement,
    /// SSMC1 kind 13.
    Contract,
    /// SSMC1 kind 14.
    TestCase,
    /// SSMC1 kind 15.
    AdapterImport,
}

impl ModeledEntityKind {
    /// Returns the frozen SSMC1 tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::TypeDef => 4,
            Self::Function => 5,
            Self::Parameter => 6,
            Self::Block => 7,
            Self::Operation => 8,
            Self::Constant => 9,
            Self::GlobalValue => 10,
            Self::EffectDef => 11,
            Self::CapabilityRequirement => 12,
            Self::Contract => 13,
            Self::TestCase => 14,
            Self::AdapterImport => 15,
        }
    }

    /// Resolves one SSMC1 tag supported by this restricted profile.
    ///
    /// # Errors
    ///
    /// Returns `IMPACT_ENTITY_UNSUPPORTED` for kinds outside 4 through 15.
    pub fn from_ssmc_tag(tag: u32) -> Result<Self, ImpactError> {
        match tag {
            4 => Ok(Self::TypeDef),
            5 => Ok(Self::Function),
            6 => Ok(Self::Parameter),
            7 => Ok(Self::Block),
            8 => Ok(Self::Operation),
            9 => Ok(Self::Constant),
            10 => Ok(Self::GlobalValue),
            11 => Ok(Self::EffectDef),
            12 => Ok(Self::CapabilityRequirement),
            13 => Ok(Self::Contract),
            14 => Ok(Self::TestCase),
            15 => Ok(Self::AdapterImport),
            _ => impact_fail(ImpactErrorCode::EntityUnsupported),
        }
    }
}

/// Borrowed modeled entity body.
#[derive(Clone, Copy, Debug)]
pub enum ImpactEntity<'a> {
    /// Type definition.
    TypeDef(&'a TypeDefinition),
    /// Function body.
    Function(&'a FunctionGraph),
    /// Parameter body.
    Parameter(&'a Parameter),
    /// Block body.
    Block(&'a Block),
    /// Operation body.
    Operation(&'a Operation),
    /// Constant body.
    Constant(&'a ConstantDefinition),
    /// Global value body.
    GlobalValue(&'a GlobalValueDefinition),
    /// Effect definition body.
    EffectDef(&'a EffectDefinition),
    /// Capability requirement body.
    CapabilityRequirement(&'a CapabilityRequirement),
    /// Contract body.
    Contract(&'a ContractDefinition),
    /// Test case body.
    TestCase(&'a TestCaseDefinition),
    /// Adapter import body.
    AdapterImport(&'a AdapterImport),
}

impl ImpactEntity<'_> {
    /// Returns the exact identity.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        match self {
            Self::TypeDef(value) => value.entity_id,
            Self::Function(value) => value.entity_id,
            Self::Parameter(value) => value.entity_id,
            Self::Block(value) => value.entity_id,
            Self::Operation(value) => value.entity_id,
            Self::Constant(value) => value.entity_id,
            Self::GlobalValue(value) => value.entity_id,
            Self::EffectDef(value) => value.entity_id,
            Self::CapabilityRequirement(value) => value.entity_id,
            Self::Contract(value) => value.entity_id,
            Self::TestCase(value) => value.entity_id,
            Self::AdapterImport(value) => value.entity_id,
        }
    }

    /// Returns the closed modeled kind.
    #[must_use]
    pub const fn kind(self) -> ModeledEntityKind {
        match self {
            Self::TypeDef(_) => ModeledEntityKind::TypeDef,
            Self::Function(_) => ModeledEntityKind::Function,
            Self::Parameter(_) => ModeledEntityKind::Parameter,
            Self::Block(_) => ModeledEntityKind::Block,
            Self::Operation(_) => ModeledEntityKind::Operation,
            Self::Constant(_) => ModeledEntityKind::Constant,
            Self::GlobalValue(_) => ModeledEntityKind::GlobalValue,
            Self::EffectDef(_) => ModeledEntityKind::EffectDef,
            Self::CapabilityRequirement(_) => ModeledEntityKind::CapabilityRequirement,
            Self::Contract(_) => ModeledEntityKind::Contract,
            Self::TestCase(_) => ModeledEntityKind::TestCase,
            Self::AdapterImport(_) => ModeledEntityKind::AdapterImport,
        }
    }
}

/// Closed direct-impact relationship kind.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ImpactKind {
    /// Ownership/membership.
    Ownership,
    /// Structural type reference.
    TypeReference,
    /// Constant or CFG value reference.
    ValueReference,
    /// Control-flow target.
    ControlFlow,
    /// Direct call or function-reference value.
    Call,
    /// Static effect relationship.
    Effect,
    /// Capability requirement relationship.
    Capability,
    /// Contract relationship.
    Contract,
    /// Immutable initializer.
    Initializer,
    /// Test target.
    TestTarget,
    /// Adapter relationship.
    Adapter,
    /// Record/variant definition membership.
    DefinitionMember,
}

impl ImpactKind {
    /// Returns the frozen numeric tag.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Ownership => 1,
            Self::TypeReference => 2,
            Self::ValueReference => 3,
            Self::ControlFlow => 4,
            Self::Call => 5,
            Self::Effect => 6,
            Self::Capability => 7,
            Self::Contract => 8,
            Self::Initializer => 9,
            Self::TestTarget => 10,
            Self::Adapter => 11,
            Self::DefinitionMember => 12,
        }
    }
}

/// One canonical direct edge: changing `dependency` may affect `dependent`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ImpactEdge {
    /// Referring entity.
    pub dependent: EntityId,
    /// Referenced entity.
    pub dependency: EntityId,
    /// Typed relationship.
    pub kind: ImpactKind,
}

/// Stable S20-250 impact error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpactErrorCode {
    /// `IMPACT_ENTITY_UNSUPPORTED`.
    EntityUnsupported,
    /// `IMPACT_SET_NOT_CANONICAL`.
    SetNotCanonical,
    /// `IMPACT_UNRESOLVED_ENTITY`.
    UnresolvedEntity,
    /// `IMPACT_WRONG_ENTITY_KIND`.
    WrongEntityKind,
    /// `IMPACT_RESOURCE_LIMIT`.
    ResourceLimit,
}

impl ImpactErrorCode {
    /// Returns the stable symbolic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntityUnsupported => "IMPACT_ENTITY_UNSUPPORTED",
            Self::SetNotCanonical => "IMPACT_SET_NOT_CANONICAL",
            Self::UnresolvedEntity => "IMPACT_UNRESOLVED_ENTITY",
            Self::WrongEntityKind => "IMPACT_WRONG_ENTITY_KIND",
            Self::ResourceLimit => "IMPACT_RESOURCE_LIMIT",
        }
    }

    /// Returns the stable numeric code.
    #[must_use]
    pub const fn numeric(self) -> u32 {
        match self {
            Self::EntityUnsupported => 25_008,
            Self::SetNotCanonical => 25_009,
            Self::UnresolvedEntity => 25_010,
            Self::WrongEntityKind => 25_011,
            Self::ResourceLimit => 25_012,
        }
    }
}

impl fmt::Display for ImpactErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One stable impact-index failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpactError(ImpactErrorCode);

impl ImpactError {
    /// Constructs a failure.
    #[must_use]
    pub const fn new(code: ImpactErrorCode) -> Self {
        Self(code)
    }

    /// Returns the stable code.
    #[must_use]
    pub const fn code(&self) -> ImpactErrorCode {
        self.0
    }
}

impl fmt::Display for ImpactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for ImpactError {}

/// Derived direct and reverse impact index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImpactIndex {
    kinds: BTreeMap<EntityId, ModeledEntityKind>,
    direct: Vec<ImpactEdge>,
    reverse: BTreeMap<EntityId, Vec<ImpactEdge>>,
}

impl ImpactIndex {
    /// Builds an exact index from a raw-ID-sorted complete modeled request.
    ///
    /// # Errors
    ///
    /// Returns the first canonicality, resolution, kind, or resource failure.
    pub fn build(entities: &[ImpactEntity<'_>]) -> Result<Self, ImpactError> {
        if entities.len() > MAX_IMPACT_ENTITIES {
            return impact_fail(ImpactErrorCode::ResourceLimit);
        }
        let mut kinds = BTreeMap::new();
        let mut prior = None;
        let mut work = 0_u64;
        for entity in entities {
            charge_work(&mut work, 1)?;
            let id = entity.entity_id();
            if prior.is_some_and(|value| value >= id) {
                return impact_fail(ImpactErrorCode::SetNotCanonical);
            }
            prior = Some(id);
            kinds.insert(id, entity.kind());
        }

        let mut builder = EdgeBuilder {
            kinds: &kinds,
            edges: BTreeSet::new(),
            work,
        };
        for entity in entities {
            builder.collect(*entity)?;
        }
        let direct: Vec<_> = builder.edges.into_iter().collect();
        let mut reverse = BTreeMap::<EntityId, Vec<ImpactEdge>>::new();
        for edge in &direct {
            reverse.entry(edge.dependency).or_default().push(*edge);
        }
        Ok(Self {
            kinds,
            direct,
            reverse,
        })
    }

    /// Returns the exact canonical direct edge set.
    #[must_use]
    pub fn direct_edges(&self) -> &[ImpactEdge] {
        &self.direct
    }

    /// Returns exact reverse edges for one dependency.
    #[must_use]
    pub fn reverse_edges(&self, dependency: EntityId) -> &[ImpactEdge] {
        self.reverse.get(&dependency).map_or(&[], Vec::as_slice)
    }

    /// Computes bounded reverse reachability including every seed.
    ///
    /// # Errors
    ///
    /// Returns canonicality, resolution, or resource failure without a partial result.
    pub fn transitive_impact(&self, seeds: &[EntityId]) -> Result<Vec<EntityId>, ImpactError> {
        if seeds.len() > MAX_IMPACT_SEEDS {
            return impact_fail(ImpactErrorCode::ResourceLimit);
        }
        let mut prior = None;
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut work = 0_u64;
        for seed in seeds {
            charge_work(&mut work, 1)?;
            if prior.is_some_and(|value| value >= *seed) {
                return impact_fail(ImpactErrorCode::SetNotCanonical);
            }
            prior = Some(*seed);
            if !self.kinds.contains_key(seed) {
                return impact_fail(ImpactErrorCode::UnresolvedEntity);
            }
            visited.insert(*seed);
            queue.push_back(*seed);
        }
        while let Some(dependency) = queue.pop_front() {
            charge_work(&mut work, 1)?;
            for edge in self.reverse_edges(dependency) {
                charge_work(&mut work, 1)?;
                if visited.insert(edge.dependent) {
                    if visited.len() > MAX_IMPACT_ENTITIES {
                        return impact_fail(ImpactErrorCode::ResourceLimit);
                    }
                    queue.push_back(edge.dependent);
                }
            }
        }
        Ok(visited.into_iter().collect())
    }
}

struct EdgeBuilder<'a> {
    kinds: &'a BTreeMap<EntityId, ModeledEntityKind>,
    edges: BTreeSet<ImpactEdge>,
    work: u64,
}

impl EdgeBuilder<'_> {
    fn add(
        &mut self,
        dependent: EntityId,
        dependency: EntityId,
        kind: ImpactKind,
        expected: Option<ModeledEntityKind>,
    ) -> Result<(), ImpactError> {
        self.charge(1)?;
        let actual = self
            .kinds
            .get(&dependency)
            .copied()
            .ok_or_else(|| ImpactError::new(ImpactErrorCode::UnresolvedEntity))?;
        if expected.is_some_and(|value| value != actual) {
            return impact_fail(ImpactErrorCode::WrongEntityKind);
        }
        self.edges.insert(ImpactEdge {
            dependent,
            dependency,
            kind,
        });
        if self.edges.len() > MAX_IMPACT_EDGES {
            return impact_fail(ImpactErrorCode::ResourceLimit);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn collect(&mut self, entity: ImpactEntity<'_>) -> Result<(), ImpactError> {
        let dependent = entity.entity_id();
        match entity {
            ImpactEntity::TypeDef(value) => {
                match &value.form {
                    TypeDefForm::Record(fields) => {
                        for field in fields {
                            self.type_expr(dependent, &field.value_type, 1)?;
                        }
                    }
                    TypeDefForm::Variant(cases) => {
                        for case in cases {
                            if let Some(value_type) = &case.payload_type {
                                self.type_expr(dependent, value_type, 1)?;
                            }
                        }
                    }
                }
                for contract in &value.invariants {
                    self.add(
                        dependent,
                        *contract,
                        ImpactKind::Contract,
                        Some(ModeledEntityKind::Contract),
                    )?;
                }
            }
            ImpactEntity::Function(value) => {
                for parameter in &value.parameters {
                    self.add(
                        dependent,
                        *parameter,
                        ImpactKind::Ownership,
                        Some(ModeledEntityKind::Parameter),
                    )?;
                }
                self.type_expr(dependent, &value.result_type, 1)?;
                for effect in &value.effects {
                    self.add(
                        dependent,
                        *effect,
                        ImpactKind::Effect,
                        Some(ModeledEntityKind::EffectDef),
                    )?;
                }
                self.add(
                    dependent,
                    value.entry_block,
                    ImpactKind::ControlFlow,
                    Some(ModeledEntityKind::Block),
                )?;
                for block in &value.blocks {
                    self.add(
                        dependent,
                        *block,
                        ImpactKind::Ownership,
                        Some(ModeledEntityKind::Block),
                    )?;
                }
                for contract in &value.contracts {
                    self.add(
                        dependent,
                        *contract,
                        ImpactKind::Contract,
                        Some(ModeledEntityKind::Contract),
                    )?;
                }
            }
            ImpactEntity::Parameter(value) => {
                let owner = match value.role {
                    ParameterRole::Function => ModeledEntityKind::Function,
                    ParameterRole::Block => ModeledEntityKind::Block,
                };
                self.add(dependent, value.owner, ImpactKind::Ownership, Some(owner))?;
                self.type_expr(dependent, &value.value_type, 1)?;
            }
            ImpactEntity::Block(value) => {
                self.add(
                    dependent,
                    value.function,
                    ImpactKind::Ownership,
                    Some(ModeledEntityKind::Function),
                )?;
                for parameter in &value.parameters {
                    self.add(
                        dependent,
                        *parameter,
                        ImpactKind::Ownership,
                        Some(ModeledEntityKind::Parameter),
                    )?;
                }
                for operation in &value.operations {
                    self.add(
                        dependent,
                        *operation,
                        ImpactKind::Ownership,
                        Some(ModeledEntityKind::Operation),
                    )?;
                }
                self.terminator(dependent, &value.terminator)?;
            }
            ImpactEntity::Operation(value) => {
                self.add(
                    dependent,
                    value.block,
                    ImpactKind::Ownership,
                    Some(ModeledEntityKind::Block),
                )?;
                for operand in &value.operands {
                    self.value_ref(dependent, *operand)?;
                }
                for result_type in &value.result_types {
                    self.type_expr(dependent, result_type, 1)?;
                }
                self.immediate(dependent, value.opcode, &value.immediate)?;
            }
            ImpactEntity::Constant(value) => self.const_value(dependent, &value.value, 1)?,
            ImpactEntity::GlobalValue(value) => {
                self.type_expr(dependent, &value.value_type, 1)?;
                self.add(
                    dependent,
                    value.initializer,
                    ImpactKind::Initializer,
                    Some(ModeledEntityKind::Constant),
                )?;
            }
            ImpactEntity::EffectDef(value) => {
                self.type_expr(dependent, &value.scope_type, 1)?;
                self.type_expr(dependent, &value.request_type, 1)?;
                self.type_expr(dependent, &value.response_type, 1)?;
                self.type_expr(dependent, &value.failure_type, 1)?;
            }
            ImpactEntity::CapabilityRequirement(value) => {
                self.add(
                    dependent,
                    value.effect,
                    ImpactKind::Effect,
                    Some(ModeledEntityKind::EffectDef),
                )?;
                for scope in &value.allowed_scopes {
                    self.const_value(dependent, scope, 1)?;
                }
                for contract in &value.constraint_contracts {
                    self.add(
                        dependent,
                        *contract,
                        ImpactKind::Contract,
                        Some(ModeledEntityKind::Contract),
                    )?;
                }
            }
            ImpactEntity::Contract(value) => {
                self.add(dependent, value.target, ImpactKind::Contract, None)?;
                self.add(
                    dependent,
                    value.predicate,
                    ImpactKind::Contract,
                    Some(ModeledEntityKind::Function),
                )?;
                for binding in &value.bindings {
                    match binding.source {
                        ContractSource::Parameter(entity) => self.add(
                            dependent,
                            entity,
                            ImpactKind::ValueReference,
                            Some(ModeledEntityKind::Parameter),
                        )?,
                        ContractSource::Global(entity) => self.add(
                            dependent,
                            entity,
                            ImpactKind::ValueReference,
                            Some(ModeledEntityKind::GlobalValue),
                        )?,
                        ContractSource::Result | ContractSource::Error => {}
                    }
                }
            }
            ImpactEntity::TestCase(value) => self.test_case(dependent, value)?,
            ImpactEntity::AdapterImport(value) => {
                self.type_expr(dependent, &value.request_type, 1)?;
                self.type_expr(dependent, &value.response_type, 1)?;
                self.type_expr(dependent, &value.failure_type, 1)?;
                for effect in &value.effects {
                    self.add(
                        dependent,
                        *effect,
                        ImpactKind::Effect,
                        Some(ModeledEntityKind::EffectDef),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn type_expr(
        &mut self,
        dependent: EntityId,
        value: &TypeExpr,
        depth: usize,
    ) -> Result<(), ImpactError> {
        self.charge(1)?;
        if depth > sley_ssmc::MAX_TYPE_DEPTH {
            return impact_fail(ImpactErrorCode::ResourceLimit);
        }
        match value {
            TypeExpr::Named(value) => {
                self.add(
                    dependent,
                    value.definition,
                    ImpactKind::TypeReference,
                    Some(ModeledEntityKind::TypeDef),
                )?;
                for argument in &value.arguments {
                    self.type_expr(dependent, argument, depth + 1)?;
                }
            }
            TypeExpr::AdapterHandle(entity) => self.add(
                dependent,
                *entity,
                ImpactKind::Adapter,
                Some(ModeledEntityKind::AdapterImport),
            )?,
            TypeExpr::CapabilityToken(entity) => self.add(
                dependent,
                *entity,
                ImpactKind::Capability,
                Some(ModeledEntityKind::CapabilityRequirement),
            )?,
            TypeExpr::Tuple(values) => {
                for value in values {
                    self.type_expr(dependent, value, depth + 1)?;
                }
            }
            TypeExpr::Vector(value) | TypeExpr::Option(value) | TypeExpr::LocalCell(value) => {
                self.type_expr(dependent, value, depth + 1)?;
            }
            TypeExpr::OrderedMap { key, value } => {
                self.type_expr(dependent, key, depth + 1)?;
                self.type_expr(dependent, value, depth + 1)?;
            }
            TypeExpr::Result { ok, error } => {
                self.type_expr(dependent, ok, depth + 1)?;
                self.type_expr(dependent, error, depth + 1)?;
            }
            TypeExpr::FunctionRef(value) => {
                for parameter in &value.parameters {
                    self.type_expr(dependent, parameter, depth + 1)?;
                }
                self.type_expr(dependent, &value.result, depth + 1)?;
                for effect in &value.effects {
                    self.add(
                        dependent,
                        *effect,
                        ImpactKind::Effect,
                        Some(ModeledEntityKind::EffectDef),
                    )?;
                }
            }
            TypeExpr::Unit
            | TypeExpr::Bool
            | TypeExpr::SInt(_)
            | TypeExpr::UInt(_)
            | TypeExpr::F32
            | TypeExpr::F64
            | TypeExpr::Bytes
            | TypeExpr::Text
            | TypeExpr::TypeParameter(_)
            | TypeExpr::BuiltinFailure(_) => {}
        }
        Ok(())
    }

    fn const_value(
        &mut self,
        dependent: EntityId,
        value: &ConstValue,
        depth: usize,
    ) -> Result<(), ImpactError> {
        self.charge(1)?;
        if depth > sley_ssmc::MAX_TYPE_DEPTH {
            return impact_fail(ImpactErrorCode::ResourceLimit);
        }
        self.type_expr(dependent, &value.value_type, depth)?;
        match &value.data {
            ConstData::Sequence(values) => {
                for value in values {
                    self.const_value(dependent, value, depth + 1)?;
                }
            }
            ConstData::Record(value) => {
                self.add(
                    dependent,
                    value.definition,
                    ImpactKind::DefinitionMember,
                    Some(ModeledEntityKind::TypeDef),
                )?;
                for field in &value.fields {
                    self.const_value(dependent, &field.value, depth + 1)?;
                }
            }
            ConstData::Variant(value) => {
                self.add(
                    dependent,
                    value.definition,
                    ImpactKind::DefinitionMember,
                    Some(ModeledEntityKind::TypeDef),
                )?;
                if let Some(payload) = &value.payload {
                    self.const_value(dependent, payload, depth + 1)?;
                }
            }
            ConstData::Map(entries) => {
                for entry in entries {
                    self.const_value(dependent, &entry.key, depth + 1)?;
                    self.const_value(dependent, &entry.value, depth + 1)?;
                }
            }
            ConstData::Option(value) => {
                if let Some(value) = value {
                    self.const_value(dependent, value, depth + 1)?;
                }
            }
            ConstData::Result(ResultConst::Ok(value) | ResultConst::Err(value)) => {
                self.const_value(dependent, value, depth + 1)?;
            }
            ConstData::FunctionRef(value) => {
                self.add(
                    dependent,
                    value.function,
                    ImpactKind::Call,
                    Some(ModeledEntityKind::Function),
                )?;
                for argument in &value.type_arguments {
                    self.type_expr(dependent, argument, depth + 1)?;
                }
            }
            ConstData::Unit
            | ConstData::Bool(_)
            | ConstData::SInt(_)
            | ConstData::UInt(_)
            | ConstData::F32Bits(_)
            | ConstData::F64Bits(_)
            | ConstData::Bytes(_)
            | ConstData::Text(_)
            | ConstData::BuiltinFailure(_) => {}
        }
        Ok(())
    }

    fn value_ref(&mut self, dependent: EntityId, value: ValueRef) -> Result<(), ImpactError> {
        self.charge(1)?;
        let (dependency, expected) = match value {
            ValueRef::Parameter(entity) => (entity, ModeledEntityKind::Parameter),
            ValueRef::OperationResult(value) => (value.operation, ModeledEntityKind::Operation),
        };
        self.add(
            dependent,
            dependency,
            ImpactKind::ValueReference,
            Some(expected),
        )
    }

    fn terminator(&mut self, dependent: EntityId, value: &Terminator) -> Result<(), ImpactError> {
        self.charge(1)?;
        match value {
            Terminator::Return(value) => self.value_ref(dependent, value.value)?,
            Terminator::Branch(value) => self.target_edge(dependent, &value.edge)?,
            Terminator::CondBranch(value) => {
                self.value_ref(dependent, value.condition)?;
                self.target_edge(dependent, &value.if_true)?;
                self.target_edge(dependent, &value.if_false)?;
            }
            Terminator::VariantSwitch(value) => {
                self.value_ref(dependent, value.value)?;
                for case in &value.cases {
                    self.add(
                        dependent,
                        case.edge.target,
                        ImpactKind::ControlFlow,
                        Some(ModeledEntityKind::Block),
                    )?;
                    for argument in &case.edge.arguments {
                        if let SwitchArgument::Value(value) = argument {
                            self.value_ref(dependent, *value)?;
                        }
                    }
                }
            }
            Terminator::Trap(value) => {
                if let Some(payload) = value.payload {
                    self.value_ref(dependent, payload)?;
                }
            }
        }
        Ok(())
    }

    fn target_edge(
        &mut self,
        dependent: EntityId,
        value: &sley_ssmc::TargetEdge,
    ) -> Result<(), ImpactError> {
        self.charge(1)?;
        self.add(
            dependent,
            value.target,
            ImpactKind::ControlFlow,
            Some(ModeledEntityKind::Block),
        )?;
        for argument in &value.arguments {
            self.value_ref(dependent, *argument)?;
        }
        Ok(())
    }

    fn immediate(
        &mut self,
        dependent: EntityId,
        opcode: Opcode,
        value: &Immediate,
    ) -> Result<(), ImpactError> {
        self.charge(1)?;
        match value {
            Immediate::Entity(entity) => {
                let (kind, expected) = match opcode {
                    Opcode::ConstantRef => {
                        (ImpactKind::ValueReference, ModeledEntityKind::Constant)
                    }
                    Opcode::RecordNew => (ImpactKind::DefinitionMember, ModeledEntityKind::TypeDef),
                    Opcode::ContractAssert => (ImpactKind::Contract, ModeledEntityKind::Contract),
                    Opcode::EffectRequest => (ImpactKind::Effect, ModeledEntityKind::EffectDef),
                    Opcode::AdapterInvoke => {
                        (ImpactKind::Adapter, ModeledEntityKind::AdapterImport)
                    }
                    Opcode::CapabilityNarrow => (
                        ImpactKind::Capability,
                        ModeledEntityKind::CapabilityRequirement,
                    ),
                    Opcode::GlobalGet => {
                        (ImpactKind::ValueReference, ModeledEntityKind::GlobalValue)
                    }
                    _ => return impact_fail(ImpactErrorCode::WrongEntityKind),
                };
                self.add(dependent, *entity, kind, Some(expected))?;
            }
            Immediate::Variant(value) => {
                if !matches!(opcode, Opcode::VariantNew | Opcode::VariantGet) {
                    return impact_fail(ImpactErrorCode::WrongEntityKind);
                }
                self.add(
                    dependent,
                    value.definition,
                    ImpactKind::DefinitionMember,
                    Some(ModeledEntityKind::TypeDef),
                )?;
            }
            Immediate::Function(value) => {
                if !matches!(opcode, Opcode::CallDirect | Opcode::FunctionRef) {
                    return impact_fail(ImpactErrorCode::WrongEntityKind);
                }
                self.add(
                    dependent,
                    value.function,
                    ImpactKind::Call,
                    Some(ModeledEntityKind::Function),
                )?;
                for argument in &value.type_arguments {
                    self.type_expr(dependent, argument, 1)?;
                }
            }
            Immediate::None
            | Immediate::Index(_)
            | Immediate::Field(_)
            | Immediate::Observation(_) => {}
        }
        Ok(())
    }

    fn test_case(
        &mut self,
        dependent: EntityId,
        value: &TestCaseDefinition,
    ) -> Result<(), ImpactError> {
        self.charge(1)?;
        self.add(
            dependent,
            value.target,
            ImpactKind::TestTarget,
            Some(ModeledEntityKind::Function),
        )?;
        for input in &value.inputs {
            self.const_value(dependent, input, 1)?;
        }
        match &value.effect_environment {
            EffectEnvironment::Replay(bindings) => {
                for binding in bindings {
                    self.add(
                        dependent,
                        binding.adapter_import,
                        ImpactKind::Adapter,
                        Some(ModeledEntityKind::AdapterImport),
                    )?;
                    for request in &binding.request {
                        self.const_value(dependent, request, 1)?;
                    }
                    match &binding.response {
                        ResultConst::Ok(value) | ResultConst::Err(value) => {
                            self.const_value(dependent, value, 1)?;
                        }
                    }
                }
            }
            EffectEnvironment::DeterministicAdapters(configurations) => {
                for configuration in configurations {
                    self.add(
                        dependent,
                        configuration.adapter_import,
                        ImpactKind::Adapter,
                        Some(ModeledEntityKind::AdapterImport),
                    )?;
                    self.const_value(dependent, &configuration.configuration, 1)?;
                }
            }
        }
        if let ExpectedOutcome::Value(value) = &value.expected {
            self.const_value(dependent, value, 1)?;
        }
        for observation in &value.observations {
            self.const_value(dependent, &observation.value, 1)?;
        }
        Ok(())
    }

    fn charge(&mut self, amount: u64) -> Result<(), ImpactError> {
        charge_work(&mut self.work, amount)
    }
}

/// Checked value-hash failure preserving S20-210 errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueHashError {
    /// Exact earlier type/constant failure.
    Type(TypeError),
    /// Exact S20-250 encoding failure.
    Fingerprint(FingerprintError),
}

impl fmt::Display for ValueHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(value) => value.fmt(formatter),
            Self::Fingerprint(value) => value.fmt(formatter),
        }
    }
}

impl std::error::Error for ValueHashError {}

/// Validates and hashes one canonically hashable SSMC value.
///
/// # Errors
///
/// Returns the exact S20-210 type/constant failure or S20-250 resource failure.
pub fn value_hash(
    environment: &TypeEnvironment,
    schema_epoch: SchemaEpochId,
    value: &ConstValue,
) -> Result<ValueHash, ValueHashError> {
    environment
        .check_constant(value)
        .map_err(ValueHashError::Type)?;
    environment
        .require_hashable(&value.value_type)
        .map_err(ValueHashError::Type)?;
    hash_validated_value(schema_epoch, value).map_err(ValueHashError::Fingerprint)
}

fn impact_fail<T>(code: ImpactErrorCode) -> Result<T, ImpactError> {
    Err(ImpactError::new(code))
}

fn charge_work(work: &mut u64, amount: u64) -> Result<(), ImpactError> {
    *work = work
        .checked_add(amount)
        .ok_or_else(|| ImpactError::new(ImpactErrorCode::ResourceLimit))?;
    if *work > MAX_IMPACT_WORK {
        impact_fail(ImpactErrorCode::ResourceLimit)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sley_ssmc::{CondBranchTerminator, IntegerWidth, Reachability, TargetEdge, Visibility};

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    #[test]
    fn direct_reverse_and_transitive_edges_are_exact() {
        let function = FunctionGraph {
            entity_id: id(1),
            type_parameters: Vec::new(),
            parameters: vec![id(2)],
            result_type: TypeExpr::Bool,
            effects: Vec::new(),
            entry_block: id(3),
            blocks: vec![id(3)],
            contracts: Vec::new(),
            visibility: Visibility::Private,
        };
        let parameter = Parameter {
            entity_id: id(2),
            owner: id(1),
            role: ParameterRole::Function,
            ordinal: 0,
            value_type: TypeExpr::Bool,
        };
        let block = Block {
            entity_id: id(3),
            function: id(1),
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: Terminator::CondBranch(CondBranchTerminator {
                condition: ValueRef::Parameter(id(2)),
                if_true: TargetEdge {
                    target: id(3),
                    arguments: Vec::new(),
                },
                if_false: TargetEdge {
                    target: id(3),
                    arguments: Vec::new(),
                },
            }),
            reachability: Reachability::Required,
        };
        let entities = [
            ImpactEntity::Function(&function),
            ImpactEntity::Parameter(&parameter),
            ImpactEntity::Block(&block),
        ];
        let index = ImpactIndex::build(&entities).unwrap();
        assert_eq!(
            index.direct_edges(),
            &[
                ImpactEdge {
                    dependent: id(1),
                    dependency: id(2),
                    kind: ImpactKind::Ownership,
                },
                ImpactEdge {
                    dependent: id(1),
                    dependency: id(3),
                    kind: ImpactKind::Ownership,
                },
                ImpactEdge {
                    dependent: id(1),
                    dependency: id(3),
                    kind: ImpactKind::ControlFlow,
                },
                ImpactEdge {
                    dependent: id(2),
                    dependency: id(1),
                    kind: ImpactKind::Ownership,
                },
                ImpactEdge {
                    dependent: id(3),
                    dependency: id(1),
                    kind: ImpactKind::Ownership,
                },
                ImpactEdge {
                    dependent: id(3),
                    dependency: id(2),
                    kind: ImpactKind::ValueReference,
                },
                ImpactEdge {
                    dependent: id(3),
                    dependency: id(3),
                    kind: ImpactKind::ControlFlow,
                },
            ]
        );
        assert_eq!(
            index.transitive_impact(&[id(2)]).unwrap(),
            vec![id(1), id(2), id(3)]
        );
        for _ in 0..128 {
            assert_eq!(ImpactIndex::build(&entities).unwrap(), index);
        }
    }

    #[test]
    fn input_must_be_raw_id_sorted() {
        let constant_a = ConstantDefinition {
            entity_id: id(2),
            value: ConstValue {
                value_type: TypeExpr::Bool,
                data: ConstData::Bool(true),
            },
        };
        let constant_b = ConstantDefinition {
            entity_id: id(1),
            value: constant_a.value.clone(),
        };
        assert_eq!(
            ImpactIndex::build(&[
                ImpactEntity::Constant(&constant_a),
                ImpactEntity::Constant(&constant_b),
            ])
            .unwrap_err()
            .code(),
            ImpactErrorCode::SetNotCanonical
        );
    }

    #[test]
    fn value_hash_preserves_type_judgment() {
        let environment = TypeEnvironment::new(Vec::new()).unwrap();
        let value = ConstValue {
            value_type: TypeExpr::UInt(IntegerWidth::from_bits(32)),
            data: ConstData::UInt(7),
        };
        let epoch = SchemaEpochId::from_bytes([1; 32]);
        assert_eq!(
            value_hash(&environment, epoch, &value).unwrap(),
            value_hash(&environment, epoch, &value).unwrap()
        );
    }

    #[test]
    fn all_impact_codes_and_tags_are_stable() {
        let codes = [
            ImpactErrorCode::EntityUnsupported,
            ImpactErrorCode::SetNotCanonical,
            ImpactErrorCode::UnresolvedEntity,
            ImpactErrorCode::WrongEntityKind,
            ImpactErrorCode::ResourceLimit,
        ];
        for (offset, code) in codes.into_iter().enumerate() {
            assert_eq!(code.numeric(), 25_008 + u32::try_from(offset).unwrap());
        }
        let kinds = [
            ImpactKind::Ownership,
            ImpactKind::TypeReference,
            ImpactKind::ValueReference,
            ImpactKind::ControlFlow,
            ImpactKind::Call,
            ImpactKind::Effect,
            ImpactKind::Capability,
            ImpactKind::Contract,
            ImpactKind::Initializer,
            ImpactKind::TestTarget,
            ImpactKind::Adapter,
            ImpactKind::DefinitionMember,
        ];
        for (offset, kind) in kinds.into_iter().enumerate() {
            assert_eq!(kind.tag(), 1 + u32::try_from(offset).unwrap());
        }
    }
}
