//! Validator-owned projection of exact SSMC1 entity objects.
//!
//! The projection is derived only from strictly decoded `EntityObject` values.
//! It supplies complete typed slices to the owning S20-210 through S20-240
//! checkers and independently extracts every epoch-1 local `EntityId`
//! reference. It is private to S20-360 and grants no root or commit authority.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sley_check::{TypeEnvironment, TypeError, TypeErrorCode};
use sley_id::{EntityId, SchemaEpochId, StateRoot};
use sley_mutate::{
    EntityObject,
    value::{DependencyBindingBody, EntityBodyValue, PolicyBindingBody},
};
use sley_ssmc::{
    AdapterImport, Block, CapabilityRequirement, ConstData, ConstValue, ConstantDefinition,
    ContractDefinition, ContractSource, EffectDefinition, EffectEnvironment, ExpectedOutcome,
    FunctionGraph, GlobalValueDefinition, Immediate, Opcode, Operation, Parameter, ParameterRole,
    ResultConst, SwitchArgument, Terminator, TestCaseDefinition, TypeDefForm, TypeDefinition,
    TypeExpr, ValueRef,
    fingerprint::{
        FingerprintError, FingerprintErrorCode, FunctionFingerprintInput, fingerprint_function,
        fingerprint_type_definition, verify_fingerprint_claim,
    },
};

const MAX_PROGRAM_ENTITIES: usize = 65_535;
const MAX_PROGRAM_EDGES: usize = 4_000_000;
const MAX_PROGRAM_GRAPH_WORK: u64 = 100_000_000;
const ALL_ENTITY_KINDS: u32 = (1_u32 << 18) - 1;
const MODELED_CONTRACT_TARGET_KINDS: u32 = ((1_u32 << 15) - 1) & !((1_u32 << 3) - 1);

/// One stable projection/reference-graph failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateProgramError {
    DuplicateEntity,
    SetNotCanonical,
    OpcodeUnknown,
    UnresolvedReference,
    WrongEntityKind,
    ResourceLimit,
}

impl CandidateProgramError {
    pub(crate) const fn source_symbol(self) -> &'static str {
        match self {
            Self::DuplicateEntity => "GRAPH_DUPLICATE_ENTITY",
            Self::SetNotCanonical => "GRAPH_INVENTORY_MISMATCH",
            Self::OpcodeUnknown => "SSMC_OPCODE_UNKNOWN",
            Self::UnresolvedReference => "GRAPH_UNRESOLVED_REFERENCE",
            Self::WrongEntityKind => "SSMC_REFERENCE_MALFORMED",
            Self::ResourceLimit => "GRAPH_RESOURCE_LIMIT",
        }
    }

    pub(crate) const fn source_numeric_code(self) -> u32 {
        match self {
            Self::DuplicateEntity => 22_000,
            Self::SetNotCanonical => 22_001,
            Self::OpcodeUnknown => 20_007,
            Self::UnresolvedReference => 22_004,
            Self::WrongEntityKind => 20_005,
            Self::ResourceLimit => 22_020,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ProgramEdge {
    dependent: EntityId,
    dependency: EntityId,
    relationship_tag: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct CandidateProgram {
    pub(crate) kinds: BTreeMap<EntityId, u16>,
    pub(crate) type_definitions: Vec<TypeDefinition>,
    pub(crate) functions: Vec<FunctionGraph>,
    pub(crate) parameters: Vec<Parameter>,
    pub(crate) blocks: Vec<Block>,
    pub(crate) operations: Vec<Operation>,
    pub(crate) constants: Vec<ConstantDefinition>,
    pub(crate) globals: Vec<GlobalValueDefinition>,
    pub(crate) effects: Vec<EffectDefinition>,
    pub(crate) requirements: Vec<CapabilityRequirement>,
    pub(crate) contracts: Vec<ContractDefinition>,
    pub(crate) tests: Vec<TestCaseDefinition>,
    pub(crate) adapters: Vec<AdapterImport>,
    pub(crate) policy_bindings: Vec<(EntityId, PolicyBindingBody)>,
    pub(crate) dependency_bindings: Vec<(EntityId, DependencyBindingBody)>,
    edges: Vec<ProgramEdge>,
    graph_work: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct OwnedFunctionUnit {
    pub(crate) function: FunctionGraph,
    pub(crate) parameters: Vec<Parameter>,
    pub(crate) blocks: Vec<Block>,
    pub(crate) operations: Vec<Operation>,
}

impl CandidateProgram {
    pub(crate) fn project(objects: &[EntityObject]) -> Result<Self, CandidateProgramError> {
        if objects.len() > MAX_PROGRAM_ENTITIES {
            return Err(CandidateProgramError::ResourceLimit);
        }
        let mut program = Self {
            kinds: BTreeMap::new(),
            type_definitions: Vec::new(),
            functions: Vec::new(),
            parameters: Vec::new(),
            blocks: Vec::new(),
            operations: Vec::new(),
            constants: Vec::new(),
            globals: Vec::new(),
            effects: Vec::new(),
            requirements: Vec::new(),
            contracts: Vec::new(),
            tests: Vec::new(),
            adapters: Vec::new(),
            policy_bindings: Vec::new(),
            dependency_bindings: Vec::new(),
            edges: Vec::new(),
            graph_work: 0,
        };

        let mut previous = None;
        for object in objects {
            let record = object.record();
            if previous.is_some_and(|prior| prior >= record.entity_id) {
                return Err(CandidateProgramError::SetNotCanonical);
            }
            previous = Some(record.entity_id);
            if program
                .kinds
                .insert(record.entity_id, record.body.kind_tag())
                .is_some()
            {
                return Err(CandidateProgramError::DuplicateEntity);
            }
            project_body(&mut program, record.entity_id, &record.body)?;
        }

        let mut collector = GraphCollector {
            kinds: &program.kinds,
            edges: BTreeSet::new(),
            work: 0,
        };
        for object in objects {
            collector.collect(object.record().entity_id, &object.record().body)?;
        }
        program.edges = collector.edges.into_iter().collect();
        program.graph_work = collector.work;
        Ok(program)
    }

    pub(crate) const fn graph_work(&self) -> u64 {
        self.graph_work
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub(crate) fn operation_analysis_supported(&self) -> bool {
        self.operations.is_empty()
    }

    pub(crate) fn dependency_roots(&self) -> Vec<StateRoot> {
        let mut roots = self
            .dependency_bindings
            .iter()
            .map(|(_, binding)| binding.dependency_root)
            .collect::<Vec<_>>();
        roots.sort_unstable();
        roots.dedup();
        roots
    }

    pub(crate) fn affected_closure(
        &self,
        seeds: &[EntityId],
    ) -> Result<Vec<EntityId>, CandidateProgramError> {
        if seeds.len() > MAX_PROGRAM_ENTITIES {
            return Err(CandidateProgramError::ResourceLimit);
        }
        let mut reverse = BTreeMap::<EntityId, Vec<EntityId>>::new();
        for edge in &self.edges {
            reverse
                .entry(edge.dependency)
                .or_default()
                .push(edge.dependent);
        }
        for dependents in reverse.values_mut() {
            dependents.sort_unstable();
            dependents.dedup();
        }
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        for seed in seeds {
            if visited.insert(*seed) {
                queue.push_back(*seed);
            }
        }
        let mut work = 0_u64;
        while let Some(dependency) = queue.pop_front() {
            charge(&mut work, 1)?;
            if let Some(dependents) = reverse.get(&dependency) {
                for dependent in dependents {
                    charge(&mut work, 1)?;
                    if visited.insert(*dependent) {
                        if visited.len() > MAX_PROGRAM_ENTITIES {
                            return Err(CandidateProgramError::ResourceLimit);
                        }
                        queue.push_back(*dependent);
                    }
                }
            }
        }
        Ok(visited.into_iter().collect())
    }

    pub(crate) fn required_capabilities(&self, closure: &[EntityId]) -> Vec<EntityId> {
        let closure = closure.iter().copied().collect::<BTreeSet<_>>();
        let mut required = BTreeSet::new();
        for (_, binding) in &self.policy_bindings {
            if closure.contains(&binding.subject) {
                required.extend(binding.requirements.as_slice().iter().copied());
            }
        }
        required.into_iter().collect()
    }

    pub(crate) fn affected_functions(&self, closure: &[EntityId]) -> Vec<EntityId> {
        closure
            .iter()
            .copied()
            .filter(|entity| self.kinds.get(entity) == Some(&5))
            .collect()
    }

    pub(crate) fn function_units(&self) -> Vec<OwnedFunctionUnit> {
        let block_functions = self
            .blocks
            .iter()
            .map(|block| (block.entity_id, block.function))
            .collect::<BTreeMap<_, _>>();
        self.functions
            .iter()
            .map(|function| OwnedFunctionUnit {
                function: function.clone(),
                parameters: self
                    .parameters
                    .iter()
                    .filter(|parameter| match parameter.role {
                        ParameterRole::Function => parameter.owner == function.entity_id,
                        ParameterRole::Block => {
                            block_functions.get(&parameter.owner) == Some(&function.entity_id)
                        }
                    })
                    .cloned()
                    .collect(),
                blocks: self
                    .blocks
                    .iter()
                    .filter(|block| block.function == function.entity_id)
                    .cloned()
                    .collect(),
                operations: self
                    .operations
                    .iter()
                    .filter(|operation| {
                        block_functions.get(&operation.block) == Some(&function.entity_id)
                    })
                    .cloned()
                    .collect(),
            })
            .collect()
    }

    pub(crate) fn validate_types(&self) -> Result<TypeEnvironment, TypeError> {
        let types = TypeEnvironment::new(self.type_definitions.clone())?;
        let block_functions = self
            .blocks
            .iter()
            .map(|block| (block.entity_id, block.function))
            .collect::<BTreeMap<_, _>>();
        let function_parameters = self
            .functions
            .iter()
            .map(|function| {
                let count = u32::try_from(function.type_parameters.len())
                    .map_err(|_| TypeError::new(TypeErrorCode::ResourceLimit))?;
                for (ordinal, parameter) in function.type_parameters.iter().enumerate() {
                    if usize::try_from(parameter.ordinal).ok() != Some(ordinal) {
                        return Err(TypeError::new(TypeErrorCode::ParameterOutOfScope));
                    }
                }
                types.check_type(&function.result_type, count)?;
                Ok((function.entity_id, count))
            })
            .collect::<Result<BTreeMap<_, _>, TypeError>>()?;

        for parameter in &self.parameters {
            let function = match parameter.role {
                ParameterRole::Function => parameter.owner,
                ParameterRole::Block => block_functions
                    .get(&parameter.owner)
                    .copied()
                    .ok_or_else(|| TypeError::new(TypeErrorCode::DefinitionUnknown))?,
            };
            let count = function_parameters
                .get(&function)
                .copied()
                .ok_or_else(|| TypeError::new(TypeErrorCode::DefinitionUnknown))?;
            types.check_type(&parameter.value_type, count)?;
        }
        for operation in &self.operations {
            let function = block_functions
                .get(&operation.block)
                .copied()
                .ok_or_else(|| TypeError::new(TypeErrorCode::DefinitionUnknown))?;
            let count = function_parameters
                .get(&function)
                .copied()
                .ok_or_else(|| TypeError::new(TypeErrorCode::DefinitionUnknown))?;
            for result in &operation.result_types {
                types.check_type(result, count)?;
            }
            if let Immediate::Function(reference) = &operation.immediate {
                for argument in &reference.type_arguments {
                    types.check_type(argument, count)?;
                }
            }
        }
        for constant in &self.constants {
            types.check_constant(&constant.value)?;
        }
        for global in &self.globals {
            types.check_closed_type(&global.value_type)?;
            types.require_persistable(&global.value_type)?;
        }
        for effect in &self.effects {
            for value in [
                &effect.scope_type,
                &effect.request_type,
                &effect.response_type,
                &effect.failure_type,
            ] {
                types.check_closed_type(value)?;
            }
        }
        for requirement in &self.requirements {
            for scope in &requirement.allowed_scopes {
                types.check_constant(scope)?;
            }
        }
        for adapter in &self.adapters {
            for value in [
                &adapter.request_type,
                &adapter.response_type,
                &adapter.failure_type,
            ] {
                types.check_closed_type(value)?;
            }
        }
        for test in &self.tests {
            validate_test_types(&types, test)?;
        }
        Ok(types)
    }

    pub(crate) fn validate_restricted_type_fingerprint_claims(
        &self,
        schema_epoch: SchemaEpochId,
        objects: &[EntityObject],
    ) -> Result<(), FingerprintError> {
        let definitions = self
            .type_definitions
            .iter()
            .map(|definition| (definition.entity_id, definition))
            .collect::<BTreeMap<_, _>>();
        for object in objects {
            let claimed = object.record().semantic_fingerprint;
            match &object.record().body {
                EntityBodyValue::TypeDef(_) => {
                    if let Some(claimed) = claimed {
                        let definition =
                            definitions.get(&object.record().entity_id).ok_or_else(|| {
                                FingerprintError::new(FingerprintErrorCode::InventoryInvalid)
                            })?;
                        let computed = fingerprint_type_definition(schema_epoch, definition)?;
                        verify_fingerprint_claim(computed, Some(claimed))?;
                    }
                }
                EntityBodyValue::Function(_) => {}
                _ if claimed.is_some() => {
                    return Err(FingerprintError::new(
                        FingerprintErrorCode::EntityUnsupported,
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn validate_restricted_function_fingerprint_claims(
        &self,
        schema_epoch: SchemaEpochId,
        objects: &[EntityObject],
    ) -> Result<(), FingerprintError> {
        let units = self
            .function_units()
            .into_iter()
            .map(|unit| (unit.function.entity_id, unit))
            .collect::<BTreeMap<_, _>>();
        for object in objects {
            if !matches!(object.record().body, EntityBodyValue::Function(_)) {
                continue;
            }
            let Some(claimed) = object.record().semantic_fingerprint else {
                continue;
            };
            let unit = units
                .get(&object.record().entity_id)
                .ok_or_else(|| FingerprintError::new(FingerprintErrorCode::InventoryInvalid))?;
            let computed = fingerprint_function(
                schema_epoch,
                FunctionFingerprintInput {
                    function: &unit.function,
                    parameters: &unit.parameters,
                    blocks: &unit.blocks,
                    operations: &unit.operations,
                },
            )?;
            verify_fingerprint_claim(computed, Some(claimed))?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
fn project_body(
    program: &mut CandidateProgram,
    entity_id: EntityId,
    body: &EntityBodyValue,
) -> Result<(), CandidateProgramError> {
    match body {
        EntityBodyValue::Workspace(_)
        | EntityBodyValue::Package(_)
        | EntityBodyValue::Namespace(_)
        | EntityBodyValue::EntryPoint(_) => {}
        EntityBodyValue::TypeDef(value) => program.type_definitions.push(TypeDefinition {
            entity_id,
            type_parameters: value.type_parameters.clone(),
            form: value.form.clone(),
            invariants: value.invariants.as_slice().to_vec(),
            visibility: value.visibility,
        }),
        EntityBodyValue::Function(value) => program.functions.push(FunctionGraph {
            entity_id,
            type_parameters: value.type_parameters.clone(),
            parameters: value.parameters.clone(),
            result_type: value.result_type.clone(),
            effects: value.effects.as_slice().to_vec(),
            entry_block: value.entry_block,
            blocks: value.blocks.clone(),
            contracts: value.contracts.as_slice().to_vec(),
            visibility: value.visibility,
        }),
        EntityBodyValue::Parameter(value) => program.parameters.push(Parameter {
            entity_id,
            owner: value.owner,
            role: value.role,
            ordinal: value.ordinal,
            value_type: value.value_type.clone(),
        }),
        EntityBodyValue::Block(value) => program.blocks.push(Block {
            entity_id,
            function: value.function,
            parameters: value.parameters.clone(),
            operations: value.operations.clone(),
            terminator: value.terminator.clone(),
            reachability: value.reachability,
        }),
        EntityBodyValue::Operation(value) => program.operations.push(Operation {
            entity_id,
            block: value.block,
            ordinal: value.ordinal,
            opcode: Opcode::from_tag(value.opcode).ok_or(CandidateProgramError::OpcodeUnknown)?,
            operands: value.operands.clone(),
            result_types: value.result_types.clone(),
            immediate: value.immediate.clone(),
        }),
        EntityBodyValue::Constant(value) => program.constants.push(ConstantDefinition {
            entity_id,
            value: value.value.clone(),
        }),
        EntityBodyValue::GlobalValue(value) => program.globals.push(GlobalValueDefinition {
            entity_id,
            value_type: value.value_type.clone(),
            initializer: value.initializer,
            visibility: value.visibility,
        }),
        EntityBodyValue::EffectDef(value) => program.effects.push(EffectDefinition {
            entity_id,
            effect_kind: value.effect_kind,
            scope_type: value.scope_type.clone(),
            request_type: value.request_type.clone(),
            response_type: value.response_type.clone(),
            failure_type: value.failure_type.clone(),
            visibility: value.visibility,
        }),
        EntityBodyValue::CapabilityRequirement(value) => {
            program.requirements.push(CapabilityRequirement {
                entity_id,
                effect: value.effect,
                allowed_scopes: value.allowed_scopes.clone(),
                constraint_contracts: value.constraint_contracts.as_slice().to_vec(),
            });
        }
        EntityBodyValue::Contract(value) => program.contracts.push(ContractDefinition {
            entity_id,
            target: value.target,
            contract_kind: value.contract_kind,
            predicate: value.predicate,
            bindings: value.bindings.clone(),
            resource_limits: value.resource_limits,
        }),
        EntityBodyValue::TestCase(value) => program.tests.push(TestCaseDefinition {
            entity_id,
            target: value.target,
            inputs: value.inputs.clone(),
            effect_environment: value.effect_environment.clone(),
            expected: value.expected.clone(),
            observations: value.observations.clone(),
            resource_limits: value.resource_limits,
        }),
        EntityBodyValue::AdapterImport(value) => program.adapters.push(AdapterImport {
            entity_id,
            adapter_id: value.adapter_id,
            abi_version: value.abi_version,
            request_type: value.request_type.clone(),
            response_type: value.response_type.clone(),
            failure_type: value.failure_type.clone(),
            effects: value.effects.as_slice().to_vec(),
        }),
        EntityBodyValue::PolicyBinding(value) => {
            program.policy_bindings.push((entity_id, value.clone()));
        }
        EntityBodyValue::DependencyBinding(value) => {
            program.dependency_bindings.push((entity_id, value.clone()));
        }
    }
    Ok(())
}

struct GraphCollector<'a> {
    kinds: &'a BTreeMap<EntityId, u16>,
    edges: BTreeSet<ProgramEdge>,
    work: u64,
}

impl GraphCollector<'_> {
    fn add(
        &mut self,
        dependent: EntityId,
        dependency: EntityId,
        relationship_tag: u32,
        expected_kinds: u32,
    ) -> Result<(), CandidateProgramError> {
        charge(&mut self.work, 1)?;
        let actual = self
            .kinds
            .get(&dependency)
            .copied()
            .ok_or(CandidateProgramError::UnresolvedReference)?;
        if expected_kinds & kind_bit(actual) == 0 {
            return Err(CandidateProgramError::WrongEntityKind);
        }
        self.edges.insert(ProgramEdge {
            dependent,
            dependency,
            relationship_tag,
        });
        if self.edges.len() > MAX_PROGRAM_EDGES {
            return Err(CandidateProgramError::ResourceLimit);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn collect(
        &mut self,
        dependent: EntityId,
        body: &EntityBodyValue,
    ) -> Result<(), CandidateProgramError> {
        charge(&mut self.work, 1)?;
        match body {
            EntityBodyValue::Workspace(value) => {
                for package in value.packages.as_slice() {
                    self.add(dependent, *package, 1, kind_bit(2))?;
                }
                self.add(dependent, value.root_namespace, 1, kind_bit(3))?;
                for requirement in value.capability_requirements.as_slice() {
                    self.add(dependent, *requirement, 7, kind_bit(12))?;
                }
                for contract in value.contracts.as_slice() {
                    self.add(dependent, *contract, 8, kind_bit(13))?;
                }
                for test in value.tests.as_slice() {
                    self.add(dependent, *test, 10, kind_bit(14))?;
                }
            }
            EntityBodyValue::Package(value) => {
                self.add(dependent, value.workspace, 1, kind_bit(1))?;
                self.add(dependent, value.root_namespace, 1, kind_bit(3))?;
                for dependency in value.dependencies.as_slice() {
                    self.add(dependent, *dependency, 1, kind_bit(18))?;
                }
                for export in value.exports.as_slice() {
                    self.add(dependent, *export, 1, ALL_ENTITY_KINDS)?;
                }
            }
            EntityBodyValue::Namespace(value) => {
                if let Some(parent) = value.parent {
                    self.add(dependent, parent, 1, kind_bit(3))?;
                }
                for member in value.members.as_slice() {
                    self.add(dependent, *member, 1, ALL_ENTITY_KINDS)?;
                }
            }
            EntityBodyValue::TypeDef(value) => {
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
                for contract in value.invariants.as_slice() {
                    self.add(dependent, *contract, 8, kind_bit(13))?;
                }
            }
            EntityBodyValue::Function(value) => {
                for parameter in &value.parameters {
                    self.add(dependent, *parameter, 1, kind_bit(6))?;
                }
                self.type_expr(dependent, &value.result_type, 1)?;
                for effect in value.effects.as_slice() {
                    self.add(dependent, *effect, 6, kind_bit(11))?;
                }
                self.add(dependent, value.entry_block, 4, kind_bit(7))?;
                for block in &value.blocks {
                    self.add(dependent, *block, 1, kind_bit(7))?;
                }
                for contract in value.contracts.as_slice() {
                    self.add(dependent, *contract, 8, kind_bit(13))?;
                }
            }
            EntityBodyValue::Parameter(value) => {
                let owner_kind = match value.role {
                    ParameterRole::Function => 5,
                    ParameterRole::Block => 7,
                };
                self.add(dependent, value.owner, 1, kind_bit(owner_kind))?;
                self.type_expr(dependent, &value.value_type, 1)?;
            }
            EntityBodyValue::Block(value) => {
                self.add(dependent, value.function, 1, kind_bit(5))?;
                for parameter in &value.parameters {
                    self.add(dependent, *parameter, 1, kind_bit(6))?;
                }
                for operation in &value.operations {
                    self.add(dependent, *operation, 1, kind_bit(8))?;
                }
                self.terminator(dependent, &value.terminator)?;
            }
            EntityBodyValue::Operation(value) => {
                let opcode =
                    Opcode::from_tag(value.opcode).ok_or(CandidateProgramError::OpcodeUnknown)?;
                self.add(dependent, value.block, 1, kind_bit(7))?;
                for operand in &value.operands {
                    self.value_ref(dependent, *operand)?;
                }
                for result in &value.result_types {
                    self.type_expr(dependent, result, 1)?;
                }
                self.immediate(dependent, opcode, &value.immediate)?;
            }
            EntityBodyValue::Constant(value) => {
                self.const_value(dependent, &value.value, 1)?;
            }
            EntityBodyValue::GlobalValue(value) => {
                self.type_expr(dependent, &value.value_type, 1)?;
                self.add(dependent, value.initializer, 9, kind_bit(9))?;
            }
            EntityBodyValue::EffectDef(value) => {
                for value in [
                    &value.scope_type,
                    &value.request_type,
                    &value.response_type,
                    &value.failure_type,
                ] {
                    self.type_expr(dependent, value, 1)?;
                }
            }
            EntityBodyValue::CapabilityRequirement(value) => {
                self.add(dependent, value.effect, 6, kind_bit(11))?;
                for scope in &value.allowed_scopes {
                    self.const_value(dependent, scope, 1)?;
                }
                for contract in value.constraint_contracts.as_slice() {
                    self.add(dependent, *contract, 8, kind_bit(13))?;
                }
            }
            EntityBodyValue::Contract(value) => {
                self.add(dependent, value.target, 8, MODELED_CONTRACT_TARGET_KINDS)?;
                self.add(dependent, value.predicate, 8, kind_bit(5))?;
                for binding in &value.bindings {
                    match binding.source {
                        ContractSource::Parameter(entity) => {
                            self.add(dependent, entity, 3, kind_bit(6))?;
                        }
                        ContractSource::Global(entity) => {
                            self.add(dependent, entity, 3, kind_bit(10))?;
                        }
                        ContractSource::Result | ContractSource::Error => {}
                    }
                }
            }
            EntityBodyValue::TestCase(value) => {
                self.add(dependent, value.target, 10, kind_bit(5))?;
                for input in &value.inputs {
                    self.const_value(dependent, input, 1)?;
                }
                self.effect_environment(dependent, &value.effect_environment)?;
                if let ExpectedOutcome::Value(value) = &value.expected {
                    self.const_value(dependent, value, 1)?;
                }
                for observation in &value.observations {
                    self.const_value(dependent, &observation.value, 1)?;
                }
            }
            EntityBodyValue::AdapterImport(value) => {
                for value in [
                    &value.request_type,
                    &value.response_type,
                    &value.failure_type,
                ] {
                    self.type_expr(dependent, value, 1)?;
                }
                for effect in value.effects.as_slice() {
                    self.add(dependent, *effect, 6, kind_bit(11))?;
                }
            }
            EntityBodyValue::EntryPoint(value) => {
                self.add(dependent, value.function, 1, kind_bit(5))?;
            }
            EntityBodyValue::PolicyBinding(value) => {
                self.add(dependent, value.subject, 1, ALL_ENTITY_KINDS)?;
                for requirement in value.requirements.as_slice() {
                    self.add(dependent, *requirement, 7, kind_bit(12))?;
                }
            }
            EntityBodyValue::DependencyBinding(value) => {
                // `external_package` resolves only in the exact external root;
                // the local closed graph contains only the local namespace.
                self.add(dependent, value.local_namespace, 1, kind_bit(3))?;
            }
        }
        Ok(())
    }

    fn type_expr(
        &mut self,
        dependent: EntityId,
        value: &TypeExpr,
        depth: usize,
    ) -> Result<(), CandidateProgramError> {
        charge(&mut self.work, 1)?;
        if depth > sley_ssmc::MAX_TYPE_DEPTH {
            return Err(CandidateProgramError::ResourceLimit);
        }
        match value {
            TypeExpr::Named(value) => {
                self.add(dependent, value.definition, 2, kind_bit(4))?;
                for argument in &value.arguments {
                    self.type_expr(dependent, argument, depth + 1)?;
                }
            }
            TypeExpr::AdapterHandle(entity) => {
                self.add(dependent, *entity, 11, kind_bit(15))?;
            }
            TypeExpr::CapabilityToken(entity) => {
                self.add(dependent, *entity, 7, kind_bit(12))?;
            }
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
                    self.add(dependent, *effect, 6, kind_bit(11))?;
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
    ) -> Result<(), CandidateProgramError> {
        charge(&mut self.work, 1)?;
        if depth > sley_ssmc::MAX_TYPE_DEPTH {
            return Err(CandidateProgramError::ResourceLimit);
        }
        self.type_expr(dependent, &value.value_type, depth)?;
        match &value.data {
            ConstData::Sequence(values) => {
                for value in values {
                    self.const_value(dependent, value, depth + 1)?;
                }
            }
            ConstData::Record(value) => {
                self.add(dependent, value.definition, 12, kind_bit(4))?;
                for field in &value.fields {
                    self.const_value(dependent, &field.value, depth + 1)?;
                }
            }
            ConstData::Variant(value) => {
                self.add(dependent, value.definition, 12, kind_bit(4))?;
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
                self.add(dependent, value.function, 5, kind_bit(5))?;
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

    fn value_ref(
        &mut self,
        dependent: EntityId,
        value: ValueRef,
    ) -> Result<(), CandidateProgramError> {
        match value {
            ValueRef::Parameter(entity) => self.add(dependent, entity, 3, kind_bit(6)),
            ValueRef::OperationResult(value) => {
                self.add(dependent, value.operation, 3, kind_bit(8))
            }
        }
    }

    fn terminator(
        &mut self,
        dependent: EntityId,
        value: &Terminator,
    ) -> Result<(), CandidateProgramError> {
        charge(&mut self.work, 1)?;
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
                    self.add(dependent, case.edge.target, 4, kind_bit(7))?;
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
    ) -> Result<(), CandidateProgramError> {
        self.add(dependent, value.target, 4, kind_bit(7))?;
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
    ) -> Result<(), CandidateProgramError> {
        charge(&mut self.work, 1)?;
        match value {
            Immediate::Entity(entity) => {
                let (relationship, expected) = match opcode {
                    Opcode::ConstantRef => (3, 9),
                    Opcode::RecordNew => (12, 4),
                    Opcode::ContractAssert => (8, 13),
                    Opcode::EffectRequest => (6, 11),
                    Opcode::AdapterInvoke => (11, 15),
                    Opcode::CapabilityNarrow => (7, 12),
                    Opcode::GlobalGet => (3, 10),
                    _ => return Err(CandidateProgramError::WrongEntityKind),
                };
                self.add(dependent, *entity, relationship, kind_bit(expected))?;
            }
            Immediate::Variant(value) => {
                if !matches!(opcode, Opcode::VariantNew | Opcode::VariantGet) {
                    return Err(CandidateProgramError::WrongEntityKind);
                }
                self.add(dependent, value.definition, 12, kind_bit(4))?;
            }
            Immediate::Function(value) => {
                if !matches!(opcode, Opcode::CallDirect | Opcode::FunctionRef) {
                    return Err(CandidateProgramError::WrongEntityKind);
                }
                self.add(dependent, value.function, 5, kind_bit(5))?;
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

    fn effect_environment(
        &mut self,
        dependent: EntityId,
        environment: &EffectEnvironment,
    ) -> Result<(), CandidateProgramError> {
        match environment {
            EffectEnvironment::Replay(bindings) => {
                for binding in bindings {
                    self.add(dependent, binding.adapter_import, 11, kind_bit(15))?;
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
                    self.add(dependent, configuration.adapter_import, 11, kind_bit(15))?;
                    self.const_value(dependent, &configuration.configuration, 1)?;
                }
            }
        }
        Ok(())
    }
}

fn validate_test_types(
    types: &TypeEnvironment,
    test: &TestCaseDefinition,
) -> Result<(), TypeError> {
    for input in &test.inputs {
        types.check_constant(input)?;
    }
    match &test.effect_environment {
        EffectEnvironment::Replay(bindings) => {
            for binding in bindings {
                for request in &binding.request {
                    types.check_constant(request)?;
                }
                match &binding.response {
                    ResultConst::Ok(value) | ResultConst::Err(value) => {
                        types.check_constant(value)?;
                    }
                }
            }
        }
        EffectEnvironment::DeterministicAdapters(configurations) => {
            for configuration in configurations {
                types.check_constant(&configuration.configuration)?;
            }
        }
    }
    if let ExpectedOutcome::Value(value) = &test.expected {
        types.check_constant(value)?;
    }
    for observation in &test.observations {
        types.check_constant(&observation.value)?;
    }
    Ok(())
}

const fn kind_bit(kind: u16) -> u32 {
    1_u32 << (kind - 1)
}

fn charge(work: &mut u64, amount: u64) -> Result<(), CandidateProgramError> {
    *work = work
        .checked_add(amount)
        .ok_or(CandidateProgramError::ResourceLimit)?;
    if *work > MAX_PROGRAM_GRAPH_WORK {
        Err(CandidateProgramError::ResourceLimit)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sley_id::SchemaEpochId;
    use sley_mutate::{
        EntityObjectRecord, build_entity_object,
        value::{EntityIdSet, FunctionBody, GlobalValueBody, NamespaceBody, ParameterBody},
    };
    use sley_ssmc::{ParameterRole, Reachability, ReturnTerminator, TypeExpr, Visibility};

    use super::*;

    fn id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 32])
    }

    fn object(entity_id: EntityId, body: EntityBodyValue) -> EntityObject {
        build_entity_object(
            SchemaEpochId::from_bytes([7; 32]),
            &EntityObjectRecord {
                entity_id,
                body,
                label: None,
                semantic_fingerprint: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn projection_validates_all_local_references_and_builds_closure() {
        let namespace = object(
            id(1),
            EntityBodyValue::Namespace(NamespaceBody {
                parent: None,
                members: EntityIdSet::from_unsorted(vec![id(2)]).unwrap(),
            }),
        );
        let function = object(
            id(2),
            EntityBodyValue::Function(FunctionBody {
                type_parameters: vec![],
                parameters: vec![id(3)],
                result_type: TypeExpr::Bool,
                effects: EntityIdSet::from_unsorted(vec![]).unwrap(),
                entry_block: id(4),
                blocks: vec![id(4)],
                contracts: EntityIdSet::from_unsorted(vec![]).unwrap(),
                visibility: Visibility::Private,
            }),
        );
        let parameter = object(
            id(3),
            EntityBodyValue::Parameter(ParameterBody {
                owner: id(2),
                role: ParameterRole::Function,
                ordinal: 0,
                value_type: TypeExpr::Bool,
            }),
        );
        let block = object(
            id(4),
            EntityBodyValue::Block(sley_mutate::value::BlockBody {
                function: id(2),
                parameters: vec![],
                operations: vec![],
                terminator: Terminator::Return(ReturnTerminator {
                    value: ValueRef::Parameter(id(3)),
                }),
                reachability: Reachability::Required,
            }),
        );
        let program = CandidateProgram::project(&[namespace, function, parameter, block]).unwrap();
        assert_eq!(
            program.affected_closure(&[id(3)]).unwrap(),
            vec![id(1), id(2), id(3), id(4)]
        );
        assert!(program.operation_analysis_supported());
        assert_eq!(program.function_units().len(), 1);
        program.validate_types().unwrap();
    }

    #[test]
    fn projection_distinguishes_unresolved_wrong_kind_and_unknown_opcode() {
        let unresolved = object(
            id(1),
            EntityBodyValue::GlobalValue(GlobalValueBody {
                value_type: TypeExpr::Bool,
                initializer: id(2),
                visibility: Visibility::Private,
            }),
        );
        assert_eq!(
            CandidateProgram::project(&[unresolved]).unwrap_err(),
            CandidateProgramError::UnresolvedReference
        );

        let wrong = object(
            id(1),
            EntityBodyValue::GlobalValue(GlobalValueBody {
                value_type: TypeExpr::Bool,
                initializer: id(2),
                visibility: Visibility::Private,
            }),
        );
        let not_constant = object(
            id(2),
            EntityBodyValue::Namespace(NamespaceBody {
                parent: None,
                members: EntityIdSet::from_unsorted(vec![]).unwrap(),
            }),
        );
        assert_eq!(
            CandidateProgram::project(&[wrong, not_constant]).unwrap_err(),
            CandidateProgramError::WrongEntityKind
        );

        let operation = object(
            id(1),
            EntityBodyValue::Operation(sley_mutate::value::OperationBody {
                block: id(2),
                ordinal: 0,
                opcode: u32::MAX,
                operands: vec![],
                result_types: vec![],
                immediate: Immediate::None,
            }),
        );
        assert_eq!(
            CandidateProgram::project(&[operation]).unwrap_err(),
            CandidateProgramError::OpcodeUnknown
        );
    }

    #[test]
    fn dependency_projection_tracks_external_roots_without_resolving_external_package() {
        let namespace = object(
            id(1),
            EntityBodyValue::Namespace(NamespaceBody {
                parent: None,
                members: EntityIdSet::from_unsorted(vec![]).unwrap(),
            }),
        );
        let binding = object(
            id(2),
            EntityBodyValue::DependencyBinding(DependencyBindingBody {
                dependency_root: StateRoot::from_bytes([9; 32]),
                external_package: id(99),
                local_namespace: id(1),
            }),
        );
        let program = CandidateProgram::project(&[namespace, binding]).unwrap();
        assert_eq!(
            program.dependency_roots(),
            vec![StateRoot::from_bytes([9; 32])]
        );
    }
}
