use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::*;

pub(super) const CONTRACT: &str = "sley2-mutation-value-v1-partial";
pub(super) const SOURCE_SCHEMA_BLAKE3: &str =
    "044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73";
pub(super) const ACCEPTED_JSON: &str =
    include_str!("../../../../conformance/mutation-value/v1/accepted.json");
pub(super) const REJECTED_JSON: &str =
    include_str!("../../../../conformance/mutation-value/v1/rejected.json");

#[derive(serde::Deserialize)]
pub(super) struct AcceptedCorpus {
    pub(super) contract: String,
    pub(super) claim: String,
    pub(super) source_schema_blake3: String,
    pub(super) vectors: Vec<AcceptedVector>,
}

#[derive(serde::Deserialize)]
pub(super) struct AcceptedVector {
    pub(super) id: String,
    pub(super) declared_type: String,
    pub(super) value: Value,
    pub(super) expected_hex: String,
}

#[derive(serde::Deserialize)]
pub(super) struct RejectedCorpus {
    pub(super) contract: String,
    pub(super) claim: String,
    pub(super) source_schema_blake3: String,
    pub(super) vectors: Vec<RejectedVector>,
}

#[derive(serde::Deserialize)]
pub(super) struct RejectedVector {
    pub(super) id: String,
    pub(super) declared_type: String,
    pub(super) input_hex: String,
    pub(super) expected_code: String,
}

#[test]
fn independent_partial_accepted_fixtures_match_exact_private_codec_bytes() {
    let corpus: AcceptedCorpus = serde_json::from_str(ACCEPTED_JSON).unwrap();
    assert_fixture_header(
        &corpus.contract,
        &corpus.claim,
        &corpus.source_schema_blake3,
    );
    assert_eq!(corpus.vectors.len(), 126);
    assert_eq!(
        corpus
            .vectors
            .iter()
            .filter(|vector| vector.id.starts_with("type_expr_"))
            .count(),
        20
    );
    assert_eq!(
        corpus
            .vectors
            .iter()
            .filter(|vector| vector.id.starts_with("body_"))
            .count(),
        11
    );
    assert_eq!(
        corpus
            .vectors
            .iter()
            .filter(|vector| vector.id.starts_with("field_"))
            .count(),
        65
    );
    assert_unique_ids(corpus.vectors.iter().map(|vector| vector.id.as_str()));
    assert!(
        corpus
            .vectors
            .iter()
            .all(|vector| !vector.declared_type.contains("Option<"))
    );
    for vector in &corpus.vectors {
        assert_accepted_vector(vector);
    }
}

#[test]
fn independent_partial_rejected_fixtures_return_exact_private_codes() {
    let corpus: RejectedCorpus = serde_json::from_str(REJECTED_JSON).unwrap();
    assert_fixture_header(
        &corpus.contract,
        &corpus.claim,
        &corpus.source_schema_blake3,
    );
    assert_eq!(corpus.vectors.len(), 18);
    assert_unique_ids(corpus.vectors.iter().map(|vector| vector.id.as_str()));
    for vector in &corpus.vectors {
        let input = fixture_hex(&Value::String(vector.input_hex.clone()));
        let error = rejected_error(&vector.declared_type, &input);
        assert_eq!(error.code().as_str(), vector.expected_code, "{}", vector.id);
    }
}

pub(super) fn assert_fixture_header(contract: &str, claim: &str, schema_digest: &str) {
    assert_eq!(contract, CONTRACT);
    assert_eq!(claim, "partial");
    assert_eq!(schema_digest, SOURCE_SCHEMA_BLAKE3);
}

pub(super) fn assert_unique_ids<'a>(ids: impl Iterator<Item = &'a str>) {
    let ids = ids.collect::<Vec<_>>();
    assert_eq!(
        ids.iter().copied().collect::<BTreeSet<_>>().len(),
        ids.len()
    );
}

fn assert_accepted_vector(vector: &AcceptedVector) {
    if assert_accepted_field_vector(vector) {
        return;
    }
    match vector.declared_type.as_str() {
        "Bool" => assert_fixture(vector, &fixture_bool(&vector.value)),
        "UInt16" => assert_fixture(vector, &fixture_u16(&vector.value)),
        "UInt32" => assert_fixture(vector, &fixture_u32(&vector.value)),
        "UInt64" => assert_fixture(vector, &fixture_u64(&vector.value)),
        "SInt64" => assert_fixture(vector, &fixture_i64(&vector.value)),
        "Bytes" => assert_fixture(vector, &fixture_hex(&vector.value)),
        "Text" => assert_fixture(vector, &fixture_string(&vector.value).to_owned()),
        "FixedBytes32" => assert_fixture(vector, &fixture_fixed32(&vector.value)),
        "EntityId" => assert_fixture(vector, &fixture_entity_id(&vector.value)),
        "StateRoot" => assert_fixture(vector, &fixture_state_root(&vector.value)),
        "MemberId" => assert_fixture(vector, &fixture_member_id(&vector.value)),
        "EntityIdSet" => assert_fixture(vector, &fixture_entity_id_set(&vector.value)),
        "List<UInt32>" => assert_fixture(vector, &fixture_vec(&vector.value, fixture_u32)),
        "List<Visibility>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_visibility));
        }
        "List<ParameterRole>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_parameter_role));
        }
        "List<Reachability>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_reachability));
        }
        "List<EffectKind>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_effect_kind));
        }
        "List<ContractKind>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_contract_kind));
        }
        "List<EntryExposure>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_entry_exposure));
        }
        "List<BuiltinFailureKind>" => {
            assert_fixture(
                vector,
                &fixture_vec(&vector.value, fixture_builtin_failure_kind),
            );
        }
        "List<BuiltinCase>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_builtin_case));
        }
        "List<TrapCode>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_trap_code));
        }
        "TypeExpr" => assert_fixture(vector, &fixture_type_expr(&vector.value)),
        "List<Immediate>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_immediate));
        }
        "VariantSwitchTerminator" => {
            assert_fixture(vector, &fixture_variant_switch(&vector.value));
        }
        "CondBranchTerminator" => {
            assert_fixture(vector, &fixture_cond_branch(&vector.value));
        }
        "List<ContractSource>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_contract_source));
        }
        "ContractBinding" => assert_fixture(vector, &fixture_contract_binding(&vector.value)),
        "ResourceLimits" => assert_fixture(vector, &fixture_resource_limits(&vector.value)),
        "BuiltinFailureValue" => {
            assert_fixture(vector, &fixture_builtin_failure_value(&vector.value));
        }
        "RecordField" => assert_fixture(vector, &fixture_record_field(&vector.value)),
        "WorkspaceBody" => assert_fixture(vector, &fixture_workspace_body(&vector.value)),
        "PackageBody" => assert_fixture(vector, &fixture_package_body(&vector.value)),
        "FunctionBody" => assert_fixture(vector, &fixture_function_body(&vector.value)),
        "ParameterBody" => assert_fixture(vector, &fixture_parameter_body(&vector.value)),
        "OperationBody" => assert_fixture(vector, &fixture_operation_body(&vector.value)),
        "GlobalValueBody" => assert_fixture(vector, &fixture_global_value_body(&vector.value)),
        "EffectDefBody" => assert_fixture(vector, &fixture_effect_def_body(&vector.value)),
        "AdapterImportBody" => {
            assert_fixture(vector, &fixture_adapter_import_body(&vector.value));
        }
        "EntryPointBody" => assert_fixture(vector, &fixture_entry_point_body(&vector.value)),
        "PolicyBindingBody" => {
            assert_fixture(vector, &fixture_policy_binding_body(&vector.value));
        }
        "DependencyBindingBody" => {
            assert_fixture(vector, &fixture_dependency_binding_body(&vector.value));
        }
        declared_type => panic!("unsupported accepted fixture type {declared_type}"),
    }
}

fn assert_accepted_field_vector(vector: &AcceptedVector) -> bool {
    match vector.declared_type.as_str() {
        "Set<EntityId>" => assert_fixture(vector, &fixture_entity_id_set(&vector.value)),
        "List<EntityId>" => assert_fixture(vector, &fixture_vec(&vector.value, fixture_entity_id)),
        "Visibility" => assert_fixture(vector, &fixture_visibility(&vector.value)),
        "ParameterRole" => assert_fixture(vector, &fixture_parameter_role(&vector.value)),
        "Reachability" => assert_fixture(vector, &fixture_reachability(&vector.value)),
        "EffectKind" => assert_fixture(vector, &fixture_effect_kind(&vector.value)),
        "ContractKind" => assert_fixture(vector, &fixture_contract_kind(&vector.value)),
        "EntryExposure" => assert_fixture(vector, &fixture_entry_exposure(&vector.value)),
        "List<TypeExpr>" => {
            assert_fixture(vector, &fixture_vec(&vector.value, fixture_type_expr));
        }
        "List<TypeParameterDef>" => {
            assert_fixture(
                vector,
                &fixture_vec(&vector.value, fixture_type_parameter_def),
            );
        }
        "List<ValueRef>" => assert_fixture(vector, &fixture_vec(&vector.value, fixture_value_ref)),
        "Immediate" => assert_fixture(vector, &fixture_immediate(&vector.value)),
        "List<ContractBinding>" => {
            assert_fixture(
                vector,
                &fixture_vec(&vector.value, fixture_contract_binding),
            );
        }
        _ => return false,
    }
    true
}

fn assert_fixture<T>(vector: &AcceptedVector, value: &T)
where
    T: MutationValueCodec + Eq + core::fmt::Debug,
{
    let expected = fixture_hex(&Value::String(vector.expected_hex.clone()));
    assert_eq!(encode_exact(value).unwrap(), expected, "{}", vector.id);
    assert_eq!(
        &decode_exact::<T>(&expected).unwrap(),
        value,
        "{}",
        vector.id
    );
}

pub(super) fn rejected_error(declared_type: &str, input: &[u8]) -> ScbError {
    match declared_type {
        "Bool" => decode_rejected::<bool>(input),
        "UInt16" => decode_rejected::<u16>(input),
        "UInt32" => decode_rejected::<u32>(input),
        "Text" => decode_rejected::<String>(input),
        "FixedBytes32" => decode_rejected::<[u8; 32]>(input),
        "EntityIdSet" => decode_rejected::<EntityIdSet>(input),
        "Visibility" => decode_rejected::<Visibility>(input),
        "TypeExpr" => decode_rejected::<TypeExpr>(input),
        "Immediate" => decode_rejected::<Immediate>(input),
        "ContractSource" => decode_rejected::<ContractSource>(input),
        "List<UInt32>" => decode_rejected::<Vec<u32>>(input),
        "OperationBody" => decode_rejected::<OperationBody>(input),
        _ => panic!("unsupported rejected fixture type {declared_type}"),
    }
}

fn decode_rejected<T>(input: &[u8]) -> ScbError
where
    T: MutationValueCodec + core::fmt::Debug,
{
    decode_exact::<T>(input).expect_err("rejected fixture decoded successfully")
}

fn fixture_object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("fixture value must be an object")
}

fn fixture_field<'a>(value: &'a Value, name: &str) -> &'a Value {
    fixture_object(value)
        .get(name)
        .unwrap_or_else(|| panic!("fixture object is missing {name}"))
}

fn fixture_array(value: &Value) -> &[Value] {
    value.as_array().expect("fixture value must be an array")
}

fn fixture_string(value: &Value) -> &str {
    value.as_str().expect("fixture value must be a string")
}

fn fixture_bool(value: &Value) -> bool {
    value.as_bool().expect("fixture value must be a Boolean")
}

fn fixture_u64(value: &Value) -> u64 {
    value.as_u64().unwrap_or_else(|| {
        fixture_string(value)
            .parse()
            .expect("fixture value must be an exact UInt64")
    })
}

fn fixture_u32(value: &Value) -> u32 {
    u32::try_from(fixture_u64(value)).expect("fixture value must fit UInt32")
}

fn fixture_u16(value: &Value) -> u16 {
    u16::try_from(fixture_u64(value)).expect("fixture value must fit UInt16")
}

fn fixture_i64(value: &Value) -> i64 {
    value.as_i64().unwrap_or_else(|| {
        fixture_string(value)
            .parse()
            .expect("fixture value must be an exact SInt64")
    })
}

pub(super) fn fixture_hex(value: &Value) -> Vec<u8> {
    let raw = fixture_string(value);
    assert_eq!(raw.len() % 2, 0, "fixture hex must have an even length");
    raw.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
                .expect("fixture value must be lowercase hex")
        })
        .collect()
}

fn fixture_fixed32(value: &Value) -> [u8; 32] {
    fixture_hex(value)
        .try_into()
        .expect("fixture value must contain exactly 32 bytes")
}

fn fixture_entity_id(value: &Value) -> EntityId {
    EntityId::from_bytes(fixture_fixed32(value))
}

fn fixture_state_root(value: &Value) -> StateRoot {
    StateRoot::from_bytes(fixture_fixed32(value))
}

fn fixture_member_id(value: &Value) -> MemberId {
    MemberId::from_bytes(fixture_fixed32(value))
}

fn fixture_vec<T>(value: &Value, parse: fn(&Value) -> T) -> Vec<T> {
    fixture_array(value).iter().map(parse).collect()
}

fn fixture_entity_id_set(value: &Value) -> EntityIdSet {
    let values = fixture_vec(value, fixture_entity_id);
    assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
    EntityIdSet::from_unsorted(values).unwrap()
}

macro_rules! fixture_enum_parser {
    ($name:ident, $type:ty, {$($text:literal => $value:path),+ $(,)?}) => {
        fn $name(value: &Value) -> $type {
            match fixture_string(value) {
                $($text => $value,)+
                other => panic!("unknown fixture enum value {other}"),
            }
        }
    };
}

fixture_enum_parser!(fixture_visibility, Visibility, {
    "Private" => Visibility::Private,
    "Package" => Visibility::Package,
    "Workspace" => Visibility::Workspace,
    "Exported" => Visibility::Exported,
});
fixture_enum_parser!(fixture_parameter_role, ParameterRole, {
    "Function" => ParameterRole::Function,
    "Block" => ParameterRole::Block,
});
fixture_enum_parser!(fixture_reachability, Reachability, {
    "Required" => Reachability::Required,
    "ExplicitlyUnreachable" => Reachability::ExplicitlyUnreachable,
});
fixture_enum_parser!(fixture_effect_kind, EffectKind, {
    "StdoutWrite" => EffectKind::StdoutWrite,
    "StderrWrite" => EffectKind::StderrWrite,
    "FileRead" => EffectKind::FileRead,
    "FileWrite" => EffectKind::FileWrite,
    "ClockRead" => EffectKind::ClockRead,
    "RandomRead" => EffectKind::RandomRead,
    "EnvironmentRead" => EffectKind::EnvironmentRead,
    "AdapterCall" => EffectKind::AdapterCall,
});
fixture_enum_parser!(fixture_contract_kind, ContractKind, {
    "Precondition" => ContractKind::Precondition,
    "Postcondition" => ContractKind::Postcondition,
    "Invariant" => ContractKind::Invariant,
    "EffectBound" => ContractKind::EffectBound,
    "CapabilityBound" => ContractKind::CapabilityBound,
    "ResultPredicate" => ContractKind::ResultPredicate,
    "ResourceCeiling" => ContractKind::ResourceCeiling,
});
fixture_enum_parser!(fixture_entry_exposure, EntryExposure, {
    "Local" => EntryExposure::Local,
    "Protocol" => EntryExposure::Protocol,
});
fixture_enum_parser!(fixture_builtin_failure_kind, BuiltinFailureKind, {
    "ArithmeticError" => BuiltinFailureKind::Arithmetic,
    "IndexError" => BuiltinFailureKind::Index,
    "DuplicateKeyError" => BuiltinFailureKind::DuplicateKey,
    "ContractViolation" => BuiltinFailureKind::ContractViolation,
    "CapabilityFailure" => BuiltinFailureKind::Capability,
});
fixture_enum_parser!(fixture_builtin_case, BuiltinCase, {
    "None" => BuiltinCase::None,
    "Some" => BuiltinCase::Some,
    "Ok" => BuiltinCase::Ok,
    "Err" => BuiltinCase::Err,
});
fixture_enum_parser!(fixture_trap_code, TrapCode, {
    "Unreachable" => TrapCode::Unreachable,
    "ResourceExhausted" => TrapCode::ResourceExhausted,
    "AdapterContractViolation" => TrapCode::AdapterContractViolation,
    "InternalInvariant" => TrapCode::InternalInvariant,
});

fn fixture_type_expr(value: &Value) -> TypeExpr {
    let variant = fixture_string(fixture_field(value, "variant"));
    let payload = || fixture_field(value, "value");
    match variant {
        "Unit" => TypeExpr::Unit,
        "Bool" => TypeExpr::Bool,
        "SInt" => TypeExpr::SInt(IntegerWidth::from_bits(fixture_u16(payload()))),
        "UInt" => TypeExpr::UInt(IntegerWidth::from_bits(fixture_u16(payload()))),
        "F32" => TypeExpr::F32,
        "F64" => TypeExpr::F64,
        "Bytes" => TypeExpr::Bytes,
        "Text" => TypeExpr::Text,
        "Tuple" => TypeExpr::Tuple(fixture_vec(payload(), fixture_type_expr)),
        "Named" => TypeExpr::Named(fixture_named_type(payload())),
        "Vector" => TypeExpr::Vector(Box::new(fixture_type_expr(payload()))),
        "OrderedMap" => TypeExpr::OrderedMap {
            key: Box::new(fixture_type_expr(fixture_field(payload(), "key"))),
            value: Box::new(fixture_type_expr(fixture_field(payload(), "value"))),
        },
        "Option" => TypeExpr::Option(Box::new(fixture_type_expr(payload()))),
        "Result" => TypeExpr::Result {
            ok: Box::new(fixture_type_expr(fixture_field(payload(), "ok"))),
            error: Box::new(fixture_type_expr(fixture_field(payload(), "error"))),
        },
        "FunctionRef" => TypeExpr::FunctionRef(fixture_function_type(payload())),
        "AdapterHandle" => TypeExpr::AdapterHandle(fixture_entity_id(payload())),
        "CapabilityToken" => TypeExpr::CapabilityToken(fixture_entity_id(payload())),
        "LocalCell" => TypeExpr::LocalCell(Box::new(fixture_type_expr(payload()))),
        "TypeParameter" => TypeExpr::TypeParameter(fixture_u32(payload())),
        "BuiltinFailure" => TypeExpr::BuiltinFailure(fixture_builtin_failure_kind(payload())),
        _ => panic!("unknown TypeExpr fixture variant {variant}"),
    }
}

fn fixture_named_type(value: &Value) -> NamedType {
    NamedType {
        definition: fixture_entity_id(fixture_field(value, "definition")),
        arguments: fixture_vec(fixture_field(value, "arguments"), fixture_type_expr),
    }
}

fn fixture_function_type(value: &Value) -> FunctionType {
    FunctionType {
        parameters: fixture_vec(fixture_field(value, "parameters"), fixture_type_expr),
        result: Box::new(fixture_type_expr(fixture_field(value, "result"))),
        effects: fixture_vec(fixture_field(value, "effects"), fixture_entity_id),
    }
}

fn fixture_value_ref(value: &Value) -> ValueRef {
    match fixture_string(fixture_field(value, "variant")) {
        "Parameter" => ValueRef::Parameter(fixture_entity_id(fixture_field(value, "value"))),
        "OperationResult" => {
            let payload = fixture_field(value, "value");
            ValueRef::OperationResult(OperationResultRef {
                operation: fixture_entity_id(fixture_field(payload, "operation")),
                result_index: fixture_u32(fixture_field(payload, "result_index")),
            })
        }
        variant => panic!("unknown ValueRef fixture variant {variant}"),
    }
}

fn fixture_function_ref_value(value: &Value) -> FunctionRefValue {
    FunctionRefValue {
        function: fixture_entity_id(fixture_field(value, "function")),
        type_arguments: fixture_vec(fixture_field(value, "type_arguments"), fixture_type_expr),
    }
}

fn fixture_immediate(value: &Value) -> Immediate {
    match fixture_string(fixture_field(value, "variant")) {
        "None" => Immediate::None,
        "Entity" => Immediate::Entity(fixture_entity_id(fixture_field(value, "value"))),
        "Index" => Immediate::Index(fixture_u32(fixture_field(value, "value"))),
        "Field" => Immediate::Field(fixture_member_id(fixture_field(value, "value"))),
        "Variant" => {
            let payload = fixture_field(value, "value");
            Immediate::Variant(VariantImmediate {
                definition: fixture_entity_id(fixture_field(payload, "definition")),
                member_id: fixture_member_id(fixture_field(payload, "member_id")),
            })
        }
        "Observation" => Immediate::Observation(fixture_fixed32(fixture_field(value, "value"))),
        "Function" => {
            Immediate::Function(fixture_function_ref_value(fixture_field(value, "value")))
        }
        variant => panic!("unknown Immediate fixture variant {variant}"),
    }
}

fn fixture_case_key(value: &Value) -> CaseKey {
    match fixture_string(fixture_field(value, "variant")) {
        "Member" => CaseKey::Member(fixture_member_id(fixture_field(value, "value"))),
        "Builtin" => CaseKey::Builtin(fixture_builtin_case(fixture_field(value, "value"))),
        variant => panic!("unknown CaseKey fixture variant {variant}"),
    }
}

fn fixture_switch_argument(value: &Value) -> SwitchArgument {
    match fixture_string(fixture_field(value, "variant")) {
        "Value" => SwitchArgument::Value(fixture_value_ref(fixture_field(value, "value"))),
        "CasePayload" => SwitchArgument::CasePayload,
        variant => panic!("unknown SwitchArgument fixture variant {variant}"),
    }
}

fn fixture_switch_edge(value: &Value) -> SwitchEdge {
    SwitchEdge {
        target: fixture_entity_id(fixture_field(value, "target")),
        arguments: fixture_vec(fixture_field(value, "arguments"), fixture_switch_argument),
    }
}

fn fixture_switch_case(value: &Value) -> SwitchCase {
    SwitchCase {
        case_key: fixture_case_key(fixture_field(value, "case_key")),
        edge: fixture_switch_edge(fixture_field(value, "edge")),
    }
}

fn fixture_target_edge(value: &Value) -> TargetEdge {
    TargetEdge {
        target: fixture_entity_id(fixture_field(value, "target")),
        arguments: fixture_vec(fixture_field(value, "arguments"), fixture_value_ref),
    }
}

fn fixture_variant_switch(value: &Value) -> VariantSwitchTerminator {
    VariantSwitchTerminator {
        value: fixture_value_ref(fixture_field(value, "value")),
        cases: fixture_vec(fixture_field(value, "cases"), fixture_switch_case),
    }
}

fn fixture_cond_branch(value: &Value) -> CondBranchTerminator {
    CondBranchTerminator {
        condition: fixture_value_ref(fixture_field(value, "condition")),
        if_true: fixture_target_edge(fixture_field(value, "if_true")),
        if_false: fixture_target_edge(fixture_field(value, "if_false")),
    }
}

fn fixture_contract_source(value: &Value) -> ContractSource {
    match fixture_string(fixture_field(value, "variant")) {
        "Parameter" => ContractSource::Parameter(fixture_entity_id(fixture_field(value, "value"))),
        "Result" => ContractSource::Result,
        "Error" => ContractSource::Error,
        "Global" => ContractSource::Global(fixture_entity_id(fixture_field(value, "value"))),
        variant => panic!("unknown ContractSource fixture variant {variant}"),
    }
}

fn fixture_contract_binding(value: &Value) -> ContractBinding {
    ContractBinding {
        predicate_parameter: fixture_u32(fixture_field(value, "predicate_parameter")),
        source: fixture_contract_source(fixture_field(value, "source")),
    }
}

fn fixture_resource_limits(value: &Value) -> ResourceLimits {
    ResourceLimits {
        fuel: fixture_u64(fixture_field(value, "fuel")),
        memory_bytes: fixture_u64(fixture_field(value, "memory_bytes")),
        output_bytes: fixture_u64(fixture_field(value, "output_bytes")),
        effect_count: fixture_u64(fixture_field(value, "effect_count")),
        call_depth: fixture_u64(fixture_field(value, "call_depth")),
        wall_timeout_millis: fixture_u64(fixture_field(value, "wall_timeout_millis")),
    }
}

fn fixture_builtin_failure_value(value: &Value) -> BuiltinFailureValue {
    BuiltinFailureValue {
        kind: fixture_builtin_failure_kind(fixture_field(value, "kind")),
        code: fixture_u16(fixture_field(value, "code")),
    }
}

fn fixture_record_field(value: &Value) -> RecordField {
    RecordField {
        member_id: fixture_member_id(fixture_field(value, "member_id")),
        value_type: fixture_type_expr(fixture_field(value, "value_type")),
        visibility: fixture_visibility(fixture_field(value, "visibility")),
    }
}

fn fixture_workspace_body(value: &Value) -> WorkspaceBody {
    WorkspaceBody {
        packages: fixture_entity_id_set(fixture_field(value, "packages")),
        root_namespace: fixture_entity_id(fixture_field(value, "root_namespace")),
        capability_requirements: fixture_entity_id_set(fixture_field(
            value,
            "capability_requirements",
        )),
        contracts: fixture_entity_id_set(fixture_field(value, "contracts")),
        tests: fixture_entity_id_set(fixture_field(value, "tests")),
    }
}

fn fixture_package_body(value: &Value) -> PackageBody {
    PackageBody {
        workspace: fixture_entity_id(fixture_field(value, "workspace")),
        root_namespace: fixture_entity_id(fixture_field(value, "root_namespace")),
        dependencies: fixture_entity_id_set(fixture_field(value, "dependencies")),
        exports: fixture_entity_id_set(fixture_field(value, "exports")),
    }
}

fn fixture_function_body(value: &Value) -> FunctionBody {
    FunctionBody {
        type_parameters: fixture_vec(
            fixture_field(value, "type_parameters"),
            fixture_type_parameter_def,
        ),
        parameters: fixture_vec(fixture_field(value, "parameters"), fixture_entity_id),
        result_type: fixture_type_expr(fixture_field(value, "result_type")),
        effects: fixture_entity_id_set(fixture_field(value, "effects")),
        entry_block: fixture_entity_id(fixture_field(value, "entry_block")),
        blocks: fixture_vec(fixture_field(value, "blocks"), fixture_entity_id),
        contracts: fixture_entity_id_set(fixture_field(value, "contracts")),
        visibility: fixture_visibility(fixture_field(value, "visibility")),
    }
}

fn fixture_type_parameter_def(value: &Value) -> TypeParameterDef {
    TypeParameterDef {
        ordinal: fixture_u32(fixture_field(value, "ordinal")),
    }
}

fn fixture_parameter_body(value: &Value) -> ParameterBody {
    ParameterBody {
        owner: fixture_entity_id(fixture_field(value, "owner")),
        role: fixture_parameter_role(fixture_field(value, "role")),
        ordinal: fixture_u32(fixture_field(value, "ordinal")),
        value_type: fixture_type_expr(fixture_field(value, "value_type")),
    }
}

fn fixture_operation_body(value: &Value) -> OperationBody {
    OperationBody {
        block: fixture_entity_id(fixture_field(value, "block")),
        ordinal: fixture_u32(fixture_field(value, "ordinal")),
        opcode: fixture_u32(fixture_field(value, "opcode")),
        operands: fixture_vec(fixture_field(value, "operands"), fixture_value_ref),
        result_types: fixture_vec(fixture_field(value, "result_types"), fixture_type_expr),
        immediate: fixture_immediate(fixture_field(value, "immediate")),
    }
}

fn fixture_global_value_body(value: &Value) -> GlobalValueBody {
    GlobalValueBody {
        value_type: fixture_type_expr(fixture_field(value, "value_type")),
        initializer: fixture_entity_id(fixture_field(value, "initializer")),
        visibility: fixture_visibility(fixture_field(value, "visibility")),
    }
}

fn fixture_effect_def_body(value: &Value) -> EffectDefBody {
    EffectDefBody {
        effect_kind: fixture_effect_kind(fixture_field(value, "effect_kind")),
        scope_type: fixture_type_expr(fixture_field(value, "scope_type")),
        request_type: fixture_type_expr(fixture_field(value, "request_type")),
        response_type: fixture_type_expr(fixture_field(value, "response_type")),
        failure_type: fixture_type_expr(fixture_field(value, "failure_type")),
        visibility: fixture_visibility(fixture_field(value, "visibility")),
    }
}

fn fixture_adapter_import_body(value: &Value) -> AdapterImportBody {
    AdapterImportBody {
        adapter_id: fixture_fixed32(fixture_field(value, "adapter_id")),
        abi_version: fixture_u32(fixture_field(value, "abi_version")),
        request_type: fixture_type_expr(fixture_field(value, "request_type")),
        response_type: fixture_type_expr(fixture_field(value, "response_type")),
        failure_type: fixture_type_expr(fixture_field(value, "failure_type")),
        effects: fixture_entity_id_set(fixture_field(value, "effects")),
    }
}

fn fixture_entry_point_body(value: &Value) -> EntryPointBody {
    EntryPointBody {
        function: fixture_entity_id(fixture_field(value, "function")),
        exposure: fixture_entry_exposure(fixture_field(value, "exposure")),
    }
}

fn fixture_policy_binding_body(value: &Value) -> PolicyBindingBody {
    PolicyBindingBody {
        subject: fixture_entity_id(fixture_field(value, "subject")),
        requirements: fixture_entity_id_set(fixture_field(value, "requirements")),
    }
}

fn fixture_dependency_binding_body(value: &Value) -> DependencyBindingBody {
    DependencyBindingBody {
        dependency_root: fixture_state_root(fixture_field(value, "dependency_root")),
        external_package: fixture_entity_id(fixture_field(value, "external_package")),
        local_namespace: fixture_entity_id(fixture_field(value, "local_namespace")),
    }
}
