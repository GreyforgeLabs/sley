use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use serde_json::Value;

use super::fixture_tests::{
    ACCEPTED_JSON, AcceptedCorpus, REJECTED_JSON, RejectedCorpus, assert_fixture_header,
    assert_unique_ids, fixture_hex,
};
use super::*;

const ACCEPTED_VECTOR_COUNT: usize = 126;
const REJECTED_VECTOR_COUNT: usize = 18;
const APPENDED_DERIVED_CASES: usize = ACCEPTED_VECTOR_COUNT * 2;
const PREFIX_DERIVED_CASES: usize = 446;
const TOTAL_DERIVED_CASES: usize = APPENDED_DERIVED_CASES + PREFIX_DERIVED_CASES;

#[test]
fn bounded_mutation_value_codec_fuzz_smoke() {
    let corpus: AcceptedCorpus = serde_json::from_str(ACCEPTED_JSON).unwrap();
    assert_fixture_header(
        &corpus.contract,
        &corpus.claim,
        &corpus.source_schema_blake3,
    );
    assert_eq!(corpus.vectors.len(), ACCEPTED_VECTOR_COUNT);
    assert_unique_ids(corpus.vectors.iter().map(|vector| vector.id.as_str()));

    let mut appended_cases = 0;
    let mut prefix_cases = 0;

    for vector in &corpus.vectors {
        let canonical = fixture_hex(&Value::String(vector.expected_hex.clone()));
        assert_decode_reencode(
            &vector.id,
            &vector.declared_type,
            "canonical",
            &canonical,
            Ok(canonical.as_slice()),
        )
        .expect("canonical fixture must decode and re-encode");

        for byte in [0x00, 0xff] {
            let mut mutated = canonical.clone();
            mutated.push(byte);
            assert_repeated_error_code(
                &vector.id,
                &vector.declared_type,
                &format!("append-{byte:02x}"),
                &mutated,
                ScbErrorCode::TrailingBytes.as_str(),
            );
            appended_cases += 1;
        }

        for prefix_len in proper_prefix_lengths(canonical.len()) {
            let prefix = &canonical[..prefix_len];
            assert_repeated_err(
                &vector.id,
                &vector.declared_type,
                &format!("prefix-{prefix_len}"),
                prefix,
            );
            prefix_cases += 1;
        }
    }

    assert_eq!(appended_cases, APPENDED_DERIVED_CASES);
    assert_eq!(prefix_cases, PREFIX_DERIVED_CASES);
    assert_eq!(appended_cases + prefix_cases, TOTAL_DERIVED_CASES);
}

#[test]
fn mutation_value_codec_adversarial() {
    let corpus: RejectedCorpus = serde_json::from_str(REJECTED_JSON).unwrap();
    assert_fixture_header(
        &corpus.contract,
        &corpus.claim,
        &corpus.source_schema_blake3,
    );
    assert_eq!(corpus.vectors.len(), REJECTED_VECTOR_COUNT);
    assert_unique_ids(corpus.vectors.iter().map(|vector| vector.id.as_str()));

    let expected = [
        ("reject_bool_invalid", "Bool", "SCB_BOOL_INVALID"),
        ("reject_uint16_overflow", "UInt16", "SCB_INTEGER_OVERFLOW"),
        (
            "reject_uint32_nonminimal",
            "UInt32",
            "SCB_VARINT_NON_MINIMAL",
        ),
        ("reject_text_utf8", "Text", "SCB_UTF8_INVALID"),
        (
            "reject_fixed32_short",
            "FixedBytes32",
            "SCB_LENGTH_OVERFLOW",
        ),
        ("reject_set_duplicate", "EntityIdSet", "SCB_MAP_DUPLICATE"),
        ("reject_set_order", "EntityIdSet", "SCB_MAP_ORDER"),
        (
            "reject_visibility_unknown",
            "Visibility",
            "SCB_UNION_INVALID",
        ),
        ("reject_type_expr_unknown", "TypeExpr", "SCB_UNION_INVALID"),
        (
            "reject_type_expr_unit_payload",
            "TypeExpr",
            "SCB_UNION_INVALID",
        ),
        (
            "reject_immediate_none_payload",
            "Immediate",
            "SCB_UNION_INVALID",
        ),
        (
            "reject_contract_source_unknown",
            "ContractSource",
            "SCB_UNION_INVALID",
        ),
        (
            "reject_list_resource_limit",
            "List<UInt32>",
            "SCB_RESOURCE_LIMIT",
        ),
        (
            "reject_operation_missing",
            "OperationBody",
            "SCB_FIELD_MISSING",
        ),
        (
            "reject_operation_unknown",
            "OperationBody",
            "SCB_FIELD_UNKNOWN",
        ),
        (
            "reject_operation_duplicate",
            "OperationBody",
            "SCB_FIELD_DUPLICATE",
        ),
        ("reject_operation_order", "OperationBody", "SCB_FIELD_ORDER"),
        (
            "reject_operation_nested_trailing",
            "OperationBody",
            "SCB_TRAILING_BYTES",
        ),
    ];

    let actual = corpus
        .vectors
        .iter()
        .map(|vector| {
            (
                vector.id.as_str(),
                vector.declared_type.as_str(),
                vector.expected_code.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);

    for vector in &corpus.vectors {
        let input = fixture_hex(&Value::String(vector.input_hex.clone()));
        assert_repeated_error_code(
            &vector.id,
            &vector.declared_type,
            "committed-rejection",
            &input,
            &vector.expected_code,
        );
    }
}

fn proper_prefix_lengths(len: usize) -> Vec<usize> {
    [0, 1, len / 2, len.saturating_sub(1)]
        .into_iter()
        .filter(|prefix_len| *prefix_len < len)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn assert_repeated_err(vector_id: &str, declared_type: &str, mutation: &str, input: &[u8]) {
    let first = assert_decode_reencode(vector_id, declared_type, mutation, input, Err(None))
        .expect_err("mutation must fail");
    let second = assert_decode_reencode(vector_id, declared_type, mutation, input, Err(None))
        .expect_err("repeated mutation must fail");
    assert_eq!(
        first, second,
        "{vector_id} {declared_type} {mutation} changed error code"
    );
}

fn assert_repeated_error_code(
    vector_id: &str,
    declared_type: &str,
    mutation: &str,
    input: &[u8],
    expected_code: &str,
) {
    let first = assert_decode_reencode(
        vector_id,
        declared_type,
        mutation,
        input,
        Err(Some(expected_code)),
    )
    .expect_err("mutation must fail");
    let second = assert_decode_reencode(
        vector_id,
        declared_type,
        mutation,
        input,
        Err(Some(expected_code)),
    )
    .expect_err("repeated mutation must fail");
    assert_eq!(
        first, second,
        "{vector_id} {declared_type} {mutation} changed error code"
    );
}

fn assert_decode_reencode(
    vector_id: &str,
    declared_type: &str,
    mutation: &str,
    input: &[u8],
    expected: core::result::Result<&[u8], Option<&str>>,
) -> core::result::Result<Vec<u8>, String> {
    let decoded = catch_unwind(AssertUnwindSafe(|| decode_reencode(declared_type, input)))
        .unwrap_or_else(|_| panic!("{vector_id} {declared_type} {mutation} decode panicked"));
    match (decoded, expected) {
        (Ok(encoded), Ok(expected_bytes)) => {
            assert_eq!(
                encoded, expected_bytes,
                "{vector_id} {declared_type} {mutation} canonical re-encode drift"
            );
            Ok(encoded)
        }
        (Ok(_), Err(_)) => panic!("{vector_id} {declared_type} {mutation} decoded unexpectedly"),
        (Err(error), Ok(_)) => {
            panic!(
                "{vector_id} {declared_type} {mutation} failed with {}",
                error.code()
            )
        }
        (Err(error), Err(expected_code)) => {
            if let Some(expected_code) = expected_code {
                assert_eq!(
                    error.code().as_str(),
                    expected_code,
                    "{vector_id} {declared_type} {mutation}"
                );
            }
            Err(error.code().as_str().to_owned())
        }
    }
}

fn decode_reencode(declared_type: &str, input: &[u8]) -> Result<Vec<u8>> {
    match declared_type {
        "Bool" => decode_reencode_typed::<bool>(input),
        "UInt16" => decode_reencode_typed::<u16>(input),
        "UInt32" => decode_reencode_typed::<u32>(input),
        "UInt64" => decode_reencode_typed::<u64>(input),
        "SInt64" => decode_reencode_typed::<i64>(input),
        "Bytes" => decode_reencode_typed::<Vec<u8>>(input),
        "Text" => decode_reencode_typed::<String>(input),
        "FixedBytes32" => decode_reencode_typed::<[u8; 32]>(input),
        "EntityId" => decode_reencode_typed::<EntityId>(input),
        "StateRoot" => decode_reencode_typed::<StateRoot>(input),
        "MemberId" => decode_reencode_typed::<MemberId>(input),
        "EntityIdSet" | "Set<EntityId>" => decode_reencode_typed::<EntityIdSet>(input),
        "List<UInt32>" => decode_reencode_typed::<Vec<u32>>(input),
        "List<Visibility>" => decode_reencode_typed::<Vec<Visibility>>(input),
        "List<ParameterRole>" => decode_reencode_typed::<Vec<ParameterRole>>(input),
        "List<Reachability>" => decode_reencode_typed::<Vec<Reachability>>(input),
        "List<EffectKind>" => decode_reencode_typed::<Vec<EffectKind>>(input),
        "List<ContractKind>" => decode_reencode_typed::<Vec<ContractKind>>(input),
        "List<EntryExposure>" => decode_reencode_typed::<Vec<EntryExposure>>(input),
        "List<BuiltinFailureKind>" => decode_reencode_typed::<Vec<BuiltinFailureKind>>(input),
        "List<BuiltinCase>" => decode_reencode_typed::<Vec<BuiltinCase>>(input),
        "List<TrapCode>" => decode_reencode_typed::<Vec<TrapCode>>(input),
        "List<EntityId>" => decode_reencode_typed::<Vec<EntityId>>(input),
        "List<TypeExpr>" => decode_reencode_typed::<Vec<TypeExpr>>(input),
        "List<TypeParameterDef>" => decode_reencode_typed::<Vec<TypeParameterDef>>(input),
        "List<ValueRef>" => decode_reencode_typed::<Vec<ValueRef>>(input),
        "List<Immediate>" => decode_reencode_typed::<Vec<Immediate>>(input),
        "List<ContractSource>" => decode_reencode_typed::<Vec<ContractSource>>(input),
        "List<ContractBinding>" => decode_reencode_typed::<Vec<ContractBinding>>(input),
        "Visibility" => decode_reencode_typed::<Visibility>(input),
        "ParameterRole" => decode_reencode_typed::<ParameterRole>(input),
        "Reachability" => decode_reencode_typed::<Reachability>(input),
        "EffectKind" => decode_reencode_typed::<EffectKind>(input),
        "ContractKind" => decode_reencode_typed::<ContractKind>(input),
        "EntryExposure" => decode_reencode_typed::<EntryExposure>(input),
        "TypeExpr" => decode_reencode_typed::<TypeExpr>(input),
        "Immediate" => decode_reencode_typed::<Immediate>(input),
        "VariantSwitchTerminator" => decode_reencode_typed::<VariantSwitchTerminator>(input),
        "CondBranchTerminator" => decode_reencode_typed::<CondBranchTerminator>(input),
        "ContractSource" => decode_reencode_typed::<ContractSource>(input),
        "ContractBinding" => decode_reencode_typed::<ContractBinding>(input),
        "ResourceLimits" => decode_reencode_typed::<ResourceLimits>(input),
        "BuiltinFailureValue" => decode_reencode_typed::<BuiltinFailureValue>(input),
        "RecordField" => decode_reencode_typed::<RecordField>(input),
        "WorkspaceBody" => decode_reencode_typed::<WorkspaceBody>(input),
        "PackageBody" => decode_reencode_typed::<PackageBody>(input),
        "FunctionBody" => decode_reencode_typed::<FunctionBody>(input),
        "ParameterBody" => decode_reencode_typed::<ParameterBody>(input),
        "OperationBody" => decode_reencode_typed::<OperationBody>(input),
        "GlobalValueBody" => decode_reencode_typed::<GlobalValueBody>(input),
        "EffectDefBody" => decode_reencode_typed::<EffectDefBody>(input),
        "AdapterImportBody" => decode_reencode_typed::<AdapterImportBody>(input),
        "EntryPointBody" => decode_reencode_typed::<EntryPointBody>(input),
        "PolicyBindingBody" => decode_reencode_typed::<PolicyBindingBody>(input),
        "DependencyBindingBody" => decode_reencode_typed::<DependencyBindingBody>(input),
        other => panic!("unsupported mutation-value adversarial type {other}"),
    }
}

fn decode_reencode_typed<T>(input: &[u8]) -> Result<Vec<u8>>
where
    T: MutationValueCodec,
{
    let value = decode_exact::<T>(input)?;
    encode_exact(&value)
}
