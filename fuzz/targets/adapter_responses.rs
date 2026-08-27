#![allow(unsafe_code)]
#![no_main]

use core::slice;
use std::collections::BTreeMap;

use sley_adapter::{
    AdapterFixtureState, AdapterInvocation, AdapterLimits, AdapterOutcome, ReferenceAdapterKind,
    ReplayEntry, invoke_reference_adapter, state_id,
};
use sley_check::TypeEnvironment;
use sley_id::{EntityId, SchemaEpochId, StateRoot, ValueHash};
use sley_ssmc::fingerprint::hash_validated_value;
use sley_ssmc::{
    AdapterImport, ConstData, ConstValue, EffectDefinition, EffectKind, IntegerWidth, ResultConst,
    TypeExpr, Visibility,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 32;
const MAX_COLLECTION_ITEMS: usize = 4;
const MAX_MUTATIONS: usize = 4;
const KIND_COUNT: u8 = 8;
const RESPONSE_SCHEMA_COUNT: u8 = 6;
const MUTATION_COUNT: u8 = 26;
const PROFILE_MAX_PREIMAGE: u64 = 67_108_864;

#[unsafe(no_mangle)]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, len: usize) -> i32 {
    if len == 0 {
        return 0;
    }
    let input = unsafe { slice::from_raw_parts(data, len) };
    fuzz_one(input);
    0
}

fn fuzz_one(input: &[u8]) {
    if input.len() > MAX_FUZZ_INPUT_BYTES {
        return;
    }

    let mut cursor = Cursor::new(input);
    let kind = reference_kind(cursor.byte() % KIND_COUNT);
    let response_schema = cursor.byte() % RESPONSE_SCHEMA_COUNT;
    let canonical_lane = cursor.byte().is_multiple_of(4);
    let types = TypeEnvironment::new(Vec::new()).expect("empty type environment is valid");
    let mut effect = effect_for(kind, response_schema);
    let mut import = import_for(kind, &effect);
    let (scope, request) = canonical_request(kind, &mut cursor);
    let mut state = canonical_state(
        kind,
        &types,
        &effect,
        &import,
        &scope,
        &request,
        &mut cursor,
    );
    let mut invocation = AdapterInvocation {
        kind,
        scope,
        request,
        limits: if canonical_lane {
            generous_limits()
        } else {
            generated_limits(&mut cursor)
        },
        cancel_at_action: None,
    };

    if !canonical_lane {
        invocation.cancel_at_action = generated_cancellation(&state, &mut cursor);
        for _ in 0..cursor.bounded(MAX_MUTATIONS) {
            mutate_boundary(
                &mut state,
                &mut import,
                &mut effect,
                &mut invocation,
                &mut cursor,
            );
        }
    }

    let before = state.clone();
    let mut first_state = before.clone();
    let mut second_state = before.clone();
    let first = invoke_reference_adapter(
        &mut first_state,
        &import,
        &effect,
        &types,
        epoch(),
        root(),
        &invocation,
    );
    let second = invoke_reference_adapter(
        &mut second_state,
        &import,
        &effect,
        &types,
        epoch(),
        root(),
        &invocation,
    );
    assert_eq!(
        first, second,
        "adapter response judgment was not deterministic"
    );
    assert_eq!(
        first_state, second_state,
        "equal adapter responses produced different fixture states"
    );

    if canonical_lane {
        assert!(
            first.is_ok(),
            "a canonical adapter fixture under generous limits was rejected"
        );
    }

    match &first {
        Err(_) => assert_eq!(
            first_state, before,
            "a rejected adapter response mutated fixture state"
        ),
        Ok(receipt) => {
            assert_success_bindings(&before, &first_state, receipt, &effect, &types, &invocation);
            if invocation.kind == ReferenceAdapterKind::GenericReplay {
                let index = usize::try_from(before.replay_cursor)
                    .expect("a successful bounded replay cursor fits usize");
                assert_eq!(
                    receipt.outcome, before.replay_entries[index].outcome,
                    "generic replay did not preserve the stored adapter response"
                );
                assert_eq!(first_state.replay_cursor, before.replay_cursor + 1);
            }

            let mut alternate_state = before.clone();
            let alternate = invoke_reference_adapter(
                &mut alternate_state,
                &import,
                &effect,
                &types,
                epoch(),
                alternate_root(),
                &invocation,
            )
            .expect("StateRoot changes must preserve a successful fixture judgment");
            assert_eq!(alternate_state, first_state);
            assert_eq!(alternate.outcome, receipt.outcome);
            assert_eq!(alternate.pre_state, receipt.pre_state);
            assert_eq!(alternate.post_state, receipt.post_state);
            assert_eq!(alternate.call_index, receipt.call_index);
            assert_eq!(alternate.actions_used, receipt.actions_used);
            assert_eq!(alternate.output_bytes, receipt.output_bytes);
            assert_ne!(
                alternate.transcript, receipt.transcript,
                "adapter transcript did not bind StateRoot"
            );
        }
    }
}

fn assert_success_bindings(
    before: &AdapterFixtureState,
    after: &AdapterFixtureState,
    receipt: &sley_adapter::AdapterReceipt,
    effect: &EffectDefinition,
    types: &TypeEnvironment,
    invocation: &AdapterInvocation,
) {
    assert_eq!(
        receipt.pre_state,
        state_id(
            before,
            types,
            epoch(),
            invocation.limits.max_state_preimage_bytes,
        )
        .expect("a successful invocation retained a valid pre-state")
    );
    assert_eq!(
        receipt.post_state,
        state_id(
            after,
            types,
            epoch(),
            invocation.limits.max_state_preimage_bytes,
        )
        .expect("a successful invocation retained a valid post-state")
    );
    assert_eq!(receipt.call_index, before.call_count);
    assert_eq!(
        after.call_count,
        before
            .call_count
            .checked_add(1)
            .expect("a successful adapter call count cannot overflow")
    );
    assert_eq!(
        receipt.actions_used,
        after
            .action_count
            .checked_sub(before.action_count)
            .expect("a successful adapter action count cannot decrease")
    );
    assert_eq!(
        receipt.output_bytes,
        u64::try_from(after.stdout.len() + after.stderr.len())
            .expect("bounded captured output length fits u64")
    );

    let (value, expected_type) = match &receipt.outcome {
        AdapterOutcome::Success(value) => (value, &effect.response_type),
        AdapterOutcome::DeclaredFailure(value) => (value, &effect.failure_type),
    };
    assert!(
        types.check_constant(value).is_ok(),
        "a successful adapter response was not a valid constant"
    );
    assert!(
        types.require_hashable(&value.value_type).is_ok(),
        "a successful adapter response was not hashable"
    );
    assert_eq!(
        &value.value_type, expected_type,
        "a successful adapter response escaped its declared type"
    );
    hash_validated_value(epoch(), value)
        .expect("a successful adapter response must retain a value hash");
}

fn effect_for(kind: ReferenceAdapterKind, response_schema: u8) -> EffectDefinition {
    let u32_type = TypeExpr::UInt(IntegerWidth::from_bits(32));
    let u64_type = TypeExpr::UInt(IntegerWidth::from_bits(64));
    let (scope_type, request_type, response_type, failure_type) = match kind {
        ReferenceAdapterKind::Stdout | ReferenceAdapterKind::Stderr => {
            (TypeExpr::Unit, TypeExpr::Bytes, TypeExpr::Unit, u32_type)
        }
        ReferenceAdapterKind::VirtualFileRead => {
            (TypeExpr::Text, TypeExpr::Text, TypeExpr::Bytes, u32_type)
        }
        ReferenceAdapterKind::VirtualFileWrite => (
            TypeExpr::Text,
            TypeExpr::Tuple(vec![TypeExpr::Text, TypeExpr::Bytes]),
            TypeExpr::Unit,
            u32_type,
        ),
        ReferenceAdapterKind::Clock => (TypeExpr::Unit, TypeExpr::Unit, u64_type, u32_type),
        ReferenceAdapterKind::Random => {
            (TypeExpr::Unit, u32_type.clone(), TypeExpr::Bytes, u32_type)
        }
        ReferenceAdapterKind::Environment => (
            TypeExpr::Unit,
            TypeExpr::Text,
            TypeExpr::Option(Box::new(TypeExpr::Text)),
            u32_type,
        ),
        ReferenceAdapterKind::GenericReplay => {
            let (response, failure) = replay_schema(response_schema);
            (TypeExpr::Unit, TypeExpr::Bytes, response, failure)
        }
    };
    EffectDefinition {
        entity_id: id(10 + kind.tag()),
        effect_kind: EffectKind::AdapterCall,
        scope_type,
        request_type,
        response_type,
        failure_type,
        visibility: Visibility::Private,
    }
}

fn replay_schema(selector: u8) -> (TypeExpr, TypeExpr) {
    let u32_type = TypeExpr::UInt(IntegerWidth::from_bits(32));
    match selector % RESPONSE_SCHEMA_COUNT {
        0 => (TypeExpr::Bytes, u32_type),
        1 => (TypeExpr::Unit, u32_type),
        2 => (TypeExpr::Text, TypeExpr::Bool),
        3 => (TypeExpr::Option(Box::new(TypeExpr::Text)), u32_type),
        4 => (
            TypeExpr::Result {
                ok: Box::new(TypeExpr::Bool),
                error: Box::new(TypeExpr::Unit),
            },
            TypeExpr::Text,
        ),
        5 => (TypeExpr::Vector(Box::new(TypeExpr::Bool)), TypeExpr::Bytes),
        _ => unreachable!(),
    }
}

fn import_for(kind: ReferenceAdapterKind, effect: &EffectDefinition) -> AdapterImport {
    AdapterImport {
        entity_id: id(100),
        adapter_id: kind.reference_id().into_bytes(),
        abi_version: 1,
        request_type: effect.request_type.clone(),
        response_type: effect.response_type.clone(),
        failure_type: effect.failure_type.clone(),
        effects: vec![effect.entity_id],
    }
}

fn canonical_request(
    kind: ReferenceAdapterKind,
    cursor: &mut Cursor<'_>,
) -> (ConstValue, ConstValue) {
    match kind {
        ReferenceAdapterKind::Stdout | ReferenceAdapterKind::Stderr => {
            (unit_value(), bytes_value(payload_bytes(cursor)))
        }
        ReferenceAdapterKind::VirtualFileRead => (text_value("root"), text_value("dir/file")),
        ReferenceAdapterKind::VirtualFileWrite => (
            text_value("root"),
            tuple_text_bytes_value("dir/file", payload_bytes(cursor)),
        ),
        ReferenceAdapterKind::Clock => (unit_value(), unit_value()),
        ReferenceAdapterKind::Random => (unit_value(), u32_value(u32::from(cursor.byte() % 65))),
        ReferenceAdapterKind::Environment => (unit_value(), text_value("key")),
        ReferenceAdapterKind::GenericReplay => (unit_value(), bytes_value(payload_bytes(cursor))),
    }
}

fn canonical_state(
    kind: ReferenceAdapterKind,
    types: &TypeEnvironment,
    effect: &EffectDefinition,
    import: &AdapterImport,
    scope: &ConstValue,
    request: &ConstValue,
    cursor: &mut Cursor<'_>,
) -> AdapterFixtureState {
    let mut state = AdapterFixtureState {
        stdout: short_payload(cursor),
        stderr: short_payload(cursor),
        virtual_files: BTreeMap::new(),
        clock_ticks: vec![cursor.u64()],
        clock_cursor: 0,
        random_seed: [cursor.byte(); 32],
        random_counter: u64::from(cursor.byte() % 4),
        environment: BTreeMap::new(),
        replay_entries: Vec::new(),
        replay_cursor: 0,
        call_count: u64::from(cursor.byte() % 4),
        action_count: u64::from(cursor.byte() % 8),
    };
    if cursor.byte().is_multiple_of(2) {
        state
            .virtual_files
            .insert("root/dir/file".to_owned(), short_payload(cursor));
    }
    if cursor.byte().is_multiple_of(2) {
        state
            .environment
            .insert("key".to_owned(), payload_text(cursor));
    }
    if kind == ReferenceAdapterKind::GenericReplay {
        let outcome = if cursor.byte().is_multiple_of(2) {
            AdapterOutcome::Success(canonical_value(&effect.response_type, cursor))
        } else {
            AdapterOutcome::DeclaredFailure(canonical_value(&effect.failure_type, cursor))
        };
        state.replay_entries.push(ReplayEntry {
            import_id: import.entity_id,
            adapter_id: import.adapter_id,
            abi_version: import.abi_version,
            call_index: state.call_count,
            scope_hash: validated_hash(types, scope),
            request_hash: validated_hash(types, request),
            outcome,
        });
    }
    state
}

fn validated_hash(types: &TypeEnvironment, value: &ConstValue) -> ValueHash {
    types
        .check_constant(value)
        .expect("canonical adapter fixture values are valid");
    types
        .require_hashable(&value.value_type)
        .expect("canonical adapter fixture values are hashable");
    hash_validated_value(epoch(), value).expect("canonical adapter fixture values are hashable")
}

fn generous_limits() -> AdapterLimits {
    AdapterLimits {
        max_calls: 64,
        max_actions: 128,
        max_output_bytes: 512,
        max_virtual_files: 8,
        max_virtual_file_bytes: 128,
        max_total_virtual_file_bytes: 512,
        max_random_bytes: 128,
        max_state_preimage_bytes: 32_768,
        max_transcript_preimage_bytes: 32_768,
    }
}

fn generated_limits(cursor: &mut Cursor<'_>) -> AdapterLimits {
    match cursor.byte() % 6 {
        0 => generous_limits(),
        1 => AdapterLimits {
            max_calls: 0,
            max_actions: 0,
            max_output_bytes: 0,
            max_virtual_files: 0,
            max_virtual_file_bytes: 0,
            max_total_virtual_file_bytes: 0,
            max_random_bytes: 0,
            max_state_preimage_bytes: 0,
            max_transcript_preimage_bytes: 0,
        },
        2 => AdapterLimits {
            max_calls: 1,
            max_actions: 1,
            max_output_bytes: 1,
            max_virtual_files: 1,
            max_virtual_file_bytes: 1,
            max_total_virtual_file_bytes: 1,
            max_random_bytes: 1,
            max_state_preimage_bytes: 256,
            max_transcript_preimage_bytes: 256,
        },
        3 => AdapterLimits::profile_max(),
        4 => AdapterLimits {
            max_calls: u64::from(cursor.byte() % 8),
            max_actions: u64::from(cursor.byte() % 16),
            max_output_bytes: u64::from(cursor.byte()),
            max_virtual_files: u64::from(cursor.byte() % 8),
            max_virtual_file_bytes: u64::from(cursor.byte()),
            max_total_virtual_file_bytes: u64::from(cursor.u16()),
            max_random_bytes: u64::from(cursor.byte() % 129),
            max_state_preimage_bytes: u64::from(cursor.u16()),
            max_transcript_preimage_bytes: u64::from(cursor.u16()),
        },
        5 => AdapterLimits {
            max_output_bytes: PROFILE_MAX_PREIMAGE + 1,
            ..AdapterLimits::profile_max()
        },
        _ => unreachable!(),
    }
}

fn generated_cancellation(state: &AdapterFixtureState, cursor: &mut Cursor<'_>) -> Option<u64> {
    match cursor.byte() % 4 {
        0 => None,
        1 => Some(0),
        2 => Some(state.action_count),
        3 => Some(
            state
                .action_count
                .saturating_add(u64::from(cursor.byte() % 4)),
        ),
        _ => unreachable!(),
    }
}

fn mutate_boundary(
    state: &mut AdapterFixtureState,
    import: &mut AdapterImport,
    effect: &mut EffectDefinition,
    invocation: &mut AdapterInvocation,
    cursor: &mut Cursor<'_>,
) {
    match cursor.byte() % MUTATION_COUNT {
        0 => {}
        1 => import.adapter_id = [cursor.byte(); 32],
        2 => import.abi_version = u32::from(cursor.byte() % 4),
        3 => import.effects.clear(),
        4 => effect.effect_kind = EffectKind::StdoutWrite,
        5 => import.request_type = raw_type(cursor),
        6 => import.response_type = raw_type(cursor),
        7 => import.failure_type = raw_type(cursor),
        8 => invocation.scope = raw_value(cursor),
        9 => invocation.request = raw_value(cursor),
        10 => {
            state
                .virtual_files
                .insert("../bad".to_owned(), payload_bytes(cursor));
        }
        11 => {
            state
                .environment
                .insert(String::new(), payload_text(cursor));
        }
        12 => {
            state.clock_cursor = u64::try_from(state.clock_ticks.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
        }
        13 => {
            state.replay_cursor = u64::try_from(state.replay_entries.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
        }
        14 => invocation.limits = generated_limits(cursor),
        15 => invocation.cancel_at_action = Some(state.action_count),
        16 => {
            state.call_count = u64::MAX;
            invocation.limits.max_calls = u64::MAX;
        }
        17 => {
            state.action_count = u64::MAX;
            invocation.limits.max_actions = u64::MAX;
        }
        18 => invocation.kind = reference_kind((invocation.kind.tag() as u8) % KIND_COUNT),
        19 => mutate_replay_outcome(state, import, cursor),
        20 => {
            if let Some(entry) = state.replay_entries.first_mut() {
                entry.request_hash = ValueHash::from_bytes([cursor.byte(); 32]);
            } else {
                push_raw_replay_entry(state, import, cursor);
            }
        }
        21 => effect.response_type = raw_type(cursor),
        22 => effect.failure_type = raw_type(cursor),
        23 => {
            invocation.limits.max_output_bytes = u64::try_from(
                state
                    .stdout
                    .len()
                    .saturating_add(state.stderr.len())
                    .saturating_sub(1),
            )
            .unwrap_or(0);
        }
        24 => invocation.limits.max_state_preimage_bytes = 0,
        25 => invocation.limits.max_transcript_preimage_bytes = 0,
        _ => unreachable!(),
    }
}

fn mutate_replay_outcome(
    state: &mut AdapterFixtureState,
    import: &AdapterImport,
    cursor: &mut Cursor<'_>,
) {
    let outcome = raw_outcome(cursor);
    if let Some(entry) = state.replay_entries.first_mut() {
        entry.outcome = outcome;
    } else {
        state.replay_entries.push(ReplayEntry {
            import_id: import.entity_id,
            adapter_id: import.adapter_id,
            abi_version: import.abi_version,
            call_index: state.call_count,
            scope_hash: ValueHash::from_bytes([cursor.byte(); 32]),
            request_hash: ValueHash::from_bytes([cursor.byte(); 32]),
            outcome,
        });
    }
}

fn push_raw_replay_entry(
    state: &mut AdapterFixtureState,
    import: &AdapterImport,
    cursor: &mut Cursor<'_>,
) {
    state.replay_entries.push(ReplayEntry {
        import_id: import.entity_id,
        adapter_id: import.adapter_id,
        abi_version: import.abi_version,
        call_index: state.call_count,
        scope_hash: ValueHash::from_bytes([cursor.byte(); 32]),
        request_hash: ValueHash::from_bytes([cursor.byte(); 32]),
        outcome: raw_outcome(cursor),
    });
}

fn raw_outcome(cursor: &mut Cursor<'_>) -> AdapterOutcome {
    if cursor.byte().is_multiple_of(2) {
        AdapterOutcome::Success(raw_value(cursor))
    } else {
        AdapterOutcome::DeclaredFailure(raw_value(cursor))
    }
}

fn canonical_value(value_type: &TypeExpr, cursor: &mut Cursor<'_>) -> ConstValue {
    let data = match value_type {
        TypeExpr::Unit => ConstData::Unit,
        TypeExpr::Bool => ConstData::Bool(cursor.byte().is_multiple_of(2)),
        TypeExpr::SInt(_) => ConstData::SInt(i128::from(cursor.byte() as i8)),
        TypeExpr::UInt(_) => ConstData::UInt(u128::from(cursor.byte())),
        TypeExpr::F32 => ConstData::F32Bits(cursor.u32()),
        TypeExpr::F64 => ConstData::F64Bits(cursor.u64()),
        TypeExpr::Bytes => ConstData::Bytes(payload_bytes(cursor)),
        TypeExpr::Text => ConstData::Text(payload_text(cursor)),
        TypeExpr::Tuple(items) => ConstData::Sequence(
            items
                .iter()
                .map(|item| canonical_value(item, cursor))
                .collect(),
        ),
        TypeExpr::Vector(item) => ConstData::Sequence(
            (0..cursor.bounded(MAX_COLLECTION_ITEMS))
                .map(|_| canonical_value(item, cursor))
                .collect(),
        ),
        TypeExpr::Option(inner) => {
            if cursor.byte().is_multiple_of(2) {
                ConstData::Option(None)
            } else {
                ConstData::Option(Some(Box::new(canonical_value(inner, cursor))))
            }
        }
        TypeExpr::Result { ok, error } => {
            if cursor.byte().is_multiple_of(2) {
                ConstData::Result(ResultConst::Ok(Box::new(canonical_value(ok, cursor))))
            } else {
                ConstData::Result(ResultConst::Err(Box::new(canonical_value(error, cursor))))
            }
        }
        _ => unreachable!("fixed adapter response schemas use supported structural types"),
    };
    ConstValue {
        value_type: value_type.clone(),
        data,
    }
}

fn raw_value(cursor: &mut Cursor<'_>) -> ConstValue {
    ConstValue {
        value_type: raw_type(cursor),
        data: raw_data(cursor),
    }
}

fn raw_type(cursor: &mut Cursor<'_>) -> TypeExpr {
    match cursor.byte() % 14 {
        0 => TypeExpr::Unit,
        1 => TypeExpr::Bool,
        2 => TypeExpr::SInt(integer_width(cursor)),
        3 => TypeExpr::UInt(integer_width(cursor)),
        4 => TypeExpr::F32,
        5 => TypeExpr::F64,
        6 => TypeExpr::Bytes,
        7 => TypeExpr::Text,
        8 => TypeExpr::Option(Box::new(TypeExpr::Text)),
        9 => TypeExpr::Result {
            ok: Box::new(TypeExpr::Bool),
            error: Box::new(TypeExpr::Unit),
        },
        10 => TypeExpr::Vector(Box::new(TypeExpr::Bool)),
        11 => TypeExpr::LocalCell(Box::new(TypeExpr::Bool)),
        12 => TypeExpr::TypeParameter(u32::from(cursor.byte() % 4)),
        13 => TypeExpr::AdapterHandle(id(cursor.u32())),
        _ => unreachable!(),
    }
}

fn raw_data(cursor: &mut Cursor<'_>) -> ConstData {
    match cursor.byte() % 11 {
        0 => ConstData::Unit,
        1 => ConstData::Bool(cursor.byte().is_multiple_of(2)),
        2 => ConstData::SInt(cursor.i128()),
        3 => ConstData::UInt(cursor.u128()),
        4 => ConstData::F32Bits(cursor.u32()),
        5 => ConstData::F64Bits(cursor.u64()),
        6 => ConstData::Bytes(payload_bytes(cursor)),
        7 => ConstData::Text(payload_text(cursor)),
        8 => ConstData::Sequence(
            (0..cursor.bounded(MAX_COLLECTION_ITEMS))
                .map(|_| bool_value(cursor.byte().is_multiple_of(2)))
                .collect(),
        ),
        9 => ConstData::Option(
            (!cursor.byte().is_multiple_of(2)).then(|| Box::new(text_value(&payload_text(cursor)))),
        ),
        10 => {
            if cursor.byte().is_multiple_of(2) {
                ConstData::Result(ResultConst::Ok(Box::new(bool_value(
                    cursor.byte().is_multiple_of(2),
                ))))
            } else {
                ConstData::Result(ResultConst::Err(Box::new(unit_value())))
            }
        }
        _ => unreachable!(),
    }
}

fn reference_kind(selector: u8) -> ReferenceAdapterKind {
    match selector % KIND_COUNT {
        0 => ReferenceAdapterKind::Stdout,
        1 => ReferenceAdapterKind::Stderr,
        2 => ReferenceAdapterKind::VirtualFileRead,
        3 => ReferenceAdapterKind::VirtualFileWrite,
        4 => ReferenceAdapterKind::Clock,
        5 => ReferenceAdapterKind::Random,
        6 => ReferenceAdapterKind::Environment,
        7 => ReferenceAdapterKind::GenericReplay,
        _ => unreachable!(),
    }
}

fn unit_value() -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Unit,
        data: ConstData::Unit,
    }
}

fn bool_value(value: bool) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Bool,
        data: ConstData::Bool(value),
    }
}

fn u32_value(value: u32) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::UInt(IntegerWidth::from_bits(32)),
        data: ConstData::UInt(u128::from(value)),
    }
}

fn bytes_value(value: Vec<u8>) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Bytes,
        data: ConstData::Bytes(value),
    }
}

fn text_value(value: &str) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Text,
        data: ConstData::Text(value.to_owned()),
    }
}

fn tuple_text_bytes_value(path: &str, bytes: Vec<u8>) -> ConstValue {
    ConstValue {
        value_type: TypeExpr::Tuple(vec![TypeExpr::Text, TypeExpr::Bytes]),
        data: ConstData::Sequence(vec![text_value(path), bytes_value(bytes)]),
    }
}

fn integer_width(cursor: &mut Cursor<'_>) -> IntegerWidth {
    let bits = match cursor.byte() % 8 {
        0 => 8,
        1 => 16,
        2 => 32,
        3 => 64,
        4 => 128,
        _ => cursor.u16(),
    };
    IntegerWidth::from_bits(bits)
}

fn short_payload(cursor: &mut Cursor<'_>) -> Vec<u8> {
    (0..cursor.bounded(8)).map(|_| cursor.byte()).collect()
}

fn payload_bytes(cursor: &mut Cursor<'_>) -> Vec<u8> {
    (0..cursor.bounded(MAX_PAYLOAD_BYTES))
        .map(|_| cursor.byte())
        .collect()
}

fn payload_text(cursor: &mut Cursor<'_>) -> String {
    (0..cursor.bounded(MAX_PAYLOAD_BYTES))
        .map(|_| char::from(0x20 + (cursor.byte() % 0x5f)))
        .collect()
}

fn id(value: u32) -> EntityId {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&value.to_be_bytes());
    EntityId::from_bytes(bytes)
}

fn epoch() -> SchemaEpochId {
    SchemaEpochId::from_bytes([9; 32])
}

fn root() -> StateRoot {
    StateRoot::from_bytes([7; 32])
}

fn alternate_root() -> StateRoot {
    StateRoot::from_bytes([8; 32])
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.input[self.offset % self.input.len()];
        self.offset = self.offset.wrapping_add(1);
        value
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes([
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
        ])
    }

    fn u128(&mut self) -> u128 {
        u128::from_be_bytes([
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
            self.byte(),
        ])
    }

    fn i128(&mut self) -> i128 {
        i128::from_be_bytes(self.u128().to_be_bytes())
    }

    fn bounded(&mut self, maximum: usize) -> usize {
        usize::from(self.byte()) % (maximum + 1)
    }
}
