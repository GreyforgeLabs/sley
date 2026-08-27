#![allow(unsafe_code)]
#![no_main]

use core::slice;

use sley_check::TypeEnvironment;
use sley_id::{EntityId, SchemaEpochId, StateRoot};
use sley_ssmc::{
    Block, ConstData, ConstValue, Immediate, IntegerWidth, Opcode, Operation, OperationResultRef,
    Parameter, ParameterRole, Reachability, ResultConst, ReturnTerminator, Terminator, TypeExpr,
    ValueRef, Visibility,
};
use sley_vm::{
    CacheProfile, ExecutionLimits, ExecutionRequest, LoweringInput, derive_observation_id,
    execute_function, validated_execution_input_hashes,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4096;
const MAX_RAW_INPUTS: usize = 4;
const MAX_COLLECTION_ITEMS: usize = 4;
const MAX_PAYLOAD_BYTES: usize = 32;
const FIXTURE_COUNT: u8 = 9;

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
    let fixture = vm_fixture(cursor.byte() % FIXTURE_COUNT);
    let canonical_inputs = cursor.byte().is_multiple_of(4);
    let inputs = if canonical_inputs {
        fixture
            .expected_input_types
            .iter()
            .map(|value_type| canonical_value(value_type, &mut cursor))
            .collect()
    } else {
        (0..cursor.bounded(MAX_RAW_INPUTS))
            .map(|_| raw_value(&mut cursor))
            .collect()
    };
    let limits_profile = cursor.byte() % 6;
    let request = ExecutionRequest {
        inputs,
        limits: generated_limits(limits_profile, &mut cursor),
    };
    let types = TypeEnvironment::new(Vec::new()).expect("empty type environment is valid");
    let lowering = fixture.lowering_input(&types);

    let first_hashes = validated_execution_input_hashes(lowering, &request);
    let second_hashes = validated_execution_input_hashes(lowering, &request);
    assert_eq!(
        first_hashes, second_hashes,
        "VM canonical-input hash judgment was not deterministic"
    );

    let first = execute_function(lowering, request.clone());
    let second = execute_function(lowering, request.clone());
    assert_eq!(first, second, "VM execution judgment was not deterministic");

    if canonical_inputs && limits_profile == 0 {
        assert!(
            first_hashes.is_ok(),
            "a canonical fixture input under normal limits was rejected"
        );
        assert!(
            first.is_ok(),
            "a valid fixed VM fixture under normal limits was rejected"
        );
    }

    if let (Ok(hashes), Ok(outcome)) = (first_hashes, first) {
        assert_eq!(hashes.len(), request.inputs.len());
        assert_eq!(outcome.schema_epoch, lowering.schema_epoch);
        assert_eq!(outcome.state_root, lowering.state_root);
        assert_eq!(outcome.function, lowering.function.entity_id);
        assert_eq!(
            derive_observation_id(
                lowering,
                request.limits,
                outcome.cache_key,
                &hashes,
                &outcome.termination,
                outcome.instruction_count,
                outcome.fuel_used,
                outcome.peak_value_units,
            )
            .expect("a completed restricted outcome must retain a valid observation"),
            outcome.observation_id,
            "VM observation identity drifted"
        );
    }
}

struct VmFixture {
    function: sley_ssmc::FunctionGraph,
    parameters: Vec<Parameter>,
    blocks: Vec<Block>,
    operations: Vec<Operation>,
    expected_input_types: Vec<TypeExpr>,
}

impl VmFixture {
    fn lowering_input<'a>(&'a self, types: &'a TypeEnvironment) -> LoweringInput<'a> {
        LoweringInput {
            types,
            function: &self.function,
            parameters: &self.parameters,
            blocks: &self.blocks,
            operations: &self.operations,
            schema_epoch: SchemaEpochId::from_bytes([8; 32]),
            state_root: StateRoot::from_bytes([9; 32]),
            profile: CacheProfile::RESTRICTED_V1,
        }
    }
}

fn vm_fixture(selector: u8) -> VmFixture {
    match selector {
        0 => identity_fixture(0, TypeExpr::Unit),
        1 => identity_fixture(1, TypeExpr::Bool),
        2 => identity_fixture(2, TypeExpr::Bytes),
        3 => identity_fixture(3, TypeExpr::Text),
        4 => identity_fixture(4, TypeExpr::Option(Box::new(TypeExpr::Bool))),
        5 => identity_fixture(
            5,
            TypeExpr::Result {
                ok: Box::new(TypeExpr::Bool),
                error: Box::new(TypeExpr::Unit),
            },
        ),
        6 => boolean_fixture(6, Opcode::BoolNot, 1),
        7 => boolean_fixture(7, Opcode::BoolAnd, 2),
        8 => boolean_fixture(8, Opcode::BoolOr, 2),
        _ => unreachable!(),
    }
}

fn identity_fixture(selector: u8, value_type: TypeExpr) -> VmFixture {
    let base = 100_u32 + (u32::from(selector) * 10);
    let function = id(base);
    let parameter = id(base + 1);
    let block = id(base + 2);
    VmFixture {
        function: function_body(function, vec![parameter], value_type.clone(), block),
        parameters: vec![function_parameter(
            parameter,
            function,
            0,
            value_type.clone(),
        )],
        blocks: vec![Block {
            entity_id: block,
            function,
            parameters: Vec::new(),
            operations: Vec::new(),
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::Parameter(parameter),
            }),
            reachability: Reachability::Required,
        }],
        operations: Vec::new(),
        expected_input_types: vec![value_type],
    }
}

fn boolean_fixture(selector: u8, opcode: Opcode, arity: usize) -> VmFixture {
    let base = 200_u32 + (u32::from(selector) * 10);
    let function = id(base);
    let block = id(base + 1);
    let operation = id(base + 2);
    let parameter_ids = (0..arity)
        .map(|offset| id(base + 3 + u32::try_from(offset).unwrap_or(u32::MAX)))
        .collect::<Vec<_>>();
    let parameters = parameter_ids
        .iter()
        .enumerate()
        .map(|(ordinal, entity_id)| {
            function_parameter(
                *entity_id,
                function,
                u32::try_from(ordinal).unwrap_or(u32::MAX),
                TypeExpr::Bool,
            )
        })
        .collect();
    VmFixture {
        function: function_body(function, parameter_ids.clone(), TypeExpr::Bool, block),
        parameters,
        blocks: vec![Block {
            entity_id: block,
            function,
            parameters: Vec::new(),
            operations: vec![operation],
            terminator: Terminator::Return(ReturnTerminator {
                value: ValueRef::OperationResult(OperationResultRef {
                    operation,
                    result_index: 0,
                }),
            }),
            reachability: Reachability::Required,
        }],
        operations: vec![Operation {
            entity_id: operation,
            block,
            ordinal: 0,
            opcode,
            operands: parameter_ids
                .iter()
                .map(|entity_id| ValueRef::Parameter(*entity_id))
                .collect(),
            result_types: vec![TypeExpr::Bool],
            immediate: Immediate::None,
        }],
        expected_input_types: vec![TypeExpr::Bool; arity],
    }
}

fn function_body(
    entity_id: EntityId,
    parameters: Vec<EntityId>,
    result_type: TypeExpr,
    entry_block: EntityId,
) -> sley_ssmc::FunctionGraph {
    sley_ssmc::FunctionGraph {
        entity_id,
        type_parameters: Vec::new(),
        parameters,
        result_type,
        effects: Vec::new(),
        entry_block,
        blocks: vec![entry_block],
        contracts: Vec::new(),
        visibility: Visibility::Private,
    }
}

fn function_parameter(
    entity_id: EntityId,
    owner: EntityId,
    ordinal: u32,
    value_type: TypeExpr,
) -> Parameter {
    Parameter {
        entity_id,
        owner,
        role: ParameterRole::Function,
        ordinal,
        value_type,
    }
}

fn canonical_value(value_type: &TypeExpr, cursor: &mut Cursor<'_>) -> ConstValue {
    let data = match value_type {
        TypeExpr::Unit => ConstData::Unit,
        TypeExpr::Bool => ConstData::Bool(cursor.byte().is_multiple_of(2)),
        TypeExpr::Bytes => ConstData::Bytes(payload_bytes(cursor)),
        TypeExpr::Text => ConstData::Text(payload_text(cursor)),
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
        _ => unreachable!("fixed VM fixtures use only supported canonical input types"),
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
        8 => TypeExpr::Option(Box::new(TypeExpr::Bool)),
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
                .map(|_| ConstValue {
                    value_type: TypeExpr::Bool,
                    data: ConstData::Bool(cursor.byte().is_multiple_of(2)),
                })
                .collect(),
        ),
        9 => ConstData::Option((!cursor.byte().is_multiple_of(2)).then(|| {
            Box::new(ConstValue {
                value_type: TypeExpr::Bool,
                data: ConstData::Bool(cursor.byte().is_multiple_of(2)),
            })
        })),
        10 => {
            if cursor.byte().is_multiple_of(2) {
                ConstData::Result(ResultConst::Ok(Box::new(ConstValue {
                    value_type: TypeExpr::Bool,
                    data: ConstData::Bool(cursor.byte().is_multiple_of(2)),
                })))
            } else {
                ConstData::Result(ResultConst::Err(Box::new(ConstValue {
                    value_type: TypeExpr::Unit,
                    data: ConstData::Unit,
                })))
            }
        }
        _ => unreachable!(),
    }
}

fn generated_limits(profile: u8, cursor: &mut Cursor<'_>) -> ExecutionLimits {
    match profile {
        0 => ExecutionLimits {
            max_instructions: 100,
            max_fuel: 100,
            max_value_units: 10_000,
            max_output_units: 10_000,
            cancel_at_fuel: None,
        },
        1 => ExecutionLimits {
            max_instructions: 0,
            max_fuel: 0,
            max_value_units: 0,
            max_output_units: 0,
            cancel_at_fuel: Some(0),
        },
        2 => ExecutionLimits {
            max_instructions: 1,
            max_fuel: 1,
            max_value_units: 1,
            max_output_units: 1,
            cancel_at_fuel: Some(1),
        },
        3 => ExecutionLimits {
            max_instructions: u64::MAX,
            max_fuel: u64::MAX,
            max_value_units: u64::MAX,
            max_output_units: u64::MAX,
            cancel_at_fuel: Some(u64::MAX),
        },
        4 => ExecutionLimits {
            max_instructions: cursor.u64(),
            max_fuel: cursor.u64(),
            max_value_units: cursor.u64(),
            max_output_units: cursor.u64(),
            cancel_at_fuel: None,
        },
        5 => ExecutionLimits {
            max_instructions: cursor.u64(),
            max_fuel: cursor.u64(),
            max_value_units: cursor.u64(),
            max_output_units: cursor.u64(),
            cancel_at_fuel: Some(cursor.u64()),
        },
        _ => unreachable!(),
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
