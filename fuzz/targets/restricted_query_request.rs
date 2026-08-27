#![allow(unsafe_code)]
#![no_main]

use core::slice;

use sley_id::{EntityId, QueryId, SchemaEpochId, StateRoot};
use sley_query::{
    ImpactEntity, ImpactKind, IndexSnapshot, MAX_QUERY_DEPTH, MAX_QUERY_REQUEST_BYTES,
    MAX_QUERY_RESPONSE_BYTES, MAX_QUERY_RETURNED_EDGES, MAX_QUERY_RETURNED_ENTITIES,
    MAX_QUERY_WORK, QueryErrorCode, QueryLimits, RestrictedQuery, RestrictedQueryResponse,
    SnapshotContext, build_index_snapshot, build_restricted_query_request,
    execute_restricted_query,
};
use sley_ssmc::{
    Block, CondBranchTerminator, FunctionGraph, Parameter, ParameterRole, Reachability, TargetEdge,
    Terminator, TypeExpr, ValueRef, Visibility,
};

const MAX_FUZZ_INPUT_BYTES: usize = 4096;
const MAX_GENERATED_KINDS: usize = 16;
const MAX_GENERATED_SEEDS: usize = 16;
const QUERY_KIND_COUNT: u8 = 4;

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
    let fixture = QueryFixture::new();
    let with_root = cursor.byte().is_multiple_of(2);
    let snapshot = fixture.snapshot(context(with_root));
    let alternate = fixture.snapshot(context(!with_root));
    assert_ne!(
        snapshot.snapshot_id(),
        alternate.snapshot_id(),
        "query-binding fixture snapshots must remain distinct"
    );

    let query = generated_query(&mut cursor);
    let limits = generated_limits(&mut cursor);
    let first = observe(&snapshot, &alternate, query.clone(), limits);
    let second = observe(&snapshot, &alternate, query, limits);
    assert_eq!(
        first, second,
        "restricted-query judgment was not deterministic"
    );
}

fn observe(
    snapshot: &IndexSnapshot,
    alternate: &IndexSnapshot,
    query: RestrictedQuery,
    limits: QueryLimits,
) -> Result<RestrictedQueryResponse, QueryErrorCode> {
    let request =
        build_restricted_query_request(snapshot, query, limits).map_err(|error| error.code())?;
    assert_eq!(
        request.query_id(),
        QueryId::derive(request.preimage()),
        "canonical query request identity drifted"
    );
    assert!(
        request.preimage().len() <= MAX_QUERY_REQUEST_BYTES,
        "accepted query request exceeded its frozen byte ceiling"
    );
    assert_eq!(
        execute_restricted_query(alternate, &request)
            .expect_err("a request must not execute against another snapshot")
            .code(),
        QueryErrorCode::SnapshotMismatch,
        "cross-snapshot request binding did not fail closed"
    );

    let response = execute_restricted_query(snapshot, &request).map_err(|error| error.code())?;
    assert_eq!(response.query_id(), request.query_id());
    assert_eq!(response.snapshot_id(), request.snapshot_id());
    assert_eq!(response.context(), request.context());
    assert_eq!(response.completeness(), request.completeness());
    assert_eq!(response.applied_limits(), request.limits());
    assert!(response.returned_entities() <= limits.max_returned_entities);
    assert!(response.returned_edges() <= limits.max_returned_edges);
    assert!(response.reached_depth() <= limits.max_depth);
    assert!(response.response_bytes() <= limits.max_response_bytes);
    assert!(response.charged_work() <= limits.max_work);
    assert_eq!(
        response.response_bytes(),
        u64::try_from(response.record().len()).expect("response length fits u64")
    );
    Ok(response)
}

fn generated_query(cursor: &mut Cursor<'_>) -> RestrictedQuery {
    match cursor.byte() % QUERY_KIND_COUNT {
        0 => RestrictedQuery::GetModeledEntityKind {
            entity: generated_entity(cursor),
        },
        1 => RestrictedQuery::ListDirectDependencies {
            entity: generated_entity(cursor),
            kinds: generated_kinds(cursor),
        },
        2 => RestrictedQuery::ListDirectDependents {
            entity: generated_entity(cursor),
            kinds: generated_kinds(cursor),
        },
        3 => RestrictedQuery::ReverseImpactClosure {
            seeds: (0..cursor.bounded(MAX_GENERATED_SEEDS))
                .map(|_| generated_entity(cursor))
                .collect(),
        },
        _ => unreachable!(),
    }
}

fn generated_kinds(cursor: &mut Cursor<'_>) -> Vec<ImpactKind> {
    (0..cursor.bounded(MAX_GENERATED_KINDS))
        .map(|_| impact_kind(cursor.byte()))
        .collect()
}

fn generated_entity(cursor: &mut Cursor<'_>) -> EntityId {
    match cursor.byte() % 5 {
        0 => id(1),
        1 => id(2),
        2 => id(3),
        3 => id(4),
        4 => id(cursor.u32()),
        _ => unreachable!(),
    }
}

fn generated_limits(cursor: &mut Cursor<'_>) -> QueryLimits {
    match cursor.byte() % 6 {
        0 => QueryLimits::profile_maximum(),
        1 => QueryLimits {
            max_returned_entities: 1,
            max_returned_edges: 1,
            max_depth: 0,
            max_response_bytes: 1,
            max_work: 1,
        },
        2 => QueryLimits {
            max_returned_entities: 0,
            max_returned_edges: 0,
            max_depth: 0,
            max_response_bytes: 0,
            max_work: 0,
        },
        3 => QueryLimits {
            max_returned_entities: MAX_QUERY_RETURNED_ENTITIES + 1,
            max_returned_edges: MAX_QUERY_RETURNED_EDGES + 1,
            max_depth: MAX_QUERY_DEPTH + 1,
            max_response_bytes: MAX_QUERY_RESPONSE_BYTES + 1,
            max_work: MAX_QUERY_WORK + 1,
        },
        4 => QueryLimits {
            max_returned_entities: bounded_u64(cursor, MAX_QUERY_RETURNED_ENTITIES),
            max_returned_edges: bounded_u64(cursor, MAX_QUERY_RETURNED_EDGES),
            max_depth: cursor.u32() % (MAX_QUERY_DEPTH + 2),
            max_response_bytes: bounded_u64(cursor, MAX_QUERY_RESPONSE_BYTES),
            max_work: bounded_u64(cursor, MAX_QUERY_WORK),
        },
        5 => {
            let maximum = QueryLimits::profile_maximum();
            QueryLimits {
                max_returned_entities: boundary_u64(cursor.byte(), maximum.max_returned_entities),
                max_returned_edges: boundary_u64(cursor.byte(), maximum.max_returned_edges),
                max_depth: boundary_u32(cursor.byte(), maximum.max_depth),
                max_response_bytes: boundary_u64(cursor.byte(), maximum.max_response_bytes),
                max_work: boundary_u64(cursor.byte(), maximum.max_work),
            }
        }
        _ => unreachable!(),
    }
}

fn bounded_u64(cursor: &mut Cursor<'_>, maximum: u64) -> u64 {
    cursor.u64() % (maximum + 2)
}

fn boundary_u64(selector: u8, maximum: u64) -> u64 {
    match selector % 3 {
        0 => 0,
        1 => maximum,
        2 => maximum + 1,
        _ => unreachable!(),
    }
}

fn boundary_u32(selector: u8, maximum: u32) -> u32 {
    match selector % 3 {
        0 => 0,
        1 => maximum,
        2 => maximum + 1,
        _ => unreachable!(),
    }
}

fn impact_kind(value: u8) -> ImpactKind {
    match value % 12 {
        0 => ImpactKind::Ownership,
        1 => ImpactKind::TypeReference,
        2 => ImpactKind::ValueReference,
        3 => ImpactKind::ControlFlow,
        4 => ImpactKind::Call,
        5 => ImpactKind::Effect,
        6 => ImpactKind::Capability,
        7 => ImpactKind::Contract,
        8 => ImpactKind::Initializer,
        9 => ImpactKind::TestTarget,
        10 => ImpactKind::Adapter,
        11 => ImpactKind::DefinitionMember,
        _ => unreachable!(),
    }
}

fn context(with_root: bool) -> SnapshotContext {
    SnapshotContext {
        schema_epoch: SchemaEpochId::from_bytes([0x11; 32]),
        claimed_root_context: with_root.then(|| StateRoot::from_bytes([0x22; 32])),
    }
}

struct QueryFixture {
    function: FunctionGraph,
    parameter: Parameter,
    block: Block,
}

impl QueryFixture {
    fn new() -> Self {
        let function = id(1);
        let parameter = id(2);
        let block = id(3);
        Self {
            function: FunctionGraph {
                entity_id: function,
                type_parameters: Vec::new(),
                parameters: vec![parameter],
                result_type: TypeExpr::Bool,
                effects: Vec::new(),
                entry_block: block,
                blocks: vec![block],
                contracts: Vec::new(),
                visibility: Visibility::Private,
            },
            parameter: Parameter {
                entity_id: parameter,
                owner: function,
                role: ParameterRole::Function,
                ordinal: 0,
                value_type: TypeExpr::Bool,
            },
            block: Block {
                entity_id: block,
                function,
                parameters: Vec::new(),
                operations: Vec::new(),
                terminator: Terminator::CondBranch(CondBranchTerminator {
                    condition: ValueRef::Parameter(parameter),
                    if_true: TargetEdge {
                        target: block,
                        arguments: Vec::new(),
                    },
                    if_false: TargetEdge {
                        target: block,
                        arguments: Vec::new(),
                    },
                }),
                reachability: Reachability::Required,
            },
        }
    }

    fn snapshot(&self, context: SnapshotContext) -> IndexSnapshot {
        build_index_snapshot(
            context,
            &[
                ImpactEntity::Function(&self.function),
                ImpactEntity::Parameter(&self.parameter),
                ImpactEntity::Block(&self.block),
            ],
        )
        .expect("the closed restricted-query fuzz fixture must remain valid")
    }
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

    fn bounded(&mut self, maximum: usize) -> usize {
        usize::from(self.byte()) % (maximum + 1)
    }
}
