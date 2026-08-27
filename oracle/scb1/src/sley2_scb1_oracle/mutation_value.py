"""Independent fixture oracle for partial SSMC1 mutation-value bytes."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from .codec import (
    Cursor,
    MAX_DEPTH,
    MAX_ELEMENTS,
    MAX_STORED_BYTES,
    encode_record,
    encode_sized,
    encode_uvar,
    read_sized,
)
from .errors import ScbError


MAX_TOTAL_ALLOCATION = 134_217_728
CONTRACT = "sley2-mutation-value-v1-partial"
SOURCE_SCHEMA_BLAKE3 = (
    "044d21d328e40d517fd09fd099c9697fbba2c95d0a519eade333c1140d648e73"
)


class DecodeBudget:
    """Cumulative allocation budget for nested fixture payloads."""

    def __init__(self) -> None:
        self.allocated = 0

    def charge(self, byte_count: int) -> None:
        self.allocated += byte_count
        if self.allocated > MAX_TOTAL_ALLOCATION:
            raise ScbError("SCB_RESOURCE_LIMIT")


SIMPLE_ENUMS: dict[str, dict[str, int]] = {
    "Visibility": {
        "Private": 1,
        "Package": 2,
        "Workspace": 3,
        "Exported": 4,
    },
    "ParameterRole": {
        "Function": 1,
        "Block": 2,
    },
    "Reachability": {
        "Required": 1,
        "ExplicitlyUnreachable": 2,
    },
    "EffectKind": {
        "StdoutWrite": 1,
        "StderrWrite": 2,
        "FileRead": 3,
        "FileWrite": 4,
        "ClockRead": 5,
        "RandomRead": 6,
        "EnvironmentRead": 7,
        "AdapterCall": 8,
    },
    "ContractKind": {
        "Precondition": 1,
        "Postcondition": 2,
        "Invariant": 3,
        "EffectBound": 4,
        "CapabilityBound": 5,
        "ResultPredicate": 6,
        "ResourceCeiling": 7,
    },
    "EntryExposure": {
        "Local": 1,
        "Protocol": 2,
    },
    "BuiltinFailureKind": {
        "ArithmeticError": 1,
        "IndexError": 2,
        "DuplicateKeyError": 3,
        "ContractViolation": 4,
        "CapabilityFailure": 5,
    },
    "BuiltinCase": {
        "None": 1,
        "Some": 2,
        "Ok": 3,
        "Err": 4,
    },
    "TrapCode": {
        "Unreachable": 1,
        "ResourceExhausted": 2,
        "AdapterContractViolation": 3,
        "InternalInvariant": 4,
    },
    "ArithmeticError": {
        "Overflow": 1,
        "DivideByZero": 2,
        "InvalidShift": 3,
    },
    "IndexError": {
        "OutOfBounds": 1,
    },
    "DuplicateKeyError": {
        "DuplicateKey": 1,
    },
    "ContractViolation": {
        "PredicateFalse": 1,
    },
    "CapabilityFailure": {
        "Denied": 1,
        "ScopeMismatch": 2,
        "Expired": 3,
        "RootMismatch": 4,
    },
}


RecordFields = tuple[tuple[int, str, str], ...]
UnionVariants = dict[str, tuple[int, str | None]]


RECORDS: dict[str, RecordFields] = {
    "NamedType": (
        (1, "definition", "EntityId"),
        (2, "arguments", "List<TypeExpr>"),
    ),
    "MapType": (
        (1, "key", "TypeExpr"),
        (2, "value", "TypeExpr"),
    ),
    "ResultType": (
        (1, "ok", "TypeExpr"),
        (2, "error", "TypeExpr"),
    ),
    "FunctionType": (
        (1, "parameters", "List<TypeExpr>"),
        (2, "result", "TypeExpr"),
        (3, "effects", "Set<EntityId>"),
    ),
    "OperationResultRef": (
        (1, "operation", "EntityId"),
        (2, "result_index", "UInt32"),
    ),
    "FunctionRefValue": (
        (1, "function", "EntityId"),
        (2, "type_arguments", "List<TypeExpr>"),
    ),
    "VariantImmediate": (
        (1, "definition", "EntityId"),
        (2, "member_id", "FixedBytes32"),
    ),
    "TargetEdge": (
        (1, "target", "EntityId"),
        (2, "arguments", "List<ValueRef>"),
    ),
    "SwitchEdge": (
        (1, "target", "EntityId"),
        (2, "arguments", "List<SwitchArgument>"),
    ),
    "SwitchCase": (
        (1, "case_key", "CaseKey"),
        (2, "edge", "SwitchEdge"),
    ),
    "ReturnTerminator": ((1, "value", "ValueRef"),),
    "BranchTerminator": ((1, "edge", "TargetEdge"),),
    "CondBranchTerminator": (
        (1, "condition", "ValueRef"),
        (2, "if_true", "TargetEdge"),
        (3, "if_false", "TargetEdge"),
    ),
    "VariantSwitchTerminator": (
        (1, "value", "ValueRef"),
        (2, "cases", "List<SwitchCase>"),
    ),
    "TypeParameterDef": ((1, "ordinal", "UInt32"),),
    "RecordField": (
        (1, "member_id", "FixedBytes32"),
        (2, "value_type", "TypeExpr"),
        (3, "visibility", "Visibility"),
    ),
    "BuiltinFailureValue": (
        (1, "kind", "BuiltinFailureKind"),
        (2, "code", "UInt16"),
    ),
    "ContractBinding": (
        (1, "predicate_parameter", "UInt32"),
        (2, "source", "ContractSource"),
    ),
    "ResourceLimits": (
        (1, "fuel", "UInt64"),
        (2, "memory_bytes", "UInt64"),
        (3, "output_bytes", "UInt64"),
        (4, "effect_count", "UInt64"),
        (5, "call_depth", "UInt64"),
        (6, "wall_timeout_millis", "UInt64"),
    ),
    "OperationBody": (
        (1, "block", "EntityId"),
        (2, "ordinal", "UInt32"),
        (3, "opcode", "UInt32"),
        (4, "operands", "List<ValueRef>"),
        (5, "result_types", "List<TypeExpr>"),
        (6, "immediate", "Immediate"),
    ),
    "WorkspaceBody": (
        (1, "packages", "Set<EntityId>"),
        (2, "root_namespace", "EntityId"),
        (3, "capability_requirements", "Set<EntityId>"),
        (4, "contracts", "Set<EntityId>"),
        (5, "tests", "Set<EntityId>"),
    ),
    "PackageBody": (
        (1, "workspace", "EntityId"),
        (2, "root_namespace", "EntityId"),
        (3, "dependencies", "Set<EntityId>"),
        (4, "exports", "Set<EntityId>"),
    ),
    "FunctionBody": (
        (1, "type_parameters", "List<TypeParameterDef>"),
        (2, "parameters", "List<EntityId>"),
        (3, "result_type", "TypeExpr"),
        (4, "effects", "Set<EntityId>"),
        (5, "entry_block", "EntityId"),
        (6, "blocks", "List<EntityId>"),
        (7, "contracts", "Set<EntityId>"),
        (8, "visibility", "Visibility"),
    ),
    "ParameterBody": (
        (1, "owner", "EntityId"),
        (2, "role", "ParameterRole"),
        (3, "ordinal", "UInt32"),
        (4, "value_type", "TypeExpr"),
    ),
    "GlobalValueBody": (
        (1, "value_type", "TypeExpr"),
        (2, "initializer", "EntityId"),
        (3, "visibility", "Visibility"),
    ),
    "EffectDefBody": (
        (1, "effect_kind", "EffectKind"),
        (2, "scope_type", "TypeExpr"),
        (3, "request_type", "TypeExpr"),
        (4, "response_type", "TypeExpr"),
        (5, "failure_type", "TypeExpr"),
        (6, "visibility", "Visibility"),
    ),
    "AdapterImportBody": (
        (1, "adapter_id", "FixedBytes32"),
        (2, "abi_version", "UInt32"),
        (3, "request_type", "TypeExpr"),
        (4, "response_type", "TypeExpr"),
        (5, "failure_type", "TypeExpr"),
        (6, "effects", "Set<EntityId>"),
    ),
    "EntryPointBody": (
        (1, "function", "EntityId"),
        (2, "exposure", "EntryExposure"),
    ),
    "PolicyBindingBody": (
        (1, "subject", "EntityId"),
        (2, "requirements", "Set<EntityId>"),
    ),
    "DependencyBindingBody": (
        (1, "dependency_root", "StateRoot"),
        (2, "external_package", "EntityId"),
        (3, "local_namespace", "EntityId"),
    ),
}


UNIONS: dict[str, UnionVariants] = {
    "TypeExpr": {
        "Unit": (1, None),
        "Bool": (2, None),
        "SInt": (3, "IntegerWidth"),
        "UInt": (4, "IntegerWidth"),
        "F32": (5, None),
        "F64": (6, None),
        "Bytes": (7, None),
        "Text": (8, None),
        "Tuple": (9, "List<TypeExpr>"),
        "Named": (10, "NamedType"),
        "Vector": (11, "TypeExpr"),
        "OrderedMap": (12, "MapType"),
        "Option": (13, "TypeExpr"),
        "Result": (14, "ResultType"),
        "FunctionRef": (15, "FunctionType"),
        "AdapterHandle": (16, "EntityId"),
        "CapabilityToken": (17, "EntityId"),
        "LocalCell": (18, "TypeExpr"),
        "TypeParameter": (19, "UInt32"),
        "BuiltinFailure": (20, "BuiltinFailureKind"),
    },
    "ValueRef": {
        "Parameter": (1, "EntityId"),
        "OperationResult": (2, "OperationResultRef"),
    },
    "Immediate": {
        "None": (1, None),
        "Entity": (2, "EntityId"),
        "Index": (3, "UInt32"),
        "Field": (4, "FixedBytes32"),
        "Variant": (5, "VariantImmediate"),
        "Observation": (6, "FixedBytes32"),
        "Function": (7, "FunctionRefValue"),
    },
    "CaseKey": {
        "Member": (1, "FixedBytes32"),
        "Builtin": (2, "BuiltinCase"),
    },
    "SwitchArgument": {
        "Value": (1, "ValueRef"),
        "CasePayload": (2, None),
    },
    "ContractSource": {
        "Parameter": (1, "EntityId"),
        "Result": (2, None),
        "Error": (3, None),
        "Global": (4, "EntityId"),
    },
}


def encode_accepted_mutation_vector(vector: Mapping[str, object]) -> bytes:
    return encode_mutation_value(str(vector["declared_type"]), vector["value"])


def encode_mutation_value(declared_type: str, value: object) -> bytes:
    encoded = _encode_type(declared_type, value, 0)
    if len(encoded) > MAX_STORED_BYTES:
        raise ScbError("SCB_RESOURCE_LIMIT")
    return encoded


def decode_declared_mutation_value(declared_type: str, data: bytes) -> None:
    if len(data) > MAX_STORED_BYTES:
        raise ScbError("SCB_RESOURCE_LIMIT")
    cursor = Cursor(data)
    budget = DecodeBudget()
    _decode_type(declared_type, cursor, 0, budget)
    cursor.finish()


def decode_accepted_mutation_vector(
    vector: Mapping[str, object], data: bytes
) -> None:
    decode_declared_mutation_value(str(vector["declared_type"]), data)


def check_mutation_value(accepted_path: Path, rejected_path: Path) -> dict[str, object]:
    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    rejected = json.loads(rejected_path.read_text(encoding="utf-8"))
    problems: list[str] = []

    for label, fixture in (("accepted", accepted), ("rejected", rejected)):
        if fixture.get("contract") != CONTRACT:
            problems.append(f"{label}: contract must be {CONTRACT}")
        if fixture.get("claim") != "partial":
            problems.append(f"{label}: claim must be partial")
        if fixture.get("source_schema_blake3") != SOURCE_SCHEMA_BLAKE3:
            problems.append(f"{label}: source schema digest drift")
        vector_ids = [vector.get("id") for vector in fixture.get("vectors", [])]
        if len(vector_ids) != len(set(vector_ids)):
            problems.append(f"{label}: duplicate vector id")

    problems.extend(_fixture_checksum_problems(accepted_path, rejected_path))

    for vector in accepted["vectors"]:
        try:
            actual = encode_accepted_mutation_vector(vector).hex()
        except (ScbError, ValueError, TypeError) as error:
            problems.append(f"{vector['id']}: oracle raised {error}")
            continue
        if actual != vector["expected_hex"]:
            problems.append(
                f"{vector['id']}: expected {vector['expected_hex']}, oracle produced {actual}"
            )
            continue
        try:
            decode_accepted_mutation_vector(vector, bytes.fromhex(actual))
        except (ScbError, ValueError, TypeError) as error:
            problems.append(
                f"{vector['id']}: oracle rejected accepted bytes with {error}"
            )

    for vector in rejected["vectors"]:
        try:
            decode_declared_mutation_value(
                str(vector["declared_type"]), bytes.fromhex(str(vector["input_hex"]))
            )
        except ScbError as error:
            if error.code != vector["expected_code"]:
                problems.append(
                    f"{vector['id']}: expected {vector['expected_code']}, oracle returned {error.code}"
                )
        except (ValueError, TypeError) as error:
            problems.append(f"{vector['id']}: unsupported oracle path: {error}")
        else:
            problems.append(f"{vector['id']}: rejected vector was accepted")

    return {
        "contract": "s20-350-independent-mutation-value-oracle-v1",
        "claim": "partial",
        "result": "FAIL" if problems else "PASS",
        "accepted_vectors": len(accepted["vectors"]),
        "rejected_vectors": len(rejected["vectors"]),
        "byte_agreement": not any("oracle produced" in problem for problem in problems),
        "accepted_decode_agreement": not any(
            "rejected accepted bytes" in problem for problem in problems
        ),
        "code_agreement": not any("oracle returned" in problem for problem in problems),
        "problems": problems,
    }


def _fixture_checksum_problems(
    accepted_path: Path, rejected_path: Path
) -> list[str]:
    if accepted_path.parent != rejected_path.parent:
        return ["fixtures: accepted and rejected files must share one directory"]
    checksum_path = accepted_path.parent / "SHA256SUMS"
    if not checksum_path.is_file():
        return ["fixtures: missing SHA256SUMS"]
    declared: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2:
            return ["fixtures: malformed SHA256SUMS"]
        digest, name = parts
        if name in declared:
            return [f"fixtures: duplicate checksum entry {name}"]
        declared[name] = digest
    expected_names = {accepted_path.name, rejected_path.name}
    problems: list[str] = []
    if set(declared) != expected_names:
        problems.append("fixtures: SHA256SUMS inventory drift")
    for path in (accepted_path, rejected_path):
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if declared.get(path.name) != actual:
            problems.append(f"fixtures: checksum drift for {path.name}")
    return problems


def _encode_type(declared_type: str, value: object, depth: int) -> bytes:
    _check_depth(depth)
    if declared_type.startswith("List<") and declared_type.endswith(">"):
        inner = declared_type[5:-1]
        return _encode_list(inner, value, depth)
    if declared_type in {"Set<EntityId>", "EntityIdSet"}:
        return _encode_entity_id_set(value, depth)
    if declared_type in RECORDS:
        return _encode_record_value(declared_type, value, depth)
    if declared_type in UNIONS:
        return _encode_union_value(declared_type, value, depth)
    if declared_type in SIMPLE_ENUMS:
        return _encode_enum(declared_type, value)
    if declared_type in {"EntityId", "StateRoot", "MemberId", "FixedBytes32"}:
        return _bytes_from_hex(value, 32)
    if declared_type in {"UInt16", "IntegerWidth"}:
        return _encode_uint(value, 16)
    if declared_type == "UInt32":
        return _encode_uint(value, 32)
    if declared_type == "UInt64":
        return _encode_uint(value, 64)
    if declared_type == "SInt64":
        return _encode_sint64(value)
    if declared_type == "Bool":
        if not isinstance(value, bool):
            raise ValueError("Bool fixture value must be true or false")
        return b"\x01" if value else b"\x00"
    if declared_type == "Bytes":
        return encode_sized(_bytes_from_hex(value))
    if declared_type == "Text":
        if not isinstance(value, str):
            raise ValueError("Text fixture value must be a string")
        return encode_sized(value.encode("utf-8"))
    if declared_type == "F32Bits":
        return _encode_float_bits(value, 32)
    if declared_type == "F64Bits":
        return _encode_float_bits(value, 64)
    raise ValueError(f"unsupported mutation-value fixture type: {declared_type}")


def _decode_type(
    declared_type: str, cursor: Cursor, depth: int, budget: DecodeBudget
) -> None:
    _check_depth(depth)
    if declared_type.startswith("List<") and declared_type.endswith(">"):
        _decode_list(declared_type[5:-1], cursor, depth, budget)
    elif declared_type in {"Set<EntityId>", "EntityIdSet"}:
        _decode_entity_id_set(cursor, depth, budget)
    elif declared_type in RECORDS:
        _decode_record_value(declared_type, cursor, depth, budget)
    elif declared_type in UNIONS:
        _decode_union_value(declared_type, cursor, depth, budget)
    elif declared_type in SIMPLE_ENUMS:
        _decode_enum(declared_type, cursor)
    elif declared_type in {"EntityId", "StateRoot", "MemberId", "FixedBytes32"}:
        cursor.read(32)
    elif declared_type in {"UInt16", "IntegerWidth"}:
        decode_uvar_width(cursor, 16)
    elif declared_type == "UInt32":
        decode_uvar_width(cursor, 32)
    elif declared_type == "UInt64":
        decode_uvar_width(cursor, 64)
    elif declared_type == "SInt64":
        decode_uvar_width(cursor, 64)
    elif declared_type == "Bool":
        _decode_bool(cursor)
    elif declared_type == "Bytes":
        budget.charge(len(read_sized(cursor)))
    elif declared_type == "Text":
        encoded = read_sized(cursor)
        budget.charge(len(encoded))
        try:
            encoded.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ScbError("SCB_UTF8_INVALID") from error
    elif declared_type == "F32Bits":
        _decode_float_bits(cursor, 32)
    elif declared_type == "F64Bits":
        _decode_float_bits(cursor, 64)
    else:
        raise ValueError(f"unsupported mutation-value fixture type: {declared_type}")


def _encode_list(inner_type: str, value: object, depth: int) -> bytes:
    _check_container_depth(depth)
    items = _expect_sequence(value)
    if len(items) > MAX_ELEMENTS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    encoded_items = [_encode_type(inner_type, item, depth + 1) for item in items]
    return encode_uvar(len(encoded_items)) + b"".join(
        encode_sized(item) for item in encoded_items
    )


def _decode_list(
    inner_type: str, cursor: Cursor, depth: int, budget: DecodeBudget
) -> None:
    _check_container_depth(depth)
    count = decode_uvar_width(cursor, 64)
    if count > MAX_ELEMENTS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    for _ in range(count):
        payload = read_sized(cursor)
        budget.charge(len(payload))
        _decode_nested_exact(inner_type, payload, depth + 1, budget)


def _encode_entity_id_set(value: object, depth: int) -> bytes:
    _check_container_depth(depth)
    items = [_bytes_from_hex(item, 32) for item in _expect_sequence(value)]
    if len(items) > MAX_ELEMENTS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    _check_strict_bytes_order(items)
    return encode_uvar(len(items)) + b"".join(encode_sized(item) for item in items)


def _decode_entity_id_set(
    cursor: Cursor, depth: int, budget: DecodeBudget
) -> None:
    _check_container_depth(depth)
    count = decode_uvar_width(cursor, 64)
    if count > MAX_ELEMENTS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    prior: bytes | None = None
    for _ in range(count):
        payload = read_sized(cursor)
        budget.charge(len(payload))
        _decode_nested_exact("EntityId", payload, depth + 1, budget)
        if prior is not None:
            if payload == prior:
                raise ScbError("SCB_MAP_DUPLICATE")
            if payload < prior:
                raise ScbError("SCB_MAP_ORDER")
        prior = payload


def _encode_record_value(declared_type: str, value: object, depth: int) -> bytes:
    _check_container_depth(depth)
    source = _expect_mapping(value)
    fields = RECORDS[declared_type]
    expected_names = {name for _, name, _ in fields}
    supplied_names = set(source)
    if supplied_names != expected_names:
        missing = sorted(expected_names - supplied_names)
        unknown = sorted(supplied_names - expected_names)
        raise ValueError(
            f"{declared_type} fixture fields mismatch; missing={missing} unknown={unknown}"
        )
    encoded_fields = [
        (tag, _encode_type(field_type, source[name], depth + 1))
        for tag, name, field_type in fields
    ]
    return encode_record(encoded_fields)


def _decode_record_value(
    declared_type: str, cursor: Cursor, depth: int, budget: DecodeBudget
) -> None:
    _check_container_depth(depth)
    fields = RECORDS[declared_type]
    count = decode_uvar_width(cursor, 64)
    expected_count = len(fields)
    if count != expected_count:
        raise ScbError("SCB_FIELD_MISSING" if count < expected_count else "SCB_FIELD_UNKNOWN")
    prior: int | None = None
    expected_tags = [tag for tag, _, _ in fields]
    for expected_tag, _, field_type in fields:
        tag = decode_uvar_width(cursor, 32)
        if prior is not None:
            if tag == prior:
                raise ScbError("SCB_FIELD_DUPLICATE")
            if tag < prior:
                raise ScbError("SCB_FIELD_ORDER")
        prior = tag
        if tag != expected_tag:
            code = "SCB_FIELD_ORDER" if tag in expected_tags else "SCB_FIELD_UNKNOWN"
            raise ScbError(code)
        payload = read_sized(cursor)
        budget.charge(len(payload))
        _decode_nested_exact(field_type, payload, depth + 1, budget)


def _encode_union_value(declared_type: str, value: object, depth: int) -> bytes:
    _check_container_depth(depth)
    source = _expect_mapping(value)
    variant_name = source.get("variant")
    if not isinstance(variant_name, str):
        raise ValueError(f"{declared_type} fixture variant must be a string")
    try:
        tag, payload_type = UNIONS[declared_type][variant_name]
    except KeyError as error:
        raise ValueError(f"unknown {declared_type} fixture variant: {variant_name}") from error
    if payload_type is None:
        if "value" in source:
            raise ValueError(f"{declared_type}.{variant_name} must not include a payload")
        payload = b""
    else:
        if "value" not in source:
            raise ValueError(f"{declared_type}.{variant_name} must include a payload")
        payload = _encode_type(payload_type, source["value"], depth + 1)
    return encode_uvar(tag) + encode_sized(payload)


def _decode_union_value(
    declared_type: str, cursor: Cursor, depth: int, budget: DecodeBudget
) -> None:
    _check_container_depth(depth)
    tag = decode_uvar_width(cursor, 32)
    payload = read_sized(cursor)
    budget.charge(len(payload))
    variants_by_tag = {tag: payload_type for tag, payload_type in UNIONS[declared_type].values()}
    if tag not in variants_by_tag:
        raise ScbError("SCB_UNION_INVALID")
    payload_type = variants_by_tag[tag]
    if payload_type is None:
        if payload:
            raise ScbError("SCB_UNION_INVALID")
        return
    _decode_nested_exact(payload_type, payload, depth + 1, budget)


def _encode_enum(declared_type: str, value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{declared_type} fixture value must be a string")
    try:
        tag = SIMPLE_ENUMS[declared_type][value]
    except KeyError as error:
        raise ValueError(f"unknown {declared_type} fixture value: {value}") from error
    width = 16 if declared_type == "BuiltinFailureKind" else 32
    return _encode_uint(tag, width)


def _decode_enum(declared_type: str, cursor: Cursor) -> None:
    width = 16 if declared_type == "BuiltinFailureKind" else 32
    tag = decode_uvar_width(cursor, width)
    if tag not in set(SIMPLE_ENUMS[declared_type].values()):
        raise ScbError("SCB_UNION_INVALID")


def _decode_nested_exact(
    declared_type: str, payload: bytes, depth: int, budget: DecodeBudget
) -> None:
    nested = Cursor(payload)
    _decode_type(declared_type, nested, depth, budget)
    nested.finish()


def _expect_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("fixture value must be an object")
    return value


def _expect_sequence(value: object) -> Sequence[object]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    raise ValueError("fixture value must be a list")


def _bytes_from_hex(value: object, length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError("byte fixture value must be lowercase hex")
    if value != value.lower():
        raise ValueError("byte fixture value must be lowercase hex")
    data = bytes.fromhex(value)
    if length is not None and len(data) != length:
        raise ValueError(f"byte fixture value must be {length} bytes")
    return data


def _encode_uint(value: object, width: int) -> bytes:
    value = _fixture_integer(value)
    if value < 0 or value >= 1 << width:
        raise ValueError(f"unsigned integer fixture value exceeds UInt{width}")
    return encode_uvar(value)


def decode_uvar_width(cursor: Cursor, width: int) -> int:
    return _decode_uvar(cursor, width)


def _decode_uvar(cursor: Cursor, width: int) -> int:
    value = 0
    groups = 0
    while True:
        if cursor.remaining == 0:
            raise ScbError("SCB_LENGTH_OVERFLOW")
        byte = cursor.read(1)[0]
        groups += 1
        payload = byte & 0x7F
        if groups > 19:
            raise ScbError("SCB_INTEGER_OVERFLOW")
        value |= payload << (7 * (groups - 1))
        if byte & 0x80 == 0:
            if groups > 1 and payload == 0:
                raise ScbError("SCB_VARINT_NON_MINIMAL")
            if value >= 1 << width:
                raise ScbError("SCB_INTEGER_OVERFLOW")
            return value


def _encode_sint64(value: object) -> bytes:
    value = _fixture_integer(value)
    if value < -(1 << 63) or value >= 1 << 63:
        raise ValueError("signed integer fixture value exceeds SInt64")
    return encode_uvar((value << 1) ^ (value >> 63))


def _fixture_integer(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value):
        return int(value)
    raise ValueError("integer fixture value must be an exact integer or decimal string")


def _decode_bool(cursor: Cursor) -> None:
    value = cursor.read(1)[0]
    if value not in (0, 1):
        raise ScbError("SCB_BOOL_INVALID")


def _encode_float_bits(value: object, width: int) -> bytes:
    length = width // 8
    if isinstance(value, int) and not isinstance(value, bool):
        if value < 0 or value >= 1 << width:
            raise ValueError(f"F{width}Bits fixture value exceeds width")
        data = value.to_bytes(length, "big")
    else:
        data = _bytes_from_hex(value, length)
    cursor = Cursor(data)
    _decode_float_bits(cursor, width)
    cursor.finish()
    return data


def _decode_float_bits(cursor: Cursor, width: int) -> None:
    encoded = cursor.read(width // 8)
    bits = int.from_bytes(encoded, "big")
    if width == 32:
        sign_mask = 0x80000000
        exponent_mask = 0x7F800000
        fraction_mask = 0x007FFFFF
        canonical_nan = 0x7FC00000
    else:
        sign_mask = 0x8000000000000000
        exponent_mask = 0x7FF0000000000000
        fraction_mask = 0x000FFFFFFFFFFFFF
        canonical_nan = 0x7FF8000000000000
    is_nan = bits & exponent_mask == exponent_mask and bits & fraction_mask != 0
    if bits == sign_mask or (is_nan and bits != canonical_nan):
        raise ScbError("SCB_FLOAT_NON_CANONICAL")


def _check_depth(depth: int) -> None:
    if depth > MAX_DEPTH:
        raise ScbError("SCB_RESOURCE_LIMIT")


def _check_container_depth(depth: int) -> None:
    if depth >= MAX_DEPTH:
        raise ScbError("SCB_RESOURCE_LIMIT")


def _check_strict_bytes_order(items: Sequence[bytes]) -> None:
    prior: bytes | None = None
    for item in items:
        if prior is not None:
            if item == prior:
                raise ScbError("SCB_MAP_DUPLICATE")
            if item < prior:
                raise ScbError("SCB_MAP_ORDER")
        prior = item
