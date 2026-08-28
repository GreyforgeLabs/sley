"""Independent S20-350 candidate construction and conformance oracle."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import blake3

from .codec import Cursor, MAX_STORED_BYTES, encode_record, encode_sized, encode_uvar, read_sized
from .errors import ScbError
from .mutation_value import (
    RECORDS,
    SIMPLE_ENUMS,
    SOURCE_SCHEMA_BLAKE3,
    DecodeBudget,
    _decode_nested_exact,
    _decode_type,
    _encode_type,
    _expect_mapping,
    _expect_sequence,
    _fixture_checksum_problems,
    decode_declared_mutation_value,
    decode_uvar_width,
    encode_mutation_value,
)


CONTRACT = "sley2-mutation-candidate-v1"
CANDIDATE_MAGIC = b"SLEYCAN1"
CANDIDATE_VERSION = 1
CANDIDATE_DOMAIN = b"sley2.candidate.v1"
ENTITY_DOMAIN = b"sley2.entity.v1"
VALIDATION_PROFILE_MAGIC = b"SLEYVAP1"
VALIDATION_PROFILE_DOMAIN = b"sley2.validation-profile.v1"
FULL_VALIDATION_PROFILE = {
    "format_version": 1,
    "phase_tags": list(range(1, 15)),
    "max_operations": 65_535,
    "max_preconditions": 65_535,
    "max_candidate_bytes": 67_108_864,
    "max_decoded_value_bytes": 67_108_864,
    "max_graph_work": 10_000_000,
    "max_selected_tests": 65_535,
}

ENTITY_BODIES = {
    1: "WorkspaceBody",
    2: "PackageBody",
    3: "NamespaceBody",
    4: "TypeDefBody",
    5: "FunctionBody",
    6: "ParameterBody",
    7: "BlockBody",
    8: "OperationBody",
    9: "ConstantBody",
    10: "GlobalValueBody",
    11: "EffectDefBody",
    12: "CapabilityRequirementBody",
    13: "ContractBody",
    14: "TestCaseBody",
    15: "AdapterImportBody",
    16: "EntryPointBody",
    17: "PolicyBindingBody",
    18: "DependencyBindingBody",
}

MUTATION_CLASSES = {
    "CreateEntity": 1,
    "ReplaceEntityVersion": 2,
    "DeleteEntityBinding": 3,
    "SetScalarField": 4,
    "ReplaceTypedField": 5,
    "RetargetReference": 6,
    "InsertOrderedChild": 7,
    "RemoveOrderedChild": 8,
    "MoveOrderedChild": 9,
    "AddEntryPoint": 10,
    "RemoveEntryPoint": 11,
    "AddTest": 12,
    "ReplaceTest": 13,
    "AddContract": 14,
    "ReplaceContract": 15,
    "UpdateDependencyBinding": 16,
}
CLASS_BY_TAG = {tag: name for name, tag in MUTATION_CLASSES.items()}
REQUIREMENTS = {
    "ExpectedIdentityAbsent": 1,
    "ExactEntityVersion": 2,
    "ExactContainerVersion": 3,
}
REQUIREMENT_BY_TAG = {tag: name for name, tag in REQUIREMENTS.items()}
SCALAR_TYPES = {
    "Bool",
    "Bytes",
    "F32",
    "F64",
    "FixedBytes32",
    "SInt",
    "Text",
    "UInt16",
    "UInt32",
    "UInt64",
}
SCALAR_TYPES.update(SIMPLE_ENUMS)


class CandidateOracleError(Exception):
    """Stable proposal-structure failure outside SCB1 syntax."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validation_profile_id() -> bytes:
    record = _encode_type("ValidationProfileRecord", FULL_VALIDATION_PROFILE, 0)
    preimage = VALIDATION_PROFILE_MAGIC + encode_uvar(1) + encode_sized(record)
    return _digest(VALIDATION_PROFILE_DOMAIN, preimage)


def derive_entity_id(
    workspace_id: bytes, candidate_nonce: bytes, target_kind: int, creation_ordinal: int
) -> bytes:
    if len(workspace_id) != 32 or len(candidate_nonce) != 32:
        raise ValueError("workspace and candidate nonce must be 32 bytes")
    preimage = (
        workspace_id
        + candidate_nonce
        + target_kind.to_bytes(4, "big")
        + creation_ordinal.to_bytes(8, "big")
    )
    return _digest(ENTITY_DOMAIN, preimage)


def build_candidate(record: Mapping[str, object]) -> dict[str, bytes]:
    record_bytes = encode_candidate_record(record)
    preimage = CANDIDATE_MAGIC + encode_uvar(CANDIDATE_VERSION) + encode_sized(record_bytes)
    if len(preimage) + 32 > MAX_STORED_BYTES:
        raise ScbError("SCB_RESOURCE_LIMIT")
    candidate_id = _digest(CANDIDATE_DOMAIN, preimage)
    return {
        "record": record_bytes,
        "preimage": preimage,
        "candidate_id": candidate_id,
        "stored": preimage + candidate_id,
    }


def encode_candidate_record(record: Mapping[str, object]) -> bytes:
    encoded = encode_candidate_record_unchecked(record)
    _decode_candidate_record(encoded)
    return encoded


def encode_candidate_record_unchecked(record: Mapping[str, object]) -> bytes:
    source = _expect_mapping(record)
    expected = {
        "format_version",
        "workspace_id",
        "base_transaction_id",
        "base_root",
        "schema_epoch_id",
        "policy_root_id",
        "principal_id",
        "capability_summary_digest",
        "operations",
        "preconditions",
        "validation_profile_id",
        "candidate_nonce",
        "expiry",
    }
    if set(source) != expected:
        raise ValueError("candidate fixture fields mismatch")
    return encode_record(
        [
            (1, _encode_type("UInt32", source["format_version"], 1)),
            (2, _encode_type("WorkspaceId", source["workspace_id"], 1)),
            (3, _encode_type("TransactionId", source["base_transaction_id"], 1)),
            (4, _encode_type("StateRoot", source["base_root"], 1)),
            (5, _encode_type("SchemaEpochId", source["schema_epoch_id"], 1)),
            (6, _encode_type("PolicyRootId", source["policy_root_id"], 1)),
            (7, _encode_type("PrincipalId", source["principal_id"], 1)),
            (
                8,
                _encode_type(
                    "CapabilitySummaryDigest", source["capability_summary_digest"], 1
                ),
            ),
            (9, _encode_custom_list(source["operations"], _encode_operation, 1)),
            (10, _encode_custom_list(source["preconditions"], _encode_precondition, 1)),
            (
                11,
                _encode_type("ValidationProfileId", source["validation_profile_id"], 1),
            ),
            (12, _encode_type("CandidateNonce", source["candidate_nonce"], 1)),
            (13, _encode_type("CandidateExpiry", source["expiry"], 1)),
        ]
    )


def import_candidate(stored: bytes) -> None:
    if len(stored) > MAX_STORED_BYTES:
        raise ScbError("SCB_RESOURCE_LIMIT")
    if len(stored) < 32:
        raise ScbError("SCB_LENGTH_OVERFLOW")
    preimage, actual_digest = stored[:-32], stored[-32:]
    cursor = Cursor(preimage)
    if cursor.read(len(CANDIDATE_MAGIC)) != CANDIDATE_MAGIC:
        raise ScbError("SCB_MAGIC_INVALID")
    if decode_uvar_width(cursor, 64) != CANDIDATE_VERSION:
        raise ScbError("SCB_VERSION_UNSUPPORTED")
    record = read_sized(cursor)
    cursor.finish()
    if _digest(CANDIDATE_DOMAIN, preimage) != actual_digest:
        raise ScbError("SCB_DIGEST_MISMATCH")
    _decode_candidate_record(record)


def stored_from_record_bytes(record: bytes) -> bytes:
    preimage = CANDIDATE_MAGIC + encode_uvar(CANDIDATE_VERSION) + encode_sized(record)
    return preimage + _digest(CANDIDATE_DOMAIN, preimage)


def check_candidate(accepted_path: Path, rejected_path: Path) -> dict[str, object]:
    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    rejected = json.loads(rejected_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    for label, corpus in (("accepted", accepted), ("rejected", rejected)):
        if corpus.get("contract") != CONTRACT:
            problems.append(f"{label}: contract must be {CONTRACT}")
        if corpus.get("claim") != "complete-s20-350-conformance":
            problems.append(f"{label}: claim drift")
        if corpus.get("source_schema_blake3") != SOURCE_SCHEMA_BLAKE3:
            problems.append(f"{label}: schema digest drift")
    problems.extend(_fixture_checksum_problems(accepted_path, rejected_path))

    for vector in accepted.get("value_vectors", []):
        try:
            encoded = encode_mutation_value(vector["declared_type"], vector["value"])
            if encoded.hex() != vector["expected_hex"]:
                problems.append(f"{vector['id']}: mutation bytes differ")
                continue
            decode_declared_mutation_value(vector["declared_type"], encoded)
        except (ScbError, ValueError, TypeError) as error:
            problems.append(f"{vector['id']}: oracle raised {error}")

    for vector in accepted.get("candidate_vectors", []):
        try:
            built = build_candidate(vector["record"])
            for key, fixture_key in (
                ("record", "expected_record_hex"),
                ("preimage", "expected_preimage_hex"),
                ("candidate_id", "expected_candidate_id"),
                ("stored", "expected_stored_hex"),
            ):
                if built[key].hex() != vector[fixture_key]:
                    problems.append(f"{vector['id']}: {key} differs")
            import_candidate(built["stored"])
        except (CandidateOracleError, ScbError, ValueError, TypeError) as error:
            problems.append(f"{vector['id']}: candidate oracle raised {error}")

    for vector in rejected.get("value_vectors", []):
        _check_rejected_value(vector, problems)
    for vector in rejected.get("candidate_vectors", []):
        try:
            import_candidate(bytes.fromhex(vector["input_hex"]))
        except (CandidateOracleError, ScbError) as error:
            if error.code != vector["expected_code"]:
                problems.append(
                    f"{vector['id']}: expected {vector['expected_code']}, got {error.code}"
                )
        except (ValueError, TypeError) as error:
            problems.append(f"{vector['id']}: unsupported fixture: {error}")
        else:
            problems.append(f"{vector['id']}: rejected candidate was accepted")

    return {
        "contract": "s20-350-independent-candidate-conformance-v1",
        "claim": "complete-s20-350-conformance",
        "result": "FAIL" if problems else "PASS",
        "value_vectors": len(accepted.get("value_vectors", [])),
        "candidate_vectors": len(accepted.get("candidate_vectors", [])),
        "rejected_value_vectors": len(rejected.get("value_vectors", [])),
        "rejected_candidate_vectors": len(rejected.get("candidate_vectors", [])),
        "problems": problems,
    }


def _check_rejected_value(vector: Mapping[str, object], problems: list[str]) -> None:
    try:
        decode_declared_mutation_value(
            str(vector["declared_type"]), bytes.fromhex(str(vector["input_hex"]))
        )
    except ScbError as error:
        if error.code != vector["expected_code"]:
            problems.append(
                f"{vector['id']}: expected {vector['expected_code']}, got {error.code}"
            )
    except (ValueError, TypeError) as error:
        problems.append(f"{vector['id']}: unsupported fixture: {error}")
    else:
        problems.append(f"{vector['id']}: rejected value was accepted")


def descriptor_inventory() -> list[tuple[str, int, int | None, str, str]]:
    rows: list[tuple[str, int, int | None, str, str]] = []
    for kind, body in ENTITY_BODIES.items():
        rows.extend(
            [
                ("CreateEntity", kind, None, body, "ExpectedIdentityAbsent"),
                ("ReplaceEntityVersion", kind, None, body, "ExactEntityVersion"),
                ("DeleteEntityBinding", kind, None, "Unit", "ExactEntityVersion"),
            ]
        )
    for kind, body in ENTITY_BODIES.items():
        for field_tag, _name, value_type in RECORDS[body]:
            if value_type in SCALAR_TYPES:
                rows.append(("SetScalarField", kind, field_tag, value_type, "ExactEntityVersion"))
            rows.append(("ReplaceTypedField", kind, field_tag, value_type, "ExactEntityVersion"))
            if value_type in {"EntityId", "Option<EntityId>"}:
                rows.append(("RetargetReference", kind, field_tag, value_type, "ExactEntityVersion"))
            if value_type == "List<EntityId>":
                for class_name in (
                    "InsertOrderedChild",
                    "RemoveOrderedChild",
                    "MoveOrderedChild",
                ):
                    rows.append(
                        (class_name, kind, field_tag, value_type, "ExactContainerVersion")
                    )
    rows.extend(
        [
            ("AddEntryPoint", 16, None, "EntryPointBody", "ExactEntityVersion"),
            ("RemoveEntryPoint", 16, None, "Unit", "ExactEntityVersion"),
            ("AddTest", 14, None, "TestCaseBody", "ExactEntityVersion"),
            ("ReplaceTest", 14, None, "TestCaseBody", "ExactEntityVersion"),
            ("AddContract", 13, None, "ContractBody", "ExactEntityVersion"),
            ("ReplaceContract", 13, None, "ContractBody", "ExactEntityVersion"),
            (
                "UpdateDependencyBinding",
                18,
                None,
                "DependencyBindingBody",
                "ExactEntityVersion",
            ),
        ]
    )
    return rows


DESCRIPTORS = {
    (class_name, kind, field_tag): (value_type, requirement)
    for class_name, kind, field_tag, value_type, requirement in descriptor_inventory()
}
if len(DESCRIPTORS) != 179:
    raise RuntimeError("independent descriptor inventory is not exactly 179")


def _descriptor(class_name: str, kind: int, field_tag: int | None) -> tuple[str, str]:
    try:
        return DESCRIPTORS[(class_name, kind, field_tag)]
    except KeyError as error:
        raise CandidateOracleError("MUTATION_CANDIDATE_DESCRIPTOR_UNKNOWN") from error


def _encode_operation(value: object, depth: int) -> bytes:
    source = _expect_mapping(value)
    class_name = str(source["class"])
    try:
        class_tag = MUTATION_CLASSES[class_name]
    except KeyError as error:
        raise ValueError("unknown mutation class") from error
    kind = _exact_int(source["target_kind"])
    field_tag_value = source["field_tag"]
    field_tag = None if field_tag_value is None else _exact_int(field_tag_value)
    value_type, _requirement = _descriptor(class_name, kind, field_tag)
    payload = _encode_payload(class_name, class_tag, kind, value_type, source["payload"], depth + 1)
    return encode_record(
        [
            (1, _encode_type("UInt32", source["ordinal"], depth + 1)),
            (2, encode_uvar(class_tag)),
            (3, _encode_type("UInt32", kind, depth + 1)),
            (4, _encode_type("EntityId", source["target_entity"], depth + 1)),
            (
                5,
                _encode_type(
                    "Option<UInt32>",
                    {"variant": "None"}
                    if field_tag is None
                    else {"variant": "Some", "value": field_tag},
                    depth + 1,
                ),
            ),
            (6, payload),
            (7, _encode_type("UInt32", source["precondition_ordinal"], depth + 1)),
        ]
    )


def _encode_payload(
    class_name: str,
    class_tag: int,
    kind: int,
    value_type: str,
    value: object,
    depth: int,
) -> bytes:
    if value_type == "Unit":
        if value is not None:
            raise ValueError("Unit mutation payload must be null")
        payload = b""
    elif class_name in {"CreateEntity", "ReplaceEntityVersion"}:
        body = _encode_type(value_type, value, depth + 1)
        payload = encode_uvar(kind) + encode_sized(body)
    else:
        wire_type = {
            "InsertOrderedChild": "OrderedInsert",
            "RemoveOrderedChild": "OrderedRemove",
            "MoveOrderedChild": "OrderedMove",
        }.get(class_name, value_type)
        payload = _encode_type(wire_type, value, depth + 1)
    return encode_uvar(class_tag) + encode_sized(payload)


def _encode_precondition(value: object, depth: int) -> bytes:
    source = _expect_mapping(value)
    requirement = str(source["requirement"])
    try:
        tag = REQUIREMENTS[requirement]
    except KeyError as error:
        raise ValueError("unknown precondition requirement") from error
    payload = _encode_type(requirement, source["payload"], depth + 1)
    return encode_record(
        [
            (1, _encode_type("UInt32", source["operation_ordinal"], depth + 1)),
            (2, encode_uvar(tag)),
            (3, encode_uvar(tag) + encode_sized(payload)),
        ]
    )


def _encode_custom_list(
    value: object, encode_item: object, depth: int
) -> bytes:
    items = _expect_sequence(value)
    encoded = [encode_item(item, depth + 1) for item in items]  # type: ignore[operator]
    return encode_uvar(len(encoded)) + b"".join(encode_sized(item) for item in encoded)


def _decode_candidate_record(record: bytes) -> None:
    fields = _read_record(record, list(range(1, 14)))
    if _read_uint(fields[1], 32) != 1:
        raise CandidateOracleError("MUTATION_CANDIDATE_FORMAT_VERSION")
    workspace = _read_fixed(fields[2])
    nonce = _read_fixed(fields[12])
    if _read_fixed(fields[11]) != validation_profile_id():
        raise CandidateOracleError("MUTATION_CANDIDATE_VALIDATION_PROFILE")
    _decode_expiry(fields[13])
    operations = [_decode_operation(item) for item in _read_list(fields[9])]
    preconditions = [_decode_precondition(item) for item in _read_list(fields[10])]
    if not operations:
        raise CandidateOracleError("MUTATION_CANDIDATE_EMPTY_OPERATIONS")
    if len(operations) > 65_535 or len(preconditions) > 65_535:
        raise ScbError("SCB_RESOURCE_LIMIT")
    if len(operations) != len(preconditions):
        raise CandidateOracleError("MUTATION_CANDIDATE_PRECONDITION_COUNT")
    create_ordinal = 0
    for index, (operation, precondition) in enumerate(zip(operations, preconditions)):
        if operation["ordinal"] != index:
            raise CandidateOracleError("MUTATION_CANDIDATE_OPERATION_ORDINAL")
        if operation["precondition_ordinal"] != operation["ordinal"]:
            raise CandidateOracleError(
                "MUTATION_CANDIDATE_OPERATION_PRECONDITION_ORDINAL"
            )
        if precondition["ordinal"] != operation["ordinal"]:
            raise CandidateOracleError("MUTATION_CANDIDATE_PRECONDITION_MISMATCH")
        _value_type, expected_requirement = _descriptor(
            operation["class"], operation["kind"], operation["field_tag"]
        )
        if precondition["requirement"] != expected_requirement:
            raise CandidateOracleError("MUTATION_CANDIDATE_PRECONDITION_MISMATCH")
        if operation["class"] == "CreateEntity":
            expected = derive_entity_id(workspace, nonce, operation["kind"], create_ordinal)
            create_ordinal += 1
            if operation["target"] != expected:
                raise CandidateOracleError("MUTATION_CANDIDATE_TARGET_ENTITY")
        _validate_precondition_target(operation, precondition)


def _decode_operation(record: bytes) -> dict[str, object]:
    fields = _read_record(record, list(range(1, 8)))
    ordinal = _read_uint(fields[1], 32)
    class_tag = _read_uint(fields[2], 32)
    try:
        class_name = CLASS_BY_TAG[class_tag]
    except KeyError as error:
        raise ScbError("SCB_UNION_INVALID") from error
    kind = _read_uint(fields[3], 32)
    if kind > 65_535:
        raise ScbError("SCB_UNION_INVALID")
    target = _read_fixed(fields[4])
    field_tag = _read_optional_u32(fields[5])
    value_type, _requirement = _descriptor(class_name, kind, field_tag)
    _decode_payload(class_name, class_tag, kind, value_type, fields[6])
    return {
        "ordinal": ordinal,
        "class": class_name,
        "kind": kind,
        "target": target,
        "field_tag": field_tag,
        "precondition_ordinal": _read_uint(fields[7], 32),
    }


def _decode_payload(
    class_name: str, class_tag: int, kind: int, value_type: str, data: bytes
) -> None:
    tag, payload = _read_union(data)
    if tag != class_tag:
        raise ScbError("SCB_UNION_INVALID")
    if value_type == "Unit":
        if payload:
            raise ScbError("SCB_UNION_INVALID")
        return
    if class_name in {"CreateEntity", "ReplaceEntityVersion"}:
        body_tag, body = _read_union(payload)
        if body_tag != kind:
            raise ScbError("SCB_UNION_INVALID")
        _decode_exact(value_type, body)
        return
    wire_type = {
        "InsertOrderedChild": "OrderedInsert",
        "RemoveOrderedChild": "OrderedRemove",
        "MoveOrderedChild": "OrderedMove",
    }.get(class_name, value_type)
    _decode_exact(wire_type, payload)


def _decode_precondition(record: bytes) -> dict[str, object]:
    fields = _read_record(record, [1, 2, 3])
    requirement_tag = _read_uint(fields[2], 32)
    try:
        requirement = REQUIREMENT_BY_TAG[requirement_tag]
    except KeyError as error:
        raise ScbError("SCB_UNION_INVALID") from error
    payload_tag, payload = _read_union(fields[3])
    if payload_tag != requirement_tag:
        raise ScbError("SCB_UNION_INVALID")
    payload_fields = _read_record(
        payload,
        {
            "ExpectedIdentityAbsent": [1],
            "ExactEntityVersion": [1, 2],
            "ExactContainerVersion": [1, 2, 3],
        }[requirement],
    )
    result: dict[str, object] = {
        "ordinal": _read_uint(fields[1], 32),
        "requirement": requirement,
        "target": _read_fixed(payload_fields[1]),
    }
    if requirement == "ExactContainerVersion":
        result["field_tag"] = _read_uint(payload_fields[3], 32)
    return result


def _validate_precondition_target(
    operation: Mapping[str, object], precondition: Mapping[str, object]
) -> None:
    if precondition["target"] != operation["target"]:
        raise CandidateOracleError("MUTATION_CANDIDATE_PRECONDITION_MISMATCH")
    if precondition["requirement"] == "ExactContainerVersion" and precondition.get(
        "field_tag"
    ) != operation["field_tag"]:
        raise CandidateOracleError("MUTATION_CANDIDATE_PRECONDITION_MISMATCH")


def _decode_expiry(data: bytes) -> None:
    fields = _read_record(data, [1, 2])
    if _read_uint(fields[1], 16) != 1 or _read_uint(fields[2], 64) == 0:
        raise CandidateOracleError("MUTATION_CANDIDATE_EXPIRY_INVALID")


def _read_record(data: bytes, expected_tags: Sequence[int]) -> dict[int, bytes]:
    cursor = Cursor(data)
    count = decode_uvar_width(cursor, 64)
    if count < len(expected_tags):
        raise ScbError("SCB_FIELD_MISSING")
    if count > len(expected_tags):
        raise ScbError("SCB_FIELD_UNKNOWN")
    result: dict[int, bytes] = {}
    prior: int | None = None
    for expected in expected_tags:
        tag = decode_uvar_width(cursor, 32)
        if prior is not None:
            if tag == prior:
                raise ScbError("SCB_FIELD_DUPLICATE")
            if tag < prior:
                raise ScbError("SCB_FIELD_ORDER")
        prior = tag
        if tag != expected:
            if tag in expected_tags:
                raise ScbError("SCB_FIELD_ORDER")
            raise ScbError("SCB_FIELD_UNKNOWN")
        result[tag] = read_sized(cursor)
    cursor.finish()
    return result


def _read_list(data: bytes) -> list[bytes]:
    cursor = Cursor(data)
    count = decode_uvar_width(cursor, 64)
    if count > 1_000_000:
        raise ScbError("SCB_RESOURCE_LIMIT")
    result = [read_sized(cursor) for _ in range(count)]
    cursor.finish()
    return result


def _read_union(data: bytes) -> tuple[int, bytes]:
    cursor = Cursor(data)
    tag = decode_uvar_width(cursor, 32)
    payload = read_sized(cursor)
    cursor.finish()
    return tag, payload


def _read_uint(data: bytes, width: int) -> int:
    cursor = Cursor(data)
    value = decode_uvar_width(cursor, width)
    cursor.finish()
    return value


def _read_fixed(data: bytes) -> bytes:
    if len(data) != 32:
        raise ScbError("SCB_LENGTH_OVERFLOW")
    return data


def _read_optional_u32(data: bytes) -> int | None:
    tag, payload = _read_union(data)
    if tag == 0:
        if payload:
            raise ScbError("SCB_UNION_INVALID")
        return None
    if tag == 1:
        return _read_uint(payload, 32)
    raise ScbError("SCB_UNION_INVALID")


def _decode_exact(declared_type: str, data: bytes) -> None:
    cursor = Cursor(data)
    budget = DecodeBudget()
    _decode_type(declared_type, cursor, 0, budget)
    cursor.finish()


def _digest(domain: bytes, preimage: bytes) -> bytes:
    hasher = blake3.blake3()
    hasher.update(domain)
    hasher.update(preimage)
    return hasher.digest()


def _exact_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("candidate integer must be exact JSON integer")
    return value
