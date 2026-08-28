"""Independent strict S20-390 transaction and receipt conformance oracle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import blake3

from .candidate import (
    CANDIDATE_DOMAIN,
    CANDIDATE_MAGIC,
    CandidateOracleError,
    import_candidate,
)
from .candidate_result import decode_candidate_result
from .codec import Cursor, decode_uvar, read_sized
from .errors import ScbError


TRANSACTION_MAGIC = b"SLEYTXN1"
TRANSACTION_DOMAIN = b"sley2.transaction.v1"
RECEIPT_MAGIC = b"SLEYRCP1"
RECEIPT_DOMAIN = b"sley2.transaction-receipt.v1"
CANDIDATE_RESULT_MAGIC = b"SLEYCRS1"
CANDIDATE_RESULT_DOMAIN = b"sley2.candidate-result.v1"
SCB_MAGIC = b"SLEYSCB1"
STATE_ROOT_DOMAIN = b"sley2.state-root.v1"
POLICY_ROOT_DOMAIN = b"sley2.policy-root.v1"
MAX_STORED_BYTES = 67_108_864
MAX_ITEMS = 65_535


class TransactionOracleError(Exception):
    """Stable semantic error from the independent transaction oracle."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> None:
    raise TransactionOracleError(code)


def _complete_uvar(payload: bytes, width: int = 64) -> int:
    cursor = Cursor(payload)
    value = decode_uvar(cursor, width)
    cursor.finish()
    return value


def _fixed(payload: bytes) -> bytes:
    if len(payload) != 32:
        raise ScbError("SCB_FIXED_LENGTH")
    return payload


def _record(payload: bytes, expected_fields: int) -> list[bytes]:
    cursor = Cursor(payload)
    count = decode_uvar(cursor)
    if count < expected_fields:
        raise ScbError("SCB_FIELD_MISSING")
    if count > expected_fields:
        raise ScbError("SCB_FIELD_UNKNOWN")
    fields: list[bytes] = []
    for expected_tag in range(1, expected_fields + 1):
        tag = decode_uvar(cursor, 32)
        if tag < expected_tag:
            raise ScbError("SCB_FIELD_DUPLICATE")
        if tag > expected_tag:
            raise ScbError("SCB_FIELD_MISSING")
        fields.append(read_sized(cursor, MAX_STORED_BYTES))
    cursor.finish()
    return fields


def _list(payload: bytes, maximum: int = MAX_ITEMS) -> list[bytes]:
    cursor = Cursor(payload)
    count = decode_uvar(cursor)
    if count > maximum:
        raise ScbError("SCB_RESOURCE_LIMIT")
    values = [read_sized(cursor, MAX_STORED_BYTES) for _ in range(count)]
    cursor.finish()
    return values


def _bytes(payload: bytes) -> bytes:
    cursor = Cursor(payload)
    value = read_sized(cursor, MAX_STORED_BYTES)
    cursor.finish()
    return value


def _option(payload: bytes, decoder) -> object | None:
    cursor = Cursor(payload)
    tag = decode_uvar(cursor, 32)
    value = read_sized(cursor, MAX_STORED_BYTES)
    cursor.finish()
    if tag == 0:
        if value:
            raise ScbError("SCB_UNION_INVALID")
        return None
    if tag == 1:
        return decoder(value)
    raise ScbError("SCB_UNION_INVALID")


def _fixed_list(payload: bytes, maximum: int = MAX_ITEMS) -> list[bytes]:
    return [_fixed(value) for value in _list(payload, maximum)]


def _sorted_unique(values: list[bytes] | list[int], code: str) -> None:
    if any(left >= right for left, right in zip(values, values[1:], strict=False)):
        _fail(code)


def _digest_envelope(data: bytes, magic: bytes, domain: bytes) -> tuple[bytes, bytes]:
    if len(data) > MAX_STORED_BYTES:
        raise ScbError("SCB_RESOURCE_LIMIT")
    if len(data) < 32:
        raise ScbError("SCB_LENGTH_OVERFLOW")
    preimage, trailer = data[:-32], data[-32:]
    cursor = Cursor(preimage)
    if cursor.read(len(magic), "SCB_MAGIC_INVALID") != magic:
        raise ScbError("SCB_MAGIC_INVALID")
    if decode_uvar(cursor) != 1:
        raise ScbError("SCB_VERSION_UNSUPPORTED")
    payload = read_sized(cursor, MAX_STORED_BYTES)
    cursor.finish()
    expected = blake3.blake3(domain + preimage).digest()
    if trailer != expected:
        raise ScbError("SCB_DIGEST_MISMATCH")
    return payload, expected


def _scb_envelope(
    data: bytes, contract_tag: int, domain: bytes
) -> tuple[bytes, bytes, bytes]:
    if len(data) > MAX_STORED_BYTES:
        raise ScbError("SCB_RESOURCE_LIMIT")
    if len(data) < 32:
        raise ScbError("SCB_LENGTH_OVERFLOW")
    preimage, trailer = data[:-32], data[-32:]
    cursor = Cursor(preimage)
    if cursor.read(len(SCB_MAGIC), "SCB_MAGIC_INVALID") != SCB_MAGIC:
        raise ScbError("SCB_MAGIC_INVALID")
    if decode_uvar(cursor) != 1:
        raise ScbError("SCB_VERSION_UNSUPPORTED")
    if decode_uvar(cursor, 32) != contract_tag:
        raise ScbError("SCB_CONTRACT_UNKNOWN")
    epoch = _fixed(cursor.read(32))
    payload = read_sized(cursor, MAX_STORED_BYTES)
    cursor.finish()
    expected = blake3.blake3(domain + preimage).digest()
    if trailer != expected:
        raise ScbError("SCB_DIGEST_MISMATCH")
    return payload, epoch, expected


def _decode_fixed_set(payload: bytes) -> list[bytes]:
    values = _fixed_list(payload)
    _sorted_unique(values, "SCB_SET_ORDER")
    return values


def _decode_u32_set(payload: bytes) -> list[int]:
    values = [_complete_uvar(value, 32) for value in _list(payload)]
    _sorted_unique(values, "SCB_SET_ORDER")
    return values


def _decode_fixed_map(payload: bytes, decode_value) -> list[tuple[bytes, object]]:
    cursor = Cursor(payload)
    count = decode_uvar(cursor)
    if count > MAX_ITEMS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    rows: list[tuple[bytes, object]] = []
    for _ in range(count):
        key = _fixed(read_sized(cursor, MAX_STORED_BYTES))
        value = decode_value(read_sized(cursor, MAX_STORED_BYTES))
        rows.append((key, value))
    cursor.finish()
    keys = [key for key, _value in rows]
    _sorted_unique(keys, "SCB_MAP_ORDER")
    return rows


def _decode_state_root(data: bytes) -> dict[str, object]:
    payload, epoch, root = _scb_envelope(data, 160, STATE_ROOT_DOMAIN)
    fields = _record(payload, 9)
    workspace = _fixed(fields[0])
    schema_epoch = _fixed(fields[1])
    if schema_epoch != epoch:
        raise ScbError("SCB_EPOCH_MISMATCH")
    bindings = _decode_fixed_map(fields[2], _fixed)
    entry_points = _decode_fixed_set(fields[3])
    _decode_fixed_set(fields[4])
    _fixed(fields[5])
    _fixed(fields[6])
    policy_root = _fixed(fields[7])
    flags = _decode_u32_set(fields[8])
    if flags:
        _fail("STATE_ROOT_FLAG_UNKNOWN")
    binding_ids = {entity_id for entity_id, _object_id in bindings}
    if any(entry not in binding_ids for entry in entry_points):
        _fail("STATE_ROOT_ENTRY_UNBOUND")
    return {
        "bindings": bindings,
        "policy_root": policy_root,
        "root": root,
        "schema_epoch": schema_epoch,
        "workspace": workspace,
    }


def _decode_grant(payload: bytes) -> None:
    fields = _record(payload, 4)
    _decode_u32_set(fields[0])
    _decode_u32_set(fields[1])
    _decode_fixed_set(fields[2])
    ceilings = _record(fields[3], 6)
    if any(_complete_uvar(value) > 1_000_000_000_000_000 for value in ceilings):
        _fail("POLICY_ROOT_RESOURCE_LIMIT")


def _decode_policy_root(data: bytes) -> dict[str, object]:
    payload, epoch, root = _scb_envelope(data, 370, POLICY_ROOT_DOMAIN)
    fields = _record(payload, 11)
    workspace = _fixed(fields[0])
    schema_epoch = _fixed(fields[1])
    if schema_epoch != epoch:
        raise ScbError("SCB_EPOCH_MISMATCH")
    if _complete_uvar(fields[2], 32) != 1:
        _fail("POLICY_ROOT_VERSION_UNSUPPORTED")
    _option(fields[3], _fixed)
    _decode_fixed_map(fields[4], _decode_grant)
    _decode_fixed_set(fields[5])
    _decode_fixed_set(fields[6])
    _decode_fixed_set(fields[7])
    _option(fields[8], lambda value: _complete_uvar(value))
    if _complete_uvar(fields[9], 32) != 1:
        _fail("POLICY_ROOT_TRANSITION_MODE_INVALID")
    if _decode_u32_set(fields[10]):
        _fail("POLICY_ROOT_FLAG_UNKNOWN")
    return {
        "root": root,
        "schema_epoch": schema_epoch,
        "workspace": workspace,
    }


def _decode_candidate(data: bytes) -> dict[str, object]:
    import_candidate(data)
    payload, candidate_id = _digest_envelope(data, CANDIDATE_MAGIC, CANDIDATE_DOMAIN)
    fields = _record(payload, 13)
    return {
        "base_root": _fixed(fields[3]),
        "base_transaction_id": _fixed(fields[2]),
        "candidate_id": candidate_id,
        "capability_summary": _fixed(fields[7]),
        "policy_root": _fixed(fields[5]),
        "principal": _fixed(fields[6]),
        "profile": _fixed(fields[10]),
        "schema_epoch": _fixed(fields[4]),
        "workspace": _fixed(fields[1]),
    }


def _decode_candidate_result(data: bytes) -> dict[str, object]:
    checked = decode_candidate_result(data)
    payload, result_id = _digest_envelope(
        data, CANDIDATE_RESULT_MAGIC, CANDIDATE_RESULT_DOMAIN
    )
    fields = _record(payload, 13)
    return {
        "candidate_id": _option(fields[2], _fixed),
        "candidate_root": _option(fields[11], _fixed),
        "context": _fixed(fields[4]),
        "decision": _complete_uvar(fields[5], 32),
        "profile": _fixed(fields[3]),
        "result_id": result_id,
        "selected_tests": _decode_fixed_set(fields[10]),
        "verified_id": bytes.fromhex(str(checked["candidate_result_id_hex"])),
    }


def _decode_changed_bindings(payload: bytes, kind: int) -> list[dict[str, object]]:
    bindings = []
    all_ordinals: list[int] = []
    for value in _list(payload):
        fields = _record(value, 4)
        preimage = _option(fields[1], _fixed)
        postimage = _option(fields[2], _fixed)
        ordinals = [_complete_uvar(item, 32) for item in _list(fields[3])]
        _sorted_unique(ordinals, "TXN_CHANGED_BINDING_INVALID")
        if (preimage is None and postimage is None) or preimage == postimage:
            _fail("TXN_CHANGED_BINDING_INVALID")
        if kind == 2 and not ordinals:
            _fail("TXN_CHANGED_BINDING_INVALID")
        if kind == 1 and ordinals:
            _fail("TXN_GENESIS_INVALID")
        all_ordinals.extend(ordinals)
        bindings.append(
            {
                "entity_id": _fixed(fields[0]),
                "ordinals": ordinals,
                "postimage": postimage,
                "preimage": preimage,
            }
        )
    entity_ids = [binding["entity_id"] for binding in bindings]
    _sorted_unique(entity_ids, "TXN_CHANGED_BINDING_INVALID")
    if len(all_ordinals) != len(set(all_ordinals)):
        _fail("TXN_CHANGED_BINDING_INVALID")
    return bindings


def decode_transaction(data: bytes) -> dict[str, object]:
    """Strictly decode one canonical parent-bound transaction."""

    payload, transaction_id = _digest_envelope(
        data, TRANSACTION_MAGIC, TRANSACTION_DOMAIN
    )
    fields = _record(payload, 19)
    if _complete_uvar(fields[0], 32) != 1:
        _fail("TXN_FORMAT_VERSION")
    kind = _complete_uvar(fields[1], 32)
    if kind not in (1, 2):
        _fail("TXN_KIND_INVALID")
    parents = _fixed_list(fields[3])
    parent_roots = _fixed_list(fields[4])
    if len(parents) != len(parent_roots):
        _fail("TXN_PARENT_SHAPE")
    options = [_option(fields[index], _fixed) for index in range(7, 12)]
    capability_summary = _option(fields[14], _fixed)
    changed_bindings = _decode_changed_bindings(fields[13], kind)
    selected_tests = _decode_fixed_set(fields[15])
    test_result_refs = _decode_fixed_set(fields[16])
    tombstones = _decode_fixed_set(fields[17])
    metadata = [_complete_uvar(value, 32) for value in _record(fields[18], 3)]
    if metadata != [1, 1, 1]:
        _fail("TXN_FIELD_SHAPE")
    if selected_tests or test_result_refs:
        _fail("TXN_TEST_EVIDENCE_UNSUPPORTED")
    ordinary_fields = [*options, capability_summary]
    if kind == 1:
        if parents or any(value is not None for value in ordinary_fields):
            _fail("TXN_GENESIS_INVALID")
    elif len(parents) != 1 or any(value is None for value in ordinary_fields):
        _fail("TXN_PARENT_SHAPE")
    return {
        "candidate_id": options[1],
        "candidate_result_id": options[2],
        "capability_summary": capability_summary,
        "changed_bindings": changed_bindings,
        "committed_root": _fixed(fields[12]),
        "context": options[3],
        "durability_profile": metadata[2],
        "kind": kind,
        "parent_roots": parent_roots,
        "parents": parents,
        "policy_root": _fixed(fields[6]),
        "principal": options[0],
        "profile": options[4],
        "schema_epoch": _fixed(fields[5]),
        "selected_tests": selected_tests,
        "tombstones": tombstones,
        "transaction_id": transaction_id,
        "workspace": _fixed(fields[2]),
    }


def _decode_manifest(payload: bytes) -> list[tuple[bytes, int]]:
    entries = []
    for value in _list(payload):
        fields = _record(value, 2)
        length = _complete_uvar(fields[1])
        if length < 32 or length > MAX_STORED_BYTES:
            _fail("TXN_OBJECT_INVENTORY_MISMATCH")
        entries.append((_fixed(fields[0]), length))
    _sorted_unique(
        [object_id for object_id, _length in entries],
        "TXN_OBJECT_INVENTORY_MISMATCH",
    )
    return entries


def decode_transaction_receipt(data: bytes) -> dict[str, object]:
    """Strictly decode and cross-bind one complete persisted receipt."""

    payload, receipt_id = _digest_envelope(data, RECEIPT_MAGIC, RECEIPT_DOMAIN)
    fields = _record(payload, 9)
    if _complete_uvar(fields[0], 32) != 1:
        _fail("TXN_FORMAT_VERSION")
    transaction_id = _fixed(fields[1])
    stored_transaction = _bytes(fields[2])
    stored_candidate = _option(fields[3], _bytes)
    stored_result = _option(fields[4], _bytes)
    stored_state = _bytes(fields[5])
    stored_policy = _bytes(fields[6])
    manifest = _decode_manifest(fields[7])
    durability = _complete_uvar(fields[8], 32)
    if durability != 1:
        _fail("TXN_FIELD_SHAPE")

    transaction = decode_transaction(stored_transaction)
    state = _decode_state_root(stored_state)
    policy = _decode_policy_root(stored_policy)
    if transaction_id != transaction["transaction_id"]:
        _fail("TXN_RECEIPT_BINDING_MISMATCH")
    if (
        transaction["committed_root"] != state["root"]
        or transaction["workspace"] != state["workspace"]
        or transaction["schema_epoch"] != state["schema_epoch"]
        or transaction["policy_root"] != state["policy_root"]
        or transaction["policy_root"] != policy["root"]
        or transaction["workspace"] != policy["workspace"]
        or transaction["durability_profile"] != durability
    ):
        _fail("TXN_RECEIPT_BINDING_MISMATCH")

    if transaction["kind"] == 1:
        if stored_candidate is not None or stored_result is not None:
            _fail("TXN_GENESIS_INVALID")
    else:
        if stored_candidate is None or stored_result is None:
            _fail("TXN_RECEIPT_BINDING_MISMATCH")
        candidate = _decode_candidate(stored_candidate)
        result = _decode_candidate_result(stored_result)
        if result["decision"] != 1:
            _fail("TXN_RESULT_NOT_VALID")
        if (
            result["result_id"] != result["verified_id"]
            or transaction["candidate_id"] != candidate["candidate_id"]
            or transaction["candidate_result_id"] != result["result_id"]
            or transaction["context"] != result["context"]
            or transaction["profile"] != result["profile"]
            or transaction["committed_root"] != result["candidate_root"]
            or transaction["selected_tests"] != result["selected_tests"]
            or result["candidate_id"] != candidate["candidate_id"]
            or candidate["base_transaction_id"] != transaction["parents"][0]
            or candidate["base_root"] != transaction["parent_roots"][0]
            or candidate["workspace"] != transaction["workspace"]
            or candidate["schema_epoch"] != transaction["schema_epoch"]
            or candidate["policy_root"] != transaction["policy_root"]
            or candidate["principal"] != transaction["principal"]
            or candidate["capability_summary"] != transaction["capability_summary"]
            or candidate["profile"] != transaction["profile"]
        ):
            _fail("TXN_RESULT_BINDING_MISMATCH")

    expected_manifest = {
        binding["postimage"]
        for binding in transaction["changed_bindings"]
        if binding["postimage"] is not None
    }
    actual_manifest = {object_id for object_id, _length in manifest}
    if expected_manifest != actual_manifest:
        _fail("TXN_OBJECT_INVENTORY_MISMATCH")
    return {
        "kind": "GENESIS" if transaction["kind"] == 1 else "ORDINARY",
        "manifest_entries": len(manifest),
        "object_manifest": [
            {"object_id_hex": object_id.hex(), "stored_length": length}
            for object_id, length in manifest
        ],
        "receipt_id": receipt_id,
        "transaction_id": transaction_id,
    }


def verify_receipt_object_inventory(
    data: bytes, expected_manifest: list[dict[str, object]]
) -> dict[str, object]:
    """Cross-check authenticated manifest lengths against durable inventory."""

    receipt = decode_transaction_receipt(data)
    if receipt["object_manifest"] != expected_manifest:
        _fail("TXN_OBJECT_INVENTORY_MISMATCH")
    return receipt


def _mutate(data: bytes, operation: str) -> bytes:
    value = bytearray(data)
    if operation == "flip-first-byte":
        value[0] ^= 1
    elif operation == "flip-last-byte":
        value[-1] ^= 1
    elif operation == "append-zero":
        value.append(0)
    elif operation == "truncate-half":
        del value[len(value) // 2 :]
    else:
        raise ValueError(f"unknown transaction mutation: {operation}")
    return bytes(value)


def check_transaction_receipt(
    accepted_path: Path, rejected_path: Path
) -> dict[str, object]:
    """Check the frozen corpus with the independent implementation."""

    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    rejected = json.loads(rejected_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    expected_contract = "sley2-transaction-receipt-v1"
    expected_claim = (
        "restricted-executable-program-operation-free-test-free-s20-390-conformance"
    )
    for label, corpus in (("accepted", accepted), ("rejected", rejected)):
        if corpus.get("contract") != expected_contract:
            problems.append(f"{label}: contract drift")
        if corpus.get("claim") != expected_claim:
            problems.append(f"{label}: claim drift")

    seeds: dict[str, dict[str, bytes]] = {}
    seen_kinds: list[str] = []
    for vector in accepted.get("vectors", []):
        vector_id = str(vector["id"])
        try:
            transaction_bytes = bytes.fromhex(str(vector["transaction_hex"]))
            receipt_bytes = bytes.fromhex(str(vector["receipt_hex"]))
            transaction = decode_transaction(transaction_bytes)
            receipt = verify_receipt_object_inventory(
                receipt_bytes, vector["object_manifest"]
            )
        except (CandidateOracleError, ScbError, TransactionOracleError, ValueError) as error:
            problems.append(f"{vector_id}: accepted vector rejected: {error}")
            continue
        seeds[vector_id] = {
            "receipt": receipt_bytes,
            "transaction": transaction_bytes,
        }
        seen_kinds.append(str(vector["kind"]))
        if transaction["transaction_id"].hex() != vector["expected_transaction_id_hex"]:
            problems.append(f"{vector_id}: transaction digest drift")
        if receipt["receipt_id"].hex() != vector["expected_receipt_id_hex"]:
            problems.append(f"{vector_id}: receipt digest drift")
        if receipt["kind"] != vector["kind"]:
            problems.append(f"{vector_id}: kind drift")
        if hashlib.sha256(transaction_bytes).hexdigest() != vector["transaction_sha256"]:
            problems.append(f"{vector_id}: transaction SHA-256 drift")
        if hashlib.sha256(receipt_bytes).hexdigest() != vector["receipt_sha256"]:
            problems.append(f"{vector_id}: receipt SHA-256 drift")
    if seen_kinds != ["GENESIS", "ORDINARY"]:
        problems.append(f"accepted kind sequence drift: {seen_kinds}")

    for vector in rejected.get("mutations", []):
        vector_id = str(vector["id"])
        try:
            operation = str(vector["operation"])
            if operation == "provided-inventory-mismatch":
                verify_receipt_object_inventory(
                    bytes.fromhex(str(vector["input_hex"])),
                    vector["expected_object_manifest"],
                )
            else:
                source = seeds[str(vector["seed"])][str(vector["target"])]
                mutated = _mutate(source, operation)
                if vector["target"] == "transaction":
                    decode_transaction(mutated)
                else:
                    decode_transaction_receipt(mutated)
        except (CandidateOracleError, ScbError, TransactionOracleError) as error:
            if error.code != vector["expected_code"]:
                problems.append(
                    f"{vector_id}: expected {vector['expected_code']}, got {error.code}"
                )
        except (KeyError, ValueError) as error:
            problems.append(f"{vector_id}: unsupported fixture: {error}")
        else:
            problems.append(f"{vector_id}: rejected mutation was accepted")

    return {
        "accepted_vectors": len(accepted.get("vectors", [])),
        "claim": expected_claim,
        "contract": "s20-390-independent-transaction-receipt-oracle-v1",
        "problems": problems,
        "rejected_vectors": len(rejected.get("mutations", [])),
        "result": "FAIL" if problems else "PASS",
    }
