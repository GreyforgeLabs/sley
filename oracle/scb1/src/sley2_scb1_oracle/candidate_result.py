"""Independent strict S20-360 candidate-result conformance oracle."""

from __future__ import annotations

import json
import re
from pathlib import Path

import blake3

from .codec import Cursor, decode_uvar, read_sized
from .errors import ScbError


MAGIC = b"SLEYCRS1"
DOMAIN = b"sley2.candidate-result.v1"
FULL_PROFILE_ID = bytes.fromhex(
    "7d8ffff97a3fdafc49b4329d47b0b12f04759c3124274024016483a263265d54"
)
MAX_STORED_BYTES = 67_108_864
MAX_DIAGNOSTICS = 1_024
MAX_ENTITY_SET = 65_535
SOURCE_SYMBOL = re.compile(rb"[A-Z][A-Z0-9_]{0,95}\Z")
FIXED_PHASE = {
    2: 1,
    3: 2,
    4: 3,
    5: 3,
    6: 4,
    7: 5,
    8: 5,
    9: 6,
    10: 7,
    11: 8,
    12: 9,
    13: 10,
    15: 11,
}
DECISION_TAG_BY_NAME = {
    "VALID": 1,
    "INVALID_ENCODING": 2,
    "INVALID_SCHEMA": 3,
    "STALE_ROOT": 4,
    "STALE_ENTITY": 5,
    "INVALID_IDENTITY": 6,
    "INVALID_GRAPH": 7,
    "UNRESOLVED_REFERENCE": 8,
    "TYPE_ERROR": 9,
    "CONTROL_FLOW_ERROR": 10,
    "EFFECT_ERROR": 11,
    "CAPABILITY_DENIED": 12,
    "CONTRACT_ERROR": 13,
    "RESOURCE_LIMIT": 14,
    "TEST_PLAN_ERROR": 15,
    "INTERNAL_ERROR": 16,
}


def _fail(code: str) -> None:
    raise ScbError(code)


def _complete_uvar(payload: bytes, width: int) -> int:
    cursor = Cursor(payload)
    value = decode_uvar(cursor, width)
    cursor.finish()
    return value


def _fixed(payload: bytes, length: int = 32) -> bytes:
    if len(payload) != length:
        _fail("SCB_FIXED_LENGTH")
    return payload


def _record(payload: bytes, expected_fields: int) -> list[bytes]:
    cursor = Cursor(payload)
    count = decode_uvar(cursor)
    if count < expected_fields:
        _fail("SCB_FIELD_MISSING")
    if count > expected_fields:
        _fail("SCB_FIELD_UNKNOWN")
    fields: list[bytes] = []
    for expected_tag in range(1, expected_fields + 1):
        tag = decode_uvar(cursor, 32)
        if tag < expected_tag:
            _fail("SCB_FIELD_DUPLICATE")
        if tag > expected_tag:
            _fail("SCB_FIELD_ORDER" if tag <= expected_fields else "SCB_FIELD_UNKNOWN")
        fields.append(read_sized(cursor))
    cursor.finish()
    return fields


def _list(payload: bytes, maximum: int) -> list[bytes]:
    cursor = Cursor(payload)
    count = decode_uvar(cursor)
    if count > maximum:
        _fail("SCB_RESOURCE_LIMIT")
    values = [read_sized(cursor) for _ in range(count)]
    cursor.finish()
    return values


def _option(payload: bytes, decode_value) -> object | None:
    cursor = Cursor(payload)
    tag = decode_uvar(cursor, 32)
    value = read_sized(cursor)
    cursor.finish()
    if tag == 0:
        if value:
            _fail("SCB_UNION_INVALID")
        return None
    if tag == 1:
        return decode_value(value)
    _fail("SCB_UNION_INVALID")


def _entity_set(payload: bytes) -> list[bytes]:
    values = [_fixed(value) for value in _list(payload, MAX_ENTITY_SET)]
    if any(left >= right for left, right in zip(values, values[1:], strict=False)):
        _fail("CANDIDATE_RESULT_SET_INVALID")
    return values


def _phase(payload: bytes) -> dict[str, object]:
    fields = _record(payload, 4)
    phase_tag = _complete_uvar(fields[0], 32)
    outcome = _complete_uvar(fields[1], 32)
    if outcome not in (1, 2, 3):
        _fail("SCB_UNION_INVALID")
    evidence = _option(fields[2], _fixed)
    terminal = _option(fields[3], lambda value: _complete_uvar(value, 32))
    if terminal is not None and not 1 <= terminal <= 16:
        _fail("SCB_UNION_INVALID")
    return {
        "phase_tag": phase_tag,
        "outcome": outcome,
        "evidence": evidence,
        "terminal": terminal,
    }


def _diagnostic(payload: bytes) -> dict[str, object]:
    fields = _record(payload, 6)
    source_cursor = Cursor(fields[3])
    source = read_sized(source_cursor, 96)
    source_cursor.finish()
    try:
        source.decode("ascii")
    except UnicodeDecodeError:
        _fail("CANDIDATE_RESULT_DIAGNOSTIC_INVALID")
    if SOURCE_SYMBOL.fullmatch(source) is None:
        _fail("CANDIDATE_RESULT_DIAGNOSTIC_INVALID")
    retryability = _complete_uvar(fields[4], 32)
    if retryability not in (1, 2, 3, 4, 5):
        _fail("SCB_UNION_INVALID")
    return {
        "phase_tag": _complete_uvar(fields[0], 32),
        "result_code": _complete_uvar(fields[1], 32),
        "source_numeric": _option(
            fields[2], lambda value: _complete_uvar(value, 32)
        ),
        "source": source.decode("ascii"),
        "retryability": retryability,
        "causal": _option(fields[5], _fixed),
    }


def decode_candidate_result(data: bytes) -> dict[str, object]:
    """Strictly decode and independently validate one stored result."""

    if len(data) > MAX_STORED_BYTES:
        _fail("SCB_RESOURCE_LIMIT")
    if len(data) < 32:
        _fail("SCB_LENGTH_OVERFLOW")
    preimage, trailer = data[:-32], data[-32:]
    cursor = Cursor(preimage)
    if cursor.read(len(MAGIC), "SCB_MAGIC_INVALID") != MAGIC:
        _fail("SCB_MAGIC_INVALID")
    if decode_uvar(cursor) != 1:
        _fail("SCB_VERSION_UNSUPPORTED")
    payload = read_sized(cursor, MAX_STORED_BYTES)
    cursor.finish()
    expected = blake3.blake3(DOMAIN + preimage).digest()
    if trailer != expected:
        _fail("SCB_DIGEST_MISMATCH")

    fields = _record(payload, 13)
    if _complete_uvar(fields[0], 32) != 1:
        _fail("CANDIDATE_RESULT_FORMAT_VERSION")
    _fixed(fields[1])
    candidate_id = _option(fields[2], _fixed)
    if _fixed(fields[3]) != FULL_PROFILE_ID:
        _fail("CANDIDATE_RESULT_PROFILE_INVALID")
    _fixed(fields[4])
    decision = _complete_uvar(fields[5], 32)
    if not 1 <= decision <= 16:
        _fail("SCB_UNION_INVALID")

    phase_payloads = _list(fields[6], 14)
    if len(phase_payloads) != 14:
        _fail("CANDIDATE_RESULT_PHASE_SHAPE")
    phases = [_phase(value) for value in phase_payloads]
    failed: int | None = None
    for expected_tag, phase in enumerate(phases, start=1):
        if phase["phase_tag"] != expected_tag:
            _fail("CANDIDATE_RESULT_PHASE_SHAPE")
        outcome = phase["outcome"]
        if outcome == 1:
            if failed is not None or phase["evidence"] is None or phase["terminal"] is not None:
                _fail("CANDIDATE_RESULT_PHASE_SHAPE")
        elif outcome == 2:
            if failed is not None or phase["evidence"] is None or phase["terminal"] != decision:
                _fail("CANDIDATE_RESULT_PHASE_SHAPE")
            failed = expected_tag
        elif failed is None or phase["evidence"] is not None or phase["terminal"] is not None:
            _fail("CANDIDATE_RESULT_PHASE_SHAPE")

    if decision == 1:
        if failed is not None:
            _fail("CANDIDATE_RESULT_PHASE_SHAPE")
    elif failed is None:
        _fail("CANDIDATE_RESULT_PHASE_SHAPE")
    expected_phase = FIXED_PHASE.get(decision)
    if expected_phase is not None and failed != expected_phase:
        _fail("CANDIDATE_RESULT_DECISION_PHASE_MISMATCH")
    if decision in (14, 16) and (failed is None or not 2 <= failed <= 14):
        _fail("CANDIDATE_RESULT_DECISION_PHASE_MISMATCH")

    diagnostic_payloads = _list(fields[7], MAX_DIAGNOSTICS)
    if any(
        left >= right
        for left, right in zip(diagnostic_payloads, diagnostic_payloads[1:], strict=False)
    ):
        _fail("CANDIDATE_RESULT_DIAGNOSTIC_INVALID")
    diagnostics = [_diagnostic(value) for value in diagnostic_payloads]
    expected_result_code = None if decision == 1 else 36_000 + decision - 2
    if decision == 1:
        if diagnostics:
            _fail("CANDIDATE_RESULT_DIAGNOSTIC_INVALID")
    elif not diagnostics:
        _fail("CANDIDATE_RESULT_DIAGNOSTIC_INVALID")
    for diagnostic in diagnostics:
        if (
            diagnostic["phase_tag"] != failed
            or diagnostic["result_code"] != expected_result_code
        ):
            _fail("CANDIDATE_RESULT_DIAGNOSTIC_INVALID")

    affected = _entity_set(fields[8])
    required = _entity_set(fields[9])
    selected = _entity_set(fields[10])
    candidate_root = _option(fields[11], _fixed)
    _complete_uvar(fields[12], 64)
    if (candidate_id is None) != (decision == 2):
        _fail("CANDIDATE_RESULT_CANDIDATE_ID_SHAPE")
    if (candidate_root is not None) != (decision == 1):
        _fail("CANDIDATE_RESULT_ROOT_SHAPE")
    if decision == 2 and (affected or required or selected):
        _fail("CANDIDATE_RESULT_SET_INVALID")
    return {
        "candidate_result_id_hex": expected.hex(),
        "decision_tag": decision,
        "failed_phase": failed,
        "phase_count": len(phases),
    }


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
        raise ValueError(f"unknown candidate-result mutation: {operation}")
    return bytes(value)


def check_candidate_result(
    accepted_path: Path, rejected_path: Path
) -> dict[str, object]:
    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    rejected = json.loads(rejected_path.read_text(encoding="utf-8"))
    problems: list[str] = []
    valid_seed: bytes | None = None
    seen_decisions: set[str] = set()
    for vector in accepted.get("vectors", []):
        decision_name = vector.get("decision")
        expected_tag = DECISION_TAG_BY_NAME.get(decision_name)
        if expected_tag is None:
            problems.append(f"{vector['id']}: unknown fixture decision {decision_name!r}")
        elif decision_name in seen_decisions:
            problems.append(f"{vector['id']}: duplicate fixture decision {decision_name}")
        else:
            seen_decisions.add(decision_name)
        try:
            stored = bytes.fromhex(vector["stored_hex"])
            result = decode_candidate_result(stored)
        except (ScbError, ValueError) as error:
            problems.append(f"{vector['id']}: accepted vector rejected: {error}")
            continue
        if decision_name == "VALID":
            valid_seed = stored
        if result["candidate_result_id_hex"] != vector["expected_candidate_result_id_hex"]:
            problems.append(f"{vector['id']}: candidate-result digest drift")
        if result["phase_count"] != vector["phase_count"]:
            problems.append(f"{vector['id']}: phase-count drift")
        if expected_tag is not None and result["decision_tag"] != expected_tag:
            problems.append(f"{vector['id']}: decision-tag drift")
        expected_failed = vector.get("failed_phase") or None
        if result["failed_phase"] != expected_failed:
            problems.append(f"{vector['id']}: failed-phase drift")

    missing_decisions = sorted(set(DECISION_TAG_BY_NAME) - seen_decisions)
    if missing_decisions:
        problems.append(f"missing fixture decisions: {','.join(missing_decisions)}")

    if valid_seed is None:
        problems.append("no VALID candidate-result seed")
    else:
        for vector in rejected.get("mutations", []):
            mutated = _mutate(valid_seed, vector["operation"])
            try:
                decode_candidate_result(mutated)
            except ScbError as error:
                if error.code != vector["expected_code"]:
                    problems.append(
                        f"{vector['id']}: expected {vector['expected_code']}, got {error.code}"
                    )
            else:
                problems.append(f"{vector['id']}: rejected mutation was accepted")
    return {
        "accepted_vectors": len(accepted.get("vectors", [])),
        "contract": "s20-360-independent-candidate-result-oracle-v1",
        "problems": problems,
        "rejected_vectors": len(rejected.get("mutations", [])),
        "result": "FAIL" if problems else "PASS",
    }
