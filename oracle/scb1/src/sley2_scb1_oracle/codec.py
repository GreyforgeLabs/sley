"""Independent schema-directed SCB1 encoder and strict fixture decoder."""

from __future__ import annotations

import math
import struct
from collections.abc import Iterable

import blake3
import unicodedata2

from .errors import ScbError


MAGIC = b"SLEYSCB1"
FORMAT_VERSION = 1
EPOCH_ID = bytes(31) + b"\x01"
OBJECT_DOMAIN = b"sley2.object.v1"
MAX_STORED_BYTES = 67_108_864
MAX_VALUE_BYTES = 16_777_216
MAX_DEPTH = 64
MAX_RECORD_FIELDS = 65_535
MAX_ELEMENTS = 1_000_000


class Cursor:
    """A bounded byte cursor that never returns partial reads."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def read(self, length: int, code: str = "SCB_LENGTH_OVERFLOW") -> bytes:
        if length < 0 or length > self.remaining:
            raise ScbError(code)
        start = self.position
        self.position += length
        return self.data[start : self.position]

    def finish(self, code: str = "SCB_TRAILING_BYTES") -> None:
        if self.remaining:
            raise ScbError(code)


def encode_uvar(value: int) -> bytes:
    if value < 0:
        raise ValueError("uvar input must be nonnegative")
    encoded = bytearray()
    while True:
        group = value & 0x7F
        value >>= 7
        encoded.append(group | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def decode_uvar(cursor: Cursor, width: int = 64) -> int:
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


def encode_sized(value: bytes) -> bytes:
    return encode_uvar(len(value)) + value


def read_sized(cursor: Cursor, maximum: int = MAX_VALUE_BYTES) -> bytes:
    length = decode_uvar(cursor)
    if length > maximum or length > cursor.remaining:
        raise ScbError("SCB_LENGTH_OVERFLOW")
    return cursor.read(length)


def encode_record(fields: Iterable[tuple[int, bytes]]) -> bytes:
    ordered = list(fields)
    return encode_uvar(len(ordered)) + b"".join(
        encode_uvar(tag) + encode_sized(value) for tag, value in ordered
    )


def encode_accepted_vector(vector: dict[str, object]) -> bytes:
    kind = vector["kind"]
    value = vector.get("value")
    if kind == "uvar":
        return encode_uvar(int(value))
    if kind == "sint64":
        number = int(value)
        return encode_uvar((number << 1) ^ (number >> 63))
    if kind == "bool":
        return b"\x01" if value is True else b"\x00"
    if kind in {"bytes_utf8_fixture", "text", "normalized_label"}:
        text = str(value)
        if kind == "normalized_label" and unicodedata2.normalize("NFC", text) != text:
            raise ValueError("accepted label is not Unicode 16.0.0 NFC")
        return encode_sized(text.encode("utf-8"))
    if kind == "raw_hex":
        return bytes.fromhex(str(value))
    if kind == "list_uvar":
        items = [encode_uvar(int(item)) for item in value]
        return encode_uvar(len(items)) + b"".join(encode_sized(item) for item in items)
    if kind == "record_bool_uvar":
        return encode_record(((1, b"\x01"), (3, encode_uvar(int(value["3"])))))
    if kind == "map_uvar_text":
        entries = [
            (encode_uvar(int(key)), encode_sized(str(text).encode("utf-8")))
            for key, text in value
        ]
        return encode_uvar(len(entries)) + b"".join(
            encode_sized(key) + encode_sized(item) for key, item in entries
        )
    if kind == "option_uvar":
        return (
            b"\x00\x00"
            if value is None
            else b"\x01" + encode_sized(encode_uvar(int(value)))
        )
    if kind == "union_bool":
        return encode_uvar(int(vector["tag"])) + encode_sized(
            b"\x01" if value is True else b"\x00"
        )
    if kind == "standalone_fixture_object":
        return encode_standalone_fixture(vector)
    raise ValueError(f"unsupported accepted fixture kind: {kind}")


def encode_standalone_fixture(vector: dict[str, object]) -> bytes:
    domain = str(vector["contract_domain"]).encode("ascii")
    epoch = bytes.fromhex(str(vector["schema_epoch_id"]))
    payload = bytes.fromhex(str(vector["payload_hex"]))
    preimage = (
        MAGIC
        + encode_uvar(FORMAT_VERSION)
        + encode_uvar(int(vector["contract_tag"]))
        + epoch
        + encode_sized(payload)
    )
    digest = blake3.blake3(domain + preimage).digest()
    if preimage.hex() != vector["preimage_hex"]:
        raise ValueError("independently constructed preimage differs from fixture")
    if digest.hex() != vector["expected_digest_hex"]:
        raise ValueError("independently computed digest differs from fixture")
    if digest.hex() != vector["expected_object_id"]:
        raise ValueError("independently computed ObjectId differs from fixture")
    return preimage + digest


def _decode_bool(cursor: Cursor) -> bool:
    byte = cursor.read(1)[0]
    if byte not in (0, 1):
        raise ScbError("SCB_BOOL_INVALID")
    return bool(byte)


def _decode_text(cursor: Cursor, normalized: bool = False) -> str:
    encoded = read_sized(cursor)
    try:
        value = encoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ScbError("SCB_UTF8_INVALID") from error
    if normalized and unicodedata2.normalize("NFC", value) != value:
        raise ScbError("SCB_LABEL_NOT_NFC")
    return value


def _decode_float(cursor: Cursor, width: int) -> float:
    encoded = cursor.read(width // 8)
    bits = int.from_bytes(encoded, "big")
    if width == 32:
        sign_mask, exponent_mask, fraction_mask = 0x80000000, 0x7F800000, 0x007FFFFF
        canonical_nan = 0x7FC00000
        value = struct.unpack(">f", encoded)[0]
    else:
        sign_mask = 0x8000000000000000
        exponent_mask = 0x7FF0000000000000
        fraction_mask = 0x000FFFFFFFFFFFFF
        canonical_nan = 0x7FF8000000000000
        value = struct.unpack(">d", encoded)[0]
    is_nan = bits & exponent_mask == exponent_mask and bits & fraction_mask != 0
    if bits == sign_mask or (is_nan and bits != canonical_nan):
        raise ScbError("SCB_FLOAT_NON_CANONICAL")
    if math.isnan(value) and bits != canonical_nan:
        raise ScbError("SCB_FLOAT_NON_CANONICAL")
    return value


def _decode_record_order(cursor: Cursor) -> None:
    count = decode_uvar(cursor)
    if count > MAX_RECORD_FIELDS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    prior = -1
    for _ in range(count):
        tag = decode_uvar(cursor, 32)
        if tag == prior:
            raise ScbError("SCB_FIELD_DUPLICATE")
        if tag < prior:
            raise ScbError("SCB_FIELD_ORDER")
        prior = tag
        read_sized(cursor)


def _decode_empty_object(payload: bytes) -> None:
    cursor = Cursor(payload)
    count = decode_uvar(cursor)
    if count:
        raise ScbError("SCB_FIELD_UNKNOWN")
    cursor.finish()


def _decode_required_bool(payload: bytes) -> None:
    cursor = Cursor(payload)
    count = decode_uvar(cursor)
    if count == 0:
        raise ScbError("SCB_FIELD_MISSING")
    prior = -1
    found = False
    for _ in range(count):
        tag = decode_uvar(cursor, 32)
        if tag == prior:
            raise ScbError("SCB_FIELD_DUPLICATE")
        if tag < prior:
            raise ScbError("SCB_FIELD_ORDER")
        prior = tag
        field = Cursor(read_sized(cursor))
        if tag != 1:
            raise ScbError("SCB_FIELD_UNKNOWN")
        _decode_bool(field)
        field.finish()
        found = True
    if not found:
        raise ScbError("SCB_FIELD_MISSING")
    cursor.finish()


def decode_standalone(data: bytes) -> None:
    if len(data) > MAX_STORED_BYTES:
        raise ScbError("SCB_RESOURCE_LIMIT")
    cursor = Cursor(data)
    if cursor.read(len(MAGIC), "SCB_MAGIC_INVALID") != MAGIC:
        raise ScbError("SCB_MAGIC_INVALID")
    if decode_uvar(cursor) != FORMAT_VERSION:
        raise ScbError("SCB_VERSION_UNSUPPORTED")
    contract_tag = decode_uvar(cursor, 32)
    if contract_tag not in (1, 2):
        raise ScbError("SCB_CONTRACT_UNKNOWN")
    if cursor.read(32) != EPOCH_ID:
        raise ScbError("SCB_EPOCH_MISMATCH")
    payload = read_sized(cursor)
    preimage_end = cursor.position
    digest = cursor.read(32)
    cursor.finish()
    preimage = data[:preimage_end]
    if blake3.blake3(OBJECT_DOMAIN + preimage).digest() != digest:
        raise ScbError("SCB_DIGEST_MISMATCH")
    if contract_tag == 1:
        _decode_empty_object(payload)
    else:
        _decode_required_bool(payload)


def _decode_map_u8_u8(cursor: Cursor) -> None:
    count = decode_uvar(cursor)
    if count > MAX_ELEMENTS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    prior: bytes | None = None
    for _ in range(count):
        key = read_sized(cursor)
        key_cursor = Cursor(key)
        decode_uvar(key_cursor, 8)
        key_cursor.finish()
        if prior is not None:
            if key == prior:
                raise ScbError("SCB_MAP_DUPLICATE")
            if key < prior:
                raise ScbError("SCB_MAP_ORDER")
        prior = key
        value_cursor = Cursor(read_sized(cursor))
        decode_uvar(value_cursor, 8)
        value_cursor.finish()


def _decode_extensions(cursor: Cursor) -> None:
    count = decode_uvar(cursor)
    if count > MAX_ELEMENTS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    prior: bytes | None = None
    for _ in range(count):
        encoded = read_sized(cursor)
        if prior is not None:
            if encoded == prior:
                raise ScbError("SCB_MAP_DUPLICATE")
            if encoded < prior:
                raise ScbError("SCB_MAP_ORDER")
        prior = encoded
        extension = Cursor(encoded)
        if decode_uvar(extension) != 4:
            raise ScbError("SCB_FIELD_MISSING")
        values: list[bytes] = []
        for expected_tag in (1, 2, 3, 4):
            if decode_uvar(extension, 32) != expected_tag:
                raise ScbError("SCB_FIELD_ORDER")
            values.append(read_sized(extension))
        extension.finish()
        if len(values[0]) != 16:
            raise ScbError("SCB_LENGTH_OVERFLOW")
        type_tag = Cursor(values[1])
        decode_uvar(type_tag, 32)
        type_tag.finish()
        version = Cursor(values[2])
        decode_uvar(version, 32)
        version.finish()
        payload = Cursor(values[3])
        read_sized(payload)
        payload.finish()
        raise ScbError("SCB_EXTENSION_UNKNOWN")


def _decode_extensible_record(cursor: Cursor) -> None:
    count = decode_uvar(cursor)
    if count != 1:
        raise ScbError("SCB_FIELD_MISSING" if count == 0 else "SCB_FIELD_UNKNOWN")
    if decode_uvar(cursor, 32) != 1:
        raise ScbError("SCB_FIELD_UNKNOWN")
    extensions = Cursor(read_sized(cursor))
    _decode_extensions(extensions)
    extensions.finish()


def encode_nested_empty_list(depth: int) -> bytes:
    if depth < 1:
        raise ValueError("nested-list depth must be positive")
    encoded = b"\x00"
    for _ in range(depth - 1):
        encoded = b"\x01" + encode_sized(encoded)
    return encoded


def _decode_nested_list(cursor: Cursor, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise ScbError("SCB_RESOURCE_LIMIT")
    count = decode_uvar(cursor)
    if count > MAX_ELEMENTS:
        raise ScbError("SCB_RESOURCE_LIMIT")
    for _ in range(count):
        child = Cursor(read_sized(cursor))
        _decode_nested_list(child, depth + 1)
        child.finish()


def decode_declared_value(declared_type: str, data: bytes) -> None:
    if declared_type in {"FixtureEmptyObject", "FixtureRequiredBool"}:
        decode_standalone(data)
        return
    cursor = Cursor(data)
    if declared_type in {"UInt64", "UInt8"}:
        decode_uvar(cursor, 8 if declared_type == "UInt8" else 64)
    elif declared_type == "Bool":
        _decode_bool(cursor)
    elif declared_type == "Text":
        _decode_text(cursor)
    elif declared_type == "NormalizedLabel":
        _decode_text(cursor, normalized=True)
    elif declared_type == "F32":
        _decode_float(cursor, 32)
    elif declared_type == "F64":
        _decode_float(cursor, 64)
    elif declared_type == "List<UInt64>":
        count = decode_uvar(cursor)
        if count > MAX_ELEMENTS:
            raise ScbError("SCB_RESOURCE_LIMIT")
        for _ in range(count):
            item = Cursor(read_sized(cursor))
            decode_uvar(item)
            item.finish()
    elif declared_type == "FixtureRecord":
        _decode_record_order(cursor)
    elif declared_type == "Option<UInt64>":
        tag = decode_uvar(cursor, 32)
        if tag not in (0, 1):
            raise ScbError("SCB_UNION_INVALID")
        payload = Cursor(read_sized(cursor))
        if tag == 0:
            if payload.remaining:
                raise ScbError("SCB_UNION_INVALID")
        else:
            decode_uvar(payload)
            payload.finish()
    elif declared_type == "Map<UInt8,UInt8>":
        _decode_map_u8_u8(cursor)
    elif declared_type == "FixtureExtensibleRecord":
        _decode_extensible_record(cursor)
    elif declared_type == "NestedListFixture":
        _decode_nested_list(cursor, 1)
    else:
        raise ValueError(f"unsupported rejected fixture type: {declared_type}")
    cursor.finish()


def decode_accepted_vector(vector: dict[str, object], data: bytes) -> None:
    kind = vector["kind"]
    if kind == "standalone_fixture_object":
        decode_standalone(data)
        return
    cursor = Cursor(data)
    if kind in {"uvar", "sint64"}:
        decode_uvar(cursor)
    elif kind == "bool":
        _decode_bool(cursor)
    elif kind == "bytes_utf8_fixture":
        read_sized(cursor)
    elif kind == "text":
        _decode_text(cursor)
    elif kind == "normalized_label":
        _decode_text(cursor, normalized=True)
    elif kind == "raw_hex":
        width = len(data) * 8
        if width not in (32, 64):
            raise ValueError(f"unsupported floating fixture width: {width}")
        _decode_float(cursor, width)
    elif kind == "list_uvar":
        count = decode_uvar(cursor)
        if count > MAX_ELEMENTS:
            raise ScbError("SCB_RESOURCE_LIMIT")
        for _ in range(count):
            item = Cursor(read_sized(cursor))
            decode_uvar(item)
            item.finish()
    elif kind == "record_bool_uvar":
        if decode_uvar(cursor) != 2:
            raise ScbError("SCB_FIELD_MISSING")
        if decode_uvar(cursor, 32) != 1:
            raise ScbError("SCB_FIELD_ORDER")
        first = Cursor(read_sized(cursor))
        _decode_bool(first)
        first.finish()
        if decode_uvar(cursor, 32) != 3:
            raise ScbError("SCB_FIELD_ORDER")
        third = Cursor(read_sized(cursor))
        decode_uvar(third)
        third.finish()
    elif kind == "map_uvar_text":
        count = decode_uvar(cursor)
        prior: bytes | None = None
        for _ in range(count):
            key = read_sized(cursor)
            if prior is not None and key <= prior:
                raise ScbError("SCB_MAP_DUPLICATE" if key == prior else "SCB_MAP_ORDER")
            prior = key
            key_cursor = Cursor(key)
            decode_uvar(key_cursor)
            key_cursor.finish()
            value_cursor = Cursor(read_sized(cursor))
            _decode_text(value_cursor)
            value_cursor.finish()
    elif kind == "option_uvar":
        tag = decode_uvar(cursor, 32)
        payload = Cursor(read_sized(cursor))
        if tag == 0:
            if payload.remaining:
                raise ScbError("SCB_UNION_INVALID")
        elif tag == 1:
            decode_uvar(payload)
            payload.finish()
        else:
            raise ScbError("SCB_UNION_INVALID")
    elif kind == "union_bool":
        if decode_uvar(cursor, 32) != int(vector["tag"]):
            raise ScbError("SCB_UNION_INVALID")
        payload = Cursor(read_sized(cursor))
        _decode_bool(payload)
        payload.finish()
    else:
        raise ValueError(f"unsupported accepted fixture kind: {kind}")
    cursor.finish()
