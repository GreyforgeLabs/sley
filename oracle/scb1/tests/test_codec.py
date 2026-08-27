from __future__ import annotations

import importlib.metadata
import json
import unittest
from pathlib import Path

import unicodedata2

from sley2_scb1_oracle.codec import (
    Cursor,
    decode_accepted_vector,
    decode_declared_value,
    decode_uvar,
    encode_accepted_vector,
    encode_nested_empty_list,
    encode_uvar,
)
from sley2_scb1_oracle.conformance import check
from sley2_scb1_oracle.errors import ScbError


ROOT = Path(__file__).resolve().parents[3]
ACCEPTED = ROOT / "conformance/scb1/v1/accepted.json"
REJECTED = ROOT / "conformance/scb1/v1/rejected.json"


class OracleTests(unittest.TestCase):
    def test_dependency_versions_are_pinned(self) -> None:
        self.assertEqual(importlib.metadata.version("blake3"), "1.0.9")
        self.assertEqual(unicodedata2.unidata_version, "16.0.0")

    def test_uvar_boundaries_round_trip(self) -> None:
        for value in (0, 1, 127, 128, 300, (1 << 64) - 1):
            cursor = Cursor(encode_uvar(value))
            self.assertEqual(decode_uvar(cursor), value)
            cursor.finish()

    def test_nested_fixture_is_real_encoded_input(self) -> None:
        encoded = encode_nested_empty_list(65)
        self.assertGreater(len(encoded), 65)
        with self.assertRaisesRegex(ScbError, "SCB_RESOURCE_LIMIT"):
            decode_declared_value("NestedListFixture", encoded)

    def test_every_accepted_vector_matches(self) -> None:
        fixture = json.loads(ACCEPTED.read_text(encoding="utf-8"))
        for vector in fixture["vectors"]:
            with self.subTest(vector=vector["id"]):
                encoded = encode_accepted_vector(vector)
                self.assertEqual(encoded.hex(), vector["expected_hex"])
                decode_accepted_vector(vector, encoded)

    def test_every_rejected_vector_returns_exact_code(self) -> None:
        fixture = json.loads(REJECTED.read_text(encoding="utf-8"))
        for vector in fixture["vectors"]:
            with self.subTest(vector=vector["id"]):
                with self.assertRaises(ScbError) as raised:
                    decode_declared_value(
                        vector["declared_type"], bytes.fromhex(vector["input_hex"])
                    )
                self.assertEqual(raised.exception.code, vector["expected_code"])

    def test_frozen_corpus_gate_passes(self) -> None:
        result = check(ACCEPTED, REJECTED)
        self.assertEqual(result["result"], "PASS", result["problems"])
        self.assertTrue(result["byte_agreement"])
        self.assertTrue(result["accepted_decode_agreement"])
        self.assertTrue(result["code_agreement"])


if __name__ == "__main__":
    unittest.main()
