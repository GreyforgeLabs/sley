from __future__ import annotations

import importlib.metadata
import json
import unittest
from pathlib import Path

import unicodedata2
from blake3 import blake3

from sley2_scb1_oracle.codec import (
    Cursor,
    EPOCH_ID,
    FORMAT_VERSION,
    MAGIC,
    OBJECT_DOMAIN,
    decode_accepted_vector,
    decode_declared_value,
    decode_uvar,
    encode_accepted_vector,
    encode_nested_empty_list,
    encode_record,
    encode_sized,
    encode_uvar,
)
from sley2_scb1_oracle.candidate import check_candidate
from sley2_scb1_oracle.candidate_result import check_candidate_result
from sley2_scb1_oracle.conformance import check
from sley2_scb1_oracle.errors import ScbError
from sley2_scb1_oracle.transaction_receipt import check_transaction_receipt


ROOT = Path(__file__).resolve().parents[3]
ACCEPTED = ROOT / "conformance/scb1/v1/accepted.json"
REJECTED = ROOT / "conformance/scb1/v1/rejected.json"
CANDIDATE_ACCEPTED = ROOT / "conformance/mutation-candidate/v1/accepted.json"
CANDIDATE_REJECTED = ROOT / "conformance/mutation-candidate/v1/rejected.json"
RESULT_ACCEPTED = ROOT / "conformance/candidate-result/v1/accepted.json"
RESULT_REJECTED = ROOT / "conformance/candidate-result/v1/rejected.json"
TRANSACTION_ACCEPTED = ROOT / "conformance/transaction-receipt/v1/accepted.json"
TRANSACTION_REJECTED = ROOT / "conformance/transaction-receipt/v1/rejected.json"


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

    def test_standalone_contract_must_match_declared_type(self) -> None:
        payload = encode_record(((1, b"\x01"),))
        preimage = (
            MAGIC
            + encode_uvar(FORMAT_VERSION)
            + encode_uvar(2)
            + EPOCH_ID
            + encode_sized(payload)
        )
        stored = preimage + blake3(OBJECT_DOMAIN + preimage).digest()
        decode_declared_value("FixtureRequiredBool", stored)
        with self.assertRaisesRegex(ScbError, "SCB_CONTRACT_UNKNOWN"):
            decode_declared_value("FixtureEmptyObject", stored)

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

    def test_s20_350_candidate_corpus_gate_passes(self) -> None:
        result = check_candidate(CANDIDATE_ACCEPTED, CANDIDATE_REJECTED)
        self.assertEqual(result["result"], "PASS", result["problems"])
        self.assertEqual(result["value_vectors"], 44)
        self.assertEqual(result["candidate_vectors"], 1)
        self.assertEqual(result["rejected_value_vectors"], 4)
        self.assertEqual(result["rejected_candidate_vectors"], 14)

    def test_s20_360_candidate_result_corpus_gate_passes(self) -> None:
        result = check_candidate_result(RESULT_ACCEPTED, RESULT_REJECTED)
        self.assertEqual(result["result"], "PASS", result["problems"])
        self.assertEqual(result["accepted_vectors"], 16)
        self.assertEqual(result["rejected_vectors"], 4)

    def test_s20_390_transaction_receipt_corpus_gate_passes(self) -> None:
        result = check_transaction_receipt(TRANSACTION_ACCEPTED, TRANSACTION_REJECTED)
        self.assertEqual(result["result"], "PASS", result["problems"])
        self.assertEqual(result["accepted_vectors"], 2)
        self.assertEqual(result["rejected_vectors"], 9)


if __name__ == "__main__":
    unittest.main()
