from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from bench.raw.runner import (
    CORPUS_PATH,
    MANIFEST_CONTRACT,
    PLAN_PATH,
    TRIAL_CONTRACT,
    RawErrorCode,
    RawRunnerError,
    append_trial_digest_claim,
    assert_fair_shared_controls,
    canonical_json_bytes,
    manifest_digest,
    task_statement_digest,
    validate_run_manifest,
    verify_digest_claim_directory,
    write_run_manifest,
)


def digest(byte: int) -> str:
    return f"{byte:02x}" * 32


def manifest() -> dict:
    return {
        "contract": MANIFEST_CONTRACT,
        "run_id": "offline-smoke-001",
        "created_at_utc": "2026-08-27T12:00:00Z",
        "repo_commit": "e" * 40,
        "corpus_version": 1,
        "corpus_digest": hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest(),
        "benchmark_plan_digest": hashlib.sha256(PLAN_PATH.read_bytes()).hexdigest(),
        "arm_fixture_digests": {
            "raw_files": digest(1),
            "sley_1_2_0": "b24f19c6a348751c93c9cf63f6f4154f6132796112c26f9d8c0e71324080dbc7",
            "sley_2_0": digest(3),
        },
        "task_statement_digest": task_statement_digest(),
        "model_provider": "offline-fake",
        "model_exact_version": "fake-v1",
        "model_configuration": {"temperature_milli": 0},
        "tool_description_digests": {
            "raw_files": digest(4),
            "sley_1_2_0": digest(5),
            "sley_2_0": digest(6),
        },
        "context_budget": 10_000,
        "action_budget": 100,
        "wall_time_budget": 60_000,
        "retry_policy": {"maximum_retries": 0},
        "hardware_manifest": {"machine": "offline-fixture"},
        "cache_state": {"mode": "cold"},
        "oracle_digest": digest(7),
        "trial_count": 1,
        "random_seeds": [11],
        "environment_manifest": {"network": "disabled"},
        "execution_mode": "offline_injected",
        "external_command_policy": "forbidden",
    }


def metrics(*, accepted: bool) -> dict:
    plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    values = {name: 0 for name in plan["metrics"]}
    values["strict_accepted_correctness"] = accepted
    values["attempted_tasks"] = 1
    values["accepted_correct_changes"] = int(accepted)
    values["model_input_tokens"] = 10
    values["model_output_tokens"] = 5
    values["total_observable_tokens"] = 15
    values["context_bytes"] = 100
    values["wall_time"] = 1_000
    values["accepted_change_tokens"] = None
    return values


def record(*, trial_id: str, task_id: str, seed: int, status: str) -> dict:
    timed_out = status == "timeout"
    return {
        "contract": TRIAL_CONTRACT,
        "run_id": "offline-smoke-001",
        "trial_id": trial_id,
        "arm_id": "raw_files",
        "task_id": task_id,
        "seed": seed,
        "started_at_utc": "2026-08-27T12:00:00Z",
        "ended_at_utc": "2026-08-27T12:00:01Z",
        "status": status,
        "failure_code": "RAW_TRIAL_TIMEOUT" if timed_out else None,
        "timeout": timed_out,
        "prompt_digest": digest(10),
        "model_output_digest": None if timed_out else digest(11),
        "tool_call_digest": None if timed_out else digest(12),
        "candidate_digest": None if timed_out else digest(13),
        "workspace_before_digest": digest(14),
        "workspace_after_digest": digest(14) if timed_out else digest(15),
        "oracle_report_digest": None if timed_out else digest(16),
        "evidence_status": "UNVERIFIED_INJECTED_DIGEST_CLAIMS",
        "oracle_verification_status": "UNVERIFIED_ADAPTER_CLAIM",
        "accounting_verification_status": "UNVERIFIED_ADAPTER_CLAIM",
        "metrics": metrics(accepted=not timed_out),
    }


class RawRunnerTests(unittest.TestCase):
    def test_success_and_timeout_are_chained_and_complete(self) -> None:
        run_manifest = manifest()
        validate_run_manifest(run_manifest)
        with tempfile.TemporaryDirectory() as temporary:
            run_directory = Path(temporary) / "run"
            anchor = write_run_manifest(run_directory, run_manifest)
            self.assertEqual(anchor, manifest_digest(run_manifest))

            first = append_trial_digest_claim(
                run_directory,
                record(
                    trial_id="raw-create-001",
                    task_id="S2B-CREATE-001",
                    seed=11,
                    status="accepted",
                ),
            )
            second = append_trial_digest_claim(
                run_directory,
                record(
                    trial_id="raw-repair-001",
                    task_id="S2B-REPAIR-001",
                    seed=11,
                    status="timeout",
                ),
            )
            corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
            for index, task in enumerate(corpus["tasks"][2:], start=2):
                append_trial_digest_claim(
                    run_directory,
                    record(
                        trial_id=f"raw-smoke-{index:03d}",
                        task_id=task["id"],
                        seed=11,
                        status="timeout",
                    ),
                )
            records = verify_digest_claim_directory(run_directory, require_complete=True)
            self.assertEqual(records[0]["previous_record_digest"], anchor)
            self.assertEqual(records[0]["record_digest"], first)
            self.assertEqual(records[1]["previous_record_digest"], first)
            self.assertEqual(records[1]["record_digest"], second)
            self.assertEqual(records[1]["failure_code"], "RAW_TRIAL_TIMEOUT")

    def test_control_drift_and_external_execution_fail_closed(self) -> None:
        baseline = manifest()
        changed = manifest()
        changed["context_budget"] += 1
        with self.assertRaises(RawRunnerError) as caught:
            assert_fair_shared_controls(baseline, changed)
        self.assertEqual(caught.exception.code, RawErrorCode.CONTROL_MISMATCH)

        external = manifest()
        external["external_command_policy"] = "allowed"
        with self.assertRaises(RawRunnerError) as caught:
            validate_run_manifest(external)
        self.assertEqual(caught.exception.code, RawErrorCode.EXTERNAL_EXECUTION_FORBIDDEN)

    def test_duplicate_and_trial_limit_preserve_existing_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_directory = Path(temporary) / "run"
            write_run_manifest(run_directory, manifest())
            accepted = record(
                trial_id="raw-create-001",
                task_id="S2B-CREATE-001",
                seed=11,
                status="accepted",
            )
            append_trial_digest_claim(run_directory, accepted)
            before = (run_directory / "trial_digest_claims.jsonl").read_bytes()
            with self.assertRaises(RawRunnerError) as caught:
                append_trial_digest_claim(run_directory, accepted)
            self.assertEqual(caught.exception.code, RawErrorCode.TRIAL_DUPLICATE)
            self.assertEqual((run_directory / "trial_digest_claims.jsonl").read_bytes(), before)

    def test_tamper_and_noncanonical_manifest_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            run_directory = Path(temporary) / "run"
            write_run_manifest(run_directory, manifest())
            append_trial_digest_claim(
                run_directory,
                record(
                    trial_id="raw-create-001",
                    task_id="S2B-CREATE-001",
                    seed=11,
                    status="accepted",
                ),
            )
            records_path = run_directory / "trial_digest_claims.jsonl"
            stored = json.loads(records_path.read_text(encoding="utf-8"))
            stored["metrics"]["tool_calls"] = 1
            records_path.write_bytes(canonical_json_bytes(stored) + b"\n")
            with self.assertRaises(RawRunnerError) as caught:
                verify_digest_claim_directory(run_directory)
            self.assertEqual(caught.exception.code, RawErrorCode.CHAIN_INVALID)

            manifest_path = run_directory / "run_manifest.json"
            manifest_path.write_bytes(b" " + manifest_path.read_bytes())
            with self.assertRaises(RawRunnerError) as caught:
                verify_digest_claim_directory(run_directory)
            self.assertEqual(caught.exception.code, RawErrorCode.MANIFEST_INVALID)


if __name__ == "__main__":
    unittest.main()
