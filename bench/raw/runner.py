#!/usr/bin/env python3
"""Fail-closed, offline-only S20-610 raw baseline evidence runner.

This module validates frozen controls and stores digest-chained observations.
It deliberately contains no subprocess, provider, model, shell, network, or
Sley 1.x execution adapter. Real adapters remain injected and unapproved.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = ROOT / "bench/benchmark-plan.json"
CORPUS_PATH = ROOT / "bench/corpus/v1/tasks.json"
MANIFEST_NAME = "run_manifest.json"
RECORDS_NAME = "trial_digest_claims.jsonl"

MANIFEST_CONTRACT = "sley2.raw-run-manifest.v1"
TRIAL_CONTRACT = "sley2.raw-trial-digest-claim.v1"
MANIFEST_DOMAIN = b"sley2.raw-run-manifest.v1\0"
TRIAL_DOMAIN = b"sley2.raw-trial-digest-claim.v1\0"
EXECUTION_MODE = "offline_injected"
EXTERNAL_COMMAND_POLICY = "forbidden"
EVIDENCE_STATUS = "UNVERIFIED_INJECTED_DIGEST_CLAIMS"
VERIFICATION_STATUS = "UNVERIFIED_ADAPTER_CLAIM"

HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
UTC_SECOND = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

MANIFEST_METADATA_FIELDS = {
    "contract",
    "run_id",
    "created_at_utc",
    "repo_commit",
    "corpus_version",
    "benchmark_plan_digest",
    "execution_mode",
    "external_command_policy",
}

TRIAL_INPUT_FIELDS = {
    "contract",
    "run_id",
    "trial_id",
    "arm_id",
    "task_id",
    "seed",
    "started_at_utc",
    "ended_at_utc",
    "status",
    "failure_code",
    "timeout",
    "prompt_digest",
    "model_output_digest",
    "tool_call_digest",
    "candidate_digest",
    "workspace_before_digest",
    "workspace_after_digest",
    "oracle_report_digest",
    "evidence_status",
    "oracle_verification_status",
    "accounting_verification_status",
    "metrics",
}
TRIAL_CHAIN_FIELDS = {"previous_record_digest", "record_digest"}
TRIAL_STATUSES = {"accepted", "rejected", "timeout", "harness_failure"}
OPTIONAL_ARTIFACT_DIGESTS = {
    "model_output_digest",
    "tool_call_digest",
    "candidate_digest",
    "oracle_report_digest",
}


class RawErrorCode(IntEnum):
    """Stable S20-610 offline runner failure codes."""

    MANIFEST_INVALID = 61_000
    CONTROL_MISMATCH = 61_001
    DIGEST_MISMATCH = 61_002
    TRIAL_LIMIT = 61_003
    TRIAL_DUPLICATE = 61_004
    CHAIN_INVALID = 61_005
    RECORD_INVALID = 61_006
    ARM_INVALID = 61_007
    TASK_UNKNOWN = 61_008
    SEED_MISMATCH = 61_009
    STATUS_INVALID = 61_010
    METRIC_INVALID = 61_011
    EXTERNAL_EXECUTION_FORBIDDEN = 61_012
    ARTIFACT_MISSING = 61_013
    APPEND_FAILED = 61_014
    INTERNAL_INVARIANT = 61_015

    @property
    def symbol(self) -> str:
        return f"RAW_{self.name}"


class RawRunnerError(ValueError):
    """One stable fail-closed raw-runner error."""

    def __init__(self, code: RawErrorCode, detail: str = "") -> None:
        super().__init__(code.symbol if not detail else f"{code.symbol}: {detail}")
        self.code = code
        self.detail = detail


@runtime_checkable
class AgentAdapter(Protocol):
    """Injected agent interface; no implementation is supplied by S20-610."""

    def run(self, task: Mapping[str, Any], controls: Mapping[str, Any], workspace: Any) -> Any:
        """Return an adapter-owned observation without ambient authority."""


@runtime_checkable
class ToolAdapter(Protocol):
    """Injected raw-file tool interface; no shell implementation is supplied."""

    def describe_digest(self) -> str:
        """Return the frozen tool-description digest."""


@runtime_checkable
class OracleAdapter(Protocol):
    """Injected strict-oracle interface; no live oracle is supplied."""

    def evaluate(self, task: Mapping[str, Any], workspace: Any, observation: Any) -> Any:
        """Return an adapter-owned strict-oracle observation."""


@runtime_checkable
class WorkspaceAdapter(Protocol):
    """Injected disposable-workspace interface; no host copier is supplied."""

    def stage(self, fixture_digest: str, trial_id: str) -> Any:
        """Return an opaque disposable workspace handle."""


@runtime_checkable
class AccountingClock(Protocol):
    """Injected accounting clock; no ambient clock is read by this module."""

    def now_utc(self) -> str:
        """Return a frozen UTC-second timestamp supplied by the adapter."""


def _fail(code: RawErrorCode, detail: str = "") -> None:
    raise RawRunnerError(code, detail)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RawRunnerError(RawErrorCode.MANIFEST_INVALID, str(error)) from error
    if not isinstance(value, dict):
        _fail(RawErrorCode.MANIFEST_INVALID, f"{path.name} is not an object")
    return value


def _require_canonical_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if -(1 << 63) <= value <= (1 << 64) - 1:
            return
        _fail(RawErrorCode.MANIFEST_INVALID, f"integer out of range at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _require_canonical_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            _fail(RawErrorCode.MANIFEST_INVALID, f"non-string key at {path}")
        for key in sorted(value):
            _require_canonical_value(value[key], f"{path}.{key}")
        return
    _fail(RawErrorCode.MANIFEST_INVALID, f"unsupported JSON value at {path}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return the frozen integer-only canonical JSON representation."""

    _require_canonical_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_domain(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + payload).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _plan_and_corpus() -> tuple[dict[str, Any], dict[str, Any]]:
    return _load_json(PLAN_PATH), _load_json(CORPUS_PATH)


def _required_arms(plan: Mapping[str, Any]) -> set[str]:
    return {
        arm["id"]
        for arm in plan.get("arms", [])
        if isinstance(arm, dict) and arm.get("required") is True
    }


def _task_ids(corpus: Mapping[str, Any]) -> set[str]:
    return {
        task["id"]
        for task in corpus.get("tasks", [])
        if isinstance(task, dict) and isinstance(task.get("id"), str)
    }


def task_statement_digest(corpus: Mapping[str, Any] | None = None) -> str:
    """Digest only the representation-neutral task intent and oracle fields."""

    if corpus is None:
        _, corpus = _plan_and_corpus()
    statements = []
    for task in corpus.get("tasks", []):
        statements.append(
            {
                key: task[key]
                for key in (
                    "id",
                    "class",
                    "goal",
                    "required_outcome",
                    "strict_oracle",
                    "forbidden_outcomes",
                )
            }
        )
    return _sha256_domain(b"sley2.benchmark-task-statements.v1\0", canonical_json_bytes(statements))


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and HEX_64.fullmatch(value) is not None


def _require_digest(value: Any, field: str) -> None:
    if not _is_digest(value):
        _fail(RawErrorCode.DIGEST_MISMATCH, field)


def _require_nonempty_string(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 65_535:
        _fail(RawErrorCode.MANIFEST_INVALID, field)


def _require_positive_int(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        _fail(RawErrorCode.MANIFEST_INVALID, field)


def _require_utc_second(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        _fail(RawErrorCode.MANIFEST_INVALID, field)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise RawRunnerError(RawErrorCode.MANIFEST_INVALID, field) from error


def validate_run_manifest(manifest: Mapping[str, Any]) -> None:
    """Validate exact frozen controls without executing any benchmark arm."""

    plan, corpus = _plan_and_corpus()
    required_controls = set(plan["run_freeze_required_fields"])
    expected_fields = MANIFEST_METADATA_FIELDS | required_controls
    if set(manifest) != expected_fields:
        _fail(RawErrorCode.MANIFEST_INVALID, "field set")
    _require_canonical_value(dict(manifest))
    if manifest["contract"] != MANIFEST_CONTRACT:
        _fail(RawErrorCode.MANIFEST_INVALID, "contract")
    if not isinstance(manifest["run_id"], str) or RUN_ID.fullmatch(manifest["run_id"]) is None:
        _fail(RawErrorCode.MANIFEST_INVALID, "run_id")
    _require_utc_second(manifest["created_at_utc"], "created_at_utc")
    if not isinstance(manifest["repo_commit"], str) or HEX_40.fullmatch(manifest["repo_commit"]) is None:
        _fail(RawErrorCode.MANIFEST_INVALID, "repo_commit")
    if manifest["corpus_version"] != corpus.get("version"):
        _fail(RawErrorCode.CONTROL_MISMATCH, "corpus_version")
    if manifest["corpus_digest"] != _file_sha256(CORPUS_PATH):
        _fail(RawErrorCode.DIGEST_MISMATCH, "corpus_digest")
    if manifest["benchmark_plan_digest"] != _file_sha256(PLAN_PATH):
        _fail(RawErrorCode.DIGEST_MISMATCH, "benchmark_plan_digest")
    if manifest["task_statement_digest"] != task_statement_digest(corpus):
        _fail(RawErrorCode.DIGEST_MISMATCH, "task_statement_digest")
    if manifest["execution_mode"] != EXECUTION_MODE:
        _fail(RawErrorCode.EXTERNAL_EXECUTION_FORBIDDEN, "execution_mode")
    if manifest["external_command_policy"] != EXTERNAL_COMMAND_POLICY:
        _fail(RawErrorCode.EXTERNAL_EXECUTION_FORBIDDEN, "external_command_policy")

    required_arms = _required_arms(plan)
    for field in ("arm_fixture_digests", "tool_description_digests"):
        mapping = manifest[field]
        if not isinstance(mapping, dict) or set(mapping) != required_arms:
            _fail(RawErrorCode.CONTROL_MISMATCH, field)
        for arm, digest in mapping.items():
            _require_digest(digest, f"{field}.{arm}")
    frozen_arm_digests = {
        arm["id"]: arm["artifact_sha256"]
        for arm in plan["arms"]
        if isinstance(arm, dict) and isinstance(arm.get("artifact_sha256"), str)
    }
    for arm, expected in frozen_arm_digests.items():
        if manifest["arm_fixture_digests"].get(arm) != expected:
            _fail(RawErrorCode.DIGEST_MISMATCH, f"arm_fixture_digests.{arm}")

    for field in ("model_provider", "model_exact_version"):
        _require_nonempty_string(manifest[field], field)
    for field in (
        "model_configuration",
        "retry_policy",
        "hardware_manifest",
        "cache_state",
        "environment_manifest",
    ):
        if not isinstance(manifest[field], dict) or not manifest[field]:
            _fail(RawErrorCode.MANIFEST_INVALID, field)
    for field in ("context_budget", "action_budget", "wall_time_budget", "trial_count"):
        _require_positive_int(manifest[field], field)
    _require_digest(manifest["oracle_digest"], "oracle_digest")

    seeds = manifest["random_seeds"]
    if (
        not isinstance(seeds, list)
        or len(seeds) != manifest["trial_count"]
        or len(set(seeds)) != len(seeds)
        or any(isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 for seed in seeds)
    ):
        _fail(RawErrorCode.SEED_MISMATCH, "random_seeds")


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Validate and digest one exact run manifest."""

    validate_run_manifest(manifest)
    return _sha256_domain(MANIFEST_DOMAIN, canonical_json_bytes(dict(manifest)))


def assert_fair_shared_controls(left: Mapping[str, Any], right: Mapping[str, Any]) -> None:
    """Reject any shared-control drift between two run manifests."""

    validate_run_manifest(left)
    validate_run_manifest(right)
    plan, _ = _plan_and_corpus()
    shared = set(plan["run_freeze_required_fields"])
    shared |= {
        "run_id",
        "created_at_utc",
        "repo_commit",
        "corpus_version",
        "benchmark_plan_digest",
        "execution_mode",
        "external_command_policy",
    }
    for field in sorted(shared):
        if left[field] != right[field]:
            _fail(RawErrorCode.CONTROL_MISMATCH, field)


def _open_run_directory(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            _fail(RawErrorCode.APPEND_FAILED, "run path is not a directory")
        return descriptor
    except RawRunnerError:
        raise
    except OSError as error:
        raise RawRunnerError(RawErrorCode.APPEND_FAILED, str(error)) from error


def _open_regular_at(directory_descriptor: int, name: str, flags: int, mode: int = 0o600) -> int:
    try:
        descriptor = os.open(
            name,
            flags | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=directory_descriptor,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            _fail(RawErrorCode.APPEND_FAILED, f"{name} is not a regular file")
        return descriptor
    except RawRunnerError:
        raise
    except OSError as error:
        raise RawRunnerError(RawErrorCode.APPEND_FAILED, str(error)) from error


def _write_exclusive_at(directory_descriptor: int, name: str, payload: bytes) -> None:
    descriptor = _open_regular_at(
        directory_descriptor,
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise RawRunnerError(RawErrorCode.APPEND_FAILED, str(error)) from error


def _read_regular_at(
    directory_descriptor: int,
    name: str,
    *,
    missing_ok: bool = False,
) -> bytes:
    try:
        descriptor = _open_regular_at(directory_descriptor, name, os.O_RDONLY)
    except RawRunnerError as error:
        if missing_ok and isinstance(error.__cause__, FileNotFoundError):
            return b""
        raise
    try:
        return _read_all(descriptor)
    finally:
        os.close(descriptor)


def write_run_manifest(run_directory: Path, manifest: Mapping[str, Any]) -> str:
    """Create a run directory and immutable canonical manifest exactly once."""

    digest = manifest_digest(manifest)
    try:
        run_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as error:
        raise RawRunnerError(RawErrorCode.APPEND_FAILED, str(error)) from error
    directory_descriptor = _open_run_directory(run_directory)
    try:
        _write_exclusive_at(
            directory_descriptor,
            MANIFEST_NAME,
            canonical_json_bytes(dict(manifest)),
        )
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return digest


def _read_manifest_exact_at(directory_descriptor: int) -> dict[str, Any]:
    try:
        raw = _read_regular_at(directory_descriptor, MANIFEST_NAME)
        manifest = json.loads(raw)
    except RawRunnerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RawRunnerError(RawErrorCode.MANIFEST_INVALID, str(error)) from error
    if not isinstance(manifest, dict) or canonical_json_bytes(manifest) != raw:
        _fail(RawErrorCode.MANIFEST_INVALID, "manifest is not exact canonical JSON")
    validate_run_manifest(manifest)
    return manifest


def _read_manifest_exact(run_directory: Path) -> dict[str, Any]:
    directory_descriptor = _open_run_directory(run_directory)
    try:
        return _read_manifest_exact_at(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _validate_metrics(metrics: Any, plan: Mapping[str, Any], status: str) -> None:
    if not isinstance(metrics, dict) or set(metrics) != set(plan["metrics"]):
        _fail(RawErrorCode.METRIC_INVALID, "metric field set")
    for name, value in metrics.items():
        if name == "strict_accepted_correctness":
            if not isinstance(value, bool):
                _fail(RawErrorCode.METRIC_INVALID, name)
        elif name == "accepted_change_tokens":
            if value is not None:
                _fail(RawErrorCode.METRIC_INVALID, "ACT is derived only by S20-630")
        elif isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _fail(RawErrorCode.METRIC_INVALID, name)
    if metrics["attempted_tasks"] != 1:
        _fail(RawErrorCode.METRIC_INVALID, "attempted_tasks")
    expected_accepted = 1 if status == "accepted" else 0
    if metrics["accepted_correct_changes"] != expected_accepted:
        _fail(RawErrorCode.METRIC_INVALID, "accepted_correct_changes")
    if metrics["strict_accepted_correctness"] is not (status == "accepted"):
        _fail(RawErrorCode.METRIC_INVALID, "strict_accepted_correctness")


def _validate_metric_controls(metrics: Mapping[str, Any], manifest: Mapping[str, Any], status: str) -> None:
    if metrics["total_observable_tokens"] != (
        metrics["model_input_tokens"] + metrics["model_output_tokens"]
    ):
        _fail(RawErrorCode.METRIC_INVALID, "total_observable_tokens")
    if metrics["model_input_tokens"] > manifest["context_budget"]:
        _fail(RawErrorCode.CONTROL_MISMATCH, "context_budget")
    if metrics["tool_calls"] > manifest["action_budget"]:
        _fail(RawErrorCode.CONTROL_MISMATCH, "action_budget")
    if status != "timeout" and metrics["wall_time"] > manifest["wall_time_budget"]:
        _fail(RawErrorCode.CONTROL_MISMATCH, "wall_time_budget")


def _validate_trial_input(record: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    if set(record) != TRIAL_INPUT_FIELDS:
        _fail(RawErrorCode.RECORD_INVALID, "field set")
    _require_canonical_value(dict(record))
    if record["contract"] != TRIAL_CONTRACT or record["run_id"] != manifest["run_id"]:
        _fail(RawErrorCode.RECORD_INVALID, "contract/run")
    if not isinstance(record["trial_id"], str) or RUN_ID.fullmatch(record["trial_id"]) is None:
        _fail(RawErrorCode.RECORD_INVALID, "trial_id")
    if record["arm_id"] != "raw_files":
        _fail(RawErrorCode.ARM_INVALID, str(record["arm_id"]))
    _, corpus = _plan_and_corpus()
    if record["task_id"] not in _task_ids(corpus):
        _fail(RawErrorCode.TASK_UNKNOWN, str(record["task_id"]))
    if record["seed"] not in manifest["random_seeds"]:
        _fail(RawErrorCode.SEED_MISMATCH, str(record["seed"]))
    try:
        started = _require_utc_second(record["started_at_utc"], "started_at_utc")
        ended = _require_utc_second(record["ended_at_utc"], "ended_at_utc")
    except RawRunnerError as error:
        raise RawRunnerError(RawErrorCode.RECORD_INVALID, error.detail) from error
    if ended < started:
        _fail(RawErrorCode.RECORD_INVALID, "time ordering")
    status = record["status"]
    if status not in TRIAL_STATUSES:
        _fail(RawErrorCode.STATUS_INVALID, str(status))
    timeout = record["timeout"]
    if not isinstance(timeout, bool) or timeout is not (status == "timeout"):
        _fail(RawErrorCode.STATUS_INVALID, "timeout")
    failure = record["failure_code"]
    if status == "accepted":
        if failure is not None:
            _fail(RawErrorCode.STATUS_INVALID, "accepted failure_code")
    elif not isinstance(failure, str) or not failure:
        _fail(RawErrorCode.STATUS_INVALID, "missing failure_code")
    if status == "timeout" and failure != "RAW_TRIAL_TIMEOUT":
        _fail(RawErrorCode.STATUS_INVALID, "timeout failure_code")
    if record["evidence_status"] != EVIDENCE_STATUS:
        _fail(RawErrorCode.RECORD_INVALID, "evidence_status")
    if record["oracle_verification_status"] != VERIFICATION_STATUS:
        _fail(RawErrorCode.RECORD_INVALID, "oracle_verification_status")
    if record["accounting_verification_status"] != VERIFICATION_STATUS:
        _fail(RawErrorCode.RECORD_INVALID, "accounting_verification_status")

    required_artifacts = set()
    if status == "accepted":
        required_artifacts = OPTIONAL_ARTIFACT_DIGESTS
    elif status == "rejected":
        required_artifacts = {
            "model_output_digest",
            "tool_call_digest",
            "oracle_report_digest",
        }
    for field in required_artifacts:
        if record[field] is None:
            _fail(RawErrorCode.ARTIFACT_MISSING, field)

    for field in TRIAL_INPUT_FIELDS & {name for name in record if name.endswith("_digest")}:
        value = record[field]
        if field in OPTIONAL_ARTIFACT_DIGESTS and value is None:
            continue
        _require_digest(value, field)
    plan, _ = _plan_and_corpus()
    _validate_metrics(record["metrics"], plan, status)
    _validate_metric_controls(record["metrics"], manifest, status)


def _record_digest(record_without_digest: Mapping[str, Any]) -> str:
    return _sha256_domain(TRIAL_DOMAIN, canonical_json_bytes(dict(record_without_digest)))


def _expected_trial_pairs(manifest: Mapping[str, Any]) -> set[tuple[str, int]]:
    _, corpus = _plan_and_corpus()
    return {
        (task_id, seed)
        for task_id in _task_ids(corpus)
        for seed in manifest["random_seeds"]
    }


def _parse_and_verify_records(raw: bytes, manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not raw:
        return []
    if not raw.endswith(b"\n"):
        _fail(RawErrorCode.CHAIN_INVALID, "missing final newline")
    records: list[dict[str, Any]] = []
    previous = manifest_digest(manifest)
    seen_trials: set[str] = set()
    seen_pairs: set[tuple[str, int]] = set()
    for index, line in enumerate(raw.splitlines()):
        try:
            record = json.loads(line)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RawRunnerError(RawErrorCode.CHAIN_INVALID, str(error)) from error
        if not isinstance(record, dict) or canonical_json_bytes(record) != line:
            _fail(RawErrorCode.CHAIN_INVALID, f"noncanonical record {index}")
        if set(record) != TRIAL_INPUT_FIELDS | TRIAL_CHAIN_FIELDS:
            _fail(RawErrorCode.CHAIN_INVALID, f"field set {index}")
        body = {key: record[key] for key in TRIAL_INPUT_FIELDS}
        _validate_trial_input(body, manifest)
        if record["previous_record_digest"] != previous:
            _fail(RawErrorCode.CHAIN_INVALID, f"previous digest {index}")
        digest_body = dict(body)
        digest_body["previous_record_digest"] = previous
        expected = _record_digest(digest_body)
        if record["record_digest"] != expected:
            _fail(RawErrorCode.CHAIN_INVALID, f"record digest {index}")
        if record["trial_id"] in seen_trials:
            _fail(RawErrorCode.TRIAL_DUPLICATE, record["trial_id"])
        pair = (record["task_id"], record["seed"])
        if pair in seen_pairs:
            _fail(RawErrorCode.TRIAL_DUPLICATE, f"{pair[0]}:{pair[1]}")
        seen_trials.add(record["trial_id"])
        seen_pairs.add(pair)
        previous = expected
        records.append(record)
    if len(records) > len(_expected_trial_pairs(manifest)):
        _fail(RawErrorCode.TRIAL_LIMIT, str(len(records)))
    return records


def _read_all(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 65_536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def append_trial_digest_claim(run_directory: Path, record: Mapping[str, Any]) -> str:
    """Append one unverified, denominator-preserving digest claim atomically."""

    directory_descriptor = _open_run_directory(run_directory)
    try:
        manifest = _read_manifest_exact_at(directory_descriptor)
        _validate_trial_input(record, manifest)
        descriptor = _open_regular_at(
            directory_descriptor,
            RECORDS_NAME,
            os.O_RDWR | os.O_CREAT | os.O_APPEND,
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            records = _parse_and_verify_records(_read_all(descriptor), manifest)
            if len(records) >= len(_expected_trial_pairs(manifest)):
                _fail(RawErrorCode.TRIAL_LIMIT, str(len(records)))
            if any(existing["trial_id"] == record["trial_id"] for existing in records):
                _fail(RawErrorCode.TRIAL_DUPLICATE, str(record["trial_id"]))
            if any(
                (existing["task_id"], existing["seed"])
                == (record["task_id"], record["seed"])
                for existing in records
            ):
                _fail(
                    RawErrorCode.TRIAL_DUPLICATE,
                    f"{record['task_id']}:{record['seed']}",
                )
            previous = records[-1]["record_digest"] if records else manifest_digest(manifest)
            digest_body = dict(record)
            digest_body["previous_record_digest"] = previous
            digest = _record_digest(digest_body)
            stored = dict(digest_body)
            stored["record_digest"] = digest
            payload = canonical_json_bytes(stored) + b"\n"
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    _fail(RawErrorCode.APPEND_FAILED, "short append")
                written += count
            os.fsync(descriptor)
            os.fsync(directory_descriptor)
            return digest
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
    except RawRunnerError:
        raise
    except OSError as error:
        raise RawRunnerError(RawErrorCode.APPEND_FAILED, str(error)) from error
    finally:
        os.close(directory_descriptor)


def verify_digest_claim_directory(
    run_directory: Path,
    *,
    require_complete: bool = False,
) -> list[dict[str, Any]]:
    """Verify manifest/chain integrity, never underlying artifact truth."""

    directory_descriptor = _open_run_directory(run_directory)
    try:
        manifest = _read_manifest_exact_at(directory_descriptor)
        raw = _read_regular_at(directory_descriptor, RECORDS_NAME, missing_ok=True)
    finally:
        os.close(directory_descriptor)
    records = _parse_and_verify_records(raw, manifest)
    if require_complete:
        expected = _expected_trial_pairs(manifest)
        actual = {(record["task_id"], record["seed"]) for record in records}
        if actual != expected:
            _fail(RawErrorCode.TRIAL_LIMIT, f"{len(actual)}/{len(expected)}")
    return records
