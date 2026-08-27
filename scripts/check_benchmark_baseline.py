#!/usr/bin/env python3
"""Validate S20-040 without external packages or executing benchmark arms."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "bench/benchmark-plan.json"
TASKS_PATH = ROOT / "bench/corpus/v1/tasks.json"
DIGEST_PATH = ROOT / "bench/corpus/v1/SHA256SUMS"

REQUIRED_CLASSES = {
    "program_creation_from_blank_state",
    "local_bug_repair",
    "cross_function_signature_migration",
    "cross_module_refactor",
    "type_model_change",
    "effect_repair",
    "capability_scope_repair",
    "dead_path_removal",
    "test_generation",
    "stale_concurrent_change",
    "semantic_branch_merge",
    "performance_oriented_transformation",
    "large_bounded_context_maintenance",
    "adversarial_prompt_repository_metadata",
    "corrupted_state_recovery",
}
REQUIRED_ARMS = {"raw_files", "sley_1_2_0", "sley_2_0"}
REQUIRED_CONTROLS = {
    "corpus_digest", "arm_fixture_digests", "task_statement_digest",
    "model_provider", "model_exact_version", "model_configuration",
    "tool_description_digests", "context_budget", "action_budget",
    "wall_time_budget", "retry_policy", "hardware_manifest", "cache_state",
    "oracle_digest", "trial_count", "random_seeds", "environment_manifest",
}
REQUIRED_METRICS = {
    "strict_accepted_correctness", "attempted_tasks",
    "accepted_correct_changes", "invalid_candidates",
    "invalid_committed_states", "stale_candidates",
    "stale_candidates_incorrectly_accepted", "collateral_semantic_changes",
    "model_input_tokens", "model_output_tokens", "total_observable_tokens",
    "accepted_change_tokens", "context_bytes", "entities_inspected",
    "relationships_inspected", "files_inspected", "tool_calls",
    "compile_or_check_attempts", "repair_loops", "wall_time", "peak_memory",
    "canonical_storage_bytes", "pack_bytes", "execution_latency",
    "human_interventions",
}


def fail(problems: list[str]) -> None:
    print(json.dumps({"contract": "s20-040-check-v1", "result": "FAIL", "problems": problems}, indent=2))
    raise SystemExit(1)


plan = json.loads(PLAN_PATH.read_text())
corpus = json.loads(TASKS_PATH.read_text())
problems: list[str] = []

if plan.get("status") != "FROZEN_DESIGN" or plan.get("not_program_input") is not True:
    problems.append("benchmark plan is not a frozen non-program-input design")
if corpus.get("status") != "FROZEN" or corpus.get("not_program_input") is not True:
    problems.append("corpus v1 is not frozen or is misclassified as program input")

tasks = corpus.get("tasks", [])
ids = [task.get("id") for task in tasks]
classes = {task.get("class") for task in tasks}
if len(tasks) != 15:
    problems.append(f"expected 15 tasks, found {len(tasks)}")
if len(ids) != len(set(ids)):
    problems.append("task IDs are not unique")
if classes != REQUIRED_CLASSES:
    problems.append(f"task class mismatch: {sorted(classes ^ REQUIRED_CLASSES)}")
for task in tasks:
    if not task.get("goal") or not task.get("required_outcome"):
        problems.append(f"{task.get('id')} lacks goal or required outcome")
    if not task.get("strict_oracle") or not task.get("forbidden_outcomes"):
        problems.append(f"{task.get('id')} lacks strict oracle or forbidden outcomes")

arms = {arm.get("id") for arm in plan.get("arms", []) if arm.get("required")}
if arms != REQUIRED_ARMS:
    problems.append(f"required arm mismatch: {sorted(arms ^ REQUIRED_ARMS)}")
if set(plan.get("run_freeze_required_fields", [])) != REQUIRED_CONTROLS:
    problems.append("run-freeze control set differs from the required exact set")
if set(plan.get("metrics", [])) != REQUIRED_METRICS:
    problems.append("metric set differs from the required exact set")

retention = plan.get("failure_retention", {})
if not all(value is True for value in retention.values()):
    problems.append("failure retention contains a non-true requirement")

actual_digest = hashlib.sha256(TASKS_PATH.read_bytes()).hexdigest()
digest_fields = DIGEST_PATH.read_text().strip().split()
if digest_fields != [actual_digest, "tasks.json"]:
    problems.append("corpus SHA256SUMS does not match tasks.json")

if problems:
    fail(problems)

print(json.dumps({
    "contract": "s20-040-check-v1",
    "result": "PASS",
    "corpus_version": 1,
    "corpus_sha256": actual_digest,
    "tasks": len(tasks),
    "required_arms": sorted(arms),
    "metrics": len(REQUIRED_METRICS),
    "run_freeze_controls": len(REQUIRED_CONTROLS),
    "trials_executed": 0,
}, sort_keys=True))
