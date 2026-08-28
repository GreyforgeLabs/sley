#!/usr/bin/env python3
"""Build and run the proposal-only S20-350 candidate libFuzzer target."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "evidence/runtime/s20-350-mutation-candidate-libfuzzer"
CORPUS = RUNTIME / "corpus"
ARTIFACTS = RUNTIME / "artifacts"
EVIDENCE = RUNTIME / "evidence.json"
TARGET_DIR = RUNTIME / "target"
FUZZER = TARGET_DIR / "release/mutation_candidate"
FIXTURES = ROOT / "conformance/mutation-candidate/v1"
CLANG = "clang-18"
RUST_TOOLCHAIN = "nightly-2026-02-27"
LIBFUZZER = Path("/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a")
MAX_CANDIDATE_BYTES = 1_048_576
MAX_INPUT_LEN = MAX_CANDIDATE_BYTES + 1
SMOKE_RUNS = 512
SMOKE_TIMEOUT_SECONDS = 60
SELECTOR_COUNT = 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manual", action="store_true", help="run until interrupted")
    parser.add_argument("--runs", type=int, default=SMOKE_RUNS)
    parser.add_argument("--timeout", type=int, default=SMOKE_TIMEOUT_SECONDS)
    args = parser.parse_args()
    if args.runs < 0 or args.timeout <= 0:
        parser.error("--runs must be nonnegative and --timeout must be positive")

    started = time.monotonic()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    reset_directory(ARTIFACTS)
    corpus_count = generate_seed_corpus()
    evidence: dict[str, object] = {
        "contract": "s20-350-mutation-candidate-persistent-libfuzzer-v1",
        "scope": "PROPOSAL_ONLY_CANDIDATE_RECORD_AND_ENVELOPE",
        "candidate_authority": False,
        "runtime_mutation": False,
        "selector_count": SELECTOR_COUNT,
        "max_candidate_bytes": MAX_CANDIDATE_BYTES,
        "corpus_count": corpus_count,
        "accepted_candidate_vectors": 1,
        "rejected_candidate_vectors": 14,
        "runtime_path": str(RUNTIME.relative_to(ROOT)),
        "source_commit": git_output(["git", "rev-parse", "HEAD"]),
        "worktree_dirty": bool(git_output(["git", "status", "--porcelain"])),
        "commands": [],
        "problems": toolchain_problems(),
    }
    if evidence["problems"]:
        evidence["result"] = "BLOCKED"
        write_evidence(evidence)
        return 2

    env = os.environ.copy()
    env["CC"] = CLANG
    build = run(
        [
            "cargo",
            f"+{RUST_TOOLCHAIN}",
            "rustc",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--bin",
            "mutation_candidate",
            "--release",
            "--target-dir",
            str(TARGET_DIR),
            "--",
            "-Cpasses=sancov-module",
            "-Cllvm-args=-sanitizer-coverage-level=4",
            "-Cllvm-args=-sanitizer-coverage-inline-8bit-counters",
            f"-Clink-arg={LIBFUZZER}",
            "-Clink-arg=-lstdc++",
        ],
        env=env,
        timeout=args.timeout,
    )
    evidence["commands"].append(build)
    if build["returncode"] != 0:
        evidence["result"] = "FAIL"
        evidence["duration_seconds"] = round(time.monotonic() - started, 3)
        write_evidence(evidence)
        return 1

    if args.manual:
        command = fuzzer_command(runs=None)
        print(" ".join(command))
        return subprocess.call(command, cwd=ROOT)

    fuzz = run(fuzzer_command(runs=args.runs), timeout=args.timeout)
    evidence["commands"].append(fuzz)
    evidence["libfuzzer_output_tail"] = (fuzz["stderr"] + fuzz["stdout"])[-4000:]
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    evidence["result"] = "PASS" if fuzz["returncode"] == 0 else "FAIL"
    write_evidence(evidence)
    return 0 if evidence["result"] == "PASS" else 1


def fuzzer_command(*, runs: int | None) -> list[str]:
    command = [
        str(FUZZER),
        f"-max_len={MAX_INPUT_LEN}",
        f"-artifact_prefix={ARTIFACTS}/",
    ]
    if runs is not None:
        command.append(f"-runs={runs}")
    command.append(str(CORPUS))
    return command


def generate_seed_corpus() -> int:
    accepted = json.loads((FIXTURES / "accepted.json").read_text(encoding="utf-8"))
    rejected = json.loads((FIXTURES / "rejected.json").read_text(encoding="utf-8"))
    vector = accepted["candidate_vectors"][0]
    seeds = [
        b"\x00" + bytes.fromhex(vector["expected_stored_hex"]),
        b"\x01" + bytes.fromhex(vector["expected_record_hex"]),
    ]
    seeds.extend(
        b"\x00" + bytes.fromhex(item["input_hex"])
        for item in rejected["candidate_vectors"]
    )
    for selector in range(SELECTOR_COUNT):
        for payload in (b"", b"\x00", b"\xff", b"SLEYCAN1", bytes(range(64))):
            seeds.append(bytes([selector]) + payload)
    unique_seeds = list(dict.fromkeys(seeds))
    if any(len(seed) > MAX_INPUT_LEN for seed in unique_seeds):
        raise ValueError("candidate conformance seed exceeds the fuzz input ceiling")
    reset_directory(CORPUS)
    for index, seed in enumerate(unique_seeds):
        digest = hashlib.sha256(seed).hexdigest()[:16]
        (CORPUS / f"seed-{index:04d}-{digest}").write_bytes(seed)
    return len(unique_seeds)


def reset_directory(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def toolchain_problems() -> list[str]:
    problems = []
    if shutil.which(CLANG) is None:
        problems.append(f"{CLANG}-missing")
    if not LIBFUZZER.exists():
        problems.append(f"libfuzzer-runtime-missing:{LIBFUZZER}")
    rustup = shutil.which("rustup")
    if rustup is None:
        problems.append("rustup-missing")
    else:
        result = subprocess.run(
            ["rustup", "toolchain", "list"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if RUST_TOOLCHAIN not in result.stdout:
            problems.append(f"rust-toolchain-missing:{RUST_TOOLCHAIN}")
    return problems


def git_output(command: list[str]) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "UNAVAILABLE"


def output_tail(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[-4000:]


def run(
    command: list[str], *, env: dict[str, str] | None = None, timeout: int
) -> dict[str, object]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "argv": command,
            "returncode": completed.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": output_tail(completed.stdout),
            "stderr": output_tail(completed.stderr),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "argv": command,
            "returncode": 124,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": output_tail(error.stdout),
            "stderr": output_tail(error.stderr),
            "timeout_seconds": timeout,
        }


def write_evidence(evidence: dict[str, object]) -> None:
    payload = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    EVIDENCE.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    sys.exit(main())
