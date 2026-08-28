#!/usr/bin/env python3
"""Build and run the S20-360 candidate-result importer libFuzzer target."""

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
RUNTIME = ROOT / "evidence/runtime/s20-360-candidate-result-libfuzzer"
CORPUS = RUNTIME / "corpus"
ARTIFACTS = RUNTIME / "artifacts"
EVIDENCE = RUNTIME / "evidence.json"
TARGET_DIR = RUNTIME / "target"
FUZZER = TARGET_DIR / "release/candidate_result"
FIXTURES = ROOT / "conformance/candidate-result/v1"
CLANG = "clang-18"
RUST_TOOLCHAIN = "nightly-2026-02-27"
LIBFUZZER = Path("/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a")
MAX_INPUT_LEN = 1_048_576
SMOKE_RUNS = 512
SMOKE_TIMEOUT_SECONDS = 60


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
        "candidate_authority": False,
        "commit_authority": False,
        "contract": "s20-360-candidate-result-persistent-libfuzzer-v1",
        "corpus_count": corpus_count,
        "max_input_bytes": MAX_INPUT_LEN,
        "problems": toolchain_problems(),
        "runtime_mutation": False,
        "runtime_path": str(RUNTIME.relative_to(ROOT)),
        "scope": "RESULT_IMPORT_AND_MONOTONIC_SHAPE_NO_AUTHORITY",
        "source_commit": git_output(["git", "rev-parse", "HEAD"]),
        "worktree_dirty": bool(git_output(["git", "status", "--porcelain"])),
        "commands": [],
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
            "candidate_result",
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
        evidence["duration_seconds"] = round(time.monotonic() - started, 3)
        evidence["result"] = "FAIL"
        write_evidence(evidence)
        return 1

    if args.manual:
        command = fuzzer_command(runs=None)
        print(" ".join(command))
        return subprocess.call(command, cwd=ROOT)

    fuzz = run(fuzzer_command(runs=args.runs), timeout=args.timeout)
    evidence["commands"].append(fuzz)
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    evidence["libfuzzer_output_tail"] = (fuzz["stderr"] + fuzz["stdout"])[-4000:]
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


def mutate(data: bytes, operation: str) -> bytes:
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


def generate_seed_corpus() -> int:
    accepted = json.loads((FIXTURES / "accepted.json").read_text(encoding="utf-8"))
    rejected = json.loads((FIXTURES / "rejected.json").read_text(encoding="utf-8"))
    stored_vectors = [bytes.fromhex(value["stored_hex"]) for value in accepted["vectors"]]
    valid_seed = next(
        bytes.fromhex(value["stored_hex"])
        for value in accepted["vectors"]
        if value["decision"] == "VALID"
    )
    seeds = list(stored_vectors)
    seeds.extend(
        mutate(valid_seed, value["operation"]) for value in rejected["mutations"]
    )
    seeds.extend((b"", b"\x00", b"\xff", b"SLEYCRS1", bytes(range(64))))
    unique_seeds = list(dict.fromkeys(seeds))
    if any(len(seed) > MAX_INPUT_LEN for seed in unique_seeds):
        raise ValueError("candidate-result conformance seed exceeds fuzz input ceiling")
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
            "duration_seconds": round(time.monotonic() - started, 3),
            "returncode": completed.returncode,
            "stderr": output_tail(completed.stderr),
            "stdout": output_tail(completed.stdout),
        }
    except subprocess.TimeoutExpired as error:
        return {
            "argv": command,
            "duration_seconds": round(time.monotonic() - started, 3),
            "returncode": 124,
            "stderr": output_tail(error.stderr),
            "stdout": output_tail(error.stdout),
            "timeout_seconds": timeout,
        }


def write_evidence(evidence: dict[str, object]) -> None:
    payload = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    EVIDENCE.write_text(payload, encoding="utf-8")
    print(payload, end="")


if __name__ == "__main__":
    sys.exit(main())
