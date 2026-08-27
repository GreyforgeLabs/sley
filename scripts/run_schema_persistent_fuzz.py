#!/usr/bin/env python3
"""Build and run the S20-700 schema bootstrap persistent libFuzzer target."""

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
RUNTIME = ROOT / "evidence/runtime/s20-700-schema-bootstrap-libfuzzer"
CORPUS = RUNTIME / "corpus"
ARTIFACTS = RUNTIME / "artifacts"
EVIDENCE = RUNTIME / "evidence.json"
TARGET_DIR = RUNTIME / "target"
FUZZER = TARGET_DIR / "release/schema_bootstrap_decoder"
FIXTURE = ROOT / "conformance/schema-epoch/v1/bootstrap.json"
CLANG = "clang-18"
RUST_TOOLCHAIN = "nightly-2026-02-27"
LIBFUZZER = Path("/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a")
MAX_LEN = 2048
SMOKE_RUNS = 256
SMOKE_TIMEOUT_SECONDS = 60
EXPECTED_SEED_COUNT = 255


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manual", action="store_true", help="run indefinitely until interrupted")
    parser.add_argument("--runs", type=int, default=SMOKE_RUNS)
    parser.add_argument("--timeout", type=int, default=SMOKE_TIMEOUT_SECONDS)
    args = parser.parse_args()
    if args.runs < 0 or args.timeout <= 0:
        parser.error("--runs must be nonnegative and --timeout must be positive")

    started = time.monotonic()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    corpus_count = generate_seed_corpus()
    if corpus_count != EXPECTED_SEED_COUNT:
        raise SystemExit(
            f"schema bootstrap seed count drifted: {corpus_count} != {EXPECTED_SEED_COUNT}"
        )

    evidence: dict[str, object] = {
        "contract": "s20-700-schema-bootstrap-persistent-libfuzzer-slice-v1",
        "scope": "SCHEMA_BOOTSTRAP_DECODER_ONLY",
        "full_s20_700_complete": False,
        "max_input_bytes": MAX_LEN,
        "corpus_count": corpus_count,
        "seed_source": str(FIXTURE.relative_to(ROOT)),
        "runtime_path": str(RUNTIME.relative_to(ROOT)),
        "commands": [],
        "problems": [],
    }

    for problem in toolchain_problems():
        evidence["problems"].append(problem)
    if evidence["problems"]:
        evidence["result"] = "BLOCKED"
        EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps(evidence, indent=2, sort_keys=True))
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
            "schema_bootstrap_decoder",
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
        EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 1

    if args.manual:
        command = [
            str(FUZZER),
            f"-max_len={MAX_LEN}",
            f"-artifact_prefix={ARTIFACTS}/",
            str(CORPUS),
        ]
        print(" ".join(command))
        return subprocess.call(command, cwd=ROOT)

    fuzz = run(
        [
            str(FUZZER),
            f"-runs={args.runs}",
            f"-max_len={MAX_LEN}",
            f"-artifact_prefix={ARTIFACTS}/",
            str(CORPUS),
        ],
        timeout=args.timeout,
    )
    evidence["commands"].append(fuzz)
    evidence["libfuzzer_output_tail"] = (fuzz["stderr"] + fuzz["stdout"])[-4000:]
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    evidence["result"] = "PASS" if fuzz["returncode"] == 0 else "FAIL"
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0 if evidence["result"] == "PASS" else 1


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


def generate_seed_corpus() -> int:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    CORPUS.mkdir(parents=True)

    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if vector.get("contract") != "sley2-schema-epoch-bootstrap-v1":
        raise SystemExit("schema bootstrap fixture contract drifted")
    canonical = bytes.fromhex(vector["preimage_hex"])
    record = bytes.fromhex(vector["record_hex"])
    if not canonical.startswith(b"SLEYEP01") or not canonical.endswith(record):
        raise SystemExit("schema bootstrap fixture structure drifted")
    if len(canonical) > MAX_LEN:
        raise SystemExit("schema bootstrap fixture exceeds fuzz target bound")

    seeds = [canonical[:length] for length in range(1, len(canonical) + 1)]
    seeds.extend([record, b"SLEYEP01", canonical + b"\x00", canonical + b"\xff"])
    for index in range(len(canonical)):
        low_flip = bytearray(canonical)
        low_flip[index] ^= 0x01
        seeds.append(bytes(low_flip))
        high_flip = bytearray(canonical)
        high_flip[index] ^= 0x80
        seeds.append(bytes(high_flip))

    unique_seeds = list(dict.fromkeys(seeds))
    for index, seed in enumerate(unique_seeds):
        digest = hashlib.sha256(seed).hexdigest()[:16]
        (CORPUS / f"seed-{index:04d}-{digest}").write_bytes(seed)
    return len(unique_seeds)


def run(command: list[str], *, env: dict[str, str] | None = None, timeout: int) -> dict[str, object]:
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
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
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


def output_tail(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return value[-4000:]


if __name__ == "__main__":
    sys.exit(main())
