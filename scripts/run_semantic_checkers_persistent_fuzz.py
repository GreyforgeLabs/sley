#!/usr/bin/env python3
"""Build and run scoped persistent fuzz targets for public semantic checkers."""

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
RUNTIME = ROOT / "evidence/runtime/s20-700-semantic-checkers-libfuzzer"
TARGET_DIR = RUNTIME / "target"
EVIDENCE = RUNTIME / "evidence.json"
HARNESS_REGRESSION = ROOT / "fuzz/regressions/S20_700_HARNESS_001.json"
CLANG = "clang-18"
RUST_TOOLCHAIN = "nightly-2026-02-27"
LIBFUZZER = Path("/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a")
MAX_INPUT_LEN = 4096
SMOKE_RUNS = 256
SMOKE_TIMEOUT_SECONDS = 60
TARGETS = {
    "type-checker": {
        "binary": "type_checker",
        "scope": "S20_210_PUBLIC_TYPED_TYPE_CHECKER",
        "corpus": RUNTIME / "type-checker-corpus",
        "artifacts": RUNTIME / "type-checker-artifacts",
    },
    "graph-cfg": {
        "binary": "ssmc_graph_cfg_checker",
        "scope": "S20_220_PUBLIC_TYPED_GRAPH_CFG_CHECKER",
        "corpus": RUNTIME / "graph-cfg-corpus",
        "artifacts": RUNTIME / "graph-cfg-artifacts",
    },
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manual", action="store_true", help="run one target until interrupted")
    parser.add_argument(
        "--target",
        choices=["all", *TARGETS],
        default="all",
        help="target to run; smoke mode defaults to both",
    )
    parser.add_argument("--runs", type=int, default=SMOKE_RUNS)
    parser.add_argument("--timeout", type=int, default=SMOKE_TIMEOUT_SECONDS)
    args = parser.parse_args()
    if args.runs < 0 or args.timeout <= 0:
        parser.error("--runs must be nonnegative and --timeout must be positive")
    if args.manual and args.target == "all":
        parser.error("--manual requires --target type-checker or --target graph-cfg")

    selected = list(TARGETS) if args.target == "all" else [args.target]
    started = time.monotonic()
    RUNTIME.mkdir(parents=True, exist_ok=True)
    corpus_counts = {
        "type-checker": generate_type_checker_corpus(),
        "graph-cfg": generate_graph_cfg_corpus(),
    }
    for target in TARGETS.values():
        reset_directory(target["artifacts"])

    evidence: dict[str, object] = {
        "contract": "s20-700-semantic-checkers-persistent-libfuzzer-slice-v1",
        "scope": "PUBLIC_TYPED_S20_210_AND_S20_220_CHECKERS_ONLY",
        "full_s20_700_complete": False,
        "canonical_graph_decoder_claimed": False,
        "private_mutation_codec_used": False,
        "max_input_bytes": MAX_INPUT_LEN,
        "selected_targets": selected,
        "synthetic_seed_grammar": "bounded fuzz-only typed constructors v1",
        "development_regression_fixture": str(HARNESS_REGRESSION.relative_to(ROOT)),
        "source_commit": git_output(["git", "rev-parse", "HEAD"]),
        "worktree_dirty": bool(git_output(["git", "status", "--porcelain"])),
        "targets": {},
        "commands": [],
        "problems": toolchain_problems(),
    }
    for name in selected:
        evidence["targets"][name] = {
            "scope": TARGETS[name]["scope"],
            "corpus_count": corpus_counts[name],
            "corpus_path": str(TARGETS[name]["corpus"].relative_to(ROOT)),
        }

    if evidence["problems"]:
        evidence["result"] = "BLOCKED"
        write_evidence(evidence)
        return 2

    env = os.environ.copy()
    env["CC"] = CLANG
    for name in selected:
        binary = str(TARGETS[name]["binary"])
        build = run(
            [
                "cargo",
                f"+{RUST_TOOLCHAIN}",
                "rustc",
                "--manifest-path",
                "fuzz/Cargo.toml",
                "--bin",
                binary,
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
        evidence["targets"][name]["build_result"] = (
            "PASS" if build["returncode"] == 0 else "FAIL"
        )
        if build["returncode"] != 0:
            evidence["result"] = "FAIL"
            evidence["duration_seconds"] = round(time.monotonic() - started, 3)
            write_evidence(evidence)
            return 1

    if args.manual:
        name = selected[0]
        command = fuzzer_command(name, runs=None)
        print(" ".join(command))
        return subprocess.call(command, cwd=ROOT)

    failed = False
    for name in selected:
        fuzz = run(fuzzer_command(name, runs=args.runs), timeout=args.timeout)
        evidence["commands"].append(fuzz)
        evidence["targets"][name]["fuzz_result"] = (
            "PASS" if fuzz["returncode"] == 0 else "FAIL"
        )
        evidence["targets"][name]["libfuzzer_output_tail"] = (
            fuzz["stderr"] + fuzz["stdout"]
        )[-4000:]
        failed = failed or fuzz["returncode"] != 0

    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    evidence["result"] = "FAIL" if failed else "PASS"
    write_evidence(evidence)
    return 1 if failed else 0


def fuzzer_command(name: str, *, runs: int | None) -> list[str]:
    target = TARGETS[name]
    command = [
        str(TARGET_DIR / "release" / str(target["binary"])),
        f"-max_len={MAX_INPUT_LEN}",
        f"-artifact_prefix={target['artifacts']}/",
    ]
    if runs is not None:
        command.append(f"-runs={runs}")
    command.append(str(target["corpus"]))
    return command


def generate_type_checker_corpus() -> int:
    seeds = [bytes([value]) for value in range(256)]
    regression = json.loads(HARNESS_REGRESSION.read_text(encoding="utf-8"))
    if regression.get("finding_id") != "S20-700-HARNESS-001":
        raise SystemExit("semantic-checker harness regression fixture drifted")
    seeds.append(bytes.fromhex(regression["input_hex"]))
    for value in range(128):
        seeds.append(
            bytes((value + (offset * 17)) % 256 for offset in range(1 + (value % 31)))
        )
    seeds.extend(
        [
            bytes([0, 0, 0, 0]),
            bytes([1, 0, 1, 0, 1, 0, 1, 0]),
            bytes([8, 4, 3, 2, 1, 0, 19, 18, 17, 16]),
            bytes(range(64)),
            bytes(reversed(range(64))),
            bytes([0xFF]) * 64,
        ]
    )
    return write_corpus(TARGETS["type-checker"]["corpus"], seeds)


def generate_graph_cfg_corpus() -> int:
    seeds = [bytes([template, 0]) for template in range(4)]
    for template in range(4):
        for mutation in range(33):
            for argument in (0, 0xFF):
                seeds.append(bytes([template, 1, mutation, argument, mutation ^ argument]))
        for offset in range(32):
            seeds.append(
                bytes(
                    [
                        template,
                        4,
                        offset % 33,
                        (offset + 7) % 33,
                        (offset + 13) % 33,
                        (offset + 23) % 33,
                        offset,
                        0xFF - offset,
                    ]
                )
            )
    return write_corpus(TARGETS["graph-cfg"]["corpus"], seeds)


def write_corpus(path: Path, seeds: list[bytes]) -> int:
    reset_directory(path)
    unique_seeds = list(dict.fromkeys(seeds))
    for index, seed in enumerate(unique_seeds):
        digest = hashlib.sha256(seed).hexdigest()[:16]
        (path / f"seed-{index:04d}-{digest}").write_bytes(seed)
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


def write_evidence(evidence: dict[str, object]) -> None:
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print(json.dumps(evidence, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
