#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORK = ROOT / "target" / "entropia-safe-tests"
FIXTURES = WORK / "fixtures"
RESULTS = WORK / "results.json"

@dataclass
class TestResult:
    name: str
    passed: bool
    seconds: float
    command: List[str]
    stdout_tail: str
    stderr_tail: str
    detail: str

def tail(s: str, n: int = 4000) -> str:
    return s[-n:] if len(s) > n else s

def log(msg: str) -> None:
    print(f"[+] {msg}", flush=True)

def err(msg: str) -> None:
    print(f"[x] {msg}", file=sys.stderr, flush=True)

def run_cmd(cmd: List[str], cwd: pathlib.Path = ROOT, timeout: int = 120, expect_ok: bool = True) -> Tuple[bool, float, str, str, int]:
    start = time.time()
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        elapsed = time.time() - start
        ok = (p.returncode == 0) if expect_ok else (p.returncode != 0)
        return ok, elapsed, p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        elapsed = time.time() - start
        out = e.stdout if isinstance(e.stdout, str) else ""
        serr = e.stderr if isinstance(e.stderr, str) else ""
        return False, elapsed, out, serr + f"\nTIMEOUT after {timeout}s", 124

def exe_name(base: str) -> str:
    return base + (".exe" if os.name == "nt" else "")

def find_entc(release: bool) -> Optional[pathlib.Path]:
    candidates = []
    if release:
        candidates.append(ROOT / "target" / "release" / exe_name("entc"))
        candidates.append(ROOT / "target" / "release" / exe_name("entropykit"))
    candidates.append(ROOT / "target" / "debug" / exe_name("entc"))
    candidates.append(ROOT / "target" / "debug" / exe_name("entropykit"))
    candidates.append(ROOT / "target" / "release" / exe_name("entc"))
    candidates.append(ROOT / "target" / "release" / exe_name("entropykit"))
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    return None

def write_fixture(path: pathlib.Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body.strip() + "\n", encoding="utf-8")

def fixture_files() -> None:
    if FIXTURES.exists():
        shutil.rmtree(FIXTURES)
    FIXTURES.mkdir(parents=True, exist_ok=True)

    write_fixture(FIXTURES / "sc_return_zero.etpy", r'''
fn main() -> int {
    ret 0;
}
''')

    write_fixture(FIXTURES / "sc_arithmetic.etpy", r'''
fn main() -> int {
    var a: int = 40;
    var b: int = 2;
    var c: int = a + b;
    ret c;
}
''')

    write_fixture(FIXTURES / "sc_loop_branch.etpy", r'''
fn main() -> int {
    var i: int = 0;
    var total: int = 0;
    while i < 5 {
        total = total + i;
        i = i + 1;
    }
    if total == 10 {
        ret 0;
    }
    ret 1;
}
''')

    write_fixture(FIXTURES / "bof_minimal.etpy", r'''
use bof;

fn go(args: char*, len: int) -> void {
    ret;
}
''')

    write_fixture(FIXTURES / "bof_print_only.etpy", r'''
use bof;

fn go(args: char*, len: int) -> void {
    BeaconPrintf(CALLBACK_OUTPUT, "entropia safe BOF compile smoke test\n");
    ret;
}
''')

    write_fixture(FIXTURES / "bad_syntax_missing_semicolon.etpy", r'''
fn main() -> int {
    var a: int = 1
    ret a;
}
''')

    write_fixture(FIXTURES / "bad_type_return_pointer_as_int.etpy", r'''
fn main() -> int {
    var p: char* = "bad";
    ret p;
}
''')

def newest_output_for(src: pathlib.Path, suffixes: List[str], since: float) -> Optional[pathlib.Path]:
    candidates = []
    dirs = [src.parent, ROOT / "examples" / "bin", WORK]
    for d in dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if p.is_file() and p.stat().st_mtime >= since - 1:
                if p.suffix.lower() in suffixes:
                    candidates.append(p)
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None

def inspect_shellcode(path: pathlib.Path) -> Tuple[bool, str]:
    data = path.read_bytes()
    if len(data) < 1:
        return False, f"{path} is empty"
    if data[:2] == b"MZ":
        return False, f"{path} starts with MZ; expected raw blob, not PE"
    if len(data) > 5_000_000:
        return False, f"{path} is unexpectedly large: {len(data)} bytes"
    return True, f"{path.name}: {len(data)} bytes; non-empty raw blob shape"

def inspect_coff(path: pathlib.Path) -> Tuple[bool, str]:
    data = path.read_bytes()
    if len(data) < 20:
        return False, f"{path} too small for COFF object"
    machine = int.from_bytes(data[0:2], "little")
    sections = int.from_bytes(data[2:4], "little")
    if machine != 0x8664:
        return False, f"{path} machine=0x{machine:04x}; expected x86-64 COFF 0x8664"
    if sections < 1 or sections > 96:
        return False, f"{path} suspicious section count: {sections}"
    if data[:2] == b"MZ":
        return False, f"{path} starts with MZ; expected COFF object, not PE"
    return True, f"{path.name}: x86-64 COFF object; sections={sections}; bytes={len(data)}"

def compiler_sanity_probe(entc: pathlib.Path, timeout: int) -> Tuple[bool, float, List[str], str, str, str]:
    probes = [
        [str(entc), "--help"],
        [str(entc), "help"],
        [str(entc)],
        [str(entc), "compile"],
    ]

    last_sec = 0.0
    last_out = ""
    last_serr = ""
    last_detail = "compiler did not produce controlled output for any sanity probe"

    for cmd in probes:
        ok, sec, out, serr, code = run_cmd(cmd, timeout=timeout, expect_ok=True)
        del ok
        combined = (out + "\n" + serr).strip()
        last_sec = sec
        last_out = out
        last_serr = serr

        if code < 0:
            last_detail = f"compiler crashed by signal {-code}"
            continue
        if code == 124:
            last_detail = f"compiler timed out after {timeout}s"
            continue
        if not combined:
            last_detail = f"compiler produced no stdout/stderr; exit={code}"
            continue
        if code == 0:
            return True, sec, cmd, out, serr, f"compiler responded successfully; exit={code}"
        if code in (1, 2):
            return True, sec, cmd, out, serr, f"compiler responded with controlled usage/error output; exit={code}"

        last_detail = f"compiler produced output but exited unexpectedly; exit={code}"

    return False, last_sec, probes[0], last_out, last_serr, last_detail

def main() -> int:
    ap = argparse.ArgumentParser(description="Safe Entropia compiler smoke tests. Compiles and inspects artifacts; never executes generated artifacts.")
    ap.add_argument("--release", action="store_true", help="Build/use release entc instead of debug")
    ap.add_argument("--skip-build", action="store_true", help="Do not run cargo build first")
    ap.add_argument("--timeout", type=int, default=120, help="Per-command timeout seconds")
    args = ap.parse_args()

    if not (ROOT / "Cargo.toml").exists():
        err("Cargo.toml not found; run from cloned entropia repo with this script under tools/")
        return 2

    WORK.mkdir(parents=True, exist_ok=True)
    fixture_files()

    results: List[TestResult] = []

    def record(name: str, passed: bool, seconds: float, command: List[str], stdout: str, stderr: str, detail: str) -> None:
        results.append(TestResult(name, passed, seconds, command, tail(stdout), tail(stderr), detail))
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {name} - {detail}", flush=True)

    if not args.skip_build:
        cmd = ["cargo", "build"]
        if args.release:
            cmd.append("--release")
        log("Building Rust workspace")
        ok, sec, out, serr, code = run_cmd(cmd, timeout=max(args.timeout, 300))
        record("cargo_build", ok, sec, cmd, out, serr, f"exit={code}")
        if not ok:
            RESULTS.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
            return 1

    entc = find_entc(args.release)
    if not entc:
        err("Could not find entc or entropykit binary under target/{debug,release}")
        RESULTS.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
        return 1

    log(f"Using compiler: {entc}")

    ok, sec, cmd, out, serr, detail = compiler_sanity_probe(entc, args.timeout)
    record("entc_binary_sanity", ok, sec, cmd, out, serr, detail)

    shellcode_cases = [
        "sc_return_zero.etpy",
        "sc_arithmetic.etpy",
        "sc_loop_branch.etpy",
    ]

    bof_cases = [
        "bof_minimal.etpy",
        "bof_print_only.etpy",
    ]

    negative_cases = [
        "bad_syntax_missing_semicolon.etpy",
        "bad_type_return_pointer_as_int.etpy",
    ]

    for name in shellcode_cases:
        src = FIXTURES / name
        before = time.time()
        cmd = [str(entc), "compile", str(src)]
        ok, sec, out, serr, code = run_cmd(cmd, timeout=args.timeout)
        detail = f"exit={code}"
        if ok:
            outp = newest_output_for(src, [".bin"], before)
            if outp:
                shape_ok, shape_detail = inspect_shellcode(outp)
                ok = ok and shape_ok
                detail = shape_detail
            else:
                ok = False
                detail = "compiled but no .bin output found"
        record(f"compile_shellcode_{src.stem}", ok, sec, cmd, out, serr, detail)

    for name in bof_cases:
        src = FIXTURES / name
        before = time.time()
        cmd = [str(entc), "compile", str(src), "--type=bof"]
        ok, sec, out, serr, code = run_cmd(cmd, timeout=args.timeout)
        detail = f"exit={code}"
        if ok:
            outp = newest_output_for(src, [".o"], before)
            if outp:
                shape_ok, shape_detail = inspect_coff(outp)
                ok = ok and shape_ok
                detail = shape_detail
            else:
                ok = False
                detail = "compiled but no .o output found"
        record(f"compile_bof_{src.stem}", ok, sec, cmd, out, serr, detail)

    for name in negative_cases:
        src = FIXTURES / name
        cmd = [str(entc), "compile", str(src)]
        ok, sec, out, serr, code = run_cmd(cmd, timeout=args.timeout, expect_ok=False)
        detail = f"expected compiler failure; exit={code}"
        record(f"negative_{src.stem}", ok, sec, cmd, out, serr, detail)

    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    RESULTS.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")

    print("")
    print(f"[+] Results written: {RESULTS}")
    print(f"[+] Summary: passed={passed} failed={failed} total={len(results)}")

    if failed:
        print("[x] Failed tests:", file=sys.stderr)
        for r in results:
            if not r.passed:
                print(f"    - {r.name}: {r.detail}", file=sys.stderr)
        return 1

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
