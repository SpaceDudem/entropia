#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""dap_asm_bp_smoke.py - verify F9 inside `asm { ... }` plants and
fires a breakpoint at the right .bin offset.

Drives entc-debug.exe over DAP-on-stdio with the exact sequence VS
Code's "set breakpoint, then F5" flow uses:

    initialize -> launch (stopOnEntry: false, no inherent break)
    -> setBreakpoints(asm_test.etpy, [<inline-asm line>])
    -> configurationDone
    -> wait for `stopped` with reason=breakpoint
    -> assert the stop's `line` == the line we set

Usage:
    python dap_asm_bp_smoke.py
"""

import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
ENTC_DEBUG = REPO / "target" / "release" / "entc-debug.exe"
SOURCE     = REPO / "example" / "asm_test.etpy"


def encode_msg(obj):
    body = json.dumps(obj).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode() + body


def read_frame(proc):
    headers = b""
    while not headers.endswith(b"\r\n\r\n"):
        b = proc.stdout.read(1)
        if not b: return None
        headers += b
    length = 0
    for line in headers.decode().split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    body = b""
    while len(body) < length:
        chunk = proc.stdout.read(length - len(body))
        if not chunk: return None
        body += chunk
    return json.loads(body)


def send(proc, seq, command, **kwargs):
    proc.stdin.write(encode_msg({
        "seq": seq, "type": "request", "command": command, "arguments": kwargs,
    }))
    proc.stdin.flush()


def main():
    # Allow overriding target line via CLI for testing several
    # asm-body lines (instruction, label, post-loop body).
    target_line = int(sys.argv[1]) if len(sys.argv) > 1 else 24

    proc = subprocess.Popen(
        [str(ENTC_DEBUG), "dap"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0,
    )

    seq = 1
    send(proc, seq, "initialize", adapterID="entropykit"); seq += 1
    send(proc, seq, "launch",
         program=str(SOURCE),
         stopOnEntry=False); seq += 1

    breakpoints_set = False
    verified_line = None    # what setBreakpoints reported
    stop_line = None        # what stackTrace reported when bp fired
    deadline = time.time() + 30
    while time.time() < deadline:
        msg = read_frame(proc)
        if msg is None: break
        if msg.get("type") == "response":
            cmd = msg["command"]
            if cmd == "launch" and msg.get("success"):
                send(proc, seq, "setBreakpoints",
                     source={"path": str(SOURCE)},
                     breakpoints=[{"line": target_line}]); seq += 1
            elif cmd == "launch":
                print(f"[asm-bp-smoke] launch failed: {msg.get('message')}")
                break
            elif cmd == "setBreakpoints":
                rows = msg.get("body", {}).get("breakpoints", [])
                verified = [r for r in rows if r.get("verified")]
                if not verified:
                    print(f"[asm-bp-smoke] FAIL: bp at line {target_line} not verified: {rows}")
                    break
                verified_line = verified[0].get("line")
                print(f"[asm-bp-smoke] bp at requested line {target_line} verified, mapped to {verified_line}")
                breakpoints_set = True
                send(proc, seq, "configurationDone"); seq += 1
            elif cmd == "configurationDone":
                pass
        elif msg.get("type") == "event":
            ev = msg.get("event")
            body = msg.get("body", {})
            if ev == "stopped" and body.get("reason") == "breakpoint":
                send(proc, seq, "stackTrace", threadId=1); seq += 1
            elif ev == "terminated":
                print("[asm-bp-smoke] terminated before bp hit")
                break
        if msg.get("command") == "stackTrace" and msg.get("type") == "response":
            frames = msg.get("body", {}).get("stackFrames", [])
            if frames:
                stop_line = frames[0].get("line")
                send(proc, seq, "disconnect", terminateDebuggee=True); seq += 1
                break

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate(); proc.wait()

    # Pass criteria:
    #   - setBreakpoints verified the bp (either the requested line
    #     or a forward-snapped one - both are valid).
    #   - The stop fired and reported a source line consistent with
    #     the verified one.
    if breakpoints_set and stop_line == verified_line and verified_line is not None:
        print(f"[asm-bp-smoke] PASS - bp at requested={target_line} verified={verified_line} stop={stop_line}")
        return 0
    print(f"[asm-bp-smoke] FAIL - requested={target_line} verified={verified_line} stop={stop_line}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
