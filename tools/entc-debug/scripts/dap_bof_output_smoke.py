#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""dap_bof_output_smoke.py - confirm BeaconPrintf output reaches DAP.

Launches a BOF through entc-debug.exe in DAP mode WITHOUT stopOnEntry,
runs it to completion, and prints every `output` event the adapter
emits. Without the output-hook wiring, the BOF's BeaconPrintf writes
land on entc-debug's own stdout (which is the DAP wire channel) and
get either dropped by VS Code or corrupt the next DAP frame - either
way the user sees nothing in the Debug Console.

With the hook installed, every BeaconPrintf turns into one DAP
`output` event with category "console", which is exactly what shows
up in VS Code's Debug Console panel.

Usage:
    python dap_bof_output_smoke.py <path/to/source.etpy> [bof_args...]
"""

import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
ENTC_DEBUG = REPO / "target" / "release" / "entc-debug.exe"


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
    if len(sys.argv) < 2:
        print("usage: dap_bof_output_smoke.py <path/to/source.etpy> [args...]")
        return 2
    source = Path(sys.argv[1]).resolve()
    bof_args = sys.argv[2:]
    if not ENTC_DEBUG.exists():
        print(f"missing: {ENTC_DEBUG}")
        return 1

    proc = subprocess.Popen(
        [str(ENTC_DEBUG), "dap"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0,
    )
    seq = 1
    send(proc, seq, "initialize", adapterID="entropykit"); seq += 1
    send(proc, seq, "launch",
         program=str(source),
         stopOnEntry=False,
         args=bof_args); seq += 1

    output_events = []
    deadline = time.time() + 60
    done = False
    while not done and time.time() < deadline:
        msg = read_frame(proc)
        if msg is None: break
        if msg.get("type") == "response":
            cmd = msg["command"]
            if cmd == "launch":
                if not msg.get("success"):
                    print(f"FAIL: launch failed: {msg.get('message')}")
                    return 1
                send(proc, seq, "configurationDone"); seq += 1
        elif msg.get("type") == "event":
            ev = msg.get("event")
            body = msg.get("body", {})
            if ev == "output":
                output_events.append(body.get("output", ""))
            elif ev in ("exited", "terminated"):
                done = True
                send(proc, seq, "disconnect", terminateDebuggee=True); seq += 1

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate(); proc.wait()

    # Reconfigure stdout for UTF-8 so non-ASCII bytes (em-dashes,
    # smart quotes, etc.) in BOF output don't trip CP1252 encoding
    # on Windows. The DAP channel itself is UTF-8 end-to-end.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    print(f"[smoke] received {len(output_events)} `output` event(s):")
    for ev in output_events:
        sys.stdout.write(f"  {ev.rstrip()}\n")
    # Pass criterion: AT LEAST ONE output event whose text contains
    # the BOF marker `[BOF]`. Without the hook, the BOF's print
    # writes never reach DAP  to  zero `[BOF]` lines.
    bof_lines = [e for e in output_events if "[BOF]" in e]
    if bof_lines:
        print(f"[smoke] PASS - saw {len(bof_lines)} [BOF] line(s) routed through DAP")
        return 0
    print("[smoke] FAIL - no [BOF] output events flowed through DAP")
    return 1


if __name__ == "__main__":
    sys.exit(main())
