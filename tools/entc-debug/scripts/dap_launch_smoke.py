#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""dap_launch_smoke.py - simulate a VS Code F5 against entc-debug.

Drives entc-debug.exe's DAP-on-stdio protocol with the exact sequence
VS Code sends:

    initialize -> launch (program=.etpy) -> configurationDone
    -> wait for `stopped` event (stopOnEntry confirms the right
        artifact loaded) -> disconnect

Exit code 0 means F5 against the given .etpy successfully:
  - auto-detected build mode
  - rebuilt the artifact
  - loaded the .dbg sidecar
  - planted the entry stopOnEntry breakpoint
  - hit it (proves the right .obj/.bin actually ran)

Usage:
    python dap_launch_smoke.py <path/to/source.etpy> [bof_arg ...]
"""

import json
import struct
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
    """Read one DAP frame from stdout. Returns the parsed dict or None
    on EOF / timeout."""
    headers = b""
    while not headers.endswith(b"\r\n\r\n"):
        b = proc.stdout.read(1)
        if not b:
            return None
        headers += b
    # Parse Content-Length.
    length = 0
    for line in headers.decode().split("\r\n"):
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    body = b""
    while len(body) < length:
        chunk = proc.stdout.read(length - len(body))
        if not chunk:
            return None
        body += chunk
    return json.loads(body)


def send(proc, seq, command, **kwargs):
    msg = {"seq": seq, "type": "request", "command": command, "arguments": kwargs}
    proc.stdin.write(encode_msg(msg))
    proc.stdin.flush()


def main():
    if len(sys.argv) < 2:
        print("usage: dap_launch_smoke.py <path/to/source.etpy> [bof_args...]")
        return 2
    source = Path(sys.argv[1]).resolve()
    bof_args = sys.argv[2:]

    # Note: we deliberately don't pre-check source.exists() - the
    # whole point of the adapter's auto-upgrade-to-source-mode path
    # is to handle a missing artifact with a sibling .etpy by
    # rebuilding from source. We want to exercise that.
    if not ENTC_DEBUG.exists():
        print(f"entc-debug not found: {ENTC_DEBUG}")
        print("Run: cargo build --release -p entc-debug")
        return 1

    print(f"[smoke] launching {ENTC_DEBUG.name} against {source.name}")
    proc = subprocess.Popen(
        [str(ENTC_DEBUG), "dap"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        bufsize=0,
    )

    seq = 1
    send(proc, seq, "initialize", clientID="smoke", adapterID="entropykit"); seq += 1
    launch_args = {
        "program":     str(source),
        "stopOnEntry": True,
        "args":        bof_args,
    }
    send(proc, seq, "launch", **launch_args); seq += 1

    stopped_received = False
    launch_ok = None
    deadline = time.time() + 30
    sent_config_done = False
    while time.time() < deadline:
        proc.stdout_ready = True
        # NOTE: read_frame blocks; that's fine for this smoke test
        # because entc-debug emits frames promptly during launch.
        msg = read_frame(proc)
        if msg is None:
            print("[smoke] EOF before stop")
            break
        kind = msg.get("type")
        if kind == "response":
            cmd = msg.get("command")
            ok = msg.get("success", False)
            if cmd == "launch":
                launch_ok = ok
                if not ok:
                    print(f"[smoke] launch failed: {msg.get('message')}")
                    break
                send(proc, seq, "configurationDone"); seq += 1
                sent_config_done = True
            elif cmd == "configurationDone":
                pass
        elif kind == "event":
            ev = msg.get("event")
            body = msg.get("body", {})
            if ev == "output":
                text = body.get("output", "").rstrip()
                if text:
                    print(f"  [stdout] {text}")
            elif ev == "stopped":
                reason = body.get("reason", "?")
                print(f"[smoke] stopped (reason={reason})")
                if reason in ("entry", "breakpoint"):
                    stopped_received = True
                    send(proc, seq, "disconnect", terminateDebuggee=True); seq += 1
                    break
            elif ev == "terminated":
                print("[smoke] terminated event")
                break
            elif ev == "exited":
                code = body.get("exitCode", 0)
                print(f"[smoke] exited code={code}")

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait()

    stderr = proc.stderr.read().decode("utf-8", errors="replace")
    if stderr.strip():
        print(f"[smoke] adapter stderr: {stderr}")

    if launch_ok and stopped_received:
        print("[smoke] PASS")
        return 0
    print(f"[smoke] FAIL (launch_ok={launch_ok}, stopped={stopped_received})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
