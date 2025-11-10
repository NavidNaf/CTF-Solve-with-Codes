#!/usr/bin/env python3
# Forge an admin signature for the nitwit Winternitz OTS service.
DESCRIPTION = "Exploit for nitwit-chal.py (Winternitz OTS service)."

from __future__ import annotations

import argparse
import ast
import hashlib
from math import log
from typing import List, Sequence

from pwn import remote, process

# Match challenge parameters
v = 256
hash_size = 32
d = 15
n_0 = 64
n_1 = int(log(n_0, d + 1)) + 1
n = n_0 + n_1


# Compute the SHA256 digest for the input bytes.
def get_hash(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


# Walk the hash chain forward by applying SHA256 repeatedly.
def hash_chain(x: bytes, steps: int) -> bytes:
    for _ in range(steps):
        x = get_hash(x)
    return x


# Convert an integer into a fixed-length vector using the provided base.
def int_to_vec(m: int, vec_len: int, base: int) -> List[int]:
    digits = [0] * vec_len
    i = len(digits) - 1
    while m > 0:
        digits[i] = m % base
        m //= base
        i -= 1
    return digits


# Build the domination-free vector for a message according to the Winternitz scheme.
def domination_free_function(m: int) -> List[int]:
    m_vec = int_to_vec(m, n_0, d + 1)
    c = (d * n_0) - sum(m_vec)
    c_vec = int_to_vec(c, n_1, d + 1)
    return m_vec + c_vec


# Messages we use
TARGET_MESSAGE = (b"admin" + b"\x00" * 27)
SIGNED_MESSAGE = (b"`dmin" + b"\x00" * 27)

TARGET_VEC = domination_free_function(int.from_bytes(TARGET_MESSAGE, "big"))
SIGNED_VEC = domination_free_function(int.from_bytes(SIGNED_MESSAGE, "big"))
DIFF_VEC = [t - s for s, t in zip(SIGNED_VEC, TARGET_VEC)]
assert all(diff >= 0 for diff in DIFF_VEC), "Vector domination assumption failed"


# Parse the multi-line signature block returned by the service.
def parse_signature(text: str) -> List[bytes]:
    sig = ast.literal_eval(text.strip())
    if not isinstance(sig, list):
        raise ValueError("Signature parse failure")
    if len(sig) != n:
        raise ValueError("Unexpected signature length")
    if not all(isinstance(x, bytes) and len(x) == hash_size for x in sig):
        raise ValueError("Malformed signature entries")
    return sig


# Forge a signature by advancing each chain entry according to the difference vector.
def forge_signature(signature: Sequence[bytes]) -> List[bytes]:
    forged = []
    for chunk, delta in zip(signature, DIFF_VEC):
        forged.append(hash_chain(chunk, delta))
    return forged


# Read the serialized signature block emitted by the challenge process.
def read_signature_block(io) -> str:
    lines: List[str] = []
    depth = 0
    while True:
        line = io.recvline()
        if not line:
            break
        decoded = line.decode()
        if not decoded.strip():
            continue
        lines.append(decoded)
        depth += decoded.count("[") - decoded.count("]")
        if depth <= 0:
            break
    return "".join(lines)


# Drive the protocol to obtain a signature, forge it, and submit the goal message.
def interact(cmd: Sequence[str] | None, host: str, port: int, use_tls: bool) -> List[str]:
    io = process(cmd) if cmd else remote(host, port, ssl=use_tls)
    outputs: List[str] = []
    io.recvuntil(b"hex string:")
    io.recvuntil(b">>> ")
    io.sendline(SIGNED_MESSAGE.hex().encode())
    io.recvuntil(b"Your signature is:")
    sig_text = read_signature_block(io)
    signature = parse_signature(sig_text)

    forged = forge_signature(signature)

    io.recvuntil(b"hex string:")
    io.recvuntil(b">>> ")
    io.sendline(TARGET_MESSAGE.hex().encode())

    io.recvuntil(b"Enter signature:")
    io.recvuntil(b">>> ")
    io.sendline(repr(forged).encode())

    outputs.append(io.recvall(timeout=2).decode(errors="replace"))
    io.close()
    return outputs


# Connect to the target (or local binary), forge the admin signature, and print the output.
def main() -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--host", default="nitwit.challs.pwnoh.io")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--local", action="store_true", help="Run against ./nitwit-chal.py")
    args = parser.parse_args()

    cmd = ["python3", "nitwit-chal.py"] if args.local else None
    output = interact(cmd, args.host, args.port, not args.no_tls)
    print("".join(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
