#!/usr/bin/env python3
# Decrypt a Cube Cipher ciphertext by recovering the remote permutation and reusing it locally.
DESCRIPTION = (
    "Decrypt an arbitrary Cube Cipher ciphertext by reusing the sampling attack "
    "from cube-cipher.py to recover the remote permutation and applying it."
)

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Sequence

DEFAULT_CIPHERTEXT = "754477f367633676ef02347641d63d65529663b6007360f40f0ebe"


# Load cube-cipher.py so we can reuse its helper functions.
def load_cube_cipher_module():
    # Dynamically import cube-cipher.py to reuse its helper functions.
    module_path = Path(__file__).with_name("cube-cipher.py")
    spec = importlib.util.spec_from_file_location("cube_cipher_solver", module_path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"Unable to load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# Establish a remote or local connection based on CLI flags.
def open_connection(args):
    try:
        from pwn import remote, process
    except ImportError as exc:
        raise SystemExit("cube-cipher2.py requires pwntools (pip install pwntools)") from exc

    if args.binary:
        import shlex

        return process(shlex.split(args.binary))
    return remote(args.host, args.port, ssl=not args.no_ssl)


# Apply the recovered permutation to the ciphertext and optionally strip padding.
def decrypt_with_perm(module, ciphertext: bytes, perm: Sequence[int], strip=True) -> bytes:
    nibbles = module.bytes_to_nibbles(ciphertext)
    plain_nibbles = [nibbles[idx] for idx in perm]
    plaintext = module.nibbles_to_bytes(plain_nibbles)
    return plaintext.rstrip(b"\x00") if strip else plaintext


# Recover the permutation, decrypt the ciphertext, and display the flag.
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument(
        "--ciphertext",
        default=DEFAULT_CIPHERTEXT,
        help="Hex-encoded ciphertext to decrypt (default: provided challenge value)",
    )
    parser.add_argument("--host", default="cube-cipher.challs.pwnoh.io")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--no-ssl", action="store_true", help="Disable TLS for the remote socket")
    parser.add_argument(
        "--binary",
        help="Path to a local cube_cipher binary for offline testing (bypasses TCP)",
    )
    parser.add_argument("--max-rounds", type=int, default=150)
    parser.add_argument("--rand-min", type=int, default=12)
    parser.add_argument("--rand-max", type=int, default=24)
    parser.add_argument("--seed", type=int, help="Seed Python's RNG inside cube-cipher.py")
    parser.add_argument("--no-strip", action="store_true", help="Keep trailing padding bytes")
    parser.add_argument("--print-hex", action="store_true", help="Also dump the plaintext as hex")
    args = parser.parse_args(argv)

    module = load_cube_cipher_module()
    if args.seed is not None:
        module.random.seed(args.seed)

    io = open_connection(args)
    namespace = SimpleNamespace(
        rand_min=args.rand_min,
        rand_max=args.rand_max,
        max_rounds=args.max_rounds,
    )
    try:
        perm, _ = module.recover_permutation(io, namespace)
    finally:
        try:
            io.sendline(b"5")
        except Exception:
            pass
        try:
            io.close()
        except Exception:
            pass

    ciphertext = bytes.fromhex(args.ciphertext)
    plaintext = decrypt_with_perm(module, ciphertext, perm, strip=not args.no_strip)

    if args.print_hex:
        print(plaintext.hex())
    try:
        decoded = plaintext.decode()
        end = "" if decoded.endswith("\n") else "\n"
        print(decoded, end=end)
    except UnicodeDecodeError:
        print(plaintext)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
