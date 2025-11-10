#!/usr/bin/env python3
# this code connects to a remote Python jail and sends a payload to execute

from pwn import context, remote

PAYLOAD = "import this"  # importing 'this' writes a 857-character poem to stdout


def main() -> None:
    context.log_level = "info"
    io = remote("pyjail.challs.infobahnc.tf", 1337)

    print(f"Sending payload: {PAYLOAD!r}")
    io.sendline(PAYLOAD.encode())
    response = io.recvall(timeout=2).decode(errors="replace")
    print(response)
    io.close()


if __name__ == "__main__":
    main()
