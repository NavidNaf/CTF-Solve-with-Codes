"""
Author: Navid Fazle Rabbi (DL28)
Summary: Decode a whimsical whitespace message by turning spaces/tabs into bits and mapping to ASCII.
"""

from __future__ import annotations

from pathlib import Path

SPACE = " "
TAB = "\t"


def whitespace_bits(text: str) -> list[str]:
    """Convert each non-empty line of whitespace into a binary string of 0s/1s."""
    bits_per_line: list[str] = []
    for line in text.splitlines():
        bits = "".join("0" if ch == SPACE else "1" if ch == TAB else "" for ch in line)
        if bits:
            bits_per_line.append(bits)
    return bits_per_line


def decode_lines(lines: list[str]) -> str:
    """Take the last 8 bits of every line and interpret them as ASCII characters."""
    chars = []
    for bits in lines:
        chunk = bits[-8:]
        chars.append(chr(int(chunk, 2)))
    return "".join(chars)


def main() -> None:
    """Load the whitespace file, rebuild the bit-stream, and print the hidden text."""
    path = Path(__file__).with_name("txt")
    text = path.read_text()
    lines = whitespace_bits(text)
    secret = decode_lines(lines)
    print(secret)


if __name__ == "__main__":
    main()
