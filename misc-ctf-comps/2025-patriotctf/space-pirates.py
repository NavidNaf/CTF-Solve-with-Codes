#!/usr/bin/env python3

# Reverses the transformations in challenge.c to recover the flag.

TARGET = [
    0x5A, 0x3D, 0x5B, 0x9C, 0x98, 0x73, 0xAE, 0x32, 0x25, 0x47,
    0x48, 0x51, 0x6C, 0x71, 0x3A, 0x62, 0xB8, 0x7B, 0x63, 0x57,
    0x25, 0x89, 0x58, 0xBF, 0x78, 0x34, 0x98, 0x71, 0x68, 0x59,
]
XOR_KEY = [0x42, 0x73, 0x21, 0x69, 0x37]
MAGIC_ADD = 0x2A


def decrypt() -> str:
    buf = bytearray(TARGET)

    for i in range(len(buf)):  # inverse of final XOR with index
        buf[i] ^= i

    for i in range(len(buf)):  # inverse of addition
        buf[i] = (buf[i] - MAGIC_ADD) % 256

    for i in range(0, len(buf), 2):  # inverse swap pairs
        buf[i], buf[i + 1] = buf[i + 1], buf[i]

    for i in range(len(buf)):  # inverse rotating XOR key
        buf[i] ^= XOR_KEY[i % len(XOR_KEY)]

    return buf.decode("utf-8")


def main() -> None:
    print(decrypt())


if __name__ == "__main__":
    main()