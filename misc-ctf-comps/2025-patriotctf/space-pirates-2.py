#!/usr/bin/env python3
# Invert the cipher from main.rs to recover the original flag.

TARGET = [
    0x15, 0x5A, 0xAC, 0xF6, 0x36, 0x22, 0x3B, 0x52,
    0x6C, 0x4F, 0x90, 0xD9, 0x35, 0x63, 0xF8, 0x0E,
    0x02, 0x33, 0xB0, 0xF1, 0xB7, 0x69, 0x42, 0x67,
    0x25, 0xEA, 0x96, 0x63, 0x1B, 0xA7, 0x03, 0x0B,
]
XOR_KEY = [0x7E, 0x33, 0x91, 0x4C, 0xA5]
ROTATION_PATTERN = [1, 3, 5, 7, 2, 4, 6]
MAGIC_SUB = 0x5D


def rotate_right(byte: int, n: int) -> int:
    return ((byte >> (n % 8)) | (byte << (8 - (n % 8)))) & 0xFF


def invert_coordinate_calibration(buf: bytearray) -> None:
    for i, b in enumerate(buf):
        buf[i] = b ^ ((i * i) % 256)


def invert_temporal_inversion(buf: bytearray) -> None:
    chunk_size = 5
    for start in range(0, len(buf), chunk_size):
        end = min(start + chunk_size, len(buf))
        buf[start:end] = reversed(buf[start:end])


def invert_gravitational_shift(buf: bytearray) -> None:
    for i, b in enumerate(buf):
        buf[i] = (b + MAGIC_SUB) & 0xFF


def invert_spatial_transposition(buf: bytearray) -> None:
    for i in range(0, len(buf), 2):
        buf[i], buf[i + 1] = buf[i + 1], buf[i]


def invert_stellar_rotation(buf: bytearray) -> None:
    for i, b in enumerate(buf):
        rot = ROTATION_PATTERN[i % 7]
        buf[i] = rotate_right(b, rot)


def invert_quantum_cipher(buf: bytearray) -> None:
    for i, b in enumerate(buf):
        buf[i] = b ^ XOR_KEY[i % len(XOR_KEY)]


def main() -> None:
    buf = bytearray(TARGET)
    invert_coordinate_calibration(buf)
    invert_temporal_inversion(buf)
    invert_gravitational_shift(buf)
    invert_spatial_transposition(buf)
    invert_stellar_rotation(buf)
    invert_quantum_cipher(buf)
    flag = buf.decode("utf-8")
    print(flag)


if __name__ == "__main__":
    main()
