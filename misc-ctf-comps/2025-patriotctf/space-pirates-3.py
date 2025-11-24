#!/usr/bin/env python3
# Invert the Go cipher in space_pirates3.go to recover the vault combination.

target = [
    0x60, 0x6D, 0x5D, 0x97, 0x2C, 0x04, 0xAF, 0x7C, 0xE2, 0x9E,
    0x77, 0x85, 0xD1, 0x0F, 0x1D, 0x17, 0xD4, 0x30, 0xB7, 0x48,
    0xDC, 0x48, 0x36, 0xC1, 0xCA, 0x28, 0xE1, 0x37, 0x58, 0x0F,
]
xorKey = [0xC7, 0x2E, 0x89, 0x51, 0xB4, 0x6D, 0x1F]
rotationPattern = [7, 5, 3, 1, 6, 4, 2, 0]
magicSub = 0x93
chunkSize = 6


def rotate_left(b: int, n: int) -> int:
    n %= 8
    return ((b << n) | (b >> (8 - n))) & 0xFF


def rotate_right(b: int, n: int) -> int:
    n %= 8
    return ((b >> n) | (b << (8 - n))) & 0xFF


# Forward operations (for optional verification)
def applyUltimateQuantumCipher(buf):
    for i in range(len(buf)):
        buf[i] ^= xorKey[i % len(xorKey)]


def applyStellarRotationV2(buf):
    for i in range(len(buf)):
        rot = rotationPattern[i % len(rotationPattern)]
        buf[i] = rotate_left(buf[i], rot)


def applySpatialTransposition(buf):
    for i in range(0, len(buf) - 1, 2):
        buf[i], buf[i + 1] = buf[i + 1], buf[i]


def applyGravitationalShiftV3(buf):
    for i in range(len(buf)):
        buf[i] = (buf[i] - magicSub) & 0xFF


def applyTemporalInversionV2(buf):
    for start in range(0, len(buf), chunkSize):
        end = min(start + chunkSize, len(buf))
        buf[start:end] = reversed(buf[start:end])


def applyCoordinateCalibrationV3(buf):
    for i in range(len(buf)):
        buf[i] ^= ((i * i + i) % 256)


def invert(buf):
    # inverse order: 6 -> 1
    applyCoordinateCalibrationV3(buf)  # self-inverse
    applyTemporalInversionV2(buf)      # self-inverse
    for i in range(len(buf)):          # inverse of subtract is add
        buf[i] = (buf[i] + magicSub) & 0xFF
    applySpatialTransposition(buf)     # self-inverse
    for i in range(len(buf)):          # inverse rotate
        rot = rotationPattern[i % len(rotationPattern)]
        buf[i] = rotate_right(buf[i], rot)
    applyUltimateQuantumCipher(buf)    # self-inverse
    return buf


def main():
    buf = bytearray(target)
    flag_bytes = invert(buf)
    flag = flag_bytes.decode("utf-8")
    # Optional verification
    test = bytearray(flag_bytes)
    applyUltimateQuantumCipher(test)
    applyStellarRotationV2(test)
    applySpatialTransposition(test)
    applyGravitationalShiftV3(test)
    applyTemporalInversionV2(test)
    applyCoordinateCalibrationV3(test)
    assert list(test) == target, "Verification failed"
    print(flag)


if __name__ == "__main__":
    main()
