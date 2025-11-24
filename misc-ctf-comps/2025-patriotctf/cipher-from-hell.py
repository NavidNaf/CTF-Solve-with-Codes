#!/usr/bin/env python3
from pathlib import Path


O = (
    (6, 0, 7),
    (8, 2, 1),
    (5, 4, 3),
)


def decrypt(data: bytes) -> bytes:
    # Build inverse lookup: base9 digit -> (msd, lsd) trits.
    inv = {}
    for i, row in enumerate(O):
        for j, val in enumerate(row):
            inv[val] = (i, j)

    ss = int.from_bytes(data, "big")
    if ss == 0:
        return b""

    # Recover base9 digits in order they were generated.
    base9 = []
    while ss:
        base9.append(ss % 9)
        ss //= 9
    base9.reverse()

    # Each base9 digit encodes two trits (outermost pair moving inward).
    length = len(base9) * 2
    base3 = [0] * length
    for idx, val in enumerate(base9):
        msd, lsd = inv[val]
        left = idx
        right = length - 1 - idx  # positions move inward from both ends
        base3[left] = msd
        base3[right] = lsd

    # Convert reconstructed base3 digits back to integer.
    s = 0
    for digit in base3:
        s = s * 3 + digit

    byte_len = (s.bit_length() + 7) // 8 or 1
    return s.to_bytes(byte_len, "big")


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    data = (base_dir / "encrypted").read_bytes()
    flag = decrypt(data).decode("utf-8", errors="replace")
    print(flag)


if __name__ == "__main__":
    main()
