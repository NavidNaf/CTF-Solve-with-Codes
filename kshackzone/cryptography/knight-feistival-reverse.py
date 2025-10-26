# https://kshackzone.com/ctfs/challenge/knightctf-2022/20/feistival

# Inverse routine for enc.py.

# enc.py performs two Feistel-style rounds on the original flag, using byte-wise
# XOR with constants m=21 and n=22. The resulting ciphertext is written as
# `x2 + x1`. To recover the original flag we reverse those operations.

# What is Feistel-style encryption? In each round, the data is split into
# left and right halves (L0, R0). The right half is XORed with a constant,
# then XORed with the left half to produce the new right half. The left half
# becomes the previous right half. After two rounds we have (L2, R2) which
# are concatenated as the ciphertext.

from pathlib import Path

m, n = 21, 22
CIPHER_PATH = Path("cipher.txt")

def recover_flag(ciphertext: bytes) -> bytes:
    if len(ciphertext) % 2 != 0:
        raise ValueError("Ciphertext length must be even.")

    half = len(ciphertext) // 2
    x2 = ciphertext[:half]
    x1 = ciphertext[half:]

    # Reverse second round:
    # x2 = (x1 XOR n) XOR R0  => R0 = x1 XOR n XOR x2
    R0 = bytes((x1[i] ^ n) ^ x2[i] for i in range(half))

    # Reverse first round:
    # x1 = (R0 XOR m) XOR L0  => L0 = (R0 XOR m) XOR x1
    L0 = bytes((R0[i] ^ m) ^ x1[i] for i in range(half))

    return L0 + R0


def main() -> None:
    if not CIPHER_PATH.exists():
        raise FileNotFoundError(f"Ciphertext file not found: {CIPHER_PATH}")

    cipher = CIPHER_PATH.read_bytes()
    flag = recover_flag(cipher)
    print(flag.decode(errors="replace"))


if __name__ == "__main__":
    main()
