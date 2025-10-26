# https://kshackzone.com/ctfs/challenge/knightctf-2024/381/random-shamir-adleman

# RSA decryption where one prime is generated from a PRNG seeded by XORing two byte strings.
# This code does not solve this. There must be another challenge that reveals one of the byte strings.

import random
from math import gcd


P2 = 81950208731605030173072901497240676460946134422613059941413476068465656250011
E = 65537
C = int(
    "1913607487336850198612381177842742944535528551492332730687709803333994170933334235248158693072452023061642877943692858799822420964044267542215434514413393"
)

S1 = b"usedistofindouttheseed"
S2 = b"thisisthekeytogetyourseed"


def xor_seed(a: bytes, b: bytes) -> int:
    """Return the integer resulting from XORing two byte strings as big-endian numbers."""
    n = max(len(a), len(b))
    ai = int.from_bytes(a.rjust(n, b"\x00"), "big")
    bi = int.from_bytes(b.rjust(n, b"\x00"), "big")
    return ai ^ bi


def is_probable_prime(n: int) -> bool:
    """Deterministic Miller–Rabin for 64-bit (and slightly larger) integers."""
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def reproduce_prime(seed: int, bits: int = 256) -> int:
    """Recreate the RNG-driven 256-bit prime used for p."""
    random.seed(seed)

    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1  # ensure MSB and odd
        if is_probable_prime(candidate):
            return candidate


def main() -> None:
    seed = xor_seed(S1, S2)
    print(f"Seed (hex): {hex(seed)}")
    print(f"Seed (dec): {seed}")

    p = reproduce_prime(seed)
    print(f"Recovered prime p: {p}")

    n = p * P2
    phi = (p - 1) * (P2 - 1)
    if gcd(E, phi) != 1:
        raise ValueError("Public exponent is not coprime with phi(N).")

    d = pow(E, -1, phi)
    m = pow(C, d, n)

    plaintext_hex = f"{m:0{(n.bit_length() + 7) // 8 * 2}x}"
    plaintext_bytes = bytes.fromhex(plaintext_hex)

    print(f"Decrypted message (hex): {plaintext_hex}")
    print(f"Decrypted message (latin-1): {plaintext_bytes.decode('latin1')}")
    try:
        import base64

        print(f"Decrypted message (base64): {base64.b64encode(plaintext_bytes).decode()}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
