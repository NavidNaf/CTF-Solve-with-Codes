# https://kshackzone.com/ctfs/challenge/smp-ctf-2024-selection-round/164/seed-the-flag-2

# This challenge involves recovering a hidden secret and prime number P2
# used in an RSA-like encryption scheme. The hidden secret is XOR-obfuscated
# using a seed derived from two known byte strings. The prime P2 is scrambled
# by shuffling its digits in chunks using a PRNG seeded with the same value.

import random


P1 = 4583053465
P2_O = "4712876638"
P3 = int("050830727770097899766746520799989608903411206")
K = 5964
MAGIC_NUMBER = 845321
HIDDEN_VALUE = int("45830534647166131662210698039087274510333927906501911560900149115")

S1 = b"kshackzoneishereforyou"
S2 = b"ohiguessyouarerightwiththis"


def xor_seed(a: bytes, b: bytes) -> int:
    # XOR two byte strings treated as equal-length big-endian integers.
    n = max(len(a), len(b))
    ai = int.from_bytes(a.rjust(n, b"\x00"), "big")
    bi = int.from_bytes(b.rjust(n, b"\x00"), "big")
    return ai ^ bi


def xor_repeat(data: bytes, key: bytes) -> bytes:
    # XOR data with a repeating key.
    if not key:
        raise ValueError("Key must not be empty.")
    return bytes(val ^ key[i % len(key)] for i, val in enumerate(data))


def chunks_of(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


def unshuffle_with_seed(text: str, seed: int, size: int) -> str:
    # Undo PRNG shuffling done on size-sized chunks using the supplied seed.
    parts = chunks_of(text, size)
    n = len(parts)
    random.seed(seed)
    order = list(range(n))
    random.shuffle(order)
    original = [None] * n
    for dest, src in enumerate(order):
        original[src] = parts[dest]
    return "".join(original)


def is_probable_prime(n: int) -> bool:
    # Deterministic Miller-Rabin for 64-bit integers.
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


def find_p2_candidates(p2_scrambled: str, seed: int) -> list[int]:
    # Generate candidate primes from the scrambled P2 string.
    candidates: set[int] = set()

    for size in (1, 2, 5, len(p2_scrambled)):
        if len(p2_scrambled) % size == 0:
            val = unshuffle_with_seed(p2_scrambled, seed, size)
            candidates.add(int(val))

    base = int(p2_scrambled)
    if is_probable_prime(base):
        candidates.add(base)
    else:
        # Nearby search bounded by the magic number.
        for delta in range(1, MAGIC_NUMBER + 1):
            for candidate in (base + delta, base - delta):
                if candidate > 1 and is_probable_prime(candidate):
                    candidates.add(candidate)
                    return sorted(n for n in candidates if is_probable_prime(n))
    return sorted(n for n in candidates if is_probable_prime(n))


def main() -> None:
    seed = xor_seed(S1, S2)
    print(f"Seed (hex): {hex(seed)}")
    print(f"Seed (dec): {seed}")

    seed_bytes = seed.to_bytes((seed.bit_length() + 7) // 8, "big")
    hidden_bytes = HIDDEN_VALUE.to_bytes((HIDDEN_VALUE.bit_length() + 7) // 8, "big")
    secret = xor_repeat(hidden_bytes, seed_bytes).lstrip(b"\x00").decode()
    print(f"Hidden secret: {secret}")

    p2_candidates = find_p2_candidates(P2_O, seed)
    if p2_candidates:
        print(f"Prime P2 candidates: {p2_candidates}")
    else:
        print("No prime candidate found. Consider widening the search bounds.")


if __name__ == "__main__":
    main()
