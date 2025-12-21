#!/usr/bin/env python3
import hashlib
import json
import math
import multiprocessing as mp
import os
import re
from typing import List, Optional

from pwn import context, remote
from sympy.ntheory.modular import crt

HOST = "154.57.164.79"
PORT = 31398

FROST_PRIME = int(
    "1a66804d885939d7acf3a4b413c9a24547b876e706913adec9684cc4a63ab0dfd"
    "2e0fd79f683de06ad17774815dfc8375370eb3d0fb5dce0019bd0632e7663a41",
    16,
)

# Factorization of FROST_PRIME - 1 (fully smooth).
FROST_P_MINUS_1_FACTORS = {
    2: 6,
    3: 35,
    5: 21,
    7: 6,
    137: 11,
    191: 2,
    331: 3,
    3469: 2,
    3613: 11,
    3967: 6,
    16561: 3,
}


def snowmark_for(msg: str) -> int:
    digest = hashlib.sha512(msg.encode()).digest()
    return int.from_bytes(digest, "big") % FROST_PRIME


def _dlog_prime_power(g: int, h: int, p: int, q: int, e: int, order: int) -> int:
    # Standard Pohlig-Hellman lifting for q^e.
    x = 0
    g0 = pow(g, order // q, p)  # generator of order q
    for k in range(e):
        exp = order // (q ** (k + 1))
        h_k = pow((h * pow(g, -x, p)) % p, exp, p)
        table = {pow(g0, d, p): d for d in range(q)}
        d = table.get(h_k)
        if d is None:
            raise RuntimeError(f"failed dlog digit extraction q={q} k={k}")
        x += d * (q**k)
    return x


def dlog_smooth(base: int, value: int) -> int:
    # Implement Pohlig-Hellman using the exact order of base.
    order = FROST_PRIME - 1
    for q, e in FROST_P_MINUS_1_FACTORS.items():
        for _ in range(e):
            if order % q == 0 and pow(base, order // q, FROST_PRIME) == 1:
                order //= q
            else:
                break

    residues = []
    moduli = []
    for q, e in FROST_P_MINUS_1_FACTORS.items():
        e_eff = 0
        tmp = order
        while tmp % q == 0:
            e_eff += 1
            tmp //= q
        if e_eff == 0:
            continue
        residues.append(_dlog_prime_power(base, value, FROST_PRIME, q, e_eff, order))
        moduli.append(q**e_eff)
    x, mod = crt(moduli, residues)
    return int(x % mod)


def k_to_bits(k: int, nbits: int) -> List[int]:
    return [int(c) for c in bin(k)[2:].zfill(nbits)]


def legendre_bit(a: int, p: int, exp: int) -> int:
    # Euler criterion: 1 if quadratic residue, -1 otherwise; map to bit.
    return 1 if pow(a, exp, p) == 1 else 0


def _scan_range(start: int, end: int, p: int, exp: int, bits: List[int]) -> Optional[int]:
    n = len(bits)
    for s in range(start, end):
        ok = True
        for i in range(n):
            if legendre_bit((s + i) % p, p, exp) != bits[i]:
                ok = False
                break
        if ok:
            return s
    return None


def recover_seed(bits: List[int], p: int, workers: int = 1) -> int:
    exp = (p - 1) // 2
    if workers <= 1:
        res = _scan_range(1, p, p, exp, bits)
        if res is None:
            raise RuntimeError("seed not found")
        return res

    # Parallel scan in chunks.
    chunk = 1_000_000
    with mp.Pool(processes=workers) as pool:
        pending = []
        for start in range(1, p, chunk):
            end = min(start + chunk, p)
            pending.append(pool.apply_async(_scan_range, (start, end, p, exp, bits)))
        for job in pending:
            res = job.get()
            if res is not None:
                pool.terminate()
                return res
    raise RuntimeError("seed not found")


def generate_bits(seed: int, p: int, nbits: int) -> List[int]:
    exp = (p - 1) // 2
    out = []
    s = seed
    for _ in range(nbits):
        if s == 0:
            s += 1
        out.append(legendre_bit(s, p, exp))
        s = (s + 1) % p
        if s == 0:
            s += 1
    return out


def bits_to_bin(bits: List[int]) -> str:
    return "".join(str(b) for b in bits)


def main() -> None:
    context.log_level = "info"
    io = remote(HOST, PORT)
    banner = io.recvuntil(b"3) Leave Booth")
    banner_text = banner.decode(errors="ignore")
    m = re.search(r"holly_prime\s*=\s*(\d+)", banner_text)
    if not m:
        print("banner_dump:", repr(banner_text))
        raise RuntimeError("failed to parse holly_prime from banner")
    holly_prime = int(m.group(1))

    # Request one signature to recover 500 RNG bits.
    io.sendline(b"1")
    io.recvuntil(b"Whisper your message: ")
    msg = "seed_recovery"
    io.sendline(msg.encode())
    resp = io.recvline().decode()
    sig = int(json.loads(resp)["signature"])

    base = snowmark_for(msg)
    k = dlog_smooth(base, sig)
    bits = k_to_bits(k, 500)

    # Recover seed from the 500-bit Legendre sequence.
    workers = max(1, os.cpu_count() or 1)
    seed = recover_seed(bits, holly_prime, workers=workers)

    # The RNG advanced by 500 bits during the signature.
    next_seed = (seed + 500) % holly_prime
    if next_seed == 0:
        next_seed += 1

    otp_bits = generate_bits(next_seed, holly_prime, 672)
    otp_bin = bits_to_bin(otp_bits)

    io.recvuntil(b"3) Leave Booth")
    io.sendline(b"2")
    io.recvuntil(b"Reveal my snow-otp (in bits): ")
    io.sendline(otp_bin.encode())
    print(io.recvline().decode().strip())


if __name__ == "__main__":
    main()
