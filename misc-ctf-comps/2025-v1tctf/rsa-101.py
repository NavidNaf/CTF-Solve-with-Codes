"""
Author: Navid Fazle Rabbi (DL28)
Summary: Solve a tiny RSA instance by factoring n, building the private key, and printing the plaintext.
"""

from __future__ import annotations

from pathlib import Path


def load_params(path: Path) -> tuple[int, int, int]:
    """Read RSA parameters (n, e, c) from the provided text file."""
    values: dict[str, int] = {}
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        values[key] = int(value)
    return values["n"], values["e"], values["c"]


def factor_small_n(n: int) -> tuple[int, int]:
    """Return (p, q) for a modulus n that has one very small factor."""
    for candidate in range(2, 1_000_000):
        if n % candidate == 0:
            return candidate, n // candidate
    raise ValueError("No small factor found in the expected range.")


def decrypt(c: int, d: int, n: int) -> bytes:
    """Compute plaintext bytes from RSA ciphertext using the private exponent d."""
    m = pow(c, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def main() -> None:
    """Resolve RSA parameters, recover the private key, and print the decoded message."""
    path = Path(__file__).with_name("RSA_101.txt")
    n, e, c = load_params(path)

    p, q = factor_small_n(n)
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    message = decrypt(c, d, n)

    print(f"p = {p}")
    print(f"q = {q}")
    print(f"d = {d}")
    print(f"plaintext (hex) = {message.hex()}")
    print(f"plaintext (ascii) = {message.decode(errors='replace')}")


if __name__ == "__main__":
    main()
