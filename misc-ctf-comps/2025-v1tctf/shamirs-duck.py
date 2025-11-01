"""
Author: Navid Fazle Rabbi (DL28)
Summary: Reconstruct a shared secret from Shamir shares stored in shares.txt and print it.
"""

from __future__ import annotations

from fractions import Fraction
from itertools import combinations
from pathlib import Path

THRESHOLD = 3


def load_shares(path: Path) -> list[tuple[int, int, str]]:
    """Return a list of (index, value, label) tuples parsed from the shares file."""
    shares: list[tuple[int, int, str]] = []
    for idx, raw_line in enumerate(path.read_text().splitlines(), start=1):
        if not raw_line.strip():
            continue
        label, hex_value = raw_line.split("-", 1)
        shares.append((idx, int(hex_value, 16), label))
    return shares


def lagrange_at_zero(points: list[tuple[int, int]]) -> int | None:
    """Evaluate the interpolating polynomial through given points at x=0."""
    total = Fraction()
    for i, (xi, yi) in enumerate(points):
        term = Fraction(yi, 1)
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            term *= Fraction(-xj, xi - xj)
        total += term
    return total.numerator if total.denominator == 1 else None


def recover_secret(shares: list[tuple[int, int, str]]) -> str | None:
    """Try every combination of THRESHOLD shares and return the first printable secret."""
    for combo in combinations(shares, THRESHOLD):
        points = [(idx, val) for idx, val, _ in combo]
        secret = lagrange_at_zero(points)
        if secret is None or secret <= 0:
            continue
        raw = secret.to_bytes((secret.bit_length() + 7) // 8, "big")
        try:
            text = raw.decode()
        except UnicodeDecodeError:
            continue
        if all(32 <= ord(ch) <= 126 for ch in text):
            return text
    return None


def main() -> None:
    """Load shares, reconstruct the secret, and display the result."""
    shares = load_shares(Path(__file__).with_name("shares.txt"))
    if len(shares) < THRESHOLD:
        raise SystemExit(f"Need at least {THRESHOLD} shares to reconstruct the secret.")

    print(f"Loaded {len(shares)} shares. Trying every {THRESHOLD}-share combination...")
    secret = recover_secret(shares)
    if secret:
        print(f"Secret: {secret}")
    else:
        print("Failed to recover a printable secret.")


if __name__ == "__main__":
    main()
