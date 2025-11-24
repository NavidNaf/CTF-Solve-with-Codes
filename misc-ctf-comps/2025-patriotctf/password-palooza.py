#!/usr/bin/env python3
"""
Crack an MD5 hash of a breached password plus two digits.
Usage: python3 password-palooza.py wordlist.txt
"""

import hashlib
import sys
from typing import Optional


TARGET_HASH = "3a52fc83037bd2cb81c5a04e49c048a2"


def md5_hex(text: str) -> str:
    """Return the hex MD5 digest of the given text."""
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def brute_force(wordlist_path: str) -> Optional[str]:
    """Return the matching password or None if not found."""
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for base in f:
            word = base.strip()
            if not word:
                continue  # skip blank or whitespace-only lines
            for i in range(100):
                candidate = f"{word}{i:02d}"
                if md5_hex(candidate) == TARGET_HASH:
                    return candidate
    return None


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python3 password-palooza.py <wordlist>")
        sys.exit(1)

    wordlist_path = sys.argv[1]
    try:
        password = brute_force(wordlist_path)
    except OSError as exc:
        print(f"Error opening wordlist: {exc}", file=sys.stderr)
        sys.exit(1)

    if password:
        print(f"pctf{{{password}}}")
    else:
        print("No match found")


if __name__ == "__main__":
    main()
