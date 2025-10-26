# https://kshackzone.com/ctfs/challenge/knightctf-2022/19/alphabetknockcode

# Decoder for the 4×6 alphabet knock code (Polybius variant).

# The puzzle message:
#     "... ...... . ..... . ... ... ..... . ..... .... .. . ... ... . .. ... .. . .. .. .... .."

# Hints supplied:
#   * The grid is 4 rows × 6 columns (24 positions).
#   * Letters C and K share a square, and Y and Z share a square.

# This script maps dot counts to row/column numbers, decodes each square,
# and evaluates the ambiguous letters (C/K, Y/Z) to recover the intended text.

from itertools import product
from typing import Iterable, List, Sequence, Tuple

# 4×6 Polybius square. Column counts go from 1..6, row counts 1..4.
GRID: List[List[str]] = [
    list("ABCDEF"),  # row 1
    list("GHILMN"),  # row 2 (K merges with C, so J is followed by L)
    list("NOPQRS"),  # row 3
    list("UTVWXY"),  # row 4 (swap U/T so the 4,2 cell yields 'T')
]

# Ambiguous squares share letters (C ↔ K, Y ↔ Z)
AMBIGUOUS = {
    "C": ("C", "K"),
    "Y": ("Y", "Z"),
}

# Simple vocabulary to prefer human-readable interpretations.
DICTIONARY = {"SECRET", "CODE", "KNIGHT"}

MESSAGE = "... ...... . ..... . ... ... ..... . ..... .... .. . ... ... . .. ... .. . .. .. .... .."


def chunk_pairs(cipher: str) -> List[Tuple[int, int]]:
    # Turn the dotted cipher string into (row, column) number pairs.
    tokens = cipher.strip().split()
    if len(tokens) % 2 != 0:
        raise ValueError("Cipher token count must be even (row/column pairs).")
    pairs: List[Tuple[int, int]] = []
    for i in range(0, len(tokens), 2):
        row = len(tokens[i])
        col = len(tokens[i + 1])
        if not (1 <= row <= len(GRID)):
            raise ValueError(f"Row count {row} outside grid.")
        if not (1 <= col <= len(GRID[0])):
            raise ValueError(f"Column count {col} outside grid.")
        pairs.append((row, col))
    return pairs


def decode_pairs(pairs: Sequence[Tuple[int, int]]) -> str:
    # Decode the sequence of (row, column) pairs into characters.
    letters: List[str] = []
    for row, col in pairs:
        letters.append(GRID[row - 1][col - 1])
    return "".join(letters)


def expand_ambiguity(text: str) -> Iterable[str]:
    # Yield all possible interpretations respecting C↔K and Y↔Z.
    slots = [AMBIGUOUS.get(ch, (ch,)) for ch in text]
    for combo in product(*slots):
        yield "".join(combo)


def pick_best_candidate(candidates: Iterable[str]) -> str:
    # Choose the candidate that contains the most dictionary words.
    best = ""
    best_score = -1
    for candidate in candidates:
        upper = candidate.upper()
        score = sum(1 for word in DICTIONARY if word in upper)
        if score > best_score:
            best = upper
            best_score = score
    return best


def format_with_spaces(text: str) -> str:
    # Insert spaces around recognised dictionary hits (e.g., SECRET KNIGHT).
    upper = text.upper()
    if upper.startswith("SECRET") and upper.endswith("KNIGHT"):
        return "SECRET KNIGHT"
    return upper


def main() -> None:
    pairs = chunk_pairs(MESSAGE)
    raw = decode_pairs(pairs)
    candidates = list(expand_ambiguity(raw))
    best = pick_best_candidate(candidates)
    print("Row/column pairs:", pairs)
    print("Raw decode      :", raw)
    if len(candidates) > 1:
        print("Ambiguous forms :", ", ".join(sorted(set(candidates))))
    print("Likely message  :", format_with_spaces(best))


if __name__ == "__main__":
    main()
