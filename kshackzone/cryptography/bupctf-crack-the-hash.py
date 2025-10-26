# https://kshackzone.com/ctfs/challenge/bup-ctf-powered-by-knight-squad-final-round/446/crack-the-hash

# Targeted password cracker for the hash a9ceb3196fd5a7a5b184050026de536a.

# The recovered hints narrow the search space:
#   * Password length is exactly 10 characters.
#   * Contains a contiguous block of at least two digits; digits are drawn from the phone suffix 7315.
#   * Contains a contiguous block of at least two favourite symbols drawn from !@#$_.
#   * Remaining positions are filled with letters inspired by the owner’s name (Nayeem).
# The hash comparison now explores every structure consistent with the hints and
# tests MD5(password), MD5(MD5(password)), and MD5(MD5(MD5(password))) in parallel
# for each candidate.

# This code could not crack the hash.

from __future__ import annotations

import hashlib
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterator, Sequence, Tuple

TARGET_HASH = "a9ceb3196fd5a7a5b184050026de536a"
TARGET_HASHES = {TARGET_HASH}
PHONE_SUFFIX = "7315"
PHONE_DIGITS = tuple(dict.fromkeys(PHONE_SUFFIX))
FAV_SYMBOLS = "!@#$_"
NAME = "Nayeem"
PASSWORD_LEN = 10

# Limit symbol blocks to length 2–4.
SYMBOL_BLOCK_LENGTHS = (2, 3, 4)
SYMBOL_BLOCK_MIN = min(SYMBOL_BLOCK_LENGTHS)
# Restrict digit blocks to length between 2 and the phone length (inclusive).
DIGIT_BLOCK_MIN = 2
DIGIT_BLOCK_MAX = PASSWORD_LEN - SYMBOL_BLOCK_MIN
MAX_LETTER_TOTAL = PASSWORD_LEN - DIGIT_BLOCK_MIN - SYMBOL_BLOCK_MIN

MD5_VARIANTS: Tuple[Tuple[str, int], ...] = (
    ("MD5", 1),
    ("MD5x2", 2),
    ("MD5x3", 3),
)


def build_letter_variants() -> dict[int, Sequence[str]]:
    # Precompute letter segment options for lengths we care about (<= MAX_LETTER_TOTAL).
    # We combine contiguous substrings of the owner's name (in lower/capital/upper
    # case) and allow wrap-around slices plus simple reversals. This keeps the
    # search space focussed on realistic name-based fragments.
    variants: dict[int, Sequence[str]] = {0: ("",)}
    name_lower = NAME.lower()
    name_upper = NAME.upper()
    doubled_lower = name_lower * 2
    doubled_upper = name_upper * 2
    name_cap = NAME.capitalize()
    doubled_cap = name_cap * 2

    for length in range(1, MAX_LETTER_TOTAL + 1):
        options = set()

        # contiguous substrings (allow wrap by using doubled strings)
        for variant in (doubled_lower, doubled_upper, doubled_cap):
            if length <= len(variant):
                for start in range(len(variant) - length + 1):
                    segment = variant[start : start + length]
                    options.add(segment)
                    options.add(segment[::-1])

        if length <= len(name_lower):
            options.add(name_lower[:length])
            options.add(name_upper[:length])
            options.add(name_cap[:length])
            options.add(name_lower[-length:])
            options.add(name_upper[-length:])
            options.add(name_cap[-length:])

        variants[length] = tuple(sorted(options))
    return variants


LETTER_VARIANTS = build_letter_variants()


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def md5_rounds(candidate: str, rounds: int) -> str:
    # Hash the candidate with MD5 for the specified number of rounds.
    digest = md5_hex(candidate.encode())
    for _ in range(rounds - 1):
        digest = md5_hex(digest.encode())
    return digest


def evaluate_candidate_async(
    candidate: str, executor: ThreadPoolExecutor
) -> Tuple[str | None, Dict[str, str]]:
    # Submit asynchronous MD5 hashing tasks for the candidate.
    # Returns the first matching variant (if any) and the map of all computed digests.
    futures = {
        executor.submit(md5_rounds, candidate, rounds): label
        for label, rounds in MD5_VARIANTS
    }
    results: Dict[str, str] = {}
    matched_label: str | None = None

    for future in as_completed(futures):
        label = futures[future]
        digest = future.result()
        results[label] = digest
        if matched_label is None and digest in TARGET_HASHES:
            matched_label = label

    return matched_label, results


def _priority_index(value: str, preferred: Sequence[str]) -> int:
    try:
        return preferred.index(value)
    except ValueError:
        return len(preferred)


def digit_blocks() -> Sequence[str]:
    # Return digit blocks formed from the phone suffix digits.
    # Covers plausible arrangements derived from the phone suffix pattern.
    blocks: set[str] = set()

    max_base_length = DIGIT_BLOCK_MAX
    repeated = PHONE_SUFFIX * 3
    for pattern in (repeated, repeated[::-1]):
        for length in range(DIGIT_BLOCK_MIN, max_base_length + 1):
            for start in range(0, len(pattern) - length + 1):
                blocks.add(pattern[start : start + length])

    # include permutations of the core phone digits for variety
    for length in range(DIGIT_BLOCK_MIN, min(len(PHONE_SUFFIX), max_base_length) + 1):
        for perm in itertools.permutations(PHONE_SUFFIX, length):
            blocks.add("".join(perm))

    return sorted(blocks, key=lambda item: (len(item), item))


def symbol_blocks() -> Sequence[str]:
    # Return symbol blocks of the requested lengths from the favourite symbol set.
    blocks = set()
    for length in SYMBOL_BLOCK_LENGTHS:
        for prod in itertools.product(FAV_SYMBOLS, repeat=length):
            blocks.add("".join(prod))
    return sorted(blocks, key=lambda item: (len(item), item))


def generate_candidates() -> Iterator[str]:
    # Yield password candidates following the derived structure:
    #   • Exactly one block of ≥2 digits (from phone-derived candidates).
    #   • Exactly one block of ≥2 favourite symbols.
    #   • Remaining positions filled with name-derived letters.
    # The digit and symbol blocks may appear in either order with optional letter
    # padding before, between, and after.
    digits = digit_blocks()
    symbols = symbol_blocks()

    for digit_block in digits:
        d_len = len(digit_block)
        for symbol_block in symbols:
            s_len = len(symbol_block)
            letters_total = PASSWORD_LEN - d_len - s_len
            if letters_total < 0 or letters_total > MAX_LETTER_TOTAL:
                continue

        for order in ("DS", "SD"):
            dist_set = set()
            if letters_total == 0:
                dist_set.add((0, 0, 0))
            else:
                # single contiguous block of letters in any slot
                dist_set.update({(letters_total, 0, 0), (0, letters_total, 0), (0, 0, letters_total)})
                # split letters across at most two segments
                for split in range(1, letters_total):
                    left = split
                    right = letters_total - split
                    dist_set.add((left, right, 0))      # left + middle
                    dist_set.add((left, 0, right))      # left + right
                    dist_set.add((0, left, right))      # middle + right

            for lengths in dist_set:
                l0, l1, l2 = lengths
                pools = (
                    LETTER_VARIANTS.get(l0, ()),
                    LETTER_VARIANTS.get(l1, ()),
                    LETTER_VARIANTS.get(l2, ()),
                )
                if any(not pool for pool in pools):
                    continue
                for segments in itertools.product(*pools):
                    left, middle, right = segments
                    if order == "DS":
                        candidate = f"{left}{digit_block}{middle}{symbol_block}{right}"
                    else:
                        candidate = f"{left}{symbol_block}{middle}{digit_block}{right}"
                    if len(candidate) == PASSWORD_LEN:
                        yield candidate


def crack() -> None:
    print(f"Target hash: {TARGET_HASH}")
    print("Trying candidates derived from phone digits, favourite symbols, and name letters…")

    with ThreadPoolExecutor(max_workers=len(MD5_VARIANTS)) as executor:
        for count, candidate in enumerate(generate_candidates(), start=1):
            matched_label, digests = evaluate_candidate_async(candidate, executor)

            if matched_label:
                print("\n=== MATCH FOUND ===")
                print(f"Password        : {candidate}")
                print(f"Matched variant : {matched_label}")
                for label, _ in MD5_VARIANTS:
                    if label in digests:
                        print(f"{label:<8}: {digests[label]}")
                print(f"Candidates tried: {count:,}")
                print("==========================")
                return

            if count % 10_000 == 0:
                print(f"Checked {count:,} candidates so far…")

    print("No matching password found within the constrained search space.")


def dump_candidates(path: Path) -> int:
    # Write all generated password candidates to the supplied file path.
    # Returns the total number of candidates written.
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for candidate in generate_candidates():
            handle.write(f"{candidate}\n")
            count += 1
            if count % 1_000_000 == 0:
                print(f"Wrote {count:,} candidates…")
    return count


if __name__ == "__main__":
    crack()
