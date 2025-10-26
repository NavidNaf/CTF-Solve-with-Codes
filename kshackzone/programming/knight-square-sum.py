# https://kshackzone.com/ctfs/challenge/knightctf-2022/11/square-sum

# This code checks if a given integer can be expressed as the sum of two squares.
# This works but the implemenation on their website is broken.

import math


def find_square_pairs(target: int) -> list[tuple[int, int]]:
    """Return all non-negative integer pairs (a, b) with a^2 + b^2 == target."""
    if target < 0:  # Negative numbers cannot be expressed as sum of two squares.
        return []  # Early exit with no pairs for invalid input.

    limit = math.isqrt(target)  # We only need to search up to sqrt(target).
    pairs = []  # Collect matching pairs (a, b) here.

    for a in range(limit + 1):  # Iterate all candidate values of a.
        remainder = target - a * a  # Compute the remaining value to match b^2.
        b = math.isqrt(remainder)  # Calculate the integer square root candidate for b.
        if b * b == remainder and a <= b:  # Check exact square and avoid duplicate permutations.
            pairs.append((a, b))  # Store the valid pair.

    return pairs  # Return all discovered pairs.


def main() -> None:
    try:
        raw_input = input("Enter an integer to test: ").strip()
    except EOFError:
        return

    if not raw_input:
        print("No input provided.")
        return

    try:
        target = int(raw_input)
    except ValueError:
        print("Invalid integer input.")
        return

    pairs = find_square_pairs(target)

    if not pairs:
        print(f"{target} cannot be expressed as a sum of two squares.")
        return

    print(f"{target} can be expressed as a sum of two squares.")
    print(f"Pairs (a, b) with a^2 + b^2 = {target}:")
    for a, b in pairs:
        print(f"{a}^2 + {b}^2 = {target}")


if __name__ == "__main__":
    main()
