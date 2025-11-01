"""
Author: Navid Fazle Rabbi (DL28)
Summary: Reassemble the two parts of the random-stuff challenge flag and print the final string.
"""

from __future__ import annotations

PART1 = "v1t{Pseud0_R4nd0m_G3ner4t0r"
PART2 = "_1s_n0t_th4t_h4rd}"


def build_flag() -> str:
    """Concatenate the two recovered fragments into the final flag."""
    return PART1 + PART2


def main() -> None:
    """Print the flag as a single string."""
    print(build_flag())


if __name__ == "__main__":
    main()
