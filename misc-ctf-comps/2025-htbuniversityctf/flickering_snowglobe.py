#!/usr/bin/env python3
import sys


def parse_input(data: str) -> str:
    parts = [p for p in data.split() if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if parts[0].isdigit():
        return parts[1]
    return parts[0]


def count_segments(s: str) -> int:
    if not s:
        return 0
    count = 1
    prev = s[0]
    for ch in s[1:]:
        if ch != prev:
            count += 1
            prev = ch
    return count


def main() -> None:
    s = parse_input(sys.stdin.read())
    print(count_segments(s))


if __name__ == "__main__":
    main()
