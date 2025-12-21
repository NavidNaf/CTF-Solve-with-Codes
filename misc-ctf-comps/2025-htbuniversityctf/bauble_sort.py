#!/usr/bin/env python3
import sys


def parse_line(line: str):
    name_part, sep, rest = line.partition(":")
    if not sep:
        return None
    name = name_part.strip()
    rest = rest.strip()
    # Expect "sparkle , stability" with optional spaces.
    if "," not in rest:
        return None
    sparkle_part, stability_part = rest.split(",", 1)
    try:
        sparkle = int(sparkle_part.strip())
        stability = int(stability_part.strip())
    except ValueError:
        return None
    return name, sparkle, stability


def main() -> None:
    data = sys.stdin.buffer.read().decode()
    if not data:
        return
    lines = [ln for ln in data.splitlines() if ln.strip()]
    if not lines:
        return
    try:
        n = int(lines[0].strip())
    except ValueError:
        # Fallback: treat all lines as entries if N is missing.
        n = len(lines)
        start = 0
    else:
        start = 1

    entries = []
    for ln in lines[start : start + n]:
        parsed = parse_line(ln)
        if parsed is None:
            continue
        name, sparkle, stability = parsed
        entries.append(( -sparkle, stability, name))

    entries.sort()
    out = "\n".join(name for _, _, name in entries)
    sys.stdout.write(out)


if __name__ == "__main__":
    main()
