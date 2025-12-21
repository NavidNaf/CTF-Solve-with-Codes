#!/usr/bin/env python3
import sys


def parse_rules(rule: str):
    rule = rule.strip()
    if "/" not in rule or "B" not in rule or "S" not in rule:
        return set(), set()
    birth_part, survive_part = rule.split("/", 1)
    birth = set(int(ch) for ch in birth_part[1:] if ch.isdigit())
    survive = set(int(ch) for ch in survive_part[1:] if ch.isdigit())
    return birth, survive


def simulate(grid, birth, survive, steps):
    n = len(grid)
    for _ in range(steps):
        pad = [[0] * (n + 2) for _ in range(n + 2)]
        for i in range(n):
            row = grid[i]
            prow = pad[i + 1]
            for j in range(n):
                prow[j + 1] = row[j]
        new_grid = [[0] * n for _ in range(n)]
        for i in range(1, n + 1):
            for j in range(1, n + 1):
                neighbors = (
                    pad[i - 1][j - 1]
                    + pad[i - 1][j]
                    + pad[i - 1][j + 1]
                    + pad[i][j - 1]
                    + pad[i][j + 1]
                    + pad[i + 1][j - 1]
                    + pad[i + 1][j]
                    + pad[i + 1][j + 1]
                )
                if pad[i][j]:
                    new_grid[i - 1][j - 1] = 1 if neighbors in survive else 0
                else:
                    new_grid[i - 1][j - 1] = 1 if neighbors in birth else 0
        grid = new_grid
    return grid


def main() -> None:
    data = sys.stdin.read().splitlines()
    if not data:
        return
    n = int(data[0].strip())
    grid = [[1 if ch == "1" else 0 for ch in line.strip()] for line in data[1 : 1 + n]]
    rule = data[1 + n].strip()
    steps = int(data[2 + n].strip())
    birth, survive = parse_rules(rule)
    final = simulate(grid, birth, survive, steps)
    out_lines = ["".join("1" if v else "0" for v in row) for row in final]
    sys.stdout.write("\n".join(out_lines))


if __name__ == "__main__":
    main()
