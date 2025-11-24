#!/usr/bin/env python3
from pathlib import Path

def parse_mc(path):
    lines = path.read_text().splitlines()
    # Skip header lines until a line starts with '$' or a digit; collect rules/boards.
    boards = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("$"):
            # Next lines are pattern rows until a line starts with digit.
            pattern = []
            while i < len(lines) and lines[i].startswith("$"):
                pattern.append(lines[i])
                i += 1
            # Next lines map metadata; skip numeric lines.
            while i < len(lines) and (lines[i][:1].isdigit() or lines[i] == ""):
                i += 1
            boards.append(pattern)
        else:
            i += 1
    return boards

def reconstruct(board):
    # Replace '$' separators, join into grid of chars '.', '*', maybe missing as ' '.
    grid = []
    for row in board:
        row = row.strip("$")
        grid.append(list(row))
    # Fill missing bites represented by '.' between stars to make shapes readable.
    h = len(grid)
    w = max(len(r) for r in grid)
    for r in grid:
        if len(r) < w:
            r.extend([" " for _ in range(w - len(r))])
    # Simple heuristic: replace spaces with '.'; keep '*' as is.
    for y in range(h):
        for x in range(w):
            if grid[y][x] == " ":
                grid[y][x] = "."
    return ["".join(r) for r in grid]

def extract_flag(grids):
    # Find the largest grid and search for pctf{...}
    text = "\n".join("\n".join(g) for g in grids)
    # Try to visually derive; fallback to known pattern reading
    # For this challenge, the flag is hidden plainly in the ASCII art as text.
    # Let's scan for pctf{ in the text.
    start = text.find("pctf{")
    if start != -1:
        end = text.find("}", start)
        if end != -1:
            return text[start:end+1]
    # Otherwise, return the text for manual extraction.
    return text

def main():
    boards = parse_mc(Path("display.mc"))
    grids = [reconstruct(b) for b in boards]
    flag = extract_flag(grids)
    print(flag)

if __name__ == "__main__":
    main()
