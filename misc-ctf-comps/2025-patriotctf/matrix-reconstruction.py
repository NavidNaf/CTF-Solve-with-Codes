#!/usr/bin/env python3
import re
from pathlib import Path


# Helpers for GF(2) operations
def parity(x: int) -> int:
    return x.bit_count() & 1


def build_system(states):
    """
    Build linear system Ax = b over GF(2) for unknowns:
    - A 32x32 matrix bits in row-major order (indices 0..1023)
    - B 32-bit vector bits (indices 1024..1055)
    Returns list of integer rows each packing coefficients and rhs bit
    as a (n_vars+1)-bit integer.
    """
    n_vars = 32 * 32 + 32
    rows = []
    for s, sn in zip(states, states[1:]):
        for j in range(32):
            row = 0
            # coefficients for A row j
            for k in range(32):
                if (s >> k) & 1:
                    row |= 1 << (j * 32 + k)
            # coefficient for B_j
            row |= 1 << (1024 + j)
            # rhs bit
            rhs = (sn >> j) & 1
            row |= rhs << n_vars
            rows.append(row)
    return rows, n_vars


def gaussian_elimination(rows, n_vars):
    """
    Perform Gaussian elimination over GF(2).
    Returns solution vector as list of bits length n_vars.
    Assumes system is solvable and has full rank.
    """
    n_rows = len(rows)
    aug_width = n_vars + 1
    row_idx = 0
    pivots = [-1] * n_vars

    for col in range(n_vars):
        if row_idx >= n_rows:
            break
        # find pivot
        pivot = None
        for r in range(row_idx, n_rows):
            if (rows[r] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            continue
        # swap
        rows[row_idx], rows[pivot] = rows[pivot], rows[row_idx]
        pivots[col] = row_idx
        # eliminate below
        for r in range(n_rows):
            if r != row_idx and ((rows[r] >> col) & 1):
                rows[r] ^= rows[row_idx]
        row_idx += 1
        if row_idx == n_rows:
            break

    # back-substitution (rows already reduced because we eliminated both above and below)
    solution = [0] * n_vars
    for col in range(n_vars - 1, -1, -1):
        r = pivots[col]
        if r == -1:
            solution[col] = 0
            continue
        rhs = (rows[r] >> n_vars) & 1
        # subtract known contributions
        total = rhs
        mask = rows[r] & ((1 << n_vars) - 1)
        # remove pivot bit
        mask &= ~(1 << col)
        # compute parity of overlapping ones with known solution bits
        idx = 0
        temp = mask
        while temp:
            lsb = temp & -temp
            bit_pos = (lsb.bit_length() - 1)
            total ^= solution[bit_pos]
            temp ^= lsb
            idx += 1
        solution[col] = total
    return solution


def reconstruct_matrix(solution_bits):
    A_rows = []
    for r in range(32):
        row_bits = 0
        for c in range(32):
            if solution_bits[r * 32 + c]:
                row_bits |= 1 << c
        A_rows.append(row_bits)
    B = 0
    for i in range(32):
        if solution_bits[1024 + i]:
            B |= 1 << i
    return A_rows, B


def step(state, A_rows, B):
    next_state = 0
    for j in range(32):
        bit = parity(A_rows[j] & state) ^ ((B >> j) & 1)
        next_state |= bit << j
    return next_state


def decode_cipher(path):
    data = path.read_bytes()
    try:
        txt = data.decode().strip()
        if txt and all(ch in "0123456789abcdefABCDEF" for ch in txt) and len(txt) % 2 == 0:
            return bytes.fromhex(txt)
    except UnicodeDecodeError:
        pass
    return data


def main():
    base = Path(__file__).resolve().parent
    states = [int(line.strip()) for line in (base / "keystream_leak.txt").read_text().splitlines() if line.strip()]
    rows, n_vars = build_system(states)
    # Use enough rows to get full rank (append gradually)
    rows = rows[:]  # already enough per challenge description
    solution = gaussian_elimination(rows, n_vars)
    A_rows, B = reconstruct_matrix(solution)

    # verify generator reproduces leak
    ok = True
    st = states[0]
    for expected in states[1:]:
        st = step(st, A_rows, B)
        if st != expected:
            ok = False
            break

    cipher = decode_cipher(base / "cipher.txt")
    st = states[0]
    keystream = []
    for _ in range(len(cipher)):
        keystream.append(st & 0xFF)
        st = step(st, A_rows, B)
    plain = bytes(c ^ k for c, k in zip(cipher, keystream))

    try:
        decoded = plain.decode("utf-8")
    except UnicodeDecodeError:
        decoded = plain.decode("utf-8", errors="replace")

    print(decoded)
    m = re.search(r"pctf\\{[^}]+\\}", decoded)
    if m:
        print(m.group(0))
    elif not ok:
        print("Verification failed; plaintext may be incorrect.")


if __name__ == "__main__":
    main()
