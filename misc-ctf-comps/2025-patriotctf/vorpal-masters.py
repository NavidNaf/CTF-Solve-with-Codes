#!/usr/bin/env python3
# Recover Vorpal Masters license by solving the arithmetic check extracted from the binary.

def to32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x & 0x80000000 else x


def u32(x: int) -> int:
    return x & 0xFFFFFFFF


def check(n: int) -> bool:
    # Range check
    if n < -5000 or n > 10000:
        return False

    # First arithmetic block
    eax = u32(n + 0x16)
    edx = (eax * 0x096D4B1F) & 0xFFFFFFFFFFFFFFFF
    edx = (edx >> 32) & 0xFFFFFFFF
    ecx = u32(to32(edx) >> 6)
    edx = 0xFFFFFFFF if eax & 0x80000000 else 0
    ecx = u32(to32(ecx) - to32(edx))
    edx = u32(ecx * 0x6CA)
    eax = u32(eax - edx)
    ecx = eax

    # Second arithmetic block
    eax = u32(n * 2)
    edx = (eax * 0x10624DD3) & 0xFFFFFFFFFFFFFFFF
    edx = (edx >> 32) & 0xFFFFFFFF
    edx = u32(to32(edx) >> 7)
    esi = (to32(eax) >> 31) & 0xFFFFFFFF
    edx = u32(edx - esi)
    esi = u32(edx * 0x7D0)
    eax = u32(eax - esi)
    edx = eax
    eax = u32(eax + eax)
    eax = u32(eax + edx)
    eax = u32(eax + eax)
    eax = u32(eax + 9)

    return to32(ecx) == to32(eax)


def main() -> None:
    # Solve for the integer component (prefer positive solution if available).
    solutions = [n for n in range(-5000, 10001) if check(n)]
    if not solutions:
        return
    valid_n = min((n for n in solutions if n >= 0), default=solutions[0])

    key = f"CACI-{valid_n}-PatriotCTF"
    print(f"CACI{{{key}}}")


if __name__ == "__main__":
    main()
