#!/usr/bin/env python3
import hashlib
import json
from itertools import product

from pwn import context, remote

HOST = "154.57.164.67"
PORT = 31146

S_BOX = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
    202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
    183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
    4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
    9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
    83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
    208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
    81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
    205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
    96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
    224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
    231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
    186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
    112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
    225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
    140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22,
]

INV_S = [0] * 256
for i, v in enumerate(S_BOX):
    INV_S[v] = i

HEXSET = set(b"0123456789abcdef")
PREFIX = b'{"s": "'


def bytes2matrix(text):
    return [list(text[i : i + 4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix):
    return bytes(sum(matrix, []))


def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a


def mix_columns(state):
    return [mix_single_column(state[i].copy()) for i in range(4)]


def inv_mix_columns(state):
    res = [row.copy() for row in state]
    for i in range(4):
        u = xtime(xtime(res[i][0] ^ res[i][2]))
        v = xtime(xtime(res[i][1] ^ res[i][3]))
        res[i][0] ^= u
        res[i][1] ^= v
        res[i][2] ^= u
        res[i][3] ^= v
    return mix_columns(res)


def sub_bytes(state):
    return [[S_BOX[b] for b in row] for row in state]


def inv_sub_bytes(state):
    return [[INV_S[b] for b in row] for row in state]


def shift_rows(state):
    res = [state[i].copy() for i in range(4)]
    res[0][1], res[1][1], res[2][1], res[3][1] = (
        res[1][1],
        res[2][1],
        res[3][1],
        res[0][1],
    )
    res[0][2], res[1][2], res[2][2], res[3][2] = (
        res[2][2],
        res[3][2],
        res[0][2],
        res[1][2],
    )
    res[0][3], res[1][3], res[2][3], res[3][3] = (
        res[3][3],
        res[0][3],
        res[1][3],
        res[2][3],
    )
    return res


def inv_shift_rows(state):
    res = [state[i].copy() for i in range(4)]
    res[0][1], res[1][1], res[2][1], res[3][1] = (
        res[3][1],
        res[0][1],
        res[1][1],
        res[2][1],
    )
    res[0][2], res[1][2], res[2][2], res[3][2] = (
        res[2][2],
        res[3][2],
        res[0][2],
        res[1][2],
    )
    res[0][3], res[1][3], res[2][3], res[3][3] = (
        res[1][3],
        res[2][3],
        res[3][3],
        res[0][3],
    )
    return res


def ark(state, key):
    return [[a ^ b for a, b in zip(row, krow)] for row, krow in zip(state, key)]


def encrypt_block(block, k0, k1):
    s = bytes2matrix(block)
    s = ark(s, k0)
    s = sub_bytes(s)
    s = shift_rows(s)
    s = mix_columns(s)
    s = ark(s, k1)
    return matrix2bytes(s)


def decrypt_block(block, k0, k1):
    s = bytes2matrix(block)
    s = ark(s, k1)
    s = inv_mix_columns(s)
    s = inv_shift_rows(s)
    s = inv_sub_bytes(s)
    s = ark(s, k0)
    return matrix2bytes(s)


def pad16(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def last_block_plain(uid):
    if uid < 10:
        return b"}" + bytes([0x0F]) * 15
    return bytes([ord(str(uid)[1])]) + b"}" + bytes([0x0E]) * 14


def recover_k0(ciphers, plains):
    base_uid = 1
    base_p = plains[base_uid]
    base_c = ciphers[base_uid]
    candidates = [set(range(256)) for _ in range(16)]

    for uid in range(10, 20):
        p = plains[uid]
        c = ciphers[uid]
        c_diff = bytes([a ^ b for a, b in zip(base_c, c)])
        state = inv_mix_columns(bytes2matrix(c_diff))
        state = inv_shift_rows(state)
        delta = sum(state, [])
        for i in range(16):
            candidates[i] = {
                k
                for k in candidates[i]
                if S_BOX[base_p[i] ^ k] ^ S_BOX[p[i] ^ k] == delta[i]
            }
    return candidates


def brute_force_key(k0_candidates, base_p, base_c, check_block):
    ambiguous = [i for i, c in enumerate(k0_candidates) if len(c) > 1]
    base = [next(iter(c)) for c in k0_candidates]

    for bits in product([0, 1], repeat=len(ambiguous)):
        k0_bytes = base[:]
        for bit, idx in zip(bits, ambiguous):
            k0_bytes[idx] = sorted(k0_candidates[idx])[bit]
        k0 = [k0_bytes[i : i + 4] for i in range(0, 16, 4)]

        s = bytes2matrix(base_p)
        s = ark(s, k0)
        s = sub_bytes(s)
        s = shift_rows(s)
        s = mix_columns(s)
        k1_bytes = [a ^ b for a, b in zip(sum(s, []), base_c)]
        k1 = [k1_bytes[i : i + 4] for i in range(0, 16, 4)]

        dec = decrypt_block(check_block, k0, k1)
        if not dec.startswith(PREFIX):
            continue
        if all(b in HEXSET for b in dec[len(PREFIX) :]):
            return bytes(k0_bytes), bytes(k1_bytes)
    raise RuntimeError("key recovery failed")


def main():
    context.log_level = "info"
    io = remote(HOST, PORT)

    tokens = {}
    for _ in range(19):
        io.recvuntil(b"> ")
        io.sendline(b"1")
        io.recvuntil(b"Enter username: ")
        io.sendline(b"user")
        resp = json.loads(io.recvline().decode())
        uid = len(tokens) + 1
        tokens[uid] = bytes.fromhex(resp["token"])

    plains = {uid: last_block_plain(uid) for uid in tokens}
    ciphers = {uid: tokens[uid][-16:] for uid in tokens}

    k0_candidates = recover_k0(ciphers, plains)
    k0_bytes, k1_bytes = brute_force_key(
        k0_candidates,
        plains[1],
        ciphers[1],
        tokens[1][:16],
    )

    key = k0_bytes + k1_bytes

    admin_uid = 0
    admin_user = b"TinselwickAdmin"
    snowprint = hashlib.shake_256(key + admin_user + b"0").digest(64)
    payload = json.dumps({"s": snowprint.hex(), "i": admin_uid}).encode()
    pt = pad16(payload)
    k0 = [list(k0_bytes[i : i + 4]) for i in range(0, 16, 4)]
    k1 = [list(k1_bytes[i : i + 4]) for i in range(0, 16, 4)]
    ct = b"".join(encrypt_block(pt[i : i + 16], k0, k1) for i in range(0, len(pt), 16))

    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"Enter UID: ")
    io.sendline(b"0")
    io.recvuntil(b"Enter username: ")
    io.sendline(admin_user)
    io.recvuntil(b"Enter token (hex): ")
    io.sendline(ct.hex().encode())
    print(io.recvline().decode().strip())


if __name__ == "__main__":
    main()
