import ast
import os
import hashlib


CANDYCANE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SZ = 6
N_ROUNDS = 14

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

INV_S_BOX = [
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
    84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
    8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
    114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
    108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
    144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
    208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
    58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
    150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
    71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
    252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
    96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
    160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
    23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
]

R_CON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def bytes2matrix(text):
    return [list(text[i : i + 4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix):
    return bytes(sum(matrix, []))


def xor_words(a, b):
    return [i ^ j for i, j in zip(a, b)]


def sub_word(word):
    return [S_BOX[b] for b in word]


def rot_word(word):
    return word[1:] + word[:1]


def expand_key(master_key):
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        word = list(key_columns[-1])
        if len(key_columns) % iteration_size == 0:
            word = xor_words(sub_word(rot_word(word)), [R_CON[i], 0, 0, 0])
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            word = sub_word(word)
        word = xor_words(word, key_columns[-iteration_size])
        key_columns.append(word)
    return [key_columns[4 * i : 4 * (i + 1)] for i in range(N_ROUNDS + 1)]


def add_round_key(state, key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[i][j]


def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = S_BOX[state[i][j]]


def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = INV_S_BOX[state[i][j]]


def shift_rows(state):
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[1][1],
        state[2][1],
        state[3][1],
        state[0][1],
    )
    state[0][2], state[1][2], state[2][2], state[3][2] = (
        state[2][2],
        state[3][2],
        state[0][2],
        state[1][2],
    )
    state[0][3], state[1][3], state[2][3], state[3][3] = (
        state[3][3],
        state[0][3],
        state[1][3],
        state[2][3],
    )


def inv_shift_rows(state):
    state[0][1], state[1][1], state[2][1], state[3][1] = (
        state[3][1],
        state[0][1],
        state[1][1],
        state[2][1],
    )
    state[0][2], state[1][2], state[2][2], state[3][2] = (
        state[2][2],
        state[3][2],
        state[0][2],
        state[1][2],
    )
    state[0][3], state[1][3], state[2][3], state[3][3] = (
        state[1][3],
        state[2][3],
        state[3][3],
        state[0][3],
    )


def xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(state):
    for i in range(4):
        mix_single_column(state[i])


def inv_mix_columns(state):
    for i in range(4):
        u = xtime(xtime(state[i][0] ^ state[i][2]))
        v = xtime(xtime(state[i][1] ^ state[i][3]))
        state[i][0] ^= u
        state[i][1] ^= v
        state[i][2] ^= u
        state[i][3] ^= v
    mix_columns(state)


class AES256:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self.round_keys = expand_key(key)

    def decrypt_block(self, ciphertext):
        if len(ciphertext) != 16:
            raise ValueError("Block must be 16 bytes")
        state = bytes2matrix(ciphertext)
        add_round_key(state, self.round_keys[-1])
        inv_shift_rows(state)
        inv_sub_bytes(state)
        for r in range(N_ROUNDS - 1, 0, -1):
            add_round_key(state, self.round_keys[r])
            inv_mix_columns(state)
            inv_shift_rows(state)
            inv_sub_bytes(state)
        add_round_key(state, self.round_keys[0])
        return matrix2bytes(state)


def aes256_ecb_decrypt(key, data):
    if len(data) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")
    aes = AES256(key)
    blocks = []
    for i in range(0, len(data), 16):
        blocks.append(aes.decrypt_block(data[i : i + 16]))
    return b"".join(blocks)


def parse_output(path):
    data = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            k, v = line.split(" = ", 1)
            data[k] = ast.literal_eval(v)
    return data["PEPPERMINT_KEYWORD"], data["PEPPERMINT_CIPHERTEXT"], data["WRAPPED_STARSHARD"]


def weave_peppermint_square(keyword):
    flat = CANDYCANE_ALPHABET
    for c in keyword:
        flat = flat.replace(c, "")
    flat = keyword + flat
    return [list(flat[i : i + SZ]) for i in range(0, len(flat), SZ)]


def build_coords(square):
    char_to_coord = {
        square[i][j]: int(f"{i+1}{j+1}") for j in range(SZ) for i in range(SZ)
    }
    coord_to_char = {v: k for k, v in char_to_coord.items()}
    return char_to_coord, coord_to_char


def solve_key_and_plaintext(ciphertext, coord_to_char):
    coords = sorted(coord_to_char.keys())
    coords_set = set(coords)
    groups = [[] for _ in range(SZ * SZ)]
    for i, ct in enumerate(ciphertext):
        groups[i % (SZ * SZ)].append(ct)

    domains = []
    for g in groups:
        opts = []
        for k in coords:
            if all((ct - k) in coords_set for ct in g):
                opts.append(k)
        domains.append(opts)

    order = sorted(range(len(domains)), key=lambda i: len(domains[i]))
    assignment = [None] * len(domains)
    used = set()

    def backtrack(idx):
        if idx == len(order):
            return True
        pos = order[idx]
        for k in domains[pos]:
            if k in used:
                continue
            used.add(k)
            assignment[pos] = k
            if backtrack(idx + 1):
                return True
            used.remove(k)
            assignment[pos] = None
        return False

    if not backtrack(0):
        raise ValueError("No valid key assignment found")

    plaintext = []
    for i, ct in enumerate(ciphertext):
        k = assignment[i % (SZ * SZ)]
        pt_coord = ct - k
        plaintext.append(coord_to_char[pt_coord])
    return "".join(plaintext)


def pkcs7_unpad(data):
    if not data:
        raise ValueError("Empty plaintext")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Bad padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bad padding")
    return data[:-pad_len]


def main():
    keyword, ciphertext, wrapped_hex = parse_output(
        os.path.join(os.path.dirname(__file__), "output.txt")
    )
    square = weave_peppermint_square(keyword)
    _, coord_to_char = build_coords(square)
    festive_whisper = solve_key_and_plaintext(ciphertext, coord_to_char)

    cocoa_key = hashlib.sha256(festive_whisper.encode()).digest()
    wrapped = bytes.fromhex(wrapped_hex)
    plaintext = aes256_ecb_decrypt(cocoa_key, wrapped)
    starshard = pkcs7_unpad(plaintext)

    print("FESTIVE_WHISPER_CLEAN =", festive_whisper)
    print("STARSHARD_SCROLL =", starshard.decode(errors="replace"))


if __name__ == "__main__":
    main()
