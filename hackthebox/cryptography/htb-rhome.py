# Exploit script for the HTB "rhome" challenge server. The server uses a
# Diffie-Hellman setup where the generator lives in a very small subgroup of
# size q ≈ 2^42. Thanks to that, a simple baby-step giant-step discrete log
# recovers the private exponent which we can then reuse to derive the AES key.

import math
import re
import sys
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from pwn import context, remote

# Upper bound for the subgroup order; q itself is a 42-bit prime.
SUBGROUP_BOUND = 1 << 42


def bsgs(base, target, modulus, bound=SUBGROUP_BOUND):
    """Baby-step giant-step discrete log in Z_p* with known exponent bound."""
    m = math.isqrt(bound) + 1  # size of the baby-step table (ceil of √bound)
    table = {}  # dictionary for baby-step values keyed by g^j
    acc = 1  # running value for g^j during baby-step population
    for j in range(m):  # iterate over baby-step exponents j
        table.setdefault(acc, j)  # record exponent j for current baby step
        acc = (acc * base) % modulus  # advance to the next g^j value
    inverse_base = pow(base, modulus - 2, modulus)  # compute g^{-1} via Fermat
    giant_factor = pow(inverse_base, m, modulus)  # precompute g^{-m} for jumps
    gamma = target  # start the giant-step walk from the target value
    for i in range(m + 1):  # loop over giant-step multiples i
        if gamma in table:  # check whether current gamma matches a baby step
            return i * m + table[gamma]  # combine exponents i*m + j when match
        gamma = (gamma * giant_factor) % modulus  # multiply by g^{-m} to step
    raise ValueError("Discrete log not found within bound.")  # no solution found


def recover_shared_secret(p, g, A, B):
    """Recover the shared secret using the small-subgroup discrete log."""
    a = bsgs(g, A, p)  # compute Alice's exponent a modulo the subgroup order
    return pow(B, a, p)  # raise Bob's public value to a to obtain g^{ab}


def derive_key(shared_secret):
    """Derive the 128-bit AES key from the shared secret as the server does."""
    hashed = sha256(long_to_bytes(shared_secret)).digest()  # H(shared_secret)
    return hashed[:16]  # truncate to the first 16 bytes for AES-128


def decrypt_flag(key, ct_hex):
    """AES-ECB decrypt + PKCS#7 unpad the flag ciphertext."""
    cipher = AES.new(key, AES.MODE_ECB)  # recreate the server's AES context
    ciphertext = bytes.fromhex(ct_hex)  # decode the hex-encoded ciphertext
    plaintext = cipher.decrypt(ciphertext)  # perform AES-ECB decryption
    return unpad(plaintext, 16)  # remove PKCS#7 padding to retrieve the flag


def parse_params(blob):
    """Extract p, g, A, B from the server response."""
    pattern = r"p = (\d+)\ng = (\d+)\nA = (\d+)\nB = (\d+)"
    match = re.search(pattern, blob)
    if not match:
        raise ValueError("Failed to parse parameters from server response.")
    return tuple(int(group) for group in match.groups())


def parse_ciphertext(blob):
    """Extract the ciphertext hex string from the server response."""
    match = re.search(r"encrypted = ([0-9a-fA-F]+)", blob)
    if not match:
        raise ValueError("Failed to parse ciphertext from server response.")
    return match.group(1)


def recv_until_prompt(conn):
    """Drain output until the next '> ' prompt shows up."""
    return conn.recvuntil(b"> ")


def send_choice(conn, choice):
    """Send a menu choice and return everything up to the next prompt."""
    conn.sendline(str(choice).encode())
    return conn.recvuntil(b"> ").decode()


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} HOST PORT")
        sys.exit(1)

    host, port = sys.argv[1], int(sys.argv[2])
    context.log_level = "error"

    with remote(host, port) as conn:
        recv_until_prompt(conn)  # initial menu banner
        params_blob = send_choice(conn, 1)
        p, g, A, B = parse_params(params_blob)

        ct_blob = send_choice(conn, 3)
        ct_hex = parse_ciphertext(ct_blob)

        shared = recover_shared_secret(p, g, A, B)
        key = derive_key(shared)
        flag = decrypt_flag(key, ct_hex)
        print(flag.decode(errors="ignore"))


if __name__ == "__main__":
    main()
