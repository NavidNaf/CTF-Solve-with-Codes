#!/usr/bin/env python3
import string
import sys

from pwn import context, remote

KEY_LENGTH = 5
FLAG_PREFIX = "THM{"
FLAG_SUFFIX = "}"


def extract_ciphertext(message):
    # Locate and return the challenge's hex-encoded ciphertext from the server banner.
    prefix = "This XOR encoded text has flag 1: "
    for line in message.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    raise ValueError("Ciphertext not found in server response.")


def decrypt(cipher_bytes, key):
    # XOR-decrypt the ciphertext bytes with the recovered repeating key.
    key_bytes = key.encode()
    plain_bytes = bytes(
        cipher_bytes[i] ^ key_bytes[i % KEY_LENGTH] for i in range(len(cipher_bytes))
    )
    return plain_bytes.decode()


def deduce_key_and_flag(cipher_hex):
    # Recover the random 5-character key and the first flag from the hex-encoded ciphertext.
    cipher_bytes = bytes.fromhex(cipher_hex.strip())
    if not cipher_bytes:
        raise ValueError("Received empty ciphertext from server.")

    allowed_key_chars = string.ascii_letters + string.digits
    allowed_key_points = {ord(ch) for ch in allowed_key_chars}

    key_codepoints = [None] * KEY_LENGTH
    key_candidates = [set() for _ in range(KEY_LENGTH)]

    for idx, ch in enumerate(FLAG_PREFIX):
        key_codepoints[idx % KEY_LENGTH] = cipher_bytes[idx] ^ ord(ch)
        if key_codepoints[idx % KEY_LENGTH] not in allowed_key_points:
            raise ValueError("Derived prefix key character is not alphanumeric.")
        key_candidates[idx % KEY_LENGTH] = {key_codepoints[idx % KEY_LENGTH]}

    suffix_slot = (len(cipher_bytes) - 1) % KEY_LENGTH
    suffix_value = cipher_bytes[-1] ^ ord(FLAG_SUFFIX)
    if suffix_value not in allowed_key_points:
        raise ValueError("Derived suffix key character is not alphanumeric.")
    if (
        key_codepoints[suffix_slot] is not None
        and key_codepoints[suffix_slot] != suffix_value
    ):
        raise ValueError("Conflicting key deduction from suffix character.")
    key_codepoints[suffix_slot] = suffix_value
    key_candidates[suffix_slot] = {suffix_value}

    for idx in range(KEY_LENGTH):
        if key_codepoints[idx] is not None:
            continue

        candidates = allowed_key_points.copy()
        for pos in range(idx, len(cipher_bytes), KEY_LENGTH):
            viable = {
                cand
                for cand in candidates
                if 32 <= (cipher_bytes[pos] ^ cand) <= 126
            }
            candidates = viable
            if not candidates:
                break

        if not candidates:
            raise ValueError(f"No valid key character found for index {idx}.")
        key_candidates[idx] = candidates

    from itertools import product

    for combo in product(
        *[tuple(sorted(cset)) for cset in key_candidates]
    ):
        key_bytes = bytes(combo)
        key = key_bytes.decode()
        plaintext = decrypt(cipher_bytes, key)
        if plaintext.startswith(FLAG_PREFIX) and plaintext.endswith(FLAG_SUFFIX):
            if all(32 <= ord(ch) <= 126 for ch in plaintext):
                return key, plaintext

    raise ValueError("Unable to determine unique key and plaintext.")


def main():
    # Connect to the challenge service, extract both flags, and print the results.
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Port must be an integer.")
        sys.exit(1)

    context.log_level = "error"
    tube = remote(host, port)
    try:
        banner = tube.recvuntil(b"What is the encryption key? ").decode()
        cipher_hex = extract_ciphertext(banner)
        key, flag_one = deduce_key_and_flag(cipher_hex)
        # Algorithm: brute-force the repeating XOR pad using prefix/suffix knowledge and printable constraints to reveal flag 1.
        print(f"Flag 1: {flag_one}")
        tube.sendline(key.encode())
        response = tube.recvall(timeout=1).decode()
    finally:
        tube.close()

    print(banner, end="")
    # Algorithm: submit the recovered key back to the service to obtain flag 2 via the challenge protocol.
    print(response, end="")


if __name__ == "__main__":
    main()
