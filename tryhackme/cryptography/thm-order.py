# Ciphertext segments intercepted from Cipher (hex encoded)
cipher_hex_segments = [
    "1c1c01041963730f31352a3a386e24356b3d32392b6f6b0d323c22243f6373",
    "1a0d0c302d3b2b1a292a3a38282c2f222d2a112d282c31202d2d2e24352e60",
]

# Convert each segment from hex to raw bytes so we can manipulate them
cipher_segments = [bytes.fromhex(segment) for segment in cipher_hex_segments]

# Known plaintext header that every message begins with
known_header = b"ORDER:"

# Derive the repeating key stream for the header bytes via known-plaintext XOR
key_stream = bytes(
    ct_byte ^ known_header[i] for i, ct_byte in enumerate(cipher_segments[0][: len(known_header)])
)

# Discover the smallest repeating pattern (the actual key) inside the derived stream
key_length = next(
    period
    for period in range(1, len(key_stream) + 1)
    if all(key_stream[i] == key_stream[i % period] for i in range(len(key_stream)))
)
key = key_stream[:key_length]

# Helper to XOR-decrypt a chunk with the repeating key, supporting an offset for later segments
def xor_with_key(data: bytes, key_bytes: bytes, start_offset: int = 0) -> bytes:
    return bytes(
        byte ^ key_bytes[(start_offset + idx) % len(key_bytes)] for idx, byte in enumerate(data)
    )

# Decrypt the first segment using the recovered key
first_plaintext = xor_with_key(cipher_segments[0], key)
print(first_plaintext.decode())

# Continue decrypting subsequent segments, taking the running key offset into account
offset = len(cipher_segments[0]) % len(key)
second_plaintext = xor_with_key(cipher_segments[1], key, offset)

# Using the recovered key (aligned with the continuing stream) to reveal the THM flag
print(second_plaintext.decode())
