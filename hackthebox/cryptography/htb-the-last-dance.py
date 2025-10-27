import sys

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def main(path):
    with open(path, "r") as f:
        iv_hex = f.readline().strip()          # not needed for recovery, but parsed for clarity
        c1_hex = f.readline().strip()         # ciphertext of the known message
        c2_hex = f.readline().strip()         # ciphertext of FLAG

    c1 = bytes.fromhex(c1_hex)
    c2 = bytes.fromhex(c2_hex)

    # Recreate the known plaintext (exactly as in the original script)
    message = (
        b"Our counter agencies have intercepted your messages and a lot "
        b"of your agent's identities have been exposed. In a matter of "
        b"days all of them will be captured"
    )

    # Ensure lengths: keystream derived from c1/message
    if len(c1) < len(message):
        raise SystemExit("ciphertext for known message is shorter than the known message bytes.")

    # Derive keystream by XORing ciphertext of known message with the known message
    keystream = xor_bytes(c1, message)

    # Use the corresponding prefix of keystream to decrypt FLAG
    ks_for_flag = keystream[: len(c2)]
    recovered_flag = xor_bytes(c2, ks_for_flag)

    # Try to print as UTF-8 if possible, else show hex
    try:
        print("Recovered FLAG (utf-8):")
        print(recovered_flag.decode("utf-8"))
    except UnicodeDecodeError:
        print("Recovered FLAG (raw bytes):")
        print(recovered_flag)
        print("Recovered FLAG (hex):", recovered_flag.hex())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 htb-the-last-dance.py out.txt")
        raise SystemExit(1)
    main(sys.argv[1])