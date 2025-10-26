# https://kshackzone.com/ctfs/challenge/uap-cyber-siege-2025-qualification-round/278/custom-xor-madness

# Simple decoder for the UAPCS “custom XOR madness” challenge.
# The original encoder ran: XOR byte → add 11 → Base64.
# Here we just walk those steps backwards with the known key.

import base64
from pathlib import Path


def decrypt(ciphertext: str, key: str) -> str:
    # Undo the +11 shift and XOR with the repeating key.
    data = base64.b64decode(ciphertext)
    key_bytes = key.encode()

    plain = []
    for i, value in enumerate(data):
        shifted = (value - 11) % 256           # Undo the +11 tweak.
        plain_byte = shifted ^ key_bytes[i % len(key_bytes)]  # Undo the XOR.
        plain.append(plain_byte)

    return bytes(plain).decode()


def main() -> None:
    encrypted_path = Path(__file__).with_name("encrypted.txt")
    ciphertext = encrypted_path.read_text(encoding="utf-8").strip()

    key = "M4sk3dC0mpLex"  # Full key recovered from the puzzle.
    plaintext = decrypt(ciphertext, key)
    print(plaintext)


if __name__ == "__main__":
    main()
