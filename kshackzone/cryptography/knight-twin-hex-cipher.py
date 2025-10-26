# https://kshackzone.com/ctfs/challenge/knightctf-2022/21/the-pairs

# Twin-Hex Cipher Implementation
# This script implements the Twin-Hex cipher, which encodes pairs of ASCII characters
# into a base36 representation using 3 characters, and decodes them back.

# Mapping digits 0-9A-Z for base36
DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASE = len(DIGITS)

# Convert integer (0–35) to base36 char
def int_to_b36(n):
    return DIGITS[n]

# Convert base36 char to integer
def b36_to_int(c):
    return DIGITS.index(c)

# -------------- ENCODER --------------
def twinhex_encode(plaintext):
    # Encodes text into Twin-Hex format.
    # Takes 2 ASCII chars → 3 Base36 chars.
    encoded = []
    pad_needed = len(plaintext) % 2
    padded = plaintext + ("\x00" if pad_needed else "")
    for i in range(0, len(padded), 2):
        block = padded[i : i + 2]
        if len(block) < 2:
            block += "\x00"
        a, b = block
        n = (ord(a) << 8) + ord(b)      # 256*a + b
        d1 = n // (BASE ** 2)
        d2 = (n // BASE) % BASE
        d3 = n % BASE
        encoded.extend((int_to_b36(d1), int_to_b36(d2), int_to_b36(d3)))
    encoded.append(int_to_b36(pad_needed))
    return "".join(encoded)

# Decoder
def twinhex_decode(ciphertext):
    """
    Decodes Twin-Hex format back to plaintext.
    Takes 3 Base36 chars → 2 ASCII chars.
    """
    payload = ciphertext.replace(" ", "").upper()
    if not payload:
        return ""
    if len(payload) % 3 == 0:
        pad_count = 0
    else:
        pad_char, payload = payload[-1], payload[:-1]
        pad_count = b36_to_int(pad_char)
        if len(payload) % 3 != 0:
            raise ValueError("Ciphertext length invalid for Twin-Hex decoding.")

    decoded_chars = []
    for i in range(0, len(payload), 3):
        block = payload[i:i+3]
        if len(block) < 3:  # ignore incomplete final block
            continue
        n = (
            b36_to_int(block[0]) * (BASE ** 2)
            + b36_to_int(block[1]) * BASE
            + b36_to_int(block[2])
        )
        a = n // 256
        b = n % 256
        decoded_chars.append(chr(a))
        decoded_chars.append(chr(b))
    if pad_count:
        if pad_count > len(decoded_chars):
            raise ValueError("Invalid padding in ciphertext.")
        decoded_chars = decoded_chars[:-pad_count]
    return "".join(decoded_chars)

# Test
def main():
    print("Twin-Hex Cipher")
    print("1) Encode text")
    print("2) Decode text")
    try:
        choice = input("Select option (1/2): ").strip()
    except EOFError:
        print("No input provided. Exiting.")
        return

    if choice == "1":
        text = input("Enter plaintext to encode: ")
        encoded = twinhex_encode(text)
        print("Encoded:", encoded)
    elif choice == "2":
        cipher = input("Enter ciphertext to decode: ")
        try:
            decoded = twinhex_decode(cipher)
            print("Decoded:", decoded)
        except ValueError as exc:
            print(f"Decoding failed: {exc}")
    else:
        print("Invalid choice. Please run again and choose 1 or 2.")


if __name__ == "__main__":
    main()
