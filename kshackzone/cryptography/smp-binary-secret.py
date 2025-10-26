# https://kshackzone.com/ctfs/challenge/smp-ctf-2024-selection-round/163/binary-secrets

# smp-binary-secret.py - decodes a binary-encoded secret string.
# This challenge involves reversing a custom encoding scheme where each character
# of the secret is converted to its ASCII integer value, multiplied by (69 + 67),
# and then represented as a binary string.

def decode_binary(encoded: str) -> str:
    # Undo the encoder: binary -> int -> divide by (69+67) -> char.
    factor = 69 + 67
    return "".join(chr(int(chunk, 2) // factor) for chunk in encoded.split())


if __name__ == "__main__":
    try:
        data = input("Enter the encoded binary string: ").strip()
    except EOFError:
        data = ""

    if data:
        print(decode_binary(data))
    else:
        print("No input provided.")
