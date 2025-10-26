# https://kshackzone.com/ctfs/challenge/uap-cyber-siege-2025-qualification-round/279/the-russian-doll-cipher

# This challenge involves reversing multiple layers of custom encoding to recover the original flag.
# The layers applied (from innermost to outermost) are:
# 1. Reversal of the string.
# 2. ROT13 encoding.
# 3. A custom digit mapping (0→3, 3→4, 4→1).
# 4. Pairwise swapping of characters.
# 5. Base64 encoding.
# 6. A Caesar cipher with a shift of +5 applied to letters only.

import base64
import codecs

CIPHERTEXT = "SM1bfIWrC0ZeWA9YR0mkYLK4iYK7W1GL"


def undo_caesar_letters(text: str, shift: int = 5) -> str:
    # Reverse a Caesar +shift applied to letters (digits/symbols untouched).
    result = []
    for ch in text:
        if "A" <= ch <= "Z":
            result.append(chr((ord(ch) - 65 - shift) % 26 + 65))
        elif "a" <= ch <= "z":
            result.append(chr((ord(ch) - 97 - shift) % 26 + 97))
        else:
            result.append(ch)
    return "".join(result)


def swap_every_two(text: str) -> str:
    # Undo the pairwise swapping (swap adjacent characters back).
    chars = list(text)
    for i in range(0, len(chars) - 1, 2):
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
    return "".join(chars)


def undo_digit_twist(text: str) -> str:
    # Invert the custom digit mapping (0→3, 3→4, 4→1 during encryption).
    return text.translate(str.maketrans({"4": "3", "3": "0", "1": "4"}))


def main() -> None:
    # Layer 6: undo Caesar +5 on letters.
    layer5 = undo_caesar_letters(CIPHERTEXT)

    # Layer 5: undo Base64 encoding.
    layer4 = base64.b64decode(layer5).decode()

    # Layer 4: restore the original adjacency (swap every two characters back).
    layer3 = swap_every_two(layer4)

    # Layer 3: undo the digit twist.
    layer2 = undo_digit_twist(layer3)

    # Layer 2: undo ROT13 (same function as encode).
    layer1 = codecs.decode(layer2, "rot_13")

    # Layer 1: undo the original reversal.
    flag = layer1[::-1]

    print(flag)


if __name__ == "__main__":
    main()
