# this script attempts to decode a binary message by manipulating bits
# in each byte, focusing on operations involving the least significant bit (LSB).

bin_msg = '01001000 01101001 01101001 01101001 00100000 01101101 01100001 01101110 00101100 01101000 01101111 01110111 00100000 01110010 00100000 01110101 00100000 00111111 01001001 01110011 00100000 01101001 01110100 00100000 00111010 00101001 00101001 00101001 00101001 01010010 01100001 01110111 01110010 00101101 01011110 01011110 01011011 01011101 00100000 00100000 01001100 01010011 01000010 01111011 00111110 00111100 01111101 00100001 01001100 01010011 01000010 01111110 01111110 01001100 01010011 01000010 01111110 01111110 00101101 00101101 00101101 01110110 00110001 01110100 00100000 00100000 01111011 00110001 00110011 00110101 00111001 00110000 00110000 0101111F 00110001 00110011 00110011 00110111 00110000 01111101'


def swap_msb_lsb(byte_str: str) -> str:
    """Swap the most and least significant bits of an 8-bit binary string."""
    if len(byte_str) != 8:
        raise ValueError("Expected 8-bit chunks.")
    if byte_str[0] == byte_str[-1]:
        return byte_str  # swapping identical bits has no effect
    return byte_str[-1] + byte_str[1:-1] + byte_str[0]


def rotate_right(byte_str: str) -> str:
    """Rotate an 8-bit binary string right by one (LSB moves to MSB position)."""
    if len(byte_str) != 8:
        raise ValueError("Expected 8-bit chunks.")
    return byte_str[-1] + byte_str[:-1]


def decode(bits_list: list[str]) -> str:
    return ''.join(chr(int(b, 2)) for b in bits_list)


bits = bin_msg.split()

# Original decode for reference.
original_message = decode(bits)

# Focus on occurrences of the substring "LSB" and try two sample LSB operations:
indices_of_lsb = []
for idx in range(len(original_message) - 2):
    if original_message[idx : idx + 3] == "LSB":
        indices_of_lsb.extend([idx, idx + 1, idx + 2])

# Demonstrate swapping MSB/LSB on those characters.
bits_swap = bits.copy()
for idx in indices_of_lsb:
    bits_swap[idx] = swap_msb_lsb(bits_swap[idx])
swap_message = decode(bits_swap)
swap_bin = ' '.join(bits_swap)

# Demonstrate a right-rotation (LSB -> MSB) on the same characters.
bits_rotate = bits.copy()
for idx in indices_of_lsb:
    bits_rotate[idx] = rotate_right(bits_rotate[idx])
rotate_message = decode(bits_rotate)
rotate_bin = ' '.join(bits_rotate)

print("Original :", original_message)
print("Original bin :", ' '.join(bits))
print("Swap MSB<->LSB :", swap_message)
print("Swap bin       :", swap_bin)
print("Rotate right   :", rotate_message)
print("Rotate bin     :", rotate_bin)
