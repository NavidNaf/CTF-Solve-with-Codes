# This script decrypts a ciphertext encrypted with a repeating-key XOR cipher. It leverages a known plaintext prefix to derive the encryption key. 
# The script reads the ciphertext from 'encrypted.txt', derives the key, and outputs both the key and the decrypted plaintext.

import binascii
import string

KEY_LEN = 5
KNOWN_PREFIX = b'HTB{'
PRINTABLE = set(bytes(string.printable, 'ascii')) - {ord('\n'), ord('\r'), ord('\t'), ord('\x0b'), ord('\x0c')}


def read_ciphertext(path: str) -> bytes:
    with open(path, 'r') as f:
        return binascii.unhexlify(f.read().strip())


def xor_with_key(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        out[i] = byte ^ key[i % key_len]
    return bytes(out)


def derive_key(enc: bytes) -> bytes:
    key = [None] * KEY_LEN

    for idx, plain_byte in enumerate(KNOWN_PREFIX):
        key_idx = idx % KEY_LEN
        candidate = enc[idx] ^ plain_byte
        stored = key[key_idx]
        if stored is None:
            key[key_idx] = candidate
        elif stored != candidate:
            raise ValueError('Known prefix does not align with repeating key.')

    if None not in key:
        return bytes(key)

    missing_index = key.index(None)
    for guess in range(256):
        key[missing_index] = guess
        plaintext = xor_with_key(enc, bytes(key))
        if plaintext.startswith(KNOWN_PREFIX) and all(ch in PRINTABLE for ch in plaintext):
            return bytes(key)
    raise ValueError('Unable to derive key from known prefix.')


def main():
    enc = read_ciphertext('encrypted.txt')
    key = derive_key(enc)
    plaintext = xor_with_key(enc, key)
    print('Key:', key)
    print('Plaintext:', plaintext.decode('ascii', errors='replace'))


if __name__ == '__main__':
    main()
