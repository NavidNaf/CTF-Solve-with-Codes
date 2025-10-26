This directory contains solves from kshackzone. The problems are.

| Type | File | Description |
| --- | --- | --- |
| Cryptography | `cryptography/uapcs-russian-doll-cipher.py` | Peels back layered encodings (Caesar, Base64, swaps, ROT13, reversal) to recover the flag. |
| Cryptography | `cryptography/knight-alphabetknockcode.py` | Decodes a 4x6 alphabet knock code and resolves ambiguous squares using simple heuristics. |
| Cryptography | `cryptography/smp-seed-the-flag.py` | Recreates a seed-driven XOR and digit shuffling process to expose the hidden secret and prime for RSA diagnostics. |
| Cryptography | `cryptography/smp-binary-secret.py` | Reverses a multiply-then-binary encoding scheme to reveal the plaintext message. |
| Cryptography | `cryptography/smp-seed-the-flag2.py` | Derives the XOR seed to recover the hidden secret and unshuffle the scrambled prime candidates. |
| Cryptography | `cryptography/knight-random-shamir-adelman.py` | Regenerates a PRNG-derived RSA prime from the shared seed to compute the private key and decrypt the ciphertext. |
| Cryptography | `cryptography/knight-feistival-reverse.py` | Inverts the two-round Feistel routine from enc.py to restore the original plaintext from the cipher file. |
| Cryptography | `cryptography/bupctf-crack-the-hash.py` | Implements a hint-driven MD5 brute forcer over structured password candidates for the target hash. |
| Cryptography | `cryptography/knight-twin-hex-cipher.py` | Provides encoding and decoding utilities for the Twin-Hex cipher that maps character pairs to Base36 triplets. |
| Cryptography | `cryptography/uapcs-custom-xor-madness.py` | Reverses a Base64/+11/XOR pipeline to decrypt the provided ciphertext with the recovered key. |
| Programming | `programming/knight-reverse-the-answer.py` | Iterates x from 1 to 543, reverses computed values, and accumulates those divisible by four. |
| Programming | `programming/knight-keep-calculating.py` | Sums (x*y) plus the concatenated xy term for x up to 666 to obtain the final flag value. |
| Programming | `programming/knight-loop-in-a-loop.py` | Undoes the nested swap loops that scrambled the flag to recover the original string from input. |
| Programming | `programming/knight-square-sum.py` | Finds all nonnegative integer pairs whose squares sum to the user-provided target and prints the decompositions. |
