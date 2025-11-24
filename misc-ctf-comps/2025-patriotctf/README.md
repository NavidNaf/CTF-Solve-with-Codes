# Solutions Overview

| File | Description |
| --- | --- |
| space-pirates.py | Inverts the level 1 pirate cipher from challenge.c to recover the initial flag by reversing XOR, swaps, and positional tweaks. |
| space-pirates-2.py | Implements the inverse of the upgraded Rust cipher in main.rs, undoing rotations, swaps, and magic shifts to reveal the treasure map flag. |
| space-pirates-3.py | Reverses the Go-based vault checker, applying inverse rotations, XORs, and chunk reversals to obtain the final Pirate King vault flag. |
| password-palooza.py | Brute-forces an MD5 hash by appending two-digit suffixes to wordlist entries to find the correct password. |
| cipher-from-hell.py | Decodes a custom trit/base9 scrambling cipher to reconstruct the original plaintext flag from the encrypted blob. |
| nonce-twice-pay-price.py | Exploits ECDSA nonce reuse to recover the private key and decrypt secret_blob.bin, revealing the flag. |
| display.py | Parses the metapixel display.mc file, reconstructs the “eaten” grid, and extracts the embedded flag text. |
| readmynote.py | Scans the Windows PE file ReadMyNote.exe (with XOR/rot/ROT transforms) to locate an obfuscated flag string. |
| matrix-reconstruction.py | Rebuilds a linear PRG (matrix A and vector B) from leaked states to decrypt a keystream-encrypted ciphertext. |
| vorpal-masters.py | Derives the required arithmetic check value from encryptor logic to produce the valid license key flag. |
| entropy-discord.py | Uses symbolic execution to drive the entropy-discord binary to a success path and recover the printed flag. |
| cursed-format.py | Drives the remote format-string service, leaking stack data via dynamic offsets to hunt for the flag output. |
