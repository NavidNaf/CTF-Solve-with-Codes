# 2025 v1tCTF Scripts

| Type | File | Description |
| ---- | ---- | ----------- |
| Crypto | `bin-decode.py` | Repairs a corrupted binary string and prints the recovered message. |
| Crypto | `random-stuff.py` | Concatenates the recovered challenge fragments into the final flag. |
| Crypto | `rsa-101.py` | Factors the tiny RSA modulus, builds the private key, and outputs the plaintext. |
| Crypto | `shamirs-duck.py` | Reconstructs the Shamir secret from the provided shares and displays it. |
| Crypto | `txt.py` | Translates whitespace-only lines into bits and reveals the hidden text. |
| Exploit | `waddler.py` | Crafts a simple overflow payload that jumps to `duck()` on the challenge service. |
