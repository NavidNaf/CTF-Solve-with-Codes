# CTF Solve with Codes

Scripts and notes for solving CTF challenges (mostly Python). Each folder mirrors a platform or event and carries short per-challenge summaries in nested READMEs.

| Source | Focus | Solves |
| --- | --- | --- |
| kshackzone | Cryptography, programming | 14 |
| picoCTF (general skills) | Encoding, automation, binary math/search | 8 |
| misc-ctf-comps (2025 events) | Crypto, pwn, reversing, misc | 32 |
| cryptohack | Cryptography helpers | 5 |
| hackthebox | Cryptography | 3 |
| tryhackme | Cryptography | 3 |
| **Total** | — | **65** |

## Directory guide
- `kshackzone/` – challenge scripts with brief notes in `kshackzone/README.md`.
- `picoCTF/` – general-skills solves and explanations in `picoCTF/README.md`.
- `misc-ctf-comps/` – grab-bag from 2025 contests; includes `2025-v1tctf/`, `2025-patriotctf/`, `2025-buckeyectf/`, `2025-infobahnctf/`, and `2025-duke-ctf/` (each has its own README).
- `cryptohack/` – small crypto utilities and warmups.
- `hackthebox/` – three crypto challenge scripts.
- `tryhackme/` – three crypto warmups.

## Running a solve
- Use `python3 path/to/script.py`.
- Some scripts expect challenge artifacts (ciphertexts, logs, binaries) beside them; see inline comments or the per-directory README first.
- Dependencies vary per script; check imports. Common extras: `pwntools`, `requests`, `sympy`, `z3-solver`.
