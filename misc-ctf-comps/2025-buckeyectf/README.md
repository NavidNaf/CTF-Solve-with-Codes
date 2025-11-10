# Buckeye CTF 2025 Scripts

| File name | What the code does |
|-----------|--------------------|
| `augury.py` | Connects to the Augury service, downloads a candidate file, and decrypts the ciphertext via the known flag prefix. |
| `awklet.py` | Exploits the Awklet font handling to inject a nul-terminated path and read `/proc/self/environ`. |
| `big-chungus.py` | Spoofs the `username[length]` query parameter to bypass the Big Chungus username length check and read the response. |
| `bigdata.py` | Queries BigQuery for unique GitHub CreateEvent repositories in 2023 and prints the count. |
| `character-assassination.py` | Abuses a signed char index bug in the service to leak bytes of the flag one at a time. |
| `clandescriptorius.py` | Exploits SHA256 concatenation ambiguity to recover timestamps, leak keystream blocks, and decrypt the flag. |
| `cube-cipher.py` | Recovers the Cube Cipher permutation from the live service and applies it to a provided ciphertext. |
| `ebg13.py` | Uses the rot13 proxy to fetch `/admin` on the loopback interface and decode the flag. |
| `nitwit.py` | Forged a Winternitz OTS signature chain to obtain an admin signature and retrieve the flag. |
| `packages.py` | SQL-injects the packages service to load SQLite’s fileio extension and read candidate flag files. |
| `ramesses.py` | Forges an unsigned session cookie with `is_pharaoh` set to true and hits `/tomb` to retrieve the flag. |
| `viewer.py` | Overflows the viewer admin sentinel by sending `flag` plus padding until the admin flag path is forced. |
