This directory contains solves from picoCTF. The problems are:

| Type of Problem | Solution Files | One-Sentence Summary |
| --- | --- | --- |
| Encoding | `general-skills/b64-convert.py` | Iteratively decodes a Base64 payload until the picoCTF flag appears. |
| Binary math | `general-skills/binary-operation.py` | Interactive calculator performing arithmetic and bitwise operations on two binary inputs. |
| Binary search | `general-skills/binary-search-game.py` | Guides a player through guessing a random 1-100 number using binary-search style hints. |
| Endianness conversion | `general-skills/little-big-endian-game.py` | Quizzes the player on big- and little-endian hex encodings of a random lowercase word to reveal a flag. |
| Log analysis | `general-skills/log-hunt.py` | Reads `server.log` and extracts lines that leak pieces of the flag. |
| Automation | `general-skills/syntax-checker.py` | Sends source code to a local Ollama model to report syntax or logic issues. |
| XOR cryptography | `general-skills/xor-flag-unlocker.py` | Reimplements the challenge XOR routine to decrypt `level2.flag.txt.enc` with the recovered password. |
| XOR cryptography | `general-skills/xor-flag-unlocker2.py` | Uses the challenge XOR routine and known password to decrypt `level1.flag.txt.enc`. |
