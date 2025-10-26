# xor-flag-unlocker2.py - recovers an XOR-obfuscated flag using the original password.
# level1.py from picoCTF General Skills challenge

import sys
from pathlib import Path


def str_xor(secret: str, key: str) -> str:
    """Replicate the challenge XOR routine, extending the key as needed."""
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key += key[i]
        i = (i + 1) % len(key)
    return "".join(
        chr(ord(secret_c) ^ ord(new_key_c))
        for secret_c, new_key_c in zip(secret, new_key)
    )


def decode_flag(enc_path: Path) -> str:
    """Load the encrypted flag and decrypt it with the known password."""
    password = "691d"
    encrypted = enc_path.read_bytes().decode()
    return str_xor(encrypted, password)


def main() -> None:
    base_dir = Path(__file__).parent
    if len(sys.argv) > 1:
        enc_file = Path(sys.argv[1]).expanduser()
    else:
        enc_file = base_dir / "level1.flag.txt.enc"
    if not enc_file.exists():
        raise FileNotFoundError(f"Encrypted flag not found at {enc_file}")
    print(decode_flag(enc_file))


if __name__ == "__main__":
    main()
