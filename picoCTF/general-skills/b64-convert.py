# This script decodes a Base64-encoded file that may contain multiple layers
# of Base64 encoding until it reveals a flag in the format picoCTF{...}.

import base64
import re
import sys


def normalize_base64(payload: bytes) -> bytes:
    # Strip whitespace and add missing padding to a Base64 payload.
    cleaned = b"".join(payload.split())
    padding = (-len(cleaned)) % 4
    if padding:
        cleaned += b"=" * padding
    return cleaned


if len(sys.argv) != 2:
    print("Usage: python b64-convert.py <encoded_file>")
    sys.exit(1)

with open(sys.argv[1], "r", encoding="utf-8") as file:
    encoded = file.read().strip()

decoded = encoded.encode()
flag_pattern = re.compile(br"^picoCTF\{.*\}$")

while not flag_pattern.match(decoded):
    decoded = base64.b64decode(normalize_base64(decoded))

print(decoded.decode())
