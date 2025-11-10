#!/usr/bin/env python3
# Exploit Augury (TLS) by retrieving and decrypting the flag ciphertext even when
# the server closes the socket unexpectedly. Lists candidate files and uses the
# known-plaintext flag prefix to derive the key stream.
DESCRIPTION = "Exploit Augury (TLS) — robust extraction of hex even if server closes socket."

from __future__ import annotations
import argparse
import re
import time
from typing import Iterable, List, Optional, Tuple
from pwn import remote, process

TARGET_HOST = "augury.challs.pwnoh.io"
TARGET_PORT = 1337
LCG_MULT = 3404970675
LCG_ADD = 3553295105
MOD32 = 2 ** 32
FLAG_PREFIX = b"bctf{"
HEX_DIGITS = set(b"0123456789abcdefABCDEF")

VERBOSE = False
DEBUG_BANNER = True
MAX_RECONNECTS = 4
CONNECT_TIMEOUT = 6.0  # seconds

HEX_RE = re.compile(rb"[0-9A-Fa-f]{8,}")  # at least 8 hex chars (>=4 bytes)


# Advance the linear congruential generator state for the keystream.
def generate_keystream(value: int) -> int:
    return (value * LCG_MULT + LCG_ADD) % MOD32


# Perform known-plaintext decryption using the recovered keystream.
def decrypt(cipher: bytes, prefix: bytes) -> bytes:
    if len(prefix) < 4:
        raise ValueError("Need at least 4 bytes of known plaintext")
    if len(cipher) < 4:
        raise ValueError("Ciphertext too short to derive keystream")
    keystream_block = bytes(c ^ p for c, p in zip(cipher[:4], prefix[:4]))
    key = int.from_bytes(keystream_block, "big")
    out = bytearray()
    offset = 0
    if VERBOSE:
        print(f"[verbose] Starting decryption with key={key:#010x}")
    while offset < len(cipher):
        block = cipher[offset : offset + 4]
        key_bytes = key.to_bytes(4, "big")
        for i, byte in enumerate(block):
            out.append(byte ^ key_bytes[i])
        key = generate_keystream(key)
        if VERBOSE:
            print(f"[verbose] processed block {offset//4}: next key={key:#010x}")
        offset += 4
    return bytes(out)


# Validate plaintext resembles the expected flag format with printable bytes.
def looks_like_flag(data: bytes) -> bool:
    if not data.startswith(FLAG_PREFIX):
        return False
    s = data.rstrip(b"\r\n")
    return s.endswith(b"}") and all(32 <= b < 127 for b in s)


# Read the remote menu prompt until a known marker appears.
def wait_for_menu(io, timeout_total: float = 4.0) -> bytes:
    accum = b""
    markers = [b"Please select an option", b"Please select", b"1. Upload", b"Available files", b"Choose a file"]
    deadline = time.time() + timeout_total
    while time.time() < deadline:
        try:
            chunk = io.recv(timeout=0.25)
        except Exception:
            chunk = b""
        if chunk:
            accum += chunk
            if VERBOSE:
                print("[verbose] recv chunk:")
                print(chunk.decode(errors="replace"))
            for m in markers:
                if m in accum:
                    return accum
    return accum


# Filter out menu noise and ensure lines look like file entries.
def is_likely_filename_line(s: str) -> bool:
    ls = s.strip().lower()
    if not ls:
        return False
    if "available files" in ls or ls.endswith(":") or ":" in ls:
        return False
    if ls.startswith("1.") or ls.startswith("2.") or ls.startswith("3.") or ls.startswith(">"):
        return False
    if "please select" in ls or "choose a file" in ls:
        return False
    return 1 <= len(s) <= 200


# Read available file names emitted by the remote service with timeout controls.
def collect_file_lines(io, timeout_total: float = 5.0) -> List[str]:
    files: List[str] = []
    deadline = time.time() + timeout_total
    if VERBOSE:
        print(f"[verbose] collect_file_lines: reading up to {timeout_total:.1f} sec")
    while time.time() < deadline:
        try:
            line = io.recvline(timeout=0.6)
        except Exception:
            line = b""
        if not line:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        try:
            s = stripped.decode(errors="replace")
        except Exception:
            continue
        lower = s.lower().strip()
        if lower.startswith("choose a file") or lower.startswith("please select"):
            if VERBOSE:
                print("[verbose] hit prompt marker while collecting file lines")
            break
        if is_likely_filename_line(s):
            files.append(s)
            if VERBOSE:
                print(f"[verbose] collected filename candidate: {s!r}")
        else:
            if VERBOSE:
                print(f"[verbose] ignored non-filename line: {s!r}")
    return files


def extract_hex_from_buffer(buf: bytes) -> Optional[bytes]:
    # Search the buffer for hex substring(s) and return the longest big match.
    # Look for any continuous hex substring of reasonable length
    m = HEX_RE.search(buf)
    if not m:
        return None
    # take the longest match in the buffer: find all and pick the longest
    matches = HEX_RE.findall(buf)
    if not matches:
        return None
    longest = max(matches, key=len)
    # Ensure even length
    if len(longest) % 2 != 0:
        longest = longest[:-1]
    try:
        return bytes.fromhex(longest.decode())
    except Exception:
        return None
def read_hex_line_resilient(io, timeout_total: float = 6.0) -> bytes:
    # Accumulate received data until a hex blob is found, handling abrupt closes.
    deadline = time.time() + timeout_total
    buf = b""
    # Try reading lines until marker or until timeout/close
    while time.time() < deadline:
        try:
            line = io.recvline(timeout=0.7)
        except EOFError:
            # connection closed; try to extract from buffer
            if VERBOSE:
                print("[verbose] recvline EOF: trying to extract hex from buffer")
            found = extract_hex_from_buffer(buf)
            if found:
                return found
            raise EOFError("Connection closed before ciphertext and no hex found")
        except Exception:
            line = b""
        if not line:
            # no new data in this slice: continue to wait
            continue
        buf += line
        if VERBOSE:
            print("[verbose] read line chunk (len=%d)" % len(line))
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        # skip prompts
        if lower.startswith(b"please select") or lower.startswith(b"choose a file"):
            continue
        # If whole line is hex, return immediately
        if all(ch in HEX_DIGITS for ch in stripped) and len(stripped) >= 8:
            try:
                return bytes.fromhex(stripped.decode())
            except Exception:
                pass
        # Otherwise, keep searching buffer for any hex substring
        found = extract_hex_from_buffer(buf)
        if found:
            return found
    # final attempt after timeout expired
    if VERBOSE:
        print("[verbose] timeout reached; trying to extract hex from buffer")
    found = extract_hex_from_buffer(buf)
    if found:
        return found
    raise EOFError("Timed out waiting for ciphertext and no hex found")

# Issue menu commands to select a file and recover its ciphertext.
def fetch_flag_single_connection(io) -> Tuple[bytes, str]:
    banner = wait_for_menu(io, timeout_total=3.0)
    if DEBUG_BANNER or VERBOSE:
        print("[banner] Received (truncated):")
        print(banner.decode(errors="replace")[:2000])
    # ask to view files
    try:
        io.sendline(b"2")
    except (EOFError, BrokenPipeError):
        raise EOFError("connection closed when trying to send '2'")

    # collect file names
    files = collect_file_lines(io, timeout_total=5.0)
    if files:
        target = next((f for f in files if any(k in f.lower() for k in ("flag", "bctf", "flag.txt"))), files[0])
        if VERBOSE:
            print(f"[verbose] picked {target!r} from parsed file list")
        # send filename with double newline to trigger server
        try:
            io.send(target.encode() + b"\r\n\r\n")
        except (EOFError, BrokenPipeError):
            raise EOFError("connection closed when sending filename")
        # wait a short moment for server to flush
        time.sleep(0.15)
        # read hex resiliently (will handle server closing)
        ciphertext = read_hex_line_resilient(io, timeout_total=8.0)
        return ciphertext, target

    # fallback: probe common names
    probes = ("flag", "flag.txt", "bctf", "secret", "secret.txt")
    for name in probes:
        try:
            io.send(name.encode() + b"\r\n\r\n")
        except (EOFError, BrokenPipeError):
            raise EOFError("connection closed while probing")
        time.sleep(0.12)
        try:
            ciphertext = read_hex_line_resilient(io, timeout_total=3.0)
            return ciphertext, name
        except EOFError:
            continue
    raise EOFError("no files and probes failed on this connection")


# Retry connections until we retrieve a ciphertext or exhaust reconnect attempts.
def fetch_flag_with_retries(host: str, port: int, local_cmd: Optional[Iterable[str]] = None) -> Tuple[bytes, str]:
    last_exc: Optional[Exception] = None
    for attempt in range(1, MAX_RECONNECTS + 1):
        if VERBOSE:
            print(f"[verbose] Attempt {attempt}/{MAX_RECONNECTS} connecting (SSL)...")
        try:
            io = process(local_cmd) if local_cmd else remote(host, port, ssl=True, timeout=CONNECT_TIMEOUT)
            try:
                initial = io.recv(timeout=1.0)
                if initial and VERBOSE:
                    print("[debug] initial recv (first chunk):")
                    print(initial.decode(errors="replace"))
            except Exception:
                pass
            result = fetch_flag_single_connection(io)
            try:
                io.sendline(b"3")
            except Exception:
                pass
            try:
                io.close()
            except Exception:
                pass
            return result
        except EOFError as e:
            last_exc = e
            if VERBOSE:
                print(f"[verbose] connection attempt failed with EOFError: {e!r}; retrying...")
            try:
                io.close()
            except Exception:
                pass
            time.sleep(0.4)
            continue
        except BrokenPipeError as e:
            last_exc = e
            if VERBOSE:
                print(f"[verbose] broken pipe: {e!r}; retrying...")
            try:
                io.close()
            except Exception:
                pass
            time.sleep(0.4)
            continue
        except Exception as e:
            last_exc = e
            if VERBOSE:
                print(f"[verbose] unexpected exception: {e!r}; retrying...")
            try:
                io.close()
            except Exception:
                pass
            time.sleep(0.4)
            continue
    raise SystemExit(f"All {MAX_RECONNECTS} connection attempts failed. Last error: {last_exc!r}")


# Orchestrate fetching and decrypting the flag via the provided endpoint.
def interact(cmd: Optional[Iterable[str]], host: str, port: int) -> bytes:
    ciphertext, name = fetch_flag_with_retries(host, port, local_cmd=cmd)
    print(f"[+] Retrieved ciphertext for {name!r} ({len(ciphertext)} bytes)")
    if VERBOSE:
        print("[verbose] ciphertext (hex head):", ciphertext.hex()[:512] + ("..." if len(ciphertext) > 512 else ""))
    plaintext = decrypt(ciphertext, FLAG_PREFIX)
    if not looks_like_flag(plaintext):
        print("[!] Decryption output didn't pass flag checks. First 200 bytes:")
        print(plaintext[:200])
        raise SystemExit("Decrypted plaintext does not look like a flag")
    print(f"[+] Decrypted flag with prefix {FLAG_PREFIX!r}")
    return plaintext


# Parse arguments and start the interactive flag retrieval pipeline.
def main() -> int:
    p = argparse.ArgumentParser(DESCRIPTION)
    p.add_argument("--host", default=TARGET_HOST)
    p.add_argument("--port", type=int, default=TARGET_PORT)
    p.add_argument("--local", action="store_true", help="Run against ./main.py")
    p.add_argument("--verbose", action="store_true", help="Print verbose progress")
    args = p.parse_args()
    global VERBOSE, DEBUG_BANNER
    VERBOSE = args.verbose
    if args.local:
        cmd = ["python3", "main.py"]
    else:
        cmd = None
    plaintext = interact(cmd, args.host, args.port)
    print(plaintext.decode(errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
