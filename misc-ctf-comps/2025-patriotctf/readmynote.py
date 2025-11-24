#!/usr/bin/env python3
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    pefile = None

FILE_NAME = "ReadMyNote.exe"


def load_blobs(data: bytes) -> list[bytes]:
    """Return list of byte blobs to scan (PE sections if possible, else whole file)."""
    if pefile:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            return [data[s.PointerToRawData : s.PointerToRawData + s.SizeOfRawData] for s in pe.sections]
        except Exception:
            return [data]
    return [data]


def find_flag(blob: bytes) -> str | None:
    """Find pctf{...} in blob; return decoded flag or None."""
    start = blob.find(b"pctf{")
    if start == -1:
        return None
    end = blob.find(b"}", start)
    if end == -1:
        return None
    return blob[start : end + 1].decode(errors="ignore")


def rot_alpha(buf: bytes, n: int) -> bytes:
    """Rotate ASCII letters by n."""
    out = bytearray()
    for b in buf:
        if 65 <= b <= 90:
            out.append((b - 65 + n) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 + n) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


def scan(blobs: list[bytes]) -> str | None:
    # Raw scan
    for blob in blobs:
        flag = find_flag(blob)
        if flag:
            return flag
    # XOR
    for k in range(256):
        for blob in blobs:
            flag = find_flag(bytes(b ^ k for b in blob))
            if flag:
                return flag
    # ADD
    for k in range(256):
        for blob in blobs:
            flag = find_flag(bytes((b + k) & 0xFF for b in blob))
            if flag:
                return flag
    # SUB
    for k in range(256):
        for blob in blobs:
            flag = find_flag(bytes((b - k) & 0xFF for b in blob))
            if flag:
                return flag
    # ROT
    for n in range(1, 26):
        for blob in blobs:
            flag = find_flag(rot_alpha(blob, n))
            if flag:
                return flag
    return None


def main() -> None:
    try:
        data = Path(FILE_NAME).read_bytes()
    except Exception:
        print("No flag found")
        return
    blobs = load_blobs(data)
    flag = scan(blobs)
    if flag:
        print(flag)
    else:
        print("No flag found")


if __name__ == "__main__":
    main()
