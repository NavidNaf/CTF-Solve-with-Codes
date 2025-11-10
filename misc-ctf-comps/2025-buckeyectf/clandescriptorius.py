#!/usr/bin/env python3
# Recover the plaintext flag from the Buckeye CTF service by exploiting SHA256 concatenation ambiguity.
DESCRIPTION = (
    "Recover the plaintext flag from the vulnerable Buckeye CTF service. "
    "Provide the session ID, your original timestamp, and the encrypted flag. "
    "The script finds collision timestamps, queries /encrypt with zero blocks to leak keystream, "
    "and decrypts the flag."
)
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

import requests

BLOCK_SIZE = 16


@dataclass
class Operation:
    block_index: int
    timestamp: int
    oracle_index: int

# Generate timestamp splits that replicate the concatenated string without leading zeros.
def split_candidates(start_ts: int, block_index: int) -> List[Tuple[int, int]]:
    target = f"{start_ts}{block_index}"
    # Every split position except the trivial suffix produces a candidate.
    # Skip prefixes that cannot be parsed (e.g., just "-") and suffixes
    # whose canonical string form would reintroduce leading zeros.
    out: List[Tuple[int, int]] = []
    for k in range(1, len(target)):
        prefix = target[:k]
        suffix = target[k:]
        if suffix == "":
            continue
        if suffix.startswith("0") and suffix != "0":
            continue
        try:
            new_ts = int(prefix)
        except ValueError:
            continue
        oracle_index = int(suffix)
        if f"{new_ts}{oracle_index}" != target:
            continue
        out.append((new_ts, oracle_index))
    out.sort()
    return out

# Plan keystream-recovery operations while keeping timestamps strictly increasing.
def plan_operations(start_ts: int, total_blocks: int) -> List[Operation]:
    candidates = {b: split_candidates(start_ts, b) for b in range(total_blocks)}
    remaining = set(range(total_blocks))
    ops: List[Operation] = []
    last_ts = start_ts

    while remaining:
        chosen_block = None
        chosen_pair = None

        for block in sorted(remaining):
            cand_list = candidates[block]
            # Drop unusable candidates (timestamps not strictly increasing)
            while cand_list and cand_list[0][0] <= last_ts:
                cand_list.pop(0)
            if not cand_list:
                continue
            if chosen_pair is None or cand_list[0][0] < chosen_pair[0]:
                chosen_block = block
                chosen_pair = cand_list[0]

        if chosen_block is None or chosen_pair is None:
            raise RuntimeError(
                "Cannot satisfy timestamp monotonicity. Start a new session with a more negative initial timestamp."
            )

        t, idx = chosen_pair
        candidates[chosen_block].pop(0)
        remaining.remove(chosen_block)
        ops.append(Operation(block_index=chosen_block, timestamp=t, oracle_index=idx))
        last_ts = t

    # Sort by timestamp to ensure we replay in the correct order
    ops.sort(key=lambda op: op.timestamp)
    return ops

# Query /encrypt to recover the keystream block for the provided oracle index.
def fetch_keystream(url: str, session_id: str, timestamp: int, oracle_index: int) -> bytes:
    block_count = oracle_index + 1
    payload = {"session_id": session_id, "timestamp": timestamp, "data": "00" * BLOCK_SIZE * block_count}
    resp = requests.post(f"{url}/encrypt", json=payload, timeout=10)
    resp.raise_for_status()
    result = resp.json()
    if "encrypted" not in result:
        raise RuntimeError(f"Oracle error: {result}")
    data = bytes.fromhex(result["encrypted"])
    start = oracle_index * BLOCK_SIZE
    end = start + BLOCK_SIZE
    if end > len(data):
        raise RuntimeError("Oracle response shorter than expected; check inputs")
    return data[start:end]

# Strip out PKCS#7 padding from the decrypted plaintext.
def unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len == 0 or pad_len > len(data):
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# Recover keystream blocks, XOR them with the ciphertext, and unpad the result to get the flag.
def decrypt_flag(url: str, session_id: str, start_ts: int, encrypted_flag: bytes) -> bytes:
    blocks = len(encrypted_flag) // BLOCK_SIZE
    if len(encrypted_flag) % BLOCK_SIZE:
        raise ValueError("Ciphertext must be a multiple of 16 bytes")
    ops = plan_operations(start_ts, blocks)
    keystreams: Dict[int, bytes] = {}
    last_ts = start_ts
    for op in ops:
        if op.timestamp <= last_ts:
            raise RuntimeError("Internal error: timestamps must be strictly increasing")
        ks = fetch_keystream(url, session_id, op.timestamp, op.oracle_index)
        keystreams[op.block_index] = ks
        last_ts = op.timestamp
        print(
            f"[+] Block {op.block_index}: timestamp {op.timestamp}, oracle index {op.oracle_index}, keystream {ks.hex()}"
        )

    pt_blocks = []
    for block_idx in range(blocks):
        if block_idx not in keystreams:
            raise RuntimeError(f"Missing keystream for block {block_idx}")
        start = block_idx * BLOCK_SIZE
        end = start + BLOCK_SIZE
        block = encrypted_flag[start:end]
        pt_blocks.append(bytes(a ^ b for a, b in zip(block, keystreams[block_idx])))
    plaintext = b"".join(pt_blocks)
    return unpad(plaintext)

# Parse CLI arguments, run the decryption flow, and print the flag.
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Service root (default: %(default)s)")
    parser.add_argument("--session-id", required=True, help="Session id from /startsession")
    parser.add_argument("--start-timestamp", type=int, required=True, help="Timestamp you sent to /startsession")
    parser.add_argument("--ciphertext", required=True, help="Hex-encoded encrypted flag")
    args = parser.parse_args(argv)

    try:
        ciphertext = bytes.fromhex(args.ciphertext)
    except ValueError as exc:
        raise SystemExit(f"Ciphertext must be hex: {exc}")

    try:
        flag = decrypt_flag(args.base_url.rstrip("/"), args.session_id, args.start_timestamp, ciphertext)
    except Exception as exc:
        raise SystemExit(f"Error: {exc}")

    print(f"\n[+] Flag: {flag.decode(errors='replace')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
