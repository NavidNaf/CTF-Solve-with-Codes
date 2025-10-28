# exploit_qubit.py

# Usage:
#   python3 exploit_qubit.py HOST PORT
# Example:
#   python3 exploit_qubit.py 127.0.0.1 1337

# What it does:
#   - Connects to HOST:PORT using pwntools
#   - Sends "Y\n" five times to request 5 time capsules
#   - Parses the returned JSON objects
#   - Performs CRT to reconstruct m^e and computes the integer e-th root
#   - Prints recovered plaintext (FLAG) as bytes and utf-8 (if decodable)

# This attack is known as Hastad's Broadcast Attack, exploiting low exponent RSA
# with no padding when the same plaintext is sent to multiple recipients.

# Chinese Remainder Theorem (CRT) and integer root extraction are implemented
# to recover the original message from the multiple ciphertexts.   

import sys
import json
from pwn import remote, context
from Crypto.Util.number import long_to_bytes

context.log_level = "error"  # quiet; change to "debug" if you want verbose

# helper to read a single line from the socket safely
def recv_line(r):
    """Read until newline (or timeout) and return decoded string."""
    data = r.recvuntil(b"\n", timeout=5)
    return data.decode(errors="ignore").strip()

# ask the remote service for k time capsules and parse the JSON responses
def collect_capsules(host, port, k=5):
    r = remote(host, int(port), timeout=5)
    capsules = []
    try:
        # initial welcome prompt (may not end with newline)
        try:
            _ = r.recvuntil(b"? (Y/n)", timeout=3)
        except Exception:
            pass

        for i in range(k):
            r.sendline(b"Y")
            line = r.recvline(timeout=5)
            if not line:
                # try to read until newline if simple recvline failed
                line = r.recvuntil(b"\n", timeout=5)
            txt = line.decode(errors="ignore").strip()
            # extract JSON object from any surrounding text
            jstart = txt.find("{")
            jend = txt.rfind("}") + 1
            if jstart == -1 or jend == 0:
                # attempt to read another line and append
                extra = ""
                try:
                    extra = r.recvline(timeout=1).decode(errors="ignore")
                    txt += extra
                    jstart = txt.find("{")
                    jend = txt.rfind("}") + 1
                except Exception:
                    pass
            obj = json.loads(txt[jstart:jend])
            capsules.append(obj)
        # politely stop
        try:
            r.sendline(b"N")
        except Exception:
            pass
    finally:
        r.close()
    return capsules

# apply the Chinese Remainder Theorem to merge ciphertexts into a single value
def crt_combine(cs, ns):
# start with product N set to 1
    N = 1  # combined modulus accumulator
    for n in ns:
        N *= n  # multiply in each modulus to form the product N
    result = 0  # accumulator for the combined residue
    for c, n in zip(cs, ns):
        Ni = N // n  # partial modulus for current congruence
        inv = pow(Ni, -1, n)  # modular inverse of Ni modulo current modulus
        result = (result + c * inv * Ni) % N  # add scaled term and reduce modulo N
    return result, N  # return combined residue and product modulus

# compute the integer n-th root with a binary search; exact flag indicates perfect power
def integer_nth_root(x, n):
    lo = 0  # lower bound for binary search
    hi = 1 << ((x.bit_length() + n - 1) // n + 1)  # high bound large enough to contain root
    while lo + 1 < hi:
        mid = (lo + hi) // 2  # midpoint candidate
        p = pow(mid, n)  # mid raised to n for comparison
        if p == x:
            return mid, True  # exact root found
        if p < x:
            lo = mid  # move lower bound up when mid^n is too small
        else:
            hi = mid  # move upper bound down when mid^n is too large
    return lo, pow(lo, n) == x  # best approximation and perfect power check

# driver to parse capsule data, run CRT, and take the integer e-th root
def solve_capsules(capsules, e=5):
    cs = []
    ns = []
    for cap in capsules:
        cs.append(int(cap["time_capsule"], 16))
        ns.append(int(cap["pubkey"][0], 16))
    M, N = crt_combine(cs, ns)
    root, exact = integer_nth_root(M, e)
    return root, exact

# CLI entry point; requests capsules and prints the recovered plaintext if possible
def main():
    if len(sys.argv) != 3:
        print("Usage: python3 exploit_qubit.py HOST PORT")
        sys.exit(1)
    host, port = sys.argv[1], sys.argv[2]
    print(f"[+] Connecting to {host}:{port} and requesting 5 capsules...")
    caps = collect_capsules(host, port, k=5)
    if len(caps) < 5:
        print(f"[-] Only collected {len(caps)} capsules; need 5 for e=5 attack.")
        sys.exit(1)
    root, exact = solve_capsules(caps, e=5)
    print(f"[+] Integer root exact: {exact}")
    try:
        b = long_to_bytes(root)
        print("[+] Recovered bytes:")
        print(b)
        try:
            print("[+] Recovered UTF-8:")
            print(b.decode())
        except Exception:
            pass
    except Exception as ex:
        print("[-] Failed to convert root to bytes:", ex)

if __name__ == "__main__":
    main()
