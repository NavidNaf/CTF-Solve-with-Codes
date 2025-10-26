# https://kshackzone.com/ctfs/challenge/smp-ctf-2024-selection-round/162/seed-the-flag

# This challenge involves recovering a hidden secret and prime number P2
# used in an RSA-like encryption scheme. The hidden secret is XOR-obfuscated
# using a seed derived from two known byte strings. The prime P2 is scrambled
# by shuffling its digits in chunks using a PRNG seeded with the same value.

from math import gcd
from itertools import permutations
from collections import Counter
import random

P1 = 7307039331
P2_O = "6983432688"
P3 = int("5284255017203633261370535345682263310336")
K  = 9531
Y  = int("11709967940066793762796184140152610769821716917529318252119959861290032840327")
H  = int("730699457350798390839309068289663772131566530906536306094973")

s1 = b'usedistofindouttheseed'
s2 = b'thisisthekeytogetyourseed'

# Helper functions
def xor_seed(a: bytes, b: bytes) -> int:
    # XOR two byte strings treating them as big-endian integers of equal length.
    n = max(len(a), len(b))
    ai = int.from_bytes(a.rjust(n, b'\x00'), 'big')
    bi = int.from_bytes(b.rjust(n, b'\x00'), 'big')
    return ai ^ bi


def xor_repeat(data: bytes, key: bytes) -> bytes:
    # XOR `data` with a repeating `key`.
    if not key:
        raise ValueError("Key must not be empty.")
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

def is_probable_prime(n: int) -> bool:
    # sympy-free Miller-Rabin for speed/repro
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n == p: return True
        if n % p == 0: return False
    # write n-1 = d*2^s
    d, s = n-1, 0
    while d % 2 == 0:
        d //= 2; s += 1
    # trial bases
    for a in [2,325,9375,28178,450775,9780504,1795265022]:
        if a % n == 0:
            return True
        x = pow(a, d, n)
        if x in (1, n-1): 
            continue
        for _ in range(s-1):
            x = (x*x) % n
            if x == n-1:
                break
        else:
            return False
    return True

def chunks_of(s: str, k: int):
    return [s[i:i+k] for i in range(0, len(s), k)]

def unshuffle_with_seed(s: str, seed: int, k: int) -> str:
    # Assume s was produced by shuffling k-sized chunks from the original using
    # random.seed(seed); random.shuffle(index). Return the inverse (original).
    ch = chunks_of(s, k)
    n = len(ch)
    random.seed(seed)
    idx = list(range(n))
    random.shuffle(idx)   # ch[d] = orig[idx[d]]
    orig = [None]*n
    for d, src in enumerate(idx):
        orig[src] = ch[d]
    return ''.join(orig)

def try_candidates(p2o: str, seed: int, brute_digits=False):
    cands = set()

    # 1) Inverse PRNG shuffle on chunk sizes 1/2/5
    for k in (1,2,5):
        cands.add(unshuffle_with_seed(p2o, seed, k))
    
    # 2) All permutations of five 2-digit chunks (120 total)
    ch2 = chunks_of(p2o, 2)  # ['69','83','43','26','88']
    seen = set()
    for perm in set(permutations(ch2)):
        val = ''.join(perm)
        if val[0] != '0':
            cands.add(val)

    # 3) (Optional) full digit-multiset brute, but prune hard
    #    (enable only if needed: 151,200 unique permutations here)
    if brute_digits:
        digs = list(p2o)
        # Quick sieve: last digit must be 1,3,7,9
        allowed_ends = {'1','3','7','9'}
        # digit sum not divisible by 3
        ssum = sum(int(d) for d in digs)
        # If sum is divisible by 3, no permutation can be prime — skip entirely
        if ssum % 3 != 0:
            for perm in set(permutations(digs)):
                if perm[0] == '0': 
                    continue
                if perm[-1] not in allowed_ends:
                    continue
                # mod 3 prune holds by digit sum; already checked
                val = ''.join(perm)
                cands.add(val)

    # 4) Look for nearby primes obtained by nudging the numeric value.
    base_val = int(p2o)
    if is_probable_prime(base_val):
        cands.add(str(base_val))
    else:
        max_delta = 100000  # generous upper bound; we usually break far earlier.
        for delta in range(1, max_delta + 1):
            for candidate in (base_val + delta, base_val - delta):
                if candidate <= 1:
                    continue
                if is_probable_prime(candidate):
                    cands.add(str(candidate))
                    break
            else:
                continue
            break

    # Filter numeric, prime
    prime_cands = []
    for s in cands:
        n = int(s)
        # Basic quick prunes
        if n % 2 == 0 or n % 5 == 0:
            continue
        # digit-sum mod 3
        if sum(int(ch) for ch in s) % 3 == 0:
            continue
        if is_probable_prime(n):
            prime_cands.append(n)

    return sorted(set(prime_cands))

def rsa_try(p1, p2, p3, K, Y, H):
    N = p1 * p2 * p3
    phi = (p1-1)*(p2-1)*(p3-1)

    out = {}
    # Case A: K is e
    if gcd(K, phi) == 1:
        # modular inverse using pow with Python 3.8+: pow(K,-1,phi)
        try:
            d = pow(K, -1, phi)
            m = pow(Y, d, N)
            out['K_as_e'] = {'N':N,'phi':phi,'d':d,'m':m,'m_hex':hex(m),
                             'check_pow_m_e_eq_Y': pow(m, K, N) == Y,
                             'check_Y_pow_e_mod_P3': pow(Y, K, p3)}  # diagnostic
        except ValueError:
            out['K_as_e_error'] = 'No modular inverse for K mod phi'
    else:
        out['K_as_e_skip'] = 'gcd(K,phi)!=1'

    # Case B: K is d
    m2 = pow(Y, K, N)
    out['K_as_d'] = {'N':N,'phi':phi,'m':m2,'m_hex':hex(m2),
                     'check_pow_m_e_eq_Y_for_e_candidates_(65537,9531,3)': {
                         65537: pow(m2, 65537, N) == Y,
                         9531:  pow(m2, 9531,  N) == Y,
                         3:     pow(m2, 3,      N) == Y
                     }}
    # Optional: see whether H matches any easy relation
    out['diagnostics'] = {
        'H_mod_P3': H % p3,
        'Y_mod_P3': Y % p3,
        'H_eq_Y_pow_K_mod_P3': (pow(Y, K, p3) == (H % p3))
    }
    return out

# Run main logic
seed = xor_seed(s1, s2)
print("Seed (hex):", hex(seed))
print("Seed (dec):", seed)

seed_bytes = seed.to_bytes((seed.bit_length() + 7) // 8, 'big')
h_bytes = H.to_bytes((H.bit_length() + 7) // 8, 'big')
hidden_secret = xor_repeat(h_bytes, seed_bytes).lstrip(b'\x00')
print("Hidden secret:", hidden_secret.decode())

# Find P2 by undoing "split & scramble"
p2_candidates = try_candidates(P2_O, seed, brute_digits=False)
print("Prime P2 candidates found:", p2_candidates)

if not p2_candidates:
    print("[!] No prime found with basic unscrambles. "
          "If intended, enable brute_digits=True in try_candidates().")

for P2 in p2_candidates[:5]:  # try first few if many
    print("\n--- Trying P2 =", P2, "---")
    res = rsa_try(P1, P2, P3, K, Y, H)
    for k,v in res.items():
        print(k, "=>", v)
