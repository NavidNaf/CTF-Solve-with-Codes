# this code decrypts a message encoded with a variant of the Caesar cipher 

ciphertext = "a_up4qr_kaiaf0_bujktaz_qm_su4ux_cpbq_ETZ_rhrudm"

def dec(ciphertext):
    """Reverse the progressive Caesar cipher by shifting each character back by its index."""
    return "".join(
        chr((ord(c) - (base := ord('A') if c.isupper() else ord('a')) - i) % 26 + base) 
        if c.isalpha() else c
        for i, c in enumerate(ciphertext)
    )

# Algorithm: decrement each alphabetic character by its index (progressive Caesar) to reveal the flag.
print(dec(ciphertext))
