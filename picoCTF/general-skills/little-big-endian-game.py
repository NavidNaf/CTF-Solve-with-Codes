# This is a little/big-endian conversion game for picoCTF.
# The user is given a random 5-letter lowercase word and must provide its little-endian
# and big-endian hexadecimal representations to receive the flag.

import random
import string

def find_little_endian(word: str) -> str:
    # Return the little-endian hex representation of a word (reversed bytes).
    return ''.join(f"{ord(c):02X}" for c in reversed(word)) # Little-endian: reverse the order of characters

def find_big_endian(word: str) -> str:
    # Return the big-endian hex representation of a word (normal order).
    return ''.join(f"{ord(c):02X}" for c in word) # Big-endian: normal order of characters

def generate_random_word(length: int = 5) -> str:
    # Generate a random lowercase word of given length.
    word = ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    print("Welcome to the Endian CTF!")
    print("You need to find both the little endian and big endian representations of a word.")
    print("If you get both correct, you will receive the flag.\n")
    print(f"Word: {word}")
    return word

def main():
    random.seed()
    challenge_word = generate_random_word()

    little_endian = find_little_endian(challenge_word)
    big_endian = find_big_endian(challenge_word)

    # Ask for Little Endian
    while True:
        user_le = input("Enter the Little Endian representation: ").strip().upper()
        if user_le == little_endian:
            print("✅ Correct Little Endian representation!\n")
            break
        else:
            print("❌ Incorrect Little Endian representation. Try again!\n")

    # Ask for Big Endian
    while True:
        user_be = input("Enter the Big Endian representation: ").strip().upper()
        if user_be == big_endian:
            print("✅ Correct Big Endian representation!\n")
            break
        else:
            print("❌ Incorrect Big Endian representation. Try again!\n")

    # Show mock flag (you can link a real file here if needed)
    try:
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
    except FileNotFoundError:
        flag = "picoCTF{example_flag_for_local_testing}"

    print("🎉 Congratulations! You found both endian representations correctly!")
    print(f"Your Flag is: {flag}")

if __name__ == "__main__":
    main()
