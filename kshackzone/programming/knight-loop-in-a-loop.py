# https://kshackzone.com/ctfs/challenge/knightctf-2022/10/reverse-the-answer

# This code unscrambles a flag that has been scrambled using a nested loop swapping algorithm.

def unscramble(flag):
    flag = list(flag)  # convert to mutable list

    for i in range(len(flag)-1, -1, -1):        # reverse outer loop
        for j in range(len(flag)-2, i-1, -1):   # reverse inner loop
            # undo swap
            flag[j], flag[j+1] = flag[j+1], flag[j]

    return ''.join(flag)

if __name__ == "__main__":
    scrambled_flag = input("Enter scrambled flag: ")
    original_flag = unscramble(scrambled_flag)
    print("Original flag:", original_flag)