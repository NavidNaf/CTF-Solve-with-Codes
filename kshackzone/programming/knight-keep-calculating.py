# https://kshackzone.com/ctfs/challenge/knightctf-2022/8/keep-calculating

# One of our clients needs a command line tool to do some math tasks. Can you create the tool by following pseudo code ? Let x = 1 Let y = 2 Let answer += (x * y) + xy [here xy = 12] Repeat this calculation till you have x = 666. The final answer will be the flag when x = 666

# This is a simple calculation problem. We need to implement the pseudo code provided in the challenge description.

x = 1
y = 2 
answer = 0

while x <= 666:
    xy = int(f"{x}{y}")
    answer += (x * y) + xy
    x += 1

print(answer)