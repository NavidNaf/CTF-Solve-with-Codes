# https://kshackzone.com/ctfs/challenge/knightctf-2022/10/reverse-the-answer

# Let x = 1 Let calculation = (x*(x+1)) + (2 *(x + 1)) Let reversed_calc = reversed number of calculation [for example if calculation = 123, reversed_calc will be 321] If reversed_calc can be divided by 4 without reminder then answer = answer + reversed_calc Repeat all the calculations until you have x = 543

x = 1
answer = 0

while x <= 543:
    calculation = (x*(x+1)) + (2 *(x + 1))
    reversed_calculation = str(calculation)[::-1]
    if int(reversed_calculation)%4 == 0:
        answer += int(reversed_calculation)
    x += 1
print(answer)
