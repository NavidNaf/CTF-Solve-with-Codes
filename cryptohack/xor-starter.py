# xor is a bitwise operation
# it takes two bits and returns 1 if the bits are different, and 0 if they are the same
# for example:
# 0 xor 0 = 0
# 0 xor 1 = 1
# 1 xor 0 = 1
# 1 xor 1 = 0

# convert integers to binary strings

s1 = 'label'
s1_bin_list = []
for i in s1:
    s1_bin_list.append(bin(ord(i))[2:])
print(s1_bin_list)

s2 = 13
s2_bin = bin(s2)[2:]  # remove the '0b' prefix
print(s2_bin)

new_val = []
# xor the two binary strings
for i in range(len(s1_bin_list)):
    xor_val = bin(int(s1_bin_list[i], 2) ^ int(s2_bin, 2))[2:]  # remove the '0b' prefix
    print(s1_bin_list[i], 'xor', s2_bin, '=', xor_val)
    new_val.append(str(xor_val))
print(new_val)

for i in new_val:
    new_val_string = i.zfill(8)  # pad with leading zeros to make it 8 bits
    string_val = chr(int(new_val_string, 2))
    print(string_val, end='')
