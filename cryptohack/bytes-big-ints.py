from Crypto.Util.number import *

message = "HELLO"
msg_ascii = [ord(c) for c in message]
print(msg_ascii)

msg_hex = ''.join([hex(c)[2:] for c in msg_ascii])
print(msg_hex)

msg_base10 = int(msg_hex, 16)
print(msg_base10)

message_2 ="11515195063862318899931685488813747395775516287289682636499965282714637259206269"

# Convert back to bytes
decrypted=long_to_bytes(int(message_2))
print(decrypted)