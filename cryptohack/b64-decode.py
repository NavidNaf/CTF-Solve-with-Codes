import base64

hex_value = '72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'

b64_value = base64.b64encode(bytes.fromhex(hex_value)).decode('utf-8')
print(b64_value)