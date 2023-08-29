#include <windows.h>
/****************************************************************/
/* This function is used to xor a string with a key             */
/* unxor(shellcode, shellcodeSize, key, keySize)                */
/****************************************************************/
void unxor(unsigned char* sc, size_t scSize, unsigned char* key, size_t keySize){
    for(int i = 0; i < scSize; i++){
        sc[i] ^= key[i%keySize];
    }
}