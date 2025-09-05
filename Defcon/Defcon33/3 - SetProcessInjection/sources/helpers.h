#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include "aes.h"

#define DEBUG(x, ...) printf(x, ##__VA_ARGS__)


static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;
static int mod_table[] = { 0, 2, 1 };

static int x64 = 1;
extern int AES_KEY_LENGTH;
void build_decoding_table();
unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length);
BOOL aes_decrypt(const uint8_t* key, size_t szKey, unsigned char* encrypted, size_t szEncrypted, unsigned char* unencryptedData);
unsigned char* xor_text(const char* buff);
wchar_t* char2wc(const char* buff);