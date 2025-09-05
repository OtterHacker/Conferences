#define _CRT_SECURE_NO_WARNINGS
#include "helpers.h"


int AES_KEY_LENGTH = 32; 

void build_decoding_table() {

    decoding_table = (char*)malloc(256);
    if (decoding_table == NULL) {
        DEBUG("[x] Cannot allocate memory for the decoding table\n");
        exit(-1);
    }
    for (int i = 0; i < 64; i++) {
        decoding_table[(unsigned char)encoding_table[i]] = i;
    }
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') {
        (*output_length)--;
    }
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        DWORD sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        DWORD sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        DWORD triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

BOOL aes_decrypt(const uint8_t* key, size_t szKey, unsigned char* encrypted, size_t szEncrypted, unsigned char* unencryptedData) {
    // First 16 bytes represent the IV.
    uint8_t* iv = (uint8_t*)calloc(16, sizeof(uint8_t));
    if (!iv) {
        DEBUG("[x] AES decryption failed (couldn't allocate IV).\n");
        return FALSE;
    }
    memcpy(iv, encrypted, 16 * sizeof(uint8_t));

    size_t szEncryptedData = szEncrypted - 16;
    memcpy(unencryptedData, &encrypted[16], szEncryptedData * sizeof(unsigned char));

    struct AES_ctx ctx;

    // If the provided key is not complete (length != 32 bytes), a bruteforce is attempted.
    // Iterates over the missing bytes using the provided partial key as input.
    if (AES_KEY_LENGTH == szKey) {
        AES_init_ctx_iv(&ctx, key, iv);
        AES_CBC_decrypt_buffer(&ctx, unencryptedData, szEncryptedData);
        free(iv);
        return TRUE;
    }
    else {
        DWORD missingKeyLength = AES_KEY_LENGTH - szKey;
        DEBUG("[-] Provided key is missing %i bytes\n", missingKeyLength);
        uint8_t* missingKey = (uint8_t*)calloc(missingKeyLength, sizeof(unsigned char));
        uint8_t* fullKey = (uint8_t*)calloc(AES_KEY_LENGTH + 1, sizeof(unsigned char));
        if (!missingKey || !fullKey) {
            DEBUG("[x] AES decryption failed (couldn't allocate key elements).\n");
            return FALSE;
        }
        uint8_t index = 0;
        memcpy(fullKey, key, (AES_KEY_LENGTH - missingKeyLength) * sizeof(uint8_t));
        while (TRUE) {
            while (missingKey[index] <= 254) {
                memcpy(&fullKey[AES_KEY_LENGTH - missingKeyLength], missingKey, missingKeyLength * sizeof(uint8_t));
                AES_init_ctx_iv(&ctx, fullKey, iv);
                AES_CBC_decrypt_buffer(&ctx, unencryptedData, szEncryptedData);
                uint8_t padding = unencryptedData[szEncryptedData - 1];

                // Validate the decryption by checking that the last 4 bytes are egal to 0.
                if (unencryptedData[szEncryptedData - padding - 4] == 0x0 && unencryptedData[szEncryptedData - padding - 3] == 0x0 && unencryptedData[szEncryptedData - padding - 2] == 0x0 && unencryptedData[szEncryptedData - padding - 1] == 0x0) {
                    free(iv);
                    free(missingKey);
                    free(fullKey);
                    return TRUE;
                }
                else {
                    memcpy(unencryptedData, &encrypted[16], szEncryptedData * sizeof(unsigned char));
                }

                missingKey[index] += 1;

            }
            for (uint8_t i = 0; i < missingKeyLength; i++) {
                if (missingKey[i] == 255) {
                    missingKey[i] = 0;
                    if (i < missingKeyLength - 1) {
                        missingKey[i + 1] += 1;
                    }
                    else {
                        DEBUG("[x] AES decryption failed could not find the key.\n");
                        return FALSE;
                    }
                }
            }
        }
    }
}

unsigned char* xor_text(const char* buff) {
    size_t size = strlen(buff);
    size_t osize;
    unsigned char* result = base64_decode(buff, size, &osize);
    for (int i = 0; i < osize; i++) {
        result[i] = result[i] ^ 0xA7;
    }
    return result;
}

wchar_t* char2wc(const char* buff) {
    const size_t cSize = strlen(buff) + 1;
    wchar_t* wc = malloc(cSize * sizeof(wchar_t));
    mbstowcs(wc, buff, cSize);
    return wc;
}