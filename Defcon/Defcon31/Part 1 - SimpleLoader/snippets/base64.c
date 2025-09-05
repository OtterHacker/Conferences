#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <windows.h>


// The encoding table used by the base64
static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;

// Build the decoding table that will be used by the base64_decode function
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

/****************************************************************/
/* This function is used to debase64 a string                   */
/* base64_decode(sc, sc_length, &szOutput);                     */
/****************************************************************/
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