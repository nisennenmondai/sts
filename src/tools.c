#include "tools.h"

void reverse_bits_order(unsigned char *b, size_t size)
{
        size_t i;

        for (i = 0; i < size; i++) {
                b[i] = (b[i] & 0xF0) >> 4 | (b[i] & 0x0F) << 4;
                b[i] = (b[i] & 0xCC) >> 2 | (b[i] & 0x33) << 2;
                b[i] = (b[i] & 0xAA) >> 1 | (b[i] & 0x55) << 1;
        }
}

void xor_bits(unsigned char *b, size_t size)
{
        size_t i;

        for (i = 0; i <= size; i++)
                *b = *b ^ 1;
}

void uchar_bin_to_hex(unsigned char *enc_msg, char *hex, int size) 
{
        int i;
        char *p;
        static const char* hex_lookup = "0123456789ABCDEF";

        p = hex;

        for (i = 0 ; i != size ; i++) {
                *p++ = hex_lookup[enc_msg[i] >> 4];
                *p++ = hex_lookup[enc_msg[i] & 0x0F];
        }
        *p = '\0';
}

void concatenate(char dst[], char src[])
{
        int c;
        int d;

        c = 0;
        d = 0;

        while (dst[c] != '\0')
                c++;

        while (src[d] != '\0') {
                dst[c] = src[d];
                d++;
                c++;
        }
        dst[c] = '\0';
}
