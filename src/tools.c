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

void concatenate(char dst[], char src[])
{
        int c = 0;
        int d = 0;

        while (dst[c] != '\0')
                c++;

        while (src[d] != '\0') {
                dst[c] = src[d];
                d++;
                c++;
        }
        dst[c] = '\0';
}
