#include "tools.h"

void genrand_str(unsigned char *str, size_t size)
{
        size_t n;
        int key;
        struct timeval tv;
        unsigned long time_in_micros;
        /* ascii */
        const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK0123456789"
                "0!@#$%^&*()-=['/<>']_+";
        gettimeofday(&tv, NULL);
        time_in_micros = 1000000 * tv.tv_sec + tv.tv_usec;

        srand((unsigned)time_in_micros);

        if (size) {
                --size;
                for (n = 0; n < size; n++) {
                        key = rand() % (int) (sizeof charset - 1);
                        str[n] = charset[key];
                }
                str[size] = '\0';
        }
}

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
        for (i = 0; i <= size; i++) {
                *b = *b ^ 1;
        }
}

void concatenate(char p[], char q[])
{
        int c = 0;
        int d = 0;

        while (p[c] != '\0') {
                c++;
        }

        while (q[d] != '\0') {
                p[c] = q[d];
                d++;
                c++;
        }
        p[c] = '\0';
}
