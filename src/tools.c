#include "tools.h"

void concatenate(char dst[], char src[])
{
        int c = 0;
        int d = 0;

        while (dst[c] != '\0') {
                c++;
        }

        while (src[d] != '\0') {
                dst[c] = src[d];
                d++;
                c++;
        }
        dst[c] = '\0';
}
