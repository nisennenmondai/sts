#ifndef TOOLS_H
#define TOOLS_H

#include <stdlib.h>
#include <sys/time.h>

void genrand_str(unsigned char *str, size_t size);
void reverse_bits_order(unsigned char *b, size_t size);
void xor_bits(unsigned char *b, size_t size);
void concatenate(char p[], char q[]);

#endif /* TOOLS.H */
