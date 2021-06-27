#ifndef TOOLS_H
#define TOOLS_H

#include <stdlib.h>
#include <sys/time.h>

/*
 * @brief               reverse bits order of array.
 * @param b             data array.
 * @param size          size of array.
 */
void reverse_bits_order(unsigned char *b, size_t size);

/*
 * @brief               xor bits of given array.
 * @param b             data array.
 * @param size          size of array.
 */
void xor_bits(unsigned char *b, size_t size);

/*
 * @brief               concatenate two char arrays.
 * @param dst           destination array.
 * @param src           source array.
 */
void concatenate(char dst[], char src[]);

#endif /* TOOLS.H */
