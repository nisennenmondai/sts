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
 * @brief               convert uchar_bin to string hex
 * @param enc_msg       encrypted msg to convert
 * @param hex           hex string output
 * @param size          size of enc_msg
 */
void uchar_bin_to_hex(unsigned char *enc_msg, char *hex, int size);

/*
 * @brief               concatenate two char arrays.
 * @param dst           destination array.
 * @param src           source array.
 */
void concatenate(char dst[], char src[]);

#endif /* TOOLS.H */
