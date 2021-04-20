#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sts.h"

/* TODO this should not be used for cryptography, use mbedtls for rnd number */
int genrand(void *rng_state, unsigned char *output, size_t len)
{
        size_t use_len;
        int rnd;

        if (rng_state != NULL)
                rng_state  = NULL;

        while (len > 0)
        {
                use_len = len;
                if (use_len > sizeof(int))
                        use_len = sizeof(int);

                srand(time(NULL));
                /* usleep is only for test, or else same keypair will be 
                 * generated for both host and remote */
                usleep(25000); 
                rnd = rand()%100;
                memcpy(output, &rnd, use_len);
                output += use_len;
                len -= use_len;
        }
        return 0;
}

int sts_verify_derived_keylen(const unsigned char *buf, size_t size, size_t len)
{
        size_t i;
        size_t tmp = 0;
        size_t shared_keysize;
        for (i = 0 ; i < size; i++) {
                if (buf[i] == '\0') {
                        break;
                }
                tmp++;
        }
        shared_keysize = tmp * BYTE;

        if (shared_keysize == len) {
                return 0;

        } else {
                return -1;
        }
}

void sts_encrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size)
{
        int i;
        int iter;

        /* compute how many iteration */
        if (size < AES_ECB_BLOCKSIZE) {
                iter = 1;
        }     

        if (size % AES_ECB_BLOCKSIZE == 0) {
                iter = size / AES_ECB_BLOCKSIZE;
        }

        if (size % AES_ECB_BLOCKSIZE > 0) {
                iter = (size / AES_ECB_BLOCKSIZE) + 1;
        }

        unsigned char *p_input = input;
        unsigned char *p_output = output;

        for (i = 0; i < iter; i++) {
                mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, 
                                p_input, p_output);
                p_input += AES_ECB_BLOCKSIZE;
                p_output += AES_ECB_BLOCKSIZE;
        }
}

void sts_decrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size)
{
        int i;
        int iter;

        /* compute how many iteration */
        if (size < AES_ECB_BLOCKSIZE) {
                iter = 1;
        }     

        if (size % AES_ECB_BLOCKSIZE == 0) {
                iter = size / AES_ECB_BLOCKSIZE;
        }

        if (size % AES_ECB_BLOCKSIZE > 0) {
                iter = (size / AES_ECB_BLOCKSIZE) + 1;
        }

        unsigned char *p_input = input;
        unsigned char *p_output = output;

        for (i = 0; i < iter; i++) {
                mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, 
                                p_input, p_output);
                p_input += AES_ECB_BLOCKSIZE;
                p_output += AES_ECB_BLOCKSIZE;
        }
}
