#include <stdio.h>
#include <string.h>

#include "sts.h"
#include "log.h"

#include "ctr_drbg.h"
#include "entropy.h"

/* TODO error handling */
int sts_genrand(void *rng_state, unsigned char *output, size_t len)
{
        if (rng_state != NULL) {
                rng_state  = NULL;
        }

        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;

        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                        (const unsigned char *) "RANDOM_GEN", 10);
        mbedtls_ctr_drbg_random(&ctr_drbg, output, sizeof(len));

        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
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

/* TODO temporary for debug */
void sts_print_derived_key(const unsigned char *buf, size_t size) 
{
        size_t i;
        INFO("sts: shared_key: ");

        for (i = 0 ; i < size; i++) {
                if (buf[i] == '\0') {
                        break;
                }
                printf("%02X", buf[i]);
        }
        printf("\n");
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
