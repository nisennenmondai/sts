#include <stdio.h>
#include <string.h>

#include "sts.h"
#include "log.h"

#include "ctr_drbg.h"
#include "entropy.h"

int sts_genrand(void *rng_state, unsigned char *output, size_t len)
{
        int ret;
        if (rng_state != NULL) {
                rng_state  = NULL;
        }

        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;

        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);

        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                        (const unsigned char *) "RANDOM_GEN", 10);

        if (ret != 0) {
                ERROR("mbedtls_ctr_drbg_seed()\n");
                goto cleanup;
        }

        ret = mbedtls_ctr_drbg_random(&ctr_drbg, output, sizeof(len));

        if (ret != 0) {
                ERROR("mbedtls_ctr_drbg_random()\n");
                goto cleanup;
        }

cleanup:
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return ret;
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
