#include <stdio.h>
#include <string.h>

#include "sts.h"
#include "log.h"
#include "tools.h"

#include "ctr_drbg.h"
#include "entropy.h"

void sts_encode(unsigned char *data, size_t size)
{
        reverse_bits_order(data, size);
        xor_bits(data, size);
}

void sts_decode(unsigned char *data, size_t size)
{
        xor_bits(data, size);
        reverse_bits_order(data, size);
}

int sts_drbg(void *rng_state, unsigned char *output, size_t len)
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

int sts_encrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size, size_t *ecb_len)
{
        int i;
        int ret;
        int iter;
        unsigned char *p_in = input;
        unsigned char *p_out = output;

        /* compute ecb_len */
        if (size < ECB_BLOCKSIZE) {
                *ecb_len = ECB_BLOCKSIZE;
        } 
        if (size > ECB_BLOCKSIZE && size % ECB_BLOCKSIZE > 0) {
                *ecb_len = (ECB_BLOCKSIZE - (size % ECB_BLOCKSIZE)) + size;

        } 
        if (size % ECB_BLOCKSIZE == 0) {
                *ecb_len = size;
        }

        /* compute nbr of iterations */
        iter = *ecb_len / ECB_BLOCKSIZE;

        for (i = 0; i < iter; i++) {
                ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, p_in, p_out);
                if (ret != 0) {
                        return ret;
                }
                p_in += ECB_BLOCKSIZE;
                p_out += ECB_BLOCKSIZE;
        }
        return 0;
}

int sts_decrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t ecb_len)
{
        int i;
        int ret;
        int iter;
        unsigned char *p_in = input;
        unsigned char *p_out = output;

        /* compute nbr of iterations */
        iter = ecb_len / ECB_BLOCKSIZE;

        for (i = 0; i < iter; i++) {
                ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, p_in, p_out);
                if (ret != 0) {
                        return ret;
                }
                p_in += ECB_BLOCKSIZE;
                p_out += ECB_BLOCKSIZE;
        }
        return 0;
}

int sts_encrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, 
                size_t size, size_t *cbc_len)
{
        int ret;

        /* compute ecb_len */
        if (size < CBC_BLOCKSIZE) {
                *cbc_len = CBC_BLOCKSIZE;
        } 
        if (size > CBC_BLOCKSIZE && size % CBC_BLOCKSIZE > 0) {
                *cbc_len = (CBC_BLOCKSIZE - (size % CBC_BLOCKSIZE)) + size;

        } 
        if (size % CBC_BLOCKSIZE == 0) {
                *cbc_len = size;
        }

        ret = mbedtls_aes_crypt_cbc(ctx, MBEDTLS_AES_ENCRYPT, *cbc_len, iv, 
                        input, output);
        return ret;
}

int sts_decrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, size_t cbc_len)
{
        int ret;

        ret = mbedtls_aes_crypt_cbc(ctx, MBEDTLS_AES_DECRYPT, cbc_len, iv, 
                        input, output);
        return ret;
}
