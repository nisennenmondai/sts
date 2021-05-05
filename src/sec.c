#include <stdio.h>
#include <string.h>

#include "sts.h"
#include "log.h"
#include "tools.h"

#include "ctr_drbg.h"
#include "entropy.h"

int sts_verify_keylen(const unsigned char *key, size_t size, size_t len)
{
        size_t i;
        size_t keylen;
        int tmp = 0; 

        for (i = 0 ; i < size; i++) {
                if (key[i] == '\0') {
                        break;
                }
                tmp++;
        }
        keylen = tmp * BYTE;

        if (keylen != len) {
                return keylen;
        } 
        return 0;
}

/* 
 * encode/decode data during authentication so it is not human readable, this 
 * algo is very simple and serves only as an example, it is recommanded to have 
 * your own PRIVATE algorithm.
 */
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


int sts_compute_shared_secret(char *X, char *Y, struct sts_context *ctx)
{
        int ret;
        size_t olen;
        ret = mbedtls_ecp_point_read_string(&ctx->host_ecdh_ctx.Qp, 16, X, Y);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecp_point_read_string()\n");
                return -1;
        }

        memset(ctx->derived_key, 0, sizeof(ctx->derived_key));
        ret = mbedtls_ecdh_calc_secret(&ctx->host_ecdh_ctx, 
                        &olen, ctx->derived_key, 
                        sizeof(ctx->derived_key), 
                        sts_drbg, NULL);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecdh_calc_secret()\n");
                return -1;
        }

        /* 
         * TODO sometimes derived_key is not 256 bits long, I don't know why 
         * we need to verify it 
         */
        ret = sts_verify_keylen(ctx->derived_key, sizeof(ctx->derived_key), 
                        ECDH_KEYSIZE_BITS);
        if (ret != 0) {
                WARN("sts: derived key != %d bits in length (only %d bits), "
                                "something went wrong, start a new session\n", 
                                ECDH_KEYSIZE_BITS, ret);
                return -1;
        }

        ret = mbedtls_aes_setkey_enc(&ctx->host_aes_ctx_enc, ctx->derived_key,
                        ECDH_KEYSIZE_BITS);
        if (ret != 0) {
                ERROR("sts: mbedtls_aes_setkey_enc()\n");
                return -1;
        }

        ret = mbedtls_aes_setkey_dec(&ctx->host_aes_ctx_dec, ctx->derived_key,
                        ECDH_KEYSIZE_BITS);
        if (ret != 0) {
                ERROR("sts: mbedtls_aes_setkey_dec()\n");
                return -1;
        }
        return 0;
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
                ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, 
                                p_in, p_out);
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
                ret = mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, 
                                p_in, p_out);
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
