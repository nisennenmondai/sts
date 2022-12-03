#include "log.h"
#include "sts.h"
#include "sec.h"

#define NUMBER_TESTS 1

void sha256_test(void)
{
        TESTS("+================================================+\n");
        TESTS("|                    SHA256                      |\n");
        TESTS("+================================================+\n");

        int ret;
        int count;
        size_t size;
        size_t olen;
        size_t cbc_len;
        char *msg;

        unsigned char host_derived_key[ECDH_KEYSIZE_BYTES];
        unsigned char remote_derived_key[ECDH_KEYSIZE_BYTES];
        unsigned char message[STS_MSG_MAXLEN];
        unsigned char enc_msg[STS_MSG_MAXLEN];
        unsigned char dec_msg[STS_MSG_MAXLEN];
        unsigned char digest_enc[HASH_SIZE];
        unsigned char digest_dec[HASH_SIZE];

        mbedtls_ecdh_context host_ecdh_ctx;
        mbedtls_ecdh_context remote_ecdh_ctx;
        mbedtls_aes_context host_aes_ctx;
        mbedtls_aes_context remote_aes_ctx;

        memset(message, 0, STS_MSG_MAXLEN);
        memset(enc_msg, 0, STS_MSG_MAXLEN);
        memset(dec_msg, 0, STS_MSG_MAXLEN);
        memset(digest_dec, 0, sizeof(digest_dec));
        memset(digest_enc, 0, sizeof(digest_enc));

        mbedtls_ecdh_init(&host_ecdh_ctx);
        mbedtls_ecdh_init(&remote_ecdh_ctx);
        mbedtls_aes_init(&host_aes_ctx);
        mbedtls_aes_init(&remote_aes_ctx);

        count = 0;
        msg = "CORE-TEX_LABS: Deadman, PafLeChien, max1point";

        /* ecdh shared secret */
        ret = mbedtls_ecdh_setup(&host_ecdh_ctx, MBEDTLS_ECP_DP_CURVE25519);

        if (ret != 0) {
                TESTS("mbedtls_ecdh_setup()\n");
                count--;
        }
        ret = mbedtls_ecdh_setup(&remote_ecdh_ctx, MBEDTLS_ECP_DP_CURVE25519);

        if (ret != 0) {
                TESTS("mbedtls_ecdh_setup()\n");
                count--;
        }

        ret = mbedtls_ecdh_gen_public(&host_ecdh_ctx.grp, &host_ecdh_ctx.d,
                        &host_ecdh_ctx.Q, sts_drbg, NULL);
        if (ret != 0) {
                TESTS("mbedtls_ecdh_gen_public()\n");
                count--;
        }

        ret = mbedtls_ecdh_gen_public(&remote_ecdh_ctx.grp, &remote_ecdh_ctx.d,
                        &remote_ecdh_ctx.Q, sts_drbg, NULL);
        if (ret != 0) {
                TESTS("mbedtls_ecdh_gen_public()\n");
                count--;
        }

        ret = mbedtls_ecp_copy(&host_ecdh_ctx.Qp, &remote_ecdh_ctx.Q);

        if (ret != 0) {
                TESTS("mbedtls_ecp_copy()\n");
                count--;
        }

        ret = mbedtls_ecp_copy(&remote_ecdh_ctx.Qp, &host_ecdh_ctx.Q);

        if (ret != 0) {
                TESTS("mbedtls_ecp_copy()\n");
                count--;
        }

        ret = mbedtls_ecdh_calc_secret(&host_ecdh_ctx, &olen, host_derived_key,
                        sizeof(host_derived_key), sts_drbg, NULL);
        if (ret != 0) {
                TESTS("mbedtls_ecdh_calc_secret()\n");
                count--;
        }

        ret = mbedtls_ecdh_calc_secret(&remote_ecdh_ctx, &olen, remote_derived_key,
                        sizeof(remote_derived_key), sts_drbg, NULL);
        if (ret != 0) {
                TESTS("mbedtls_ecdh_calc_secret()\n");
                count--;
        }

        size = strlen(msg);
        memcpy(message, msg, size);

        ret = mbedtls_aes_setkey_enc(&host_aes_ctx, host_derived_key,
                        ECDH_KEYSIZE_BITS);
        if (ret != 0) {
                TESTS("mbedtls_aes_setkey_enc()\n");
                count--;
        }

        /* hash before enc */
        mbedtls_sha256(message, sizeof(message), digest_enc, 0);

        ret = mbedtls_aes_setkey_dec(&remote_aes_ctx, remote_derived_key,
                        ECDH_KEYSIZE_BITS);

        if (ret != 0) {
                TESTS("mbedtls_aes_setkey_enc()\n");
                count--;
        }

        ret = sts_encrypt_aes_cbc(&host_aes_ctx, host_derived_key, message, enc_msg, 
                        size, &cbc_len);
        if (ret != 0) {
                TESTS("sts_encrypt_aes_cbc()\n");
                count--;
        }

        /* hash after dec */
        ret = sts_decrypt_aes_cbc(&remote_aes_ctx, remote_derived_key, enc_msg, 
                        dec_msg, cbc_len);

        if (ret != 0) {
                TESTS("sts_decrypt_aes_cbc()\n");
                count--;
        }
        mbedtls_sha256(dec_msg, sizeof(dec_msg), digest_dec, 0);

        /* test 1.0 */
        ret = sts_verify_hash(digest_enc, digest_dec);

        if (ret == 0) {
                TESTS("test 1.0: hash comparison OK!\n");
                count++;

        } else {
                TESTS("test 1.0: hash comparison FAILED!\n");
                count--;
        }

        /* free */
        mbedtls_aes_free(&host_aes_ctx);
        mbedtls_aes_free(&remote_aes_ctx);
        mbedtls_ecdh_free(&host_ecdh_ctx);
        mbedtls_ecdh_free(&remote_ecdh_ctx);
        printf("\n");

        if (count == NUMBER_TESTS) {
                TESTS("TESTS PASSED: %d/%d\n", count, NUMBER_TESTS);
                INFO("----------------------------------------->\n\n");

        } else {
                TESTS("TESTS FAILED: %d/%d\n", count, NUMBER_TESTS);
                INFO("----------------------------------------->\n\n");
        }
}

int main(void)
{
        sha256_test();
}
