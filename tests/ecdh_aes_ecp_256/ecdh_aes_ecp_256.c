#include "sts.h"
#include "log.h"

#define NUMBER_TESTS 13

int sts_ecdh_aes_test(void)
{
        TESTS("+================================================+\n");
        TESTS("|       ECDH - AES MBEDTLS_ECP_DP_SECP256K1      |\n");
        TESTS("+================================================+\n");
        int ret;
        int count = 0;
        size_t olen;
        size_t size;
        char *msg = "CORE-TEX_LABS";

        mbedtls_ecdh_context host_ecdh_ctx;
        mbedtls_ecdh_context remote_ecdh_ctx;
        mbedtls_aes_context host_aes_ctx;
        mbedtls_aes_context remote_aes_ctx;

        unsigned char host_derived_key[ECDH_SHARED_KEYSIZE_BYTES];
        unsigned char remote_derived_key[ECDH_SHARED_KEYSIZE_BYTES];
        unsigned char message[STS_MSG_MAXLEN];
        unsigned char enc_msg[STS_MSG_MAXLEN];
        unsigned char dec_msg[STS_MSG_MAXLEN];

        mbedtls_ecdh_init(&host_ecdh_ctx);
        mbedtls_ecdh_init(&remote_ecdh_ctx);

        /* test 1.0 */
        ret = mbedtls_ecdh_setup(&host_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
        if (ret < 0) {
                TESTS("test 1.0: mbedtls_ecdh_setup host FAILED!\n");
        } else {
                count++;
                TESTS("test 1.0: mbedtls_ecdh_setup host OK!\n");
        }
        /* test 1.1 */
        ret = mbedtls_ecdh_setup(&remote_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
        if (ret < 0) {
                TESTS("test 1.1: mbedtls_ecdh_setup remote FAILED!\n");
        } else {
                count++;
                TESTS("test 1.1: mbedtls_ecdh_setup remote OK!\n");
        }

        /* test 2.0 */
        ret = mbedtls_ecdh_gen_public(&host_ecdh_ctx.grp, &host_ecdh_ctx.d,
                        &host_ecdh_ctx.Q, genrand, NULL);
        if (ret < 0) {
                TESTS("test 2.0: mbedtls_ecdh_gen_public host FAILED!\n");
        } else {
                count++;
                TESTS("test 2.0: mbedtls_ecdh_gen_public host OK!\n");
        }

        /* test 2.1 */
        ret = mbedtls_ecdh_gen_public(&remote_ecdh_ctx.grp, &remote_ecdh_ctx.d,
                        &remote_ecdh_ctx.Q, genrand, NULL);
        if (ret < 0) {
                TESTS("test 2.1: mbedtls_ecdh_gen_public remote FAILED!\n");
        } else {
                count++;
                TESTS("test 2.1: mbedtls_ecdh_gen_public remote OK!\n");
        }

        /* test 3.0 */
        ret = mbedtls_ecp_copy(&host_ecdh_ctx.Qp, &remote_ecdh_ctx.Q);
        if (ret < 0) {
                TESTS("test 3.0: mbedtls_ecp_copy host FAILED!\n");
        } else {
                count++;
                TESTS("test 3.0: mbedtls_ecp_copy host OK!\n");
        }

        /* test 3.1 */
        ret = mbedtls_ecp_copy(&remote_ecdh_ctx.Qp, &host_ecdh_ctx.Q);
        if (ret < 0) {
                TESTS("test 3.1: mbedtls_ecp_copy remote FAILED!\n");
        } else {
                count++;
                TESTS("test 3.1: mbedtls_ecp_copy remote OK!\n");
        }

        /* test 4.0 */
        ret = mbedtls_ecdh_calc_secret(&host_ecdh_ctx, &olen, host_derived_key,
                        sizeof(host_derived_key), genrand, NULL);
        if (ret < 0) {
                TESTS("test 4.0: mbedtls_ecdh_calc_secret host FAILED!\n");
        } else {
                count++;
                TESTS("test 4.0: mbedtls_ecdh_calc_secret host OK!\n");
        }

        /* test 4.1 */
        ret = mbedtls_ecdh_calc_secret(&remote_ecdh_ctx, &olen, remote_derived_key,
                        sizeof(remote_derived_key), genrand, NULL);
        if (ret < 0) {
                TESTS("test 4.1: mbedtls_ecdh_calc_secret remote FAILED!\n");
        } else {
                count++;
                TESTS("test 4.1: mbedtls_ecdh_calc_secret remote OK!\n");
        }

        /* test 5.0 */
        ret = sts_verify_derived_keylen(host_derived_key, sizeof(host_derived_key),
                        ECDH_SHARED_KEYSIZE_BITS);
        if (ret < 0) {
                TESTS("test 5.0: sts_verify_derived_keylen host FAILED!\n");
        } else {
                count++;
                TESTS("test 5.0: sts_verify_derived_keylen host OK!\n");
        }

        /* test 5.1 */
        ret = sts_verify_derived_keylen(remote_derived_key,
                        sizeof(remote_derived_key), ECDH_SHARED_KEYSIZE_BITS);
        if (ret < 0) {
                TESTS("test 5.1: sts_verify_derived_keylen remote FAILED!\n");
        } else {
                count++;
                TESTS("test 5.1: sts_verify_derived_keylen remote OK!\n");
        }

        /* test 6.0 */
        mbedtls_aes_init(&host_aes_ctx);
        mbedtls_aes_init(&remote_aes_ctx);
        memset(message, 0, STS_MSG_MAXLEN);
        memset(enc_msg, 0, STS_MSG_MAXLEN);
        memset(dec_msg, 0, STS_MSG_MAXLEN);

        size = strlen(msg);
        strcpy((char*)message, msg);
        ret = mbedtls_aes_setkey_enc(&host_aes_ctx, host_derived_key,
                        ECDH_SHARED_KEYSIZE_BITS);
        if (ret < 0) {
                TESTS("test 6.0: mbedtls_aes_setkey_enc host FAILED!\n");
        } else {
                count++;
                TESTS("test 6.0: mbedtls_aes_setkey_enc host OK!\n");
        }
        /* test 6.1 */
        ret = mbedtls_aes_setkey_dec(&remote_aes_ctx, remote_derived_key,
                        ECDH_SHARED_KEYSIZE_BITS);
        if (ret < 0) {
                TESTS("test 6.1: mbedtls_aes_setkey_enc remote FAILED!\n");
        } else {
                count++;
                TESTS("test 6.1: mbedtls_aes_setkey_enc remote OK!\n");
        }

        sts_encrypt_aes_ecb(&host_aes_ctx, message, enc_msg, size);
        sts_decrypt_aes_ecb(&remote_aes_ctx, enc_msg, dec_msg, size);

        /* test 7.0 */
        ret = strcmp((char*)message, (char*)dec_msg);
        if (ret < 0) {
                TESTS("test 7.0: sts_encrypt_decrypt verification FAILED!\n");
        } else {
                count++;
                TESTS("test 7.0: sts_encrypt_decrypt verification OK!\n\n");
        }

        /* free */
        mbedtls_ecdh_free(&host_ecdh_ctx);
        mbedtls_ecdh_free(&remote_ecdh_ctx);
        mbedtls_aes_free(&host_aes_ctx);
        mbedtls_aes_free(&remote_aes_ctx);

        if (count == NUMBER_TESTS) {
                TESTS("TESTS PASSED: %d/%d\n", count, NUMBER_TESTS);
        } else {
                TESTS("TESTS FAILED: %d/%d\n", count, NUMBER_TESTS);
        }

        return 0;
}

int main(void)
{
        sts_ecdh_aes_test();
}
