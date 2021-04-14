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
                rnd = rand()%100;
                memcpy(output, &rnd, use_len);
                output += use_len;
                len -= use_len;
        }
        return 0;
}

static void _print_derived_key(const unsigned char *buf, size_t size, int client) 
{
        size_t i;
        if (client == 0) {
                printf("sts: host derived shared_key:   ");
        }

        if (client == 1) {
                printf("\nsts: remote derived shared_key: ");
        }

        for (i = 0 ; i < size; i++) {
                if (buf[i] == '\0') {
                        break;
                }
                printf("%02X", buf[i]);
        }
}

static int _verify_derived_keylen(const unsigned char *buf, size_t size, size_t len)
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
                printf("\nsts: keylen: %lu bits", shared_keysize);
                return 0;

        } else {
                printf("\nsts: error! derived keylen not 256 bits\n");
                return -1;
        }
}

static void _encrypt(mbedtls_aes_context *ctx, unsigned char *input, 
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
                mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, p_input, p_output);
                p_input += AES_ECB_BLOCKSIZE;
                p_output += AES_ECB_BLOCKSIZE;
        }
}

static void _decrypt(mbedtls_aes_context *ctx, unsigned char *input, 
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
                mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, p_input, p_output);
                p_input += AES_ECB_BLOCKSIZE;
                p_output += AES_ECB_BLOCKSIZE;
        }
}

int sts_ecdh_aes_test(char **argv)
{
        (void)argv;

        int i;
        int ret;
        size_t olen;

        if (argv[1] == NULL) {
                printf("sts: error! wrong number of arguments -> sectest [MSG]\n");
                return STS_PROMPT;
        }
        char *msg = argv[1];
        int msg_size = 0;

        mbedtls_ecdh_context host_ecdh_ctx;
        mbedtls_ecdh_context remote_ecdh_ctx;
        mbedtls_aes_context host_aes_ctx;
        mbedtls_aes_context remote_aes_ctx;

        unsigned char host_derived_key[ECDH_SHARED_KEYSIZE_BYTES];
        unsigned char remote_derived_key[ECDH_SHARED_KEYSIZE_BYTES];
        unsigned char message[STS_MSG_MAXLEN];
        unsigned char enc_msg[STS_MSG_MAXLEN];
        unsigned char dec_msg[STS_MSG_MAXLEN];

        /* init mbedtls context and generate keypair for host and remote clients */
        mbedtls_ecdh_init(&host_ecdh_ctx);
        mbedtls_ecdh_setup(&host_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
        mbedtls_ecdh_gen_public(&host_ecdh_ctx.grp, &host_ecdh_ctx.d, 
                        &host_ecdh_ctx.Q, genrand, NULL);
        printf("sts: host private key: %lu\n", *host_ecdh_ctx.d.p);
        printf("sts: host public key X:%lu Y:%lu Z:%lu\n\n", 
                        *host_ecdh_ctx.Q.X.p, *host_ecdh_ctx.Q.Y.p, 
                        *host_ecdh_ctx.Q.Z.p);

        mbedtls_ecdh_init(&remote_ecdh_ctx);
        mbedtls_ecdh_setup(&remote_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
        mbedtls_ecdh_gen_public(&remote_ecdh_ctx.grp, &remote_ecdh_ctx.d, 
                        &remote_ecdh_ctx.Q, genrand, NULL);
        printf("sts: remote private key: %lu\n", *remote_ecdh_ctx.d.p);
        printf("sts: remote public key X:%lu Y:%lu Z:%lu\n\n", *remote_ecdh_ctx.Q.X.p, 
                        *remote_ecdh_ctx.Q.Y.p, *remote_ecdh_ctx.Q.Z.p);

        /* exchange public key */
        mbedtls_ecp_copy(&host_ecdh_ctx.Qp, &remote_ecdh_ctx.Q);
        mbedtls_ecp_copy(&remote_ecdh_ctx.Qp, &host_ecdh_ctx.Q);

        /* derive shared secret */
        mbedtls_ecdh_calc_secret(&host_ecdh_ctx, &olen, host_derived_key, 
                        sizeof(host_derived_key), genrand, NULL);
        mbedtls_ecdh_calc_secret(&remote_ecdh_ctx, &olen, remote_derived_key, 
                        sizeof(remote_derived_key), genrand, NULL);

        _print_derived_key(host_derived_key, sizeof(host_derived_key), STS_HOST);
        _print_derived_key(remote_derived_key, sizeof(remote_derived_key), STS_REMOTE);

        /* check if shared secret is valid */
        ret = _verify_derived_keylen(host_derived_key, sizeof(host_derived_key), 
                        ECDH_SHARED_KEYSIZE_BITS);
        if (ret == -1) {
                return STS_PROMPT;
        }
        ret = _verify_derived_keylen(remote_derived_key, sizeof(remote_derived_key), 
                        ECDH_SHARED_KEYSIZE_BITS);
        if (ret == -1) {
                return STS_PROMPT;
        }

        for (i = 0; i < ECDH_SHARED_KEYSIZE_BITS / BYTE; i++) {
                if (host_derived_key[i] != remote_derived_key[i]) {
                        printf("sts: error! host and remote derived key not identical\n");
                        return STS_PROMPT;
                }
        }

        /* init ctx */
        mbedtls_aes_init(&host_aes_ctx);
        mbedtls_aes_init(&remote_aes_ctx);
        memset(message, 0, STS_MSG_MAXLEN);
        memset(enc_msg, 0, STS_MSG_MAXLEN);
        memset(dec_msg, 0, STS_MSG_MAXLEN);

        /* compute size of msg */
        for (i = 0; i < STS_MSG_MAXLEN; i++) {
                if (msg[i] == '\0') {
                        break;
                }
                msg_size++;
        }

        /* copy msg to be encrypted to input buffer and compute size */
        printf("\n\nsts: message: ");
        for (i = 0; i < msg_size; i++) {
                if (msg[i] == '\0') {
                        break;
                }
                message[i] = msg[i];
                printf("%c", message[i]);
        }
        printf("\nsts: message size: %d bytes\n\n", msg_size);

        /* set encryption key for host and decryption key for remote */
        mbedtls_aes_setkey_enc(&host_aes_ctx, host_derived_key, 
                        ECDH_SHARED_KEYSIZE_BITS); 
        mbedtls_aes_setkey_dec(&remote_aes_ctx, remote_derived_key, 
                        ECDH_SHARED_KEYSIZE_BITS); 

        /* encrypt and decrypt data */
        _encrypt(&host_aes_ctx, message, enc_msg, msg_size);
        _decrypt(&remote_aes_ctx, enc_msg, dec_msg, msg_size);
        printf("sts: encrypted message on host side: %s\n\n", enc_msg);
        printf("sts: decrypted message on remote side: %s\n\n", dec_msg);

        /* free */
        mbedtls_ecdh_free(&host_ecdh_ctx);
        mbedtls_ecdh_free(&remote_ecdh_ctx);
        mbedtls_aes_free(&host_aes_ctx); 
        mbedtls_aes_free(&remote_aes_ctx);

        return STS_PROMPT;
}
