#include <stdio.h>
#include <stdlib.h>

#include "sts.h"

static int genrand(void *rng_state, unsigned char *output, size_t len)
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

        rnd = rand();
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
        printf("sts: master derived shared_key: ");
    }

    if (client == 1) {
        printf("\nsts: slave derived shared_key: ");
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

    mbedtls_ecdh_context master_ecdh_ctx;
    mbedtls_ecdh_context slave_ecdh_ctx;
    mbedtls_aes_context master_aes_ctx;
    mbedtls_aes_context slave_aes_ctx;

    unsigned char master_derived_key[ECDH_SHARED_KEYSIZE_BYTES];
    unsigned char slave_derived_key[ECDH_SHARED_KEYSIZE_BYTES];
    unsigned char message[STS_MSG_MAXLEN];
    unsigned char enc_msg[STS_MSG_MAXLEN];
    unsigned char dec_msg[STS_MSG_MAXLEN];

    /* init mbedtls context and generate keypair for master and slave clients */
    mbedtls_ecdh_init(&master_ecdh_ctx);
    mbedtls_ecdh_setup(&master_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
    mbedtls_ecdh_gen_public(&master_ecdh_ctx.grp, &master_ecdh_ctx.d, 
            &master_ecdh_ctx.Q, genrand, NULL);
    printf("sts: master private key: %lu\n", *master_ecdh_ctx.d.p);
    printf("sts: master public key X:%lu Y:%lu Z:%lu\n\n", 
            *master_ecdh_ctx.Q.X.p, *master_ecdh_ctx.Q.Y.p, 
            *master_ecdh_ctx.Q.Z.p);

    mbedtls_ecdh_init(&slave_ecdh_ctx);
    mbedtls_ecdh_setup(&slave_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
    mbedtls_ecdh_gen_public(&slave_ecdh_ctx.grp, &slave_ecdh_ctx.d, 
            &slave_ecdh_ctx.Q, genrand, NULL);
    printf("sts: slave private key: %lu\n", *slave_ecdh_ctx.d.p);
    printf("sts: slave public key X:%lu Y:%lu Z:%lu\n\n", *slave_ecdh_ctx.Q.X.p, 
            *slave_ecdh_ctx.Q.Y.p, *slave_ecdh_ctx.Q.Z.p);

    /* exchange public key */
    mbedtls_ecp_copy(&master_ecdh_ctx.Qp, &slave_ecdh_ctx.Q);
    mbedtls_ecp_copy(&slave_ecdh_ctx.Qp, &master_ecdh_ctx.Q);

    /* derive shared secret */
    mbedtls_ecdh_calc_secret(&master_ecdh_ctx, &olen, master_derived_key, 
            sizeof(master_derived_key), genrand, NULL);
    mbedtls_ecdh_calc_secret(&slave_ecdh_ctx, &olen, slave_derived_key, 
            sizeof(slave_derived_key), genrand, NULL);

    _print_derived_key(master_derived_key, sizeof(master_derived_key), STS_MASTER);
    _print_derived_key(slave_derived_key, sizeof(slave_derived_key), STS_SLAVE);

    /* check if shared secret is valid */
    ret = _verify_derived_keylen(master_derived_key, sizeof(master_derived_key), 
            ECDH_SHARED_KEYSIZE_BITS);
    if (ret == -1) {
        return STS_PROMPT;
    }
    ret = _verify_derived_keylen(slave_derived_key, sizeof(slave_derived_key), 
            ECDH_SHARED_KEYSIZE_BITS);
    if (ret == -1) {
        return STS_PROMPT;
    }

    for (i = 0; i < ECDH_SHARED_KEYSIZE_BITS / BYTE; i++) {
        if (master_derived_key[i] != slave_derived_key[i]) {
            printf("sts: error! master and slave derived key not identical\n");
            return STS_PROMPT;
        }
    }

    /* init ctx */
    mbedtls_aes_init(&master_aes_ctx);
    mbedtls_aes_init(&slave_aes_ctx);
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
    printf("\nsts: message size: %d\n\n", msg_size);

    /* set encryption key for master and decryption key for slave */
    mbedtls_aes_setkey_enc(&master_aes_ctx, master_derived_key, 
            ECDH_SHARED_KEYSIZE_BITS); 
    mbedtls_aes_setkey_dec(&slave_aes_ctx, slave_derived_key, 
            ECDH_SHARED_KEYSIZE_BITS); 

    /* encrypt and decrypt data */
    _encrypt(&master_aes_ctx, message, enc_msg, msg_size);
    _decrypt(&slave_aes_ctx, enc_msg, dec_msg, msg_size);
    printf("sts: encrypted message on master side: %s\n\n", enc_msg);
    printf("sts: decrypted message on slave side: %s\n\n", dec_msg);

    /* free */
    mbedtls_ecdh_free(&master_ecdh_ctx);
    mbedtls_ecdh_free(&slave_ecdh_ctx);
    mbedtls_aes_free(&master_aes_ctx); 
    mbedtls_aes_free(&slave_aes_ctx);

    return STS_PROMPT;
}
