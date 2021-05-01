#ifndef STS_H
#define STS_H

#include "MQTTLinux.h"
#include "MQTTClient.h"
#include "ecdh.h"
#include "aes.h"

/* init */
#define READBUFFSIZE              1024
#define SENDBUFFSIZE              1024
#define COMMAND_TIMEOUT_MS        10000

/* config file */
#define CONF_KEY_MAXLEN    16
#define CONF_VAL_MAXLEN    128

/* shell */
#define STS_TOK_BUFFSIZE          64
#define STS_RL_BUFFSIZE           1024
#define STS_TOK_DELIM             " \t\r\n\a"

/* sec */
#define BYTE                      8
#define ECB_BLOCKSIZE             16
#define CBC_BLOCKSIZE             16
#define ID_SIZE                   32
#define MPI_STRING_SIZE           128
#define ECDH_KEYSIZE_BITS         256
#define ECDH_KEYSIZE_BYTES        ECDH_KEYSIZE_BITS / BYTE

#define AES_NULL    "null"
#define AES_ECB     "ecb"
#define AES_CBC     "cbc"

/* return code */
#define STS_EXIT    0
#define STS_PROMPT  1

/* status */
#define STS_STARTED 0
#define STS_STOPPED 1 
#define STS_KILL_THREAD 1

/* sts msg types */
#define STS_INIT       "INIT:"
#define STS_INITACK    "INITACK:"
#define STS_AUTHREQ    "AUTHREQ:"
#define STS_AUTHACK    "AUTHACK:"
#define STS_RDYREQ     "RDYREQ:"
#define STS_RDYACK     "RDYACK:"
#define STS_ENC        "ENC:"
#define STS_KILL       "KILL:"

/* sts msg sizes */
#define STS_HEADERSIZE 10
#define STS_MSG_MAXLEN 1024
#define STS_DATASIZE   STS_MSG_MAXLEN - STS_HEADERSIZE

/* sts modes */
#define STS_NOSEC      "nosec"
#define STS_SECSLAVE   "slave"
#define STS_SECMASTER  "master"

/* sts protocole states */
#define STS_STEP_0 0
#define STS_STEP_1 1
#define STS_STEP_2 2
#define STS_STEP_3 3
#define STS_STEP_4 4
#define STS_STEP_5 5

struct sts_message {
        char header[STS_HEADERSIZE];
        char data[STS_DATASIZE];
};

struct sts_context {
        unsigned int pid;
        unsigned int mqtt_version;
        unsigned int port;
        unsigned int msg_sent;
        unsigned int msg_recv;
        unsigned int thrd_msg_type;
        unsigned short status;
        volatile unsigned short master_flag;
        volatile unsigned short slave_flag;
        volatile unsigned short kill_flag;
        unsigned short no_print;
        unsigned short encryption;
        unsigned char derived_key[ECDH_KEYSIZE_BYTES];
        char topic_sub[CONF_VAL_MAXLEN];
        char topic_pub[CONF_VAL_MAXLEN];
        char clientid[CONF_VAL_MAXLEN];
        char username[CONF_VAL_MAXLEN];
        char password[CONF_VAL_MAXLEN];
        char id_master[CONF_VAL_MAXLEN];
        char id_slave[CONF_VAL_MAXLEN];
        char sts_mode[CONF_VAL_MAXLEN];
        char aes[CONF_VAL_MAXLEN];
        char ip[16];
        Network network;
        MQTTClient client;
        mbedtls_aes_context host_aes_ctx_enc;
        mbedtls_aes_context host_aes_ctx_dec;
        mbedtls_ecdh_context host_ecdh_ctx;
};

/* mqtt */
int mqtt_connect(void);
int mqtt_disconnect(void);
int mqtt_subscribe(void);
int mqtt_unsubscribe(void);
int mqtt_publish(char *string);
int mqtt_publish_aes_ecb(unsigned char *enc, size_t ecb_len);
int mqtt_publish_aes_cbc(unsigned char *enc, size_t cbc_len);

/* sts */
void sts_free_sec(void);
void sts_reset_ctx(void);
int sts_init(const char *config);
int sts_init_sec(void);
struct sts_context *sts_get_ctx(void);

/* sts cmd */
int sts_start_session(char **argv);
int sts_stop_session(char **argv);
int sts_send_nosec(char *str);
int sts_send_sec(char *str);
int sts_help(char **argv);
int sts_exit(char **argv);
int sts_status(char **argv);
int sts_test_send_nosec(char **argv);   /* for tests only */
int sts_test_send_sec(char **argv);     /* for tests only */

/* sts sec */
int sts_encrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size, size_t *ecb_len);
int sts_decrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t ecb_len);
int sts_encrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, 
                size_t size, size_t *cbc_len);
int sts_decrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, size_t cbc_len);
int sts_drbg(void *rng_state, unsigned char *output, size_t len);


int sts_verify_keylen(const unsigned char *buf, size_t size, size_t len);
/* 
 * this is a simple algorithm as an example so msg aren't human readable during
 * init_sec. it is recommended to modify it for your own use.
 */
void sts_encode(unsigned char *data, size_t size);
void sts_decode(unsigned char *data, size_t size);

#endif /* STS_H */
