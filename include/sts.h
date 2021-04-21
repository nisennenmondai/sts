/*
 * =============================================================================
 *
 *       Filename:  sts.h
 *
 *    Description:  Secure Telemetry Shell 
 *
 *        Version:  1.0
 *        Created:  03/11/2020 10:24:53 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nisennenmondai,
 *   Organization:  
 *
 * =============================================================================
 */
#ifndef STS_H
#define STS_H

#include <stdlib.h>
#include <time.h>

#include "MQTTLinux.h"
#include "MQTTClient.h"
#include "ecdh.h"
#include "aes.h"

/* init */
#define READBUFFSIZE              1024
#define SENDBUFFSIZE              1024
#define COMMAND_TIMEOUT_MS        10000
#define CONFIG_VALUE_MAXLENGTH    128

/* shell */
#define STS_TOK_BUFFSIZE          64
#define STS_RL_BUFFSIZE           1024
#define STS_TOK_DELIM             " \t\r\n\a"

/* sec */
#define BYTE                      8
#define AES_ECB_BLOCKSIZE         16
#define MPI_STRING_SIZE           128
#define ECDH_SHARED_KEYSIZE_BITS  256
#define ECDH_SHARED_KEYSIZE_BYTES ECDH_SHARED_KEYSIZE_BITS / BYTE

/* return code */
#define STS_EXIT    0
#define STS_PROMPT  1

/* status */
#define STS_STARTED 0
#define STS_STOPPED 1 
#define STS_KILL_THREAD 1

/* sts msg types */
#define STS_AUTHREQ  "AUTHREQ:"
#define STS_AUTHACK  "AUTHACK:"
#define STS_RDYREQ   "RDYREQ:"
#define STS_RDYACK   "RDYACK:"
#define STS_HEADERSIZE 10
#define STS_MSG_MAXLEN 1024

/* sts protocole state */
#define STS_STEP_0 0
#define STS_STEP_1 1
#define STS_STEP_2 2
#define STS_STEP_3 3
#define STS_STEP_4 4

struct sts_message {
        char header[STS_HEADERSIZE]; /* max header length */
        char data[STS_MSG_MAXLEN];
};

struct sts_context {
        unsigned int mqtt_version;
        unsigned int qos;
        unsigned int port;
        unsigned int keep_alive;
        unsigned int clean_session;
        unsigned int is_retained;
        unsigned int msg_sent;
        unsigned int msg_recv;
        unsigned int thrd_msg_type;
        unsigned short status;
        unsigned short master_flag;
        unsigned short slave_flag;
        unsigned short no_print;
        unsigned char derived_key[ECDH_SHARED_KEYSIZE_BYTES];
        char topic_sub[CONFIG_VALUE_MAXLENGTH];
        char topic_pub[CONFIG_VALUE_MAXLENGTH];
        char clientid[CONFIG_VALUE_MAXLENGTH];
        char username[CONFIG_VALUE_MAXLENGTH];
        char password[CONFIG_VALUE_MAXLENGTH];
        char id_master[CONFIG_VALUE_MAXLENGTH];
        char id_slave[CONFIG_VALUE_MAXLENGTH];
        char sts_mode[CONFIG_VALUE_MAXLENGTH];
        char ip[16];
        Network network;
        MQTTClient client;
        mbedtls_ecdh_context host_ecdh_ctx;
};

/* mqtt */
void mqtt_disconnect(void);
int mqtt_connect(void);
int mqtt_unsubscribe(void);
int mqtt_subscribe(void);
int mqtt_publish(char *message);

/* sts */
void sts_free_sec(void);
void sts_reset_ctx(void);
int sts_init(const char *config);
int sts_init_sec(void);
struct sts_context *sts_get_ctx(void);

/* sts commands */
int sts_help(char **argv);
int sts_exit(char **argv);
int sts_start_session(char **argv);
int sts_stop_session(char **argv);
int sts_send(char **argv);
int sts_status(char **argv);

/* security */
void sts_encrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size);
void sts_decrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size);
void sts_print_derived_key(const unsigned char *buf, size_t size);
int sts_verify_derived_keylen(const unsigned char *buf, size_t size, size_t len);
int sts_genrand(void *rng_state, unsigned char *output, size_t len);

/* tests */
int sts_ecdh_aes_test(void);

/* tools */
void sts_concatenate(char p[], char q[]);
#endif /* STS_H */
