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
#define STS_MSG_MAXLEN            1024
#define ECDH_SHARED_KEYSIZE_BYTES ECDH_SHARED_KEYSIZE_BITS / BYTE

/* return code */
#define STS_EXIT    0
#define STS_PROMPT  1

/* status */
#define STS_STARTED 0
#define STS_STOPPED 1
#define STS_KILL_THREAD 1

/* sec test */
#define STS_HOST    0
#define STS_REMOTE  1

/* sts message types */
#define STS_AUTHREQ "AUTHREQ:"
#define STS_AUTHACK "AUTHACK:"
#define STS_RDYREQ  "RDYREQ:"
#define STS_RDYACK  "RDYACK:"
#define STS_HEADERSIZE 10

/* sts conn status */
#define STS_STEP_0 0
#define STS_STEP_1 1
#define STS_STEP_2 2
#define STS_STEP_3 3

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

/* sts commands */
int sts_help(char **argv);
int sts_exit(char **argv);
int sts_start_session(char **argv);
int sts_stop_session(char **argv);
int sts_send(char **argv);
int sts_status(char **argv);
int sts_ecdh_aes_test(void);

void sts_welcome(void);
void sts_loop(void);
int genrand(void *rng_state, unsigned char *output, size_t len);
struct sts_context *sts_get_ctx(void);

void sts_encrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size);
void sts_decrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size);
#endif /* STS_H */
