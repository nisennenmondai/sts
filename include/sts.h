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

#include "MQTTLinux.h"
#include "MQTTClient.h"
#include "ecdh.h"
#include "aes.h"

/* init */
#define READBUFFSIZE             1024
#define SENDBUFFSIZE             1024
#define COMMAND_TIMEOUT_MS       10000
#define CONFIG_VALUE_MAXLENGTH   64

/* shell parsing */
#define STS_TOK_BUFFSIZE         64
#define STS_RL_BUFFSIZE          1024
#define STS_TOK_DELIM            " \t\r\n\a"

/* sec */
#define BYTE                     8
#define AES_ECB_BLOCKSIZE        16
#define STS_MSG_MAXLEN           256 /* must be identical to slave client */
#define ECDH_SHARED_KEYSIZE_BITS 256
#define ECDH_SHARED_KEYSIZE_BYTES ECDH_SHARED_KEYSIZE_BITS / BYTE

enum sts_return_value {
        STS_EXIT   = 0,
        STS_PROMPT = 1,
};

enum sts_clients {
        STS_MASTER   = 0,
        STS_SLAVE    = 1,
};

/* types of message that can be sent between the two clients */
enum sts_msg_type {
        STS_CMD = 'C', /* user keyboard input command */
};

enum sts_status {
        STS_STARTED = 0,
        STS_STOPPED = 1,
};

enum sts_thrd_msg_type {
        STS_KILL_THREAD = 1,
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
        unsigned short sts_status;
        char topic_sub[CONFIG_VALUE_MAXLENGTH];
        char topic_pub[CONFIG_VALUE_MAXLENGTH];
        char clientid[CONFIG_VALUE_MAXLENGTH];
        char username[CONFIG_VALUE_MAXLENGTH];
        char password[CONFIG_VALUE_MAXLENGTH];
        char ip[16];
        Network network;
        MQTTClient client;
        mbedtls_ecdh_context master_ecdh_ctx;
};

/* sts commands */
int sts_help(char **argv);
int sts_exit(char **argv);
int sts_start_session(char **argv);
int sts_stop_session(char **argv);
int sts_send_cmd(char **argv);
int sts_status(char **argv);
int sts_ecdh_aes_test(char **argv);
