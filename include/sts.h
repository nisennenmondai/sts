#ifndef STS_H
#define STS_H

#include "MQTTLinux.h"
#include "MQTTClient.h"

#include "mbedtls/aes.h"
#include "mbedtls/ecdh.h"

/* sts config */
#define CONF_KEY_MAXLEN 16
#define CONF_VAL_MAXLEN 128

/* sts sec */
#define BYTE               8
#define ECB_BLOCKSIZE      16
#define CBC_BLOCKSIZE      16
#define ID_SIZE            32
#define MPI_STRING_SIZE    128
#define ECDH_KEYSIZE_BITS  256
#define ECDH_KEYSIZE_BYTES (ECDH_KEYSIZE_BITS / BYTE)
#define AES_NULL           "null"
#define AES_ECB            "ecb"
#define AES_CBC            "cbc"

/* sts status */
#define STS_STARTED 0
#define STS_STOPPED 1 
#define STS_KILL_THREAD 1

/* sts msg types */
#define STS_INITREQ "INITREQ:"
#define STS_INITACK "INITACK:"
#define STS_AUTHREQ "AUTHREQ:"
#define STS_AUTHACK "AUTHACK:"
#define STS_RDYREQ  "RDYREQ:"
#define STS_RDYACK  "RDYACK:"
#define STS_KILL    "KILL:"
#define STS_ENC     "ENC:"

/* sts msg sizes */
#define STS_HEADERSIZE 10
#define STS_MSG_MAXLEN 1024
#define STS_DATASIZE   (STS_MSG_MAXLEN - STS_HEADERSIZE)

/* sts modes */
#define STS_NOSEC     "nosec"
#define STS_SECSLAVE  "slave"
#define STS_SECMASTER "master"

/* sts protocole states */
#define STS_STEP_0 0
#define STS_STEP_1 1
#define STS_STEP_2 2
#define STS_STEP_3 3
#define STS_STEP_4 4
#define STS_STEP_5 5

/*
 * @brief       sts message struct, an sts msg is defined as 1024 bytes in size.
 * @header      contains the msg type.
 * @data        contains the msg.
 */
struct sts_message {
        char header[STS_HEADERSIZE];
        char data[STS_DATASIZE];
};

/*
 * @brief               sts context.
 * @mqtt_version        actual mqtt version used by the client (3|4).
 * @port                mqtt port for connection with broker.
 * @msg_sent            number of message sent to broker.
 * @msg_recv            number of message receved from broker subscription.
 * @pid                 linux pid of main process.
 * @thrd_msg_type       msg type sent to mqttyield thread.
 * @status              sts status, can be STARTED | STOPPED.
 * @no_print_out        flag, if set to 1, published msg won't be displayed.
 * @no_print_inc        flag, if set to 1, income msg won't be displayed.
 * @encryption          flag, tell if encryption is active or not.                 
 * @derived_key         computed shared secret for symmetric encryption.
 * @master_flag         flag used durint init_sec, STS_STEP 0|1|2|3|4|5.
 * @slave_flag          flag used durint init_sec, STS_STEP 0|1|2|3|4|5.
 * @kill_flag           flag used to send KILL msg to remote client.
 * @topic_sub           mqtt subscription topic.
 * @topic_pub           mqtt publish topic.
 * @clientid            mqtt client id.
 * @username            mqtt username, only useful if broker requires it.
 * @password            mqtt passowrd, only useful if broker requires it.
 * @id_master           auto-generated id during init_sec.
 * @id_slave            auto-generated id during init_sec.
 * @sts_mode            mode in which sts client is running, nosec|master|slave.
 * @aes                 aes block cipher mode of operation, ecb|cbc.
 * @ip                  mqtt broker ip.
 * @network             paho-mqtt structure to init mqtt.
 * @client              paho-mqtt structure that holds mqtt clients.
 * @host_aes_ctx_enc    mbedtls aes ctx for encryption.
 * @host_aes_ctx_dec    mbedtls aes ctx for decryption.
 * @host_ecdh_ctx       mbedtls ecdh ctx for crypto key agreement protocole.
 */
struct sts_context {
        unsigned int mqtt_version;
        unsigned int port;
        unsigned int msg_sent;
        unsigned int msg_recv;
        unsigned int pid;
        unsigned int thrd_msg_type;
        unsigned short status;
        unsigned short no_print_out;
        unsigned short no_print_inc;
        unsigned short encryption;
        unsigned char derived_key[ECDH_KEYSIZE_BYTES];
        volatile unsigned short master_flag;
        volatile unsigned short slave_flag;
        volatile unsigned short kill_flag;
        char topic_sub[CONF_VAL_MAXLEN];
        char topic_pub[CONF_VAL_MAXLEN];
        char clientid[CONF_VAL_MAXLEN];
        char username[CONF_VAL_MAXLEN];
        char password[CONF_VAL_MAXLEN];
        char id_master[CONF_VAL_MAXLEN];
        char id_slave[CONF_VAL_MAXLEN];
        char sts_mode[CONF_VAL_MAXLEN];
        char aes[CONF_VAL_MAXLEN];
        char url[CONF_VAL_MAXLEN];
        Network network;
        MQTTClient client;
        mbedtls_aes_context host_aes_ctx_enc;
        mbedtls_aes_context host_aes_ctx_dec;
        mbedtls_ecdh_context host_ecdh_ctx;
};

/*
 * @brief               load sts config file.
 * @param config        path to config file.
 * @return              -1 if can't load config file.
 */
int sts_load_config(const char *config);

/*
 * @brief               sts initialization.
 * @param config        path to config file.
 * @return              -1 if can't init sts.
 */
int sts_init(const char *config);

/*
 * @brief       initialize sts security, authentication and key exchange.
 * @return      -1 if timer finishes, alarm(30).
 */
int sts_init_sec(void);

/*
 * @brief       free mbedtls context.
 */
void sts_free_sec(void);

/*
 * @brief       reset sts context, set all variables to 0.
 */
void sts_reset_ctx(void);

/*
 * @brief               send a message with no encryption.
 * @param str           message.
 * @return              -1 if fails to send message.
 */
int sts_send_nosec(char *str);

/*
 * @brief               send a message with encryption.
 * @param str           message.
 * @return              -1 if fails to send message.
 */
int sts_send_sec(char *str);

/*
 * @brief       retrieve context.
 */
struct sts_context *sts_get_ctx(void);

/*
 * @brief               extract sts header and data.
 * @param inc           incoming message.
 * @parem msg           sts message with extracted header and data.
 */
void sts_parse_msg(char *inc, struct sts_message *msg);

/*
 * @brief               handle incoming sts message regarding their types
 * @parem msg           sts message with extracted header and data.
 */
void sts_msg_handlers(struct sts_message *msg);

#endif /* STS_H */
