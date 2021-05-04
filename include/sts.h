#ifndef STS_H
#define STS_H

#include "MQTTLinux.h"
#include "MQTTClient.h"
#include "ecdh.h"
#include "aes.h"

/* init mqtt */
#define READBUFFSIZE       1024
#define SENDBUFFSIZE       1024
#define COMMAND_TIMEOUT_MS 10000

/* config file */
#define CONF_KEY_MAXLEN 16
#define CONF_VAL_MAXLEN 128

/* shell */
#define STS_TOK_BUFFSIZE 64
#define STS_RL_BUFFSIZE  1024
#define STS_TOK_DELIM    " \t\r\n\a"

/* sec */
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

/* return code */
#define STS_EXIT   0
#define STS_PROMPT 1

/* status */
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
 * @no_print            flag, if set to 1, published msg won't be displayed.
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
        unsigned short no_print;
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
        char ip[16];
        Network network;
        MQTTClient client;
        mbedtls_aes_context host_aes_ctx_enc;
        mbedtls_aes_context host_aes_ctx_dec;
        mbedtls_ecdh_context host_ecdh_ctx;
};

/*
 * @brief       initialize network.
 */
void mqtt_init(void);

/*
 * @brief       connect to a mqtt broker.
 * @return      -1 if connection fails.
 */
int mqtt_connect(void);

/*
 * @brief       disconnect from a mqtt broker.
 * @return      -1 if disconnection fails.
 */
int mqtt_disconnect(void);

/*
 * @brief       subscribe to a topic.
 * @return      -1 if subscription fails.
 */
int mqtt_subscribe(void);

/*
 * @brief       unsubscribe from a topic.
 * @return      -1 if unsubscription fails.
 */
int mqtt_unsubscribe(void);

/*
 * @brief               publish to a topic.
 * @param string        message to publish.
 * @return              -1 if publish fails.
 */
int mqtt_publish(char *string);

/*
 * @brief               publish to a topic with aes-ecb mode
 * @param enc           encrypted data.
 * @param ecb_len       encrypted data length aligned with ecb blocksize.
 * @return              -1 if publish fails.
 */
int mqtt_publish_aes_ecb(unsigned char *enc, size_t ecb_len);

/*
 * @brief               publish to a topic with aes-cbc mode
 * @param enc           encrypted data.
 * @param cbc_len       encrypted data length aligned with cbc blocksize.
 * @return              -1 if publish fails.
 */
int mqtt_publish_aes_cbc(unsigned char *enc, size_t cbc_len);

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
 * @brief       retrieve context.
 */
struct sts_context *sts_get_ctx(void);

/*
 * @brief               start a sts session.
 * @param argv          path to config file entered in shell.
 * @return              STS_PROMPT.
 */
int sts_start_session(char **argv);

/*
 * @brief               stop a sts session.
 * @param argv          null.
 * @return              STS_PROMPT.
 */
int sts_stop_session(char **argv);

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
 * @brief               print help in shell.
 * @param argv          null.
 * @return              STS_PROMPT
 */
int sts_help(char **argv);

/*
 * @brief               exit shell.
 * @param argv          null.
 * @return              STS_EXIT.
 */
int sts_exit(char **argv);

/*
 * @brief               print sts status in shell.
 * @param argv          null.
 * @return              STS_PROMPT.
 */
int sts_status(char **argv);

/*
 * @brief               test to send a message with no encryption.
 * @param argv          message.
 * @return              STS_PROMPT.
 */
int sts_test_send_nosec(char **argv);

/*
 * @brief               test to send a message with encryption.
 * @param argv          message.
 * @return              STS_PROMPT.
 */
int sts_test_send_sec(char **argv);

/*
 * @brief               encrypt data using aes-ecb block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param input         data to be encrypted.
 * @param ouput         encrypted data.
 * @param size          size of data to be encrypted.
 * @param ecb_len       size of encrypted data aligned with ecb block.
 * @return              != 0 if encryption fails.
 */
int sts_encrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t size, size_t *ecb_len);

/*
 * @brief               decrypt data using aes-ecb block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param input         encrypted data.
 * @param ouput         decrypted data.
 * @param ecb_len       size of encrypted data aligned with ecb block.
 * @return              != 0 if decryption fails.
 */
int sts_decrypt_aes_ecb(mbedtls_aes_context *ctx, unsigned char *input, 
                unsigned char *output, size_t ecb_len);

/*
 * @brief               encrypt data using aes-cbc block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param iv            cbc initialization vector, should be random value, in
 *                      our case derived_key is used.
 * @param input         data to be encrypted.
 * @param ouput         decrypted data.
 * @param cbc_len       size of encrypted data aligned with cbc block.
 * @return              != 0 if encryption fails.
 */
int sts_encrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, 
                size_t size, size_t *cbc_len);

/*
 * @brief               decrypt data using aes-cbc block cipher mode.
 * @param ctx           mbedtls aes context.
 * @param iv            cbc initialization vector, should be random value, in
 *                      our case derived_key is used.
 * @param input         encrypted data.
 * @param ouput         decrypted data.
 * @param cbc_len       size of encrypted data aligned with cbc block.
 * @return              != 0 if encryption fails.
 */
int sts_decrypt_aes_cbc(mbedtls_aes_context *ctx, unsigned char *iv, 
                unsigned char *input, unsigned char *output, size_t cbc_len);

/*
 * @brief               generate a random number for key generation.
 * @param rng_state     this callback isn't used.
 * @param ouput         random gen.
 * @param len           length of output.
 * @return              != 0 if genrand fails.
 */
int sts_drbg(void *rng_state, unsigned char *output, size_t len);

/*
 * @brief               verify the length of derived_ley.
 * @param buf           derived key.
 * @param size          size of derived_key.
 * @param len           reference length we want to verify (256).
 * @return              != 0 if length of derived_ley is not equal to len.
 */
int sts_verify_keylen(const unsigned char *key, size_t size, size_t len);

/*
 * @brief               encode data.
 * @param data          data to be encoded.
 * @param size          size of data.
 */
void sts_encode(unsigned char *data, size_t size);

/*
 * @brief               decode data.
 * @param data          data to be decoded.
 * @param size          size of data.
 */
void sts_decode(unsigned char *data, size_t size);

#endif /* STS_H */
