#include <pthread.h>

#include "log.h"
#include "mqtt.h"
#include "sec.h"

static unsigned char sendbuff[SENDBUFFSIZE];
static unsigned char readbuff[READBUFFSIZE];

static pthread_t _mqttyield_thrd_pid;

static void _mqtt_on_msg_recv(MessageData *data)
{
        struct sts_message msg;
        struct sts_context *ctx;

        memset(msg.header, 0, sizeof(msg.header));
        memset(msg.data, 0, sizeof(msg.data));

        ctx = sts_get_ctx();

        /* if nosec mode */
        if (strcmp(ctx->sts_mode, STS_NOSEC) == 0) {
                char *msg_inc = NULL;

                msg_inc = calloc((size_t)data->message->payloadlen + 
                                1, sizeof(char));
                memcpy(msg_inc, data->message->payload, 
                                data->message->payloadlen);
                sts_parse_msg(msg_inc, &msg);
                sts_msg_handlers(&msg);

                if (ctx->no_print_inc == 0) {
                        INFO("[MQTT_INC]: %s\n", msg.data);
                }

                ctx->no_print_inc = 0;
                ctx->msg_recv++;
                free(msg_inc);
        }

        /* if init_sec */
        if (ctx->encryption == 0 && ctx->status < STS_STEP_3 && (
                                strcmp(ctx->sts_mode, STS_SECMASTER) == 0 || 
                                strcmp(ctx->sts_mode, STS_SECSLAVE) == 0)) {
                char *msg_inc = NULL;
                msg_inc = calloc((size_t)data->message->payloadlen + 1, 
                                sizeof(char));
                memcpy(msg_inc, data->message->payload, 
                                data->message->payloadlen);

                sts_parse_msg(msg_inc, &msg);
                sts_msg_handlers(&msg);

                ctx->msg_recv++;
                free(msg_inc);
        }

        if (ctx->encryption == 1) {
                unsigned char *enc = NULL;
                unsigned char dec[STS_MSG_MAXLEN];
                size_t ecb_len;
                size_t cbc_len;
                int ret;
                enc = calloc((size_t)data->message->payloadlen, 
                                sizeof(unsigned char));
                memcpy(enc, data->message->payload, 
                                data->message->payloadlen);
                memset(dec, 0, sizeof(dec));

                if (strcmp(ctx->aes, AES_ECB) == 0) {
                        ecb_len = data->message->payloadlen;
                        ret = sts_decrypt_aes_ecb(&ctx->host_aes_ctx_dec, 
                                        enc, dec, ecb_len);
                        if (ret != 0) {
                                ERROR("sts: sts_decrypt_aes_ecb()\n");
                                ctx->msg_recv++;
                                free(enc);
                                return;
                        }
                }

                if (strcmp(ctx->aes, AES_CBC) == 0) {
                        cbc_len = data->message->payloadlen;
                        ret = sts_decrypt_aes_cbc(&ctx->host_aes_ctx_dec, 
                                        ctx->derived_key, enc, dec, cbc_len);
                        if (ret != 0) {
                                ERROR("sts: sts_decrypt_aes_cbc()\n");
                                ctx->msg_recv++;
                                free(enc);
                                return;
                        }
                }

                sts_parse_msg((char*)dec, &msg);
                sts_msg_handlers(&msg);

                if (ctx->no_print_inc == 0) {
                        INFO("[MQTT_INC]: %s\n", msg.data);
                }

                ctx->no_print_inc = 0;
                ctx->msg_recv++;
                free(enc);
        }
}

static void *_mqtt_yield(void *argv)
{
        (void)argv;
        int ret;
        struct sts_context *ctx;
        ctx = sts_get_ctx();

        while (1) {

                if (ctx->thrd_msg_type == STS_KILL_THREAD || 
                                ctx->client.isconnected == 0) {
                        INFO("sts: killing mqttyield thread...\n");
                        ctx->thrd_msg_type = 0;
                        ctx->status = STS_STOPPED;
                        return NULL;
                }

                if ((ret = MQTTYield(&ctx->client, 1000)) != 0) {
                        ERROR("sts: error while MQTTYield()(%d)\n", ret);
                        ctx->thrd_msg_type = STS_KILL_THREAD;
                }
        }
        return NULL;
}

void mqtt_init(void)
{
        struct sts_context *ctx;

        ctx = sts_get_ctx();

        NetworkInit(&ctx->network);
        MQTTClientInit(&ctx->client, &ctx->network, COMMAND_TIMEOUT_MS,
                        sendbuff, SENDBUFFSIZE, readbuff, READBUFFSIZE);
        INFO("sts: network and client initialized\n");
}

int mqtt_connect(void)
{
        int ret;
        struct sts_context *ctx;

        ctx = sts_get_ctx();

        /* setting conn params */
        MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
        data.MQTTVersion = MQTT_VERSION;
        data.clientID.cstring = ctx->clientid;

        /* keepalive not implemented */
        data.keepAliveInterval = 0;

        /* no persistent session */
        data.cleansession = 1;
        data.username.cstring = ctx->username;
        data.password.cstring = ctx->password;
        data.willFlag = 0;

        ret = NetworkConnect(&ctx->network, ctx->url, ctx->port);
        if (ret < 0) {
                ERROR("sts: could not connect to the network\n");
                return -1;
        }

        ret = MQTTConnect(&ctx->client, &data);

        if (ret < 0) {
                ERROR("sts: could not connect to broker\n");
                return -1;
        }
        INFO("sts: connected to broker %s\n", ctx->url);
        return 0;
}

int mqtt_disconnect(void)
{
        int ret;
        struct sts_context *ctx;

        ctx = sts_get_ctx();

        ret = MQTTDisconnect(&ctx->client);

        if (ret < 0) {
                ERROR("sts: couldn't disconnect client, "
                                "forcing network disconnection\n");
                NetworkDisconnect(&ctx->network);
                INFO("sts: disconnected from broker\n");
                return ret;
        }
        NetworkDisconnect(&ctx->network);
        INFO("sts: disconnected from broker\n");
        return 0;
}

int mqtt_subscribe(void)
{
        int ret;
        struct sts_context *ctx;

        ctx = sts_get_ctx();

        ret = MQTTSubscribe(&ctx->client, ctx->topic_sub, 0, 
                        _mqtt_on_msg_recv);
        if (ret < 0) {
                return -1;
        }

        /* start mqttyield thread to receive msg */
        _mqttyield_thrd_pid = pthread_create(&_mqttyield_thrd_pid, NULL, 
                        _mqtt_yield, NULL);
        INFO("sts: subscribed to topic %s\n", ctx->topic_sub);
        return 0;
}

int mqtt_unsubscribe(void)
{
        int ret;
        struct sts_context *ctx;

        ctx = sts_get_ctx();

        ret = MQTTUnsubscribe(&ctx->client, ctx->topic_pub);
        if (ret < 0) {
                return -1;
        }
        INFO("sts: unsubscribed from topic %s\n", ctx->topic_sub);
        return 0;
}

int mqtt_publish(char *string)
{
        int ret;
        struct sts_context *ctx;
        MQTTMessage msg;

        ctx = sts_get_ctx();

        if (strlen(string) > STS_MSG_MAXLEN) {
                ERROR("sts: publish failed, msg > %d\n", STS_MSG_MAXLEN);
                return -1;
        }

        /* if qos > 0, triggers seg fault */
        msg.qos = 0;
        msg.payload = (void*)string;
        msg.payloadlen = strlen(string);
        msg.retained = 0;

        ret = MQTTPublish(&ctx->client, ctx->topic_pub, &msg);

        if (ret < 0) {
                mqtt_disconnect();
                return -1;
        }

        /* echo */
        if (ctx->no_print_out == 0) {
                INFO("[MQTT_OUT]: %s\n", string);
        }
        ctx->no_print_out = 0;
        ctx->msg_sent++;
        return 0;
}

int mqtt_publish_aes_ecb(unsigned char *enc, size_t ecb_len)
{
        int ret;
        struct sts_context *ctx;
        MQTTMessage msg;

        ctx = sts_get_ctx();

        if (ecb_len > STS_MSG_MAXLEN) {
                ERROR("sts: mqtt_publish_aes_ecb, msg > %d\n", STS_MSG_MAXLEN);
                return -1;
        }

        msg.qos = 0;
        msg.payload = (void*)enc;

        /* 
         * we are not sending the size of the actual encrypted data but the size
         * of the original message aligned with ecb_blocksize (16) so if msg
         * was 17 bytes long, we will need 2 ecb blocks (32 bytes). ecb_len is
         * needed for the decrypt function 
         */
        msg.payloadlen = ecb_len;
        msg.retained = 0;

        ret = MQTTPublish(&ctx->client, ctx->topic_pub, &msg);

        if (ret < 0) {
                mqtt_disconnect();
                return -1;
        }

        /* echo */
        if (ctx->no_print_out == 0) {
                INFO("[MQTT_OUT]: %s\n", enc);
        }
        ctx->no_print_out = 0;
        ctx->msg_sent++;
        return 0;
}


int mqtt_publish_aes_cbc(unsigned char *enc, size_t cbc_len)
{
        int ret;
        struct sts_context *ctx;
        MQTTMessage msg;

        ctx = sts_get_ctx();

        if (cbc_len > STS_MSG_MAXLEN) {
                ERROR("sts: mqtt_publish_aes_cbc, msg > %d\n", STS_MSG_MAXLEN);
                return -1;
        }

        msg.qos = 0;
        msg.payload = (void*)enc;

        /* 
         * we are not sending the size of the actual encrypted data but the size
         * of the original message aligned with cbc_blocksize (16) so if msg
         * was 17 bytes long, we will need 2 cbc blocks (32 bytes). cbc_len is
         * needed for the decrypt function 
         */
        msg.payloadlen = cbc_len;
        msg.retained = 0;

        ret = MQTTPublish(&ctx->client, ctx->topic_pub, &msg);

        if (ret < 0) {
                mqtt_disconnect();
                return -1;
        }

        /* echo */
        if (ctx->no_print_out == 0) {
                INFO("[MQTT_OUT]: %s\n", enc);
        }
        ctx->no_print_out = 0;
        ctx->msg_sent++;
        return 0;
}
