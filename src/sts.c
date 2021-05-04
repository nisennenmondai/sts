#include <pthread.h>

#include "sts.h"
#include "log.h"
#include "tools.h"

////////////////////////////////////////////////////////////////////////////////
/* VARIABLES */
////////////////////////////////////////////////////////////////////////////////
static struct sts_context ctx = {
        .mqtt_version   = 0,
        .port           = 0,
        .no_print       = 0,
        .msg_sent       = 0,
        .msg_recv       = 0,
        .thrd_msg_type  = 0,
        .encryption     = 0,
        .kill_flag      = 0,
        .status         = STS_STOPPED,
        .master_flag    = STS_STEP_0,
        .slave_flag     = STS_STEP_0,
};

static unsigned char sendbuff[SENDBUFFSIZE];
static unsigned char readbuff[READBUFFSIZE];

static pthread_t _mqttyield_thrd_pid;

////////////////////////////////////////////////////////////////////////////////
/* STS */
////////////////////////////////////////////////////////////////////////////////

static void _extract_pubkey(char *X, char *Y, struct sts_message *msg)
{
        int i;
        int idx_X = 0;
        int idx_Y = 0;

        /* extract slave public key X */
        for (i = 0; i < STS_DATASIZE; i++) {
                if (msg->data[i] == 'Y') {
                        idx_X = idx_X - 1;
                        break;
                }
                idx_X++;
        }
        memcpy(X, &msg->data[1], idx_X * sizeof(char));

        /* extract slave public key Y */
        for (i = idx_X + 2; i < STS_DATASIZE; i++) {
                if (msg->data[i] == '\0') {
                        idx_Y = idx_Y + 1;
                        break;
                }
                idx_Y++;
        }
        memcpy(Y, &msg->data[idx_X + 2], idx_Y * sizeof(char));
}

static void _parse_msg(char *inc, struct sts_message *msg)
{
        size_t i;
        int idx = 0;

        /* extract header */
        for (i = 0; i < STS_HEADERSIZE; i++) {
                msg->header[i] = inc[i];
                if (msg->header[i] == ':') {
                        idx = i + 1;
                        break;
                }
        }

        /* extract data */
        for (i = 0; i < STS_DATASIZE; i++) {
                if (inc[idx + i] != '\0') {
                        msg->data[i] = inc[idx + i];
                } 
                if (inc[idx + i] == '\0') {
                        break;
                }
        }
}

static int _compute_shared_secret(char *master_QX, char *master_QY)
{
        int ret;
        size_t olen;
        ret = mbedtls_ecp_point_read_string(
                        &ctx.host_ecdh_ctx.Qp, 16,
                        master_QX, master_QY);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecp_point_read_string()\n");
                return -1;
        }

        memset(ctx.derived_key, 0, sizeof(ctx.derived_key));
        ret = mbedtls_ecdh_calc_secret(&ctx.host_ecdh_ctx, 
                        &olen, ctx.derived_key, 
                        sizeof(ctx.derived_key), 
                        sts_drbg, NULL);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecdh_calc_secret()\n");
                return -1;
        }

        /* 
         * TODO sometimes derived_key is not 256 bits long, I don't know why 
         * we need to verify it 
         */
        ret = sts_verify_keylen(ctx.derived_key, sizeof(ctx.derived_key), 
                        ECDH_KEYSIZE_BITS);
        if (ret != 0) {
                WARN("sts: derived key != %d bits in length (only %d bits), "
                                "something went wrong, start a new session\n", 
                                ECDH_KEYSIZE_BITS, ret);
                return -1;
        }

        ret = mbedtls_aes_setkey_enc(&ctx.host_aes_ctx_enc, ctx.derived_key,
                        ECDH_KEYSIZE_BITS);
        if (ret != 0) {
                ERROR("sts: mbedtls_aes_setkey_enc()\n");
                return -1;
        }

        ret = mbedtls_aes_setkey_dec(&ctx.host_aes_ctx_dec, ctx.derived_key,
                        ECDH_KEYSIZE_BITS);
        if (ret != 0) {
                ERROR("sts: mbedtls_aes_setkey_dec()\n");
                return -1;
        }
        return 0;
}

static void _extract_ids(struct sts_message *msg)
{
        int i;
        int idx;
        for (i = 0; i < ID_SIZE - 1; i++) {
                ctx.id_master[i] = msg->data[i];
        }

        idx = ID_SIZE - 1;
        for (i = 0; i < ID_SIZE + 1; i++) {
                ctx.id_slave[i] = msg->data[idx];
                idx++;
        }
}

static void _msg_handlers(struct sts_message *msg)
{
        int ret;

        /* SLAVE SIDE */
        if (strcmp(ctx.sts_mode, STS_SECSLAVE) == 0) {
                /* receive KILL from master */
                if (strcmp(msg->header, STS_KILL) == 0 && ctx.encryption == 1) {
                        ctx.kill_flag = 1;
                        INFO("sts: Received KILL from master\n");
                        kill(ctx.pid, SIGUSR1);
                }

                /* receive INIT from master */
                if (strcmp(msg->header, STS_INIT) == 0 && 
                                ctx.slave_flag == STS_STEP_0) {
                        TRACE("sts: Received INIT from master\n");
                        _extract_ids(msg);
                        ctx.slave_flag = STS_STEP_1;
                        return;
                }

                /* receive AUTHREQ from master*/
                if (strcmp(msg->header, STS_AUTHREQ) == 0 && 
                                ctx.slave_flag == STS_STEP_1) {
                        TRACE("sts: Received AUTHREQ from master\n");
                        if (strcmp(msg->data, ctx.id_slave) == 0) {
                                INFO("sts: Authentication SUCCESS\n");
                                ctx.slave_flag = STS_STEP_2;
                                return;

                        } else {
                                ERROR("sts: Authentication FAILURE! master "
                                                "sent wrong ID\n");
                                return;
                        }
                }

                /* receive AUTHACK from master */
                if (strcmp(msg->header, STS_AUTHACK) == 0 && 
                                ctx.slave_flag == STS_STEP_2 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Received AUTHACK from master\n");
                        ctx.slave_flag = STS_STEP_3;
                        return;
                }

                /* receive RDYREQ from master */
                if (strcmp(msg->header, STS_RDYREQ) == 0 && 
                                ctx.slave_flag == STS_STEP_3) {
                        char master_QX[MPI_STRING_SIZE];
                        char master_QY[MPI_STRING_SIZE];

                        memset(master_QX, 0, sizeof(master_QX));
                        memset(master_QY, 0, sizeof(master_QY));

                        _extract_pubkey(master_QX, master_QY, msg);
                        ret = _compute_shared_secret(master_QX, master_QY);
                        if (ret != 0) {
                                ERROR("sts: _sts_compute_shared_secret()\n");
                                return;
                        }

                        TRACE("sts: Received RDYREQ from master\n");
                        ctx.slave_flag = STS_STEP_4;
                        return;
                }

                /* receive RDYACK from master */
                if (strcmp(msg->header, STS_RDYACK) == 0 && 
                                ctx.slave_flag == STS_STEP_4 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Received RDYACK from master\n");
                        ctx.slave_flag = STS_STEP_5;
                        return;
                }
        }

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, STS_SECMASTER) == 0) {
                /* receive KILL from slave */
                if (strcmp(msg->header, STS_KILL) == 0 && ctx.encryption == 1) {
                        ctx.kill_flag = 1;
                        INFO("sts: Received KILL from slave\n");
                        kill(ctx.pid, SIGUSR1);
                        return;
                }

                /* receive INITACK from slave */
                if (strcmp(msg->header, STS_INITACK) == 0 && 
                                ctx.master_flag == STS_STEP_0 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Receive INITACK from slave\n");
                        ctx.master_flag = STS_STEP_1;
                        return;
                }

                /* receive AUTHACK from slave */
                if (strcmp(msg->header, STS_AUTHACK) == 0 && 
                                ctx.master_flag == STS_STEP_1 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Received AUTHACK from slave\n");
                        ctx.master_flag = STS_STEP_2;
                        return;
                }

                /* receive AUTHREQ from slave */
                if (strcmp(msg->header, STS_AUTHREQ) == 0 && 
                                ctx.master_flag == STS_STEP_2) {
                        TRACE("sts: Received AUTHREQ from slave\n");
                        if (strcmp(msg->data, ctx.id_master) == 0) {
                                INFO("sts: Authentication SUCCESS\n");
                                ctx.master_flag = STS_STEP_3;
                                return;

                        } else {
                                ERROR("sts: Authentication FAILURE! slave "
                                                "sent wrong ID\n");
                                return;
                        }
                }

                /* receive RDYACK from slave */
                if (strcmp(msg->header, STS_RDYACK) == 0 && 
                                ctx.master_flag == STS_STEP_3 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Received RDYACK from slave\n");
                        ctx.master_flag = STS_STEP_4;
                        return;
                }

                /* receive RDYREQ from slave */
                if (strcmp(msg->header, STS_RDYREQ) == 0 && 
                                ctx.master_flag == STS_STEP_4) {
                        char slave_QX[MPI_STRING_SIZE];
                        char slave_QY[MPI_STRING_SIZE];

                        memset(slave_QX, 0, sizeof(slave_QX));
                        memset(slave_QY, 0, sizeof(slave_QY));

                        _extract_pubkey(slave_QX, slave_QY, msg);
                        ret = _compute_shared_secret(slave_QX, slave_QY);
                        if (ret != 0) {
                                ERROR("sts: _sts_compute_shared_secret()\n");
                                return;
                        }

                        TRACE("sts: Received RDYREQ from slave\n");
                        ctx.master_flag = STS_STEP_5;
                        return;
                }
        }
}

int sts_load_config(const char *config)
{
        FILE *fp;

        fp = fopen(config, "r");
        if (fp == NULL)
        {
                ERROR("sts: while opening config file -> start [FILE]\n");
                return -1;
        }

        char key[CONF_KEY_MAXLEN] = {0};
        char cmp[2] = {0};
        char value[CONF_VAL_MAXLEN] = {0};

        while (fscanf(fp, "%s %s %s ", key, cmp, value) != EOF) {
                if (strcmp(key, "mqtt_version") == 0) {
                        ctx.mqtt_version = atoi(value);
                } else if (strcmp(key, "ip") == 0) {
                        strcpy(ctx.ip, value);
                } else if (strcmp(key, "port") == 0) {
                        ctx.port = atoi(value);
                } else if (strcmp(key, "username") == 0) {
                        strcpy(ctx.username, value);
                } else if (strcmp(key, "password") == 0) {
                        strcpy(ctx.password, value);
                } else if (strcmp(key, "subtop") == 0) {
                        strcpy(ctx.topic_sub, value);
                } else if (strcmp(key, "pubtop") == 0) {
                        strcpy(ctx.topic_pub, value);
                } else if (strcmp(key, "clientid") == 0) {
                        strcpy(ctx.clientid, value);
                } else if (strcmp(key, "sts_mode") == 0) {
                        /* if nosec mode then aes = null */
                        if (strcmp(value,STS_NOSEC) == 0) {
                                strcpy(ctx.sts_mode, value);
                                strcpy(ctx.aes, AES_NULL);
                                fclose(fp);
                                config = NULL;
                                return 0;

                        } else if (strcmp(value, STS_SECMASTER) == 0) {
                                strcpy(ctx.sts_mode, value);
                        } else if (strcmp(value, STS_SECSLAVE) == 0) {
                                strcpy(ctx.sts_mode, value);
                        } else {
                                ERROR("sts: wrong value for sts_mode "
                                                "nosec | master | slave\n");
                                fclose(fp);
                                config = NULL;
                                return -1;
                        }

                } else if (strcmp(key, "aes") == 0) {
                        if (strcmp(value, AES_NULL) == 0) {
                                strcpy(ctx.aes, value);
                        } else if (strcmp(value, AES_ECB) == 0) {
                                strcpy(ctx.aes, value);
                        } else if (strcmp(value, AES_CBC) == 0) {
                                strcpy(ctx.aes, value);
                        } else {
                                ERROR("sts: wrong value for aes "
                                                "null | ecb | cbc\n");
                                fclose(fp);
                                config = NULL;
                                return -1;
                        }

                } else {
                        ERROR("sts: wrong key(s) in config file, please "
                                        "check 'config_' examples\n");
                        fclose(fp);
                        config = NULL;
                        return -1;
                }
        }
        fclose(fp);
        config = NULL;
        return 0;
}

int sts_init(const char *config)
{
        int ret;

        sts_reset_ctx();
        ret = sts_load_config(config);
        if (ret < 0) {
                return -1;
        }

        mqtt_init();
        return 0;
}

void sts_reset_ctx(void)
{
        ctx.mqtt_version  = 0;
        ctx.port          = 0;
        ctx.no_print      = 0;
        ctx.msg_sent      = 0;
        ctx.msg_recv      = 0;
        ctx.thrd_msg_type = 0;
        ctx.encryption    = 0;
        ctx.kill_flag     = 0;
        ctx.status        = STS_STOPPED;
        ctx.master_flag   = STS_STEP_0;
        ctx.slave_flag    = STS_STEP_0;
        memset(ctx.derived_key, 0, sizeof(ctx.derived_key));
        memset(ctx.topic_sub,   0, sizeof(ctx.topic_sub));
        memset(ctx.topic_pub,   0, sizeof(ctx.topic_pub));
        memset(ctx.clientid,    0, sizeof(ctx.clientid));
        memset(ctx.username,    0, sizeof(ctx.username));
        memset(ctx.password,    0, sizeof(ctx.password));
        memset(ctx.id_master,   0, sizeof(ctx.id_master));
        memset(ctx.id_slave,    0, sizeof(ctx.id_slave));
        memset(ctx.sts_mode,    0, sizeof(ctx.sts_mode));
        memset(ctx.aes,         0, sizeof(ctx.aes));
        memset(ctx.ip,          0, sizeof(ctx.ip));
}

struct sts_context *sts_get_ctx(void)
{
        return &ctx;
}

////////////////////////////////////////////////////////////////////////////////
/* MQTT */
////////////////////////////////////////////////////////////////////////////////
static void _mqtt_on_msg_recv(MessageData *data)
{
        struct sts_message msg;
        memset(msg.header, 0, sizeof(msg.header));
        memset(msg.data, 0, sizeof(msg.data));

        /* if nosec mode */
        if (strcmp(ctx.sts_mode, STS_NOSEC) == 0) {
                char *msg_inc = NULL;
                msg_inc = calloc((size_t)data->message->payloadlen + 1, 
                                sizeof(char));
                memcpy(msg_inc, data->message->payload, 
                                data->message->payloadlen);
                _parse_msg(msg_inc, &msg);
                _msg_handlers(&msg);

                INFO("[MQTT_INC]: %s\n", msg.data);
                ctx.msg_recv++;
                free(msg_inc);
        }

        /* if init_sec */
        if (ctx.encryption == 0 && ctx.status < STS_STEP_5 && (
                                strcmp(ctx.sts_mode, STS_SECMASTER) == 0 || 
                                strcmp(ctx.sts_mode, STS_SECSLAVE) == 0)) {
                char *msg_inc = NULL;
                sts_decode((unsigned char*)data->message->payload, 
                                STS_MSG_MAXLEN);
                msg_inc = calloc((size_t)data->message->payloadlen + 1, 
                                sizeof(char));
                memcpy(msg_inc, data->message->payload, 
                                data->message->payloadlen);

                _parse_msg(msg_inc, &msg);
                _msg_handlers(&msg);

                ctx.msg_recv++;
                free(msg_inc);
        }

        if (ctx.encryption == 1) {
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

                if (strcmp(ctx.aes, AES_ECB) == 0) {
                        ecb_len = data->message->payloadlen;
                        ret = sts_decrypt_aes_ecb(&ctx.host_aes_ctx_dec, 
                                        enc, dec, ecb_len);
                        if (ret != 0) {
                                ERROR("sts: sts_decrypt_aes_ecb()\n");
                                ctx.msg_recv++;
                                free(enc);
                                return;
                        }
                }

                if (strcmp(ctx.aes, AES_CBC) == 0) {
                        cbc_len = data->message->payloadlen;
                        ret = sts_decrypt_aes_cbc(&ctx.host_aes_ctx_dec, 
                                        ctx.derived_key, enc, dec, cbc_len);
                        if (ret != 0) {
                                ERROR("sts: sts_decrypt_aes_cbc()\n");
                                ctx.msg_recv++;
                                free(enc);
                                return;
                        }
                }

                _parse_msg((char*)dec, &msg);
                _msg_handlers(&msg);

                INFO("[MQTT_INC]: %s\n", msg.data );
                ctx.msg_recv++;
                free(enc);
        }
}

static void *_mqtt_yield(void *argv)
{
        (void)argv;
        int ret;

        while (1) {
                if (ctx.thrd_msg_type == STS_KILL_THREAD || 
                                ctx.client.isconnected == 0) {
                        INFO("sts: killing mqttyield thread...\n");
                        ctx.thrd_msg_type = 0;
                        ctx.status = STS_STOPPED;
                        return NULL;
                }
                if ((ret = MQTTYield(&ctx.client, 1000)) != 0) {
                        ERROR("sts: error while MQTTYield()(%d)\n", ret);
                        ctx.thrd_msg_type = STS_KILL_THREAD;
                }
        }
        return NULL;
}

void mqtt_init(void)
{
        NetworkInit(&ctx.network);
        MQTTClientInit(&ctx.client, &ctx.network, COMMAND_TIMEOUT_MS,
                        sendbuff, SENDBUFFSIZE, readbuff, READBUFFSIZE);
        INFO("sts: network and client initialized\n");
}

int mqtt_connect(void)
{
        int ret;

        /* setting conn params */
        MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
        data.MQTTVersion = ctx.mqtt_version;
        data.clientID.cstring = ctx.clientid;
        /* keepalive not implemented */
        data.keepAliveInterval = 0;
        /* no persistent session */
        data.cleansession = 1;
        data.username.cstring = ctx.username;
        data.password.cstring = ctx.password;
        data.willFlag = 0;

        ret = NetworkConnect(&ctx.network, ctx.ip, ctx.port);
        if (ret < 0) {
                ERROR("sts: could not connect to the network\n");
                return -1;
        }

        ret = MQTTConnect(&ctx.client, &data);
        if (ret < 0) {
                ERROR("sts: could not connect to broker\n");
                return -1;
        }
        INFO("sts: connected to broker %s\n", ctx.ip);
        return 0;
}

int mqtt_disconnect(void)
{
        int ret;

        ret = MQTTDisconnect(&ctx.client);
        if (ret < 0) {
                ERROR("sts: couldn't disconnect client, "
                                "forcing network disconnection\n");
                NetworkDisconnect(&ctx.network);
                INFO("sts: disconnected from broker\n");
                return ret;
        }
        NetworkDisconnect(&ctx.network);
        INFO("sts: disconnected from broker\n");
        return 0;
}

int mqtt_subscribe(void)
{
        int ret;

        ret = MQTTSubscribe(&ctx.client, ctx.topic_sub, 0, 
                        _mqtt_on_msg_recv);
        if (ret < 0) {
                return -1;
        }
        /* start mqttyield thread to receive msg */
        _mqttyield_thrd_pid = pthread_create(&_mqttyield_thrd_pid, NULL, 
                        _mqtt_yield, NULL);
        INFO("sts: subscribed to topic %s\n", ctx.topic_sub);
        return 0;
}

int mqtt_unsubscribe(void)
{
        int ret;

        ret = MQTTUnsubscribe(&ctx.client, ctx.topic_pub);
        if (ret < 0) {
                return -1;
        }
        INFO("sts: unsubscribed from topic %s\n", ctx.topic_sub);
        return 0;
}

int mqtt_publish(char *string)
{
        int ret;
        MQTTMessage msg;

        if (strlen(string) > STS_MSG_MAXLEN) {
                ERROR("sts: publish failed, msg > %d\n", STS_MSG_MAXLEN);
                return -1;
        }
        /* TODO if qos > 0, triggers seg fault */
        msg.qos = 0;
        msg.payload = (void*)string;
        msg.payloadlen = strlen(string);
        msg.retained = 0;

        ret = MQTTPublish(&ctx.client, ctx.topic_pub, &msg);
        if (ret < 0) {
                mqtt_disconnect();
                return -1;
        }

        /* echo */
        if (ctx.no_print == 0) {
                INFO("[MQTTOUT]: %s\n", string);
        }
        ctx.no_print = 0;
        ctx.msg_sent++;
        return 0;
}

int mqtt_publish_aes_ecb(unsigned char *enc, size_t ecb_len)
{
        int ret;
        MQTTMessage msg;

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

        ret = MQTTPublish(&ctx.client, ctx.topic_pub, &msg);
        if (ret < 0) {
                mqtt_disconnect();
                return -1;
        }

        /* echo */
        if (ctx.no_print == 0) {
                INFO("[MQTTOUT]: %s\n", enc);
        }
        ctx.no_print = 0;
        ctx.msg_sent++;
        return 0;
}


int mqtt_publish_aes_cbc(unsigned char *enc, size_t cbc_len)
{
        int ret;
        MQTTMessage msg;

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

        ret = MQTTPublish(&ctx.client, ctx.topic_pub, &msg);
        if (ret < 0) {
                mqtt_disconnect();
                return -1;
        }

        /* echo */
        if (ctx.no_print == 0) {
                INFO("[MQTTOUT]: %s\n", enc);
        }
        ctx.no_print = 0;
        ctx.msg_sent++;
        return 0;
}

////////////////////////////////////////////////////////////////////////////////
/* STS SECURITY */
////////////////////////////////////////////////////////////////////////////////
int sts_init_sec(void)
{
        int ret;
        size_t olen = 0;
        char msg_out[STS_MSG_MAXLEN];
        char slave_QX[MPI_STRING_SIZE];
        char slave_QY[MPI_STRING_SIZE];
        char master_QX[MPI_STRING_SIZE];
        char master_QY[MPI_STRING_SIZE];
        unsigned char id_master[ID_SIZE];
        unsigned char id_slave[ID_SIZE];

        /* generate ids on master side */
        if (strcmp(ctx.sts_mode, STS_SECMASTER) == 0) {
                memset(id_master, 0, sizeof(id_master));
                memset(id_slave, 0, sizeof(id_slave));

                genrand_str(id_master, ID_SIZE);
                genrand_str(id_slave, ID_SIZE);

                memcpy(ctx.id_master, id_master, sizeof(id_master));
                memcpy(ctx.id_slave, id_slave, sizeof(id_slave));
        }

        ctx.master_flag = STS_STEP_0;
        ctx.slave_flag = STS_STEP_0;

        memset(msg_out, 0, sizeof(msg_out));
        memset(slave_QX, 0, sizeof(slave_QX));
        memset(slave_QY, 0, sizeof(slave_QY));
        memset(master_QX, 0, sizeof(master_QX));
        memset(master_QY, 0, sizeof(master_QY));

        mbedtls_aes_init(&ctx.host_aes_ctx_dec);
        mbedtls_aes_init(&ctx.host_aes_ctx_enc);
        mbedtls_ecdh_init(&ctx.host_ecdh_ctx);

        ret = mbedtls_ecdh_setup(&ctx.host_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecdh_setup()\n");
                return -1;
        }
        ret = mbedtls_ecdh_gen_public(&ctx.host_ecdh_ctx.grp, 
                        &ctx.host_ecdh_ctx.d, &ctx.host_ecdh_ctx.Q, 
                        sts_drbg, NULL);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecdh_gen_public()\n");
                return -1;
        }

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, STS_SECMASTER) == 0) {
                /* send INIT to slave */
                TRACE("sts: Sending INIT to slave\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, "INIT:");
                concatenate(msg_out, (char*)id_master);
                concatenate(msg_out, (char*)id_slave);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait INITACK from slave */
                TRACE("sts: Waiting INITACK from slave\n");
                while (ctx.master_flag == STS_STEP_0) {};


                /* send AUTHREQ to slave */
                TRACE("sts: Sending AUTHREQ to slave\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_AUTHREQ);
                concatenate(msg_out, ctx.id_slave);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait AUTHACK from slave */
                TRACE("sts: Waiting AUTHACK from slave\n");
                while (ctx.master_flag == STS_STEP_1) {};

                /* wait AUTHREQ from slave */
                TRACE("sts: Waiting AUTHREQ from slave\n");
                while (ctx.master_flag == STS_STEP_2) {};

                /* send AUTHACK to slave */
                TRACE("sts: Sending AUTHACK to slave...\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_AUTHACK);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* send RDYREQ to slave */
                TRACE("sts: Sending RDYREQ to slave...\n");
                memset(msg_out, 0, sizeof(msg_out));
                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.X, 16, 
                                master_QX, MPI_STRING_SIZE, &olen);
                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }
                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.Y, 16, 
                                master_QY, MPI_STRING_SIZE, &olen);
                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }
                concatenate(msg_out, STS_RDYREQ);
                concatenate(msg_out, "X");
                concatenate(msg_out, master_QX);
                concatenate(msg_out, "Y");
                concatenate(msg_out, master_QY);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait RDYACK from slave */
                TRACE("sts: Waiting RDYACK from slave\n");
                while (ctx.master_flag == STS_STEP_3) {};

                /* wait RDYREQ from slave */
                TRACE("sts: Waiting RDYREQ from slave\n");
                while (ctx.master_flag == STS_STEP_4) {};

                /* send RDYACK to slave */
                TRACE("sts: Sending RDYACK to slave\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_RDYACK);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                ctx.encryption = 1;
                INFO("sts: Encryption established with slave\n");
                return 0;
        }

        /* SLAVE SIDE */
        if (strcmp(ctx.sts_mode, STS_SECSLAVE) == 0) {
                /* wait INIT from master */
                TRACE("sts: Waiting INIT from master\n");
                while (ctx.slave_flag == STS_STEP_0) {};

                /* send INITACK to master */
                TRACE("sts: Sending INITACK to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_INITACK);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait AUTHREQ from master */
                TRACE("sts: Waiting AUTHREQ from master\n");
                while (ctx.slave_flag == STS_STEP_1) {};

                /* send AUTHACK to master */
                TRACE("sts: Sending AUTHACK to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_AUTHACK);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* send AUTHREQ to master */
                TRACE("sts: Sending AUTHREQ to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_AUTHREQ);
                concatenate(msg_out, ctx.id_master);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait AUTHACK from master */
                TRACE("sts: Waiting AUTHACK from master\n");
                while (ctx.slave_flag == STS_STEP_2) {};

                /* wait RDYREQ from master */
                TRACE("sts: Waiting RDYREQ from master\n");
                while (ctx.slave_flag == STS_STEP_3) {};

                /* send RDYACK to master */
                TRACE("sts: Sending RDYACK to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_RDYACK);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* send RDYREQ */
                TRACE("sts: Sending RDYREQ to master\n");
                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.X, 16, 
                                slave_QX, MPI_STRING_SIZE, &olen);
                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }
                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.Y, 16, 
                                slave_QY, MPI_STRING_SIZE, &olen);
                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_RDYREQ);
                concatenate(msg_out, "X");
                concatenate(msg_out, slave_QX);
                concatenate(msg_out, "Y");
                concatenate(msg_out, slave_QY);
                sts_encode((unsigned char*)msg_out, STS_MSG_MAXLEN);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait RDYACK from master */
                TRACE("sts: Waiting RDYACK from master\n");
                while (ctx.slave_flag == STS_STEP_4) {};

                /* wait for master to finish */
                sleep(1);
                ctx.encryption = 1;
                INFO("sts: Encryption established with master\n");
                return 0;
        }
        return 0;
}

void sts_free_sec(void)
{
        mbedtls_aes_free(&ctx.host_aes_ctx_enc);
        mbedtls_aes_free(&ctx.host_aes_ctx_dec);
        mbedtls_ecdh_free(&ctx.host_ecdh_ctx);
}
