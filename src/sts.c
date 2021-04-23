#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>

#include "sts.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
/* VARIABLES */
////////////////////////////////////////////////////////////////////////////////
static struct sts_context ctx = {
        .status      = STS_STOPPED,
        .master_flag = STS_STEP_0,
        .slave_flag  = STS_STEP_0,
        .encryption  = 0,
};

static unsigned char sendbuff[SENDBUFFSIZE];
static unsigned char readbuff[READBUFFSIZE];

static pthread_t _mqttyield_thrd_pid;

////////////////////////////////////////////////////////////////////////////////
/* TOOLS */
////////////////////////////////////////////////////////////////////////////////
void sts_concatenate(char p[], char q[])
{
        int c = 0;
        int d = 0;

        while (p[c] != '\0') {
                c++;
        }

        while (q[d] != '\0') {
                p[c] = q[d];
                d++;
                c++;
        }
        p[c] = '\0';
}

////////////////////////////////////////////////////////////////////////////////
/* STS */
////////////////////////////////////////////////////////////////////////////////
static void _sts_extract_pubkey(char *X, char *Y, struct sts_message *msg)
{
        int i;
        int idx_X = 0;
        int idx_Y = 0;

        /* extract slave public key X */
        for (i = 0; i < STS_MSG_MAXLEN; i++) {
                if (msg->data[i] == 'Y') {
                        idx_X = idx_X - 1;
                        break;
                }
                idx_X++;
        }
        memcpy(X, &msg->data[1], idx_X * sizeof(char));

        /* extract slave public key Y */
        for (i = idx_X + 2; i < STS_MSG_MAXLEN; i++) {
                if (msg->data[i] == '\0') {
                        idx_Y = idx_Y + 1;
                        break;
                }
                idx_Y++;
        }
        memcpy(Y, &msg->data[idx_X + 2], idx_Y * sizeof(char));
}

static void _sts_parse_msg(char *inc, struct sts_message *msg)
{
        size_t i;
        int idx = 0;

        /* extract header */
        for (i = 0; i < sizeof(msg->header); i++) {
                msg->header[i] = inc[i];
                if (msg->header[i] == ':') {
                        idx = i + 1;
                        break;
                }
        }

        /* extract data */
        for (i = 0; i < STS_MSG_MAXLEN; i++) {
                if (inc[idx + i] != '\0') {
                        msg->data[i] = inc[idx + i];
                } 
                if (inc[idx + i] == '\0') {
                        break;
                }
        }
}

static int _sts_compute_shared_secret(char *master_QX, char *master_QY)
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
                        sts_genrand, NULL);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecp_point_read_string()\n");
                return -1;
        }
        ret = sts_verify_derived_keylen(ctx.derived_key, 
                        sizeof(ctx.derived_key), 256);
        if (ret != 0) {
                ERROR("sts: sts_verify_derived_keylen()\n");
                return -1;
        }

        ret = mbedtls_aes_setkey_enc(&ctx.host_aes_ctx_enc, ctx.derived_key,
                        ECDH_SHARED_KEYSIZE_BITS);
        if (ret != 0) {
                ERROR("sts: mbedtls_aes_setkey_enc()\n");
                return -1;
        }

        ret = mbedtls_aes_setkey_dec(&ctx.host_aes_ctx_dec, ctx.derived_key,
                        ECDH_SHARED_KEYSIZE_BITS);
        if (ret != 0) {
                ERROR("sts: mbedtls_aes_setkey_dec()\n");
                return -1;
        }
        return 0;
}

static void _sts_handlers(struct sts_message *msg)
{
        int ret;

        /* SLAVE SIDE */
        if (strcmp(ctx.sts_mode, "slave") == 0) {
                /* receive AUTHREQ from master*/
                if (strcmp(msg->header, STS_AUTHREQ) == 0 && 
                                ctx.slave_flag == STS_STEP_0) {
                        TRACE("sts: Received AUTHREQ from master\n");
                        if (strcmp(msg->data, ctx.id_slave) == 0) {
                                INFO("sts: Authentication SUCCESS\n");
                                ctx.slave_flag = STS_STEP_1;
                                return;

                        } else {
                                ERROR("sts: Authentication FAILURE! master "
                                                "sent wrong ID\n");
                                return;
                        }
                }

                /* receive AUTHACK from master */
                if (strcmp(msg->header, STS_AUTHACK) == 0 && 
                                ctx.slave_flag == STS_STEP_1) {
                        TRACE("sts: Received AUTHACK from master\n");
                        ctx.slave_flag = STS_STEP_2;
                }

                /* receive RDYREQ from master */
                if (strcmp(msg->header, STS_RDYREQ) == 0 && 
                                ctx.slave_flag == STS_STEP_2) {
                        char master_QX[MPI_STRING_SIZE];
                        char master_QY[MPI_STRING_SIZE];

                        memset(master_QX, 0, sizeof(master_QX));
                        memset(master_QY, 0, sizeof(master_QY));

                        _sts_extract_pubkey(master_QX, master_QY, msg);
                        ret = _sts_compute_shared_secret(master_QX, master_QY);
                        if (ret != 0) {
                                ERROR("sts: _sts_compute_shared_secret()\n");
                                return;
                        }

                        TRACE("sts: Received RDYREQ from master\n");
                        ctx.slave_flag = STS_STEP_3;
                        return;
                }

                /* receive RDYACK from master */
                if (strcmp(msg->header, STS_RDYACK) == 0 && 
                                ctx.slave_flag == STS_STEP_3) {
                        TRACE("sts: Received RDYACK from master\n");
                        ctx.slave_flag = STS_STEP_4;
                        return;
                }
        }

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, "master") == 0) {
                /* receive AUTHACK from slave */
                if (strcmp(msg->header, STS_AUTHACK) == 0 && 
                                ctx.master_flag == STS_STEP_0) {
                        TRACE("sts: Received AUTHACK from slave\n");
                        ctx.master_flag = STS_STEP_1;
                }

                /* receive AUTHREQ from slave */
                if (strcmp(msg->header, STS_AUTHREQ) == 0 && 
                                ctx.master_flag == STS_STEP_1) {
                        TRACE("sts: Received AUTHREQ from slave\n");
                        if (strcmp(msg->data, ctx.id_master) == 0) {
                                INFO("sts: Authentication SUCCESS\n");
                                ctx.master_flag = STS_STEP_2;
                                return;

                        } else {
                                ERROR("sts: Authentication FAILURE! slave "
                                                "sent wrong ID\n");
                                return;
                        }
                }

                /* receive RDYACK from slave */
                if (strcmp(msg->header, STS_RDYACK) == 0 && 
                                ctx.master_flag == STS_STEP_2) {
                        TRACE("sts: Received RDYACK from slave\n");
                        ctx.master_flag = STS_STEP_3;
                        return;
                }

                /* receive RDYREQ from slave */
                if (strcmp(msg->header, STS_RDYREQ) == 0 && 
                                ctx.master_flag == STS_STEP_3) {
                        char slave_QX[MPI_STRING_SIZE];
                        char slave_QY[MPI_STRING_SIZE];

                        memset(slave_QX, 0, sizeof(slave_QX));
                        memset(slave_QY, 0, sizeof(slave_QY));

                        _sts_extract_pubkey(slave_QX, slave_QY, msg);
                        ret = _sts_compute_shared_secret(slave_QX, slave_QY);
                        if (ret != 0) {
                                ERROR("sts: _sts_compute_shared_secret()\n");
                                return;
                        }

                        TRACE("sts: Received RDYREQ from slave\n");
                        ctx.master_flag = STS_STEP_4;
                        return;
                }
        }
}

static int _sts_load_config(const char *config)
{
        FILE *fp;
        fp = fopen(config, "r");
        if (fp == NULL)
        {
                ERROR("sts: while opening config file -> start [FILE]\n");
                return -1;
        }

        char key[CONFIG_KEY_MAXLENGTH] = {0};
        char cmp[2] = {0};
        char value[CONFIG_VALUE_MAXLENGTH] = {0};

        while (fscanf(fp, "%s %s %s ", key, cmp, value) != EOF) {
                if (strcmp(key, "ip") == 0) {
                        strcpy(ctx.ip, value);
                } else if (strcmp(key, "port") == 0) {
                        ctx.port = atoi(value);
                } else if (strcmp(key, "qos") == 0) {
                        ctx.qos = atoi(value);
                } else if (strcmp(key, "username") == 0) {
                        strcpy(ctx.username, value);
                } else if (strcmp(key, "password") == 0) {
                        strcpy(ctx.password, value);
                } else if (strcmp(key, "subtop") == 0) {
                        strcpy(ctx.topic_sub, value);
                } else if (strcmp(key, "pubtop") == 0) {
                        strcpy(ctx.topic_pub, value);
                } else if (strcmp(key, "mqtt_version") == 0) {
                        ctx.mqtt_version = atoi(value);
                } else if (strcmp(key, "clientid") == 0) {
                        strcpy(ctx.clientid, value);
                } else if (strcmp(key, "clean_session") == 0) {
                        ctx.clean_session = atoi(value);
                } else if (strcmp(key, "is_retained") == 0) {
                        ctx.is_retained = atoi(value);
                } else if (strcmp(key, "sts_mode") == 0) {
                        if (strcmp(value, "nosec") == 0) {
                                strcpy(ctx.sts_mode, value);
                        } else if (strcmp(value, "master") == 0) {
                                strcpy(ctx.sts_mode, value);
                        } else if (strcmp(value, "slave") == 0) {
                                strcpy(ctx.sts_mode, value);
                        } else {
                                ERROR("sts: wrong value for sts_mode "
                                                "set to nosec by default\n");
                                strcpy(ctx.sts_mode, "nosec");
                        }
                } else if (strcmp(key, "id_master") == 0) {
                        strcpy(ctx.id_master, value);
                } else if (strcmp(key, "id_slave") == 0) {
                        strcpy(ctx.id_slave, value);
                } else {
                        ERROR("sts: wrong key in config file, please "
                                        "see 'template_config'\n");
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
        sts_reset_ctx();
        int ret = _sts_load_config(config);
        if (ret < 0) {
                return -1;
        }

        NetworkInit(&ctx.network);
        MQTTClientInit(&ctx.client, &ctx.network, COMMAND_TIMEOUT_MS,
                        sendbuff, SENDBUFFSIZE, readbuff, READBUFFSIZE);
        INFO("sts: network and client initialized\n");
        return 0;
}

void sts_reset_ctx(void)
{
        ctx.mqtt_version = 0;
        ctx.qos = 0;
        ctx.port = 0;
        ctx.clean_session = 0;
        ctx.is_retained = 0;
        ctx.no_print = 0;
        ctx.msg_sent = 0;
        ctx.msg_recv = 0;
        ctx.thrd_msg_type = 0;
        ctx.encryption = 0;
        ctx.status = STS_STOPPED;
        ctx.master_flag = STS_STEP_0;
        ctx.slave_flag = STS_STEP_0;
        memset(ctx.derived_key, 0, sizeof(ctx.derived_key));
        memset(ctx.topic_sub, 0, sizeof(ctx.topic_sub));
        memset(ctx.topic_pub, 0, sizeof(ctx.topic_pub));
        memset(ctx.clientid, 0, sizeof(ctx.clientid));
        memset(ctx.username, 0, sizeof(ctx.username));
        memset(ctx.password, 0, sizeof(ctx.password));
        memset(ctx.id_master, 0, sizeof(ctx.id_master));
        memset(ctx.id_slave, 0, sizeof(ctx.id_slave));
        memset(ctx.sts_mode, 0, sizeof(ctx.sts_mode));
        memset(ctx.ip, 0, sizeof(ctx.ip));
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
        char *msg_inc = NULL;
        memset(msg.header, 0, sizeof(msg.header));
        memset(msg.data, 0, sizeof(msg.data));
        msg_inc = calloc((size_t)data->message->payloadlen + 1, sizeof(char));
        memcpy(msg_inc, data->message->payload, data->message->payloadlen);

        /* if security mode */
        if (strcmp(ctx.sts_mode, "master") == 0 || 
                        strcmp(ctx.sts_mode, "slave") == 0) {
                _sts_parse_msg(msg_inc, &msg);
                _sts_handlers(&msg);
                if (ctx.encryption == 1) {
                        unsigned char dec[STS_MSG_MAXLEN];
                        unsigned char buf[STS_MSG_MAXLEN];
                        memset(dec, 0, sizeof(dec));
                        memset(buf, 0, sizeof(buf));

                        strcpy((char*)buf, msg_inc);
                        sts_decrypt_aes_ecb(&ctx.host_aes_ctx_dec, buf, dec, 
                                        sizeof(buf));
                        INFO("[MQTT_INC]: %s\n", dec);
                }
                ctx.msg_recv++;
                free(msg_inc);
                return;
        }
        INFO("[MQTT_INC]: %s\n", msg_inc);
        ctx.msg_recv++;
        free(msg_inc);
}

static void *_mqtt_yield(void *argv)
{
        (void)argv;
        int ret = 0;
        INFO("sts: starting mqttyield thread...\n");
        while (1) {
                if (ctx.thrd_msg_type == STS_KILL_THREAD || 
                                ctx.client.isconnected == 0) {
                        INFO("sts: stopping mqttyield thread...\n");
                        INFO("sts: terminating sts client...\n");
                        ctx.thrd_msg_type = 0;
                        return NULL;
                }
                if ((ret = MQTTYield(&ctx.client, 1000)) != 0) {
                        ERROR("sts: error while MQTTYield()(%d)\n", ret);
                        ctx.thrd_msg_type = STS_KILL_THREAD;
                }
        }
        return NULL;
}

int mqtt_connect(void)
{
        int ret = 0;

        /* setting conn params */
        MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
        data.MQTTVersion = ctx.mqtt_version;
        data.clientID.cstring = ctx.clientid;
        data.keepAliveInterval = 0;
        data.cleansession = ctx.clean_session;
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
        int ret = 0;

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
        int ret = 0;
        ret = MQTTSubscribe(&ctx.client, ctx.topic_sub, ctx.qos, 
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
        int ret = 0;
        ret = MQTTUnsubscribe(&ctx.client, ctx.topic_pub);
        if (ret < 0) {
                return -1;
        }
        INFO("sts: unsubscribed from topic %s\n", ctx.topic_sub);
        return 0;
}

int mqtt_publish(char *message)
{
        int ret = 0;
        MQTTMessage msg;
        size_t size = strlen(message);
        if (size > STS_MSG_MAXLEN) {
                ERROR("sts: publish failed, msg exceed %d\n", STS_MSG_MAXLEN);
                return -1;
        }
        msg.qos = ctx.qos;
        msg.payload = (void*)message;
        msg.payloadlen = size;
        msg.retained = ctx.is_retained;

        ret = MQTTPublish(&ctx.client, ctx.topic_pub, &msg);
        if (ret < 0) {
                mqtt_disconnect();
                return -1;
        }

        /* echo */
        if (ctx.no_print == 0) {
                INFO("[MQTTOUT]: %s\n", message);
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
        int ret = 0;
        size_t olen = 0;
        char msg_out[STS_MSG_MAXLEN];
        char slave_QX[MPI_STRING_SIZE];
        char slave_QY[MPI_STRING_SIZE];
        char master_QX[MPI_STRING_SIZE];
        char master_QY[MPI_STRING_SIZE];

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
                        &ctx.host_ecdh_ctx.d, &ctx.host_ecdh_ctx.Q, sts_genrand, 
                        NULL);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecdh_gen_public()\n");
                return -1;
        }
        INFO("sts: ecdh keypair generated\n");

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, "master") == 0) {
                /* send AUTHREQ to slave */
                TRACE("sts: Sending AUTHREQ to slave...\n");
                memset(msg_out, 0, sizeof(msg_out));
                sts_concatenate(msg_out, STS_AUTHREQ);
                sts_concatenate(msg_out, ctx.id_slave);
                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait AUTHACK from slave */
                TRACE("sts: Waiting AUTHACK from slave\n");
                while (ctx.master_flag == STS_STEP_0) {};

                /* wait AUTHREQ from slave */
                TRACE("sts: Waiting AUTHREQ from slave\n");
                while (ctx.master_flag == STS_STEP_1) {};

                /* send AUTHACK to slave */
                TRACE("sts: Sending AUTHACK to slave...\n");
                memset(msg_out, 0, sizeof(msg_out));
                sts_concatenate(msg_out, STS_AUTHACK);

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
                sts_concatenate(msg_out, STS_RDYREQ);
                sts_concatenate(msg_out, "X");
                sts_concatenate(msg_out, master_QX);
                sts_concatenate(msg_out, "Y");
                sts_concatenate(msg_out, master_QY);

                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait RDYACK from slave */
                TRACE("sts: Waiting RDYACK from slave\n");
                while (ctx.master_flag == STS_STEP_2) {};

                /* wait RDYREQ from slave */
                TRACE("sts: Waiting RDYREQ from slave\n");
                while (ctx.master_flag == STS_STEP_3) {};

                /* send RDYACK to slave */
                TRACE("sts: Sending RDYACK to slave\n");
                memset(msg_out, 0, sizeof(msg_out));
                sts_concatenate(msg_out, STS_RDYACK);

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
        if (strcmp(ctx.sts_mode, "slave") == 0) {
                /* wait AUTHREQ from master */
                TRACE("sts: Waiting AUTHREQ from master\n");
                while (ctx.slave_flag == STS_STEP_0) {};

                /* send AUTHACK to master */
                TRACE("sts: Sending AUTHACK to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                sts_concatenate(msg_out, STS_AUTHACK);
                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ctx.slave_flag = STS_STEP_0;
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* send AUTHREQ to master */
                TRACE("sts: Sending AUTHREQ to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                sts_concatenate(msg_out, STS_AUTHREQ);
                sts_concatenate(msg_out, ctx.id_master);
                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ctx.slave_flag = STS_STEP_0;
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait AUTHACK from master */
                TRACE("sts: Waiting AUTHACK from master\n");
                while (ctx.slave_flag == STS_STEP_1) {};

                /* wait RDYREQ from master */
                TRACE("sts: Waiting RDYREQ from master\n");
                while (ctx.slave_flag == STS_STEP_2) {};

                /* send RDYACK to master */
                TRACE("sts: Sending RDYACK to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                sts_concatenate(msg_out, STS_RDYACK);
                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ctx.slave_flag = STS_STEP_0;
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
                sts_concatenate(msg_out, STS_RDYREQ);
                sts_concatenate(msg_out, "X");
                sts_concatenate(msg_out, slave_QX);
                sts_concatenate(msg_out, "Y");
                sts_concatenate(msg_out, slave_QY);
                ctx.no_print = 1;
                ret = mqtt_publish(msg_out);
                if (ret < 0) {
                        ctx.slave_flag = STS_STEP_0;
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait RDYACK from master */
                TRACE("sts: Waiting RDYACK from master\n");
                while (ctx.slave_flag == STS_STEP_3) {};

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
