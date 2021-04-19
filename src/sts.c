#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "sts.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
/* VARIABLES */
////////////////////////////////////////////////////////////////////////////////
static struct sts_context ctx = {
        .status = STS_STOPPED,
};

static unsigned char sendbuff[SENDBUFFSIZE];
static unsigned char readbuff[READBUFFSIZE];

static unsigned int thrd_msg_type = 0;
static pthread_t _mqttyield_thrd_pid;

////////////////////////////////////////////////////////////////////////////////
/* STS COMMANDS LISTS */
////////////////////////////////////////////////////////////////////////////////
static char *builtin_cmd[] = {
        "help",
        "exit",
        "start",
        "stop",
        "status",
        "sendtest",
        "sectest",
};

static char *builtin_cmd_desc[] = {
        "help              prints all commands                        |",
        "exit              exit shell                                 |",
        "start [CONFIG]    start STS session                          |",
        "stop              stop STS session                           |",
        "                  example: 'send blah1 blah2 blah3'          |\n| "
                "status            display status of current session          |",
        "sendtest [MSG]    send a message to the broker               |",
        "sectest [MSG]     ecdh aes enc/dec test (no space)           |",
};

static int (*builtin_func[]) (char **argv) = {
        &sts_help,
        &sts_exit,
        &sts_start_session,
        &sts_stop_session,
        &sts_status,
        &sts_send_test,
        &sts_ecdh_aes_test,
};

static int sts_num_builtins(void) {
        return sizeof(builtin_cmd) / sizeof(char *);
}

static void _concatenate(char p[], char q[]) {
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

/* TODO temporary for debug */
static void _print_derived_key(const unsigned char *buf, size_t size) 
{
        size_t i;
        INFO("sts: shared_key: ");

        for (i = 0 ; i < size; i++) {
                if (buf[i] == '\0') {
                        break;
                }
                printf("%02X", buf[i]);
        }
        printf("\n");
}

////////////////////////////////////////////////////////////////////////////////
/* STS */
////////////////////////////////////////////////////////////////////////////////
static int _sts_load_config(const char *config)
{
        FILE *fp;
        fp = fopen(config, "r");
        if (fp == NULL)
        {
                ERROR("sts: while opening config file -> start [FILE]\n");
                return -1;
        }

        char key[16] = {0};
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
                } else if (strcmp(key, "keep_alive") == 0) {
                        ctx.keep_alive = atoi(value);
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
                        return STS_PROMPT;
                }
        }
        fclose(fp);
        config = NULL;
        return 0;
}

static void _sts_reset_ctx(void)
{
        ctx.mqtt_version = 0;
        ctx.qos = 0;
        ctx.port = 0;
        ctx.keep_alive = 0;
        ctx.clean_session = 0;
        ctx.is_retained = 0;
        ctx.no_print = 0;
        ctx.msg_sent = 0;
        ctx.msg_recv = 0;
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

static int _sts_init(const char *config)
{
        _sts_reset_ctx();
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

/* TODO VERIFY EVERY STEP WITH ERROR HANDLING LOT OF BUGS */
static void _sts_handlers(struct sts_message *msg)
{
        size_t olen;

        /* slave side, receive AUTHREQ */
        if (strcmp(msg->header, STS_AUTHREQ) == 0 && 
                        ctx.slave_flag == STS_STEP_0) {
                if (strcmp(msg->data, ctx.id_slave) == 0) {
                        ctx.slave_flag = STS_STEP_1;
                        return;

                } else {
                        /* TODO should send it to master so it disconnects */
                        ERROR("sts: Authentification FAILURE!\n");
                        return;
                }
        }

        /* master side, receive AUTHACK */
        /* TODO master should handle wrong id feedback with disconnection */
        if (strcmp(msg->header, STS_AUTHACK) == 0 && 
                        ctx.master_flag ==  STS_STEP_1) {
                char slave_QX[MPI_STRING_SIZE];
                char slave_QY[MPI_STRING_SIZE];

                memset(slave_QX, 0, sizeof(slave_QX));
                memset(slave_QY, 0, sizeof(slave_QY));

                _sts_extract_pubkey(slave_QX, slave_QY, msg);

                /* copy X Y */
                mbedtls_ecp_point_read_string(&ctx.host_ecdh_ctx.Qp, 16, 
                                slave_QX, slave_QY);

                /* compute derived_key */
                memset(ctx.derived_key, 0, sizeof(ctx.derived_key));
                mbedtls_ecdh_calc_secret(&ctx.host_ecdh_ctx, &olen, 
                                ctx.derived_key, sizeof(ctx.derived_key), 
                                genrand, NULL);

                ctx.master_flag = STS_STEP_2;
                return;
        }

        /* slave side, receive RDYREQ */
        if (strcmp(msg->header, STS_RDYREQ) == 0 && 
                        ctx.slave_flag ==  STS_STEP_1) {
                char master_QX[MPI_STRING_SIZE];
                char master_QY[MPI_STRING_SIZE];

                memset(master_QX, 0, sizeof(master_QX));
                memset(master_QY, 0, sizeof(master_QY));

                _sts_extract_pubkey(master_QX, master_QY, msg);

                /* copy X Y */
                mbedtls_ecp_point_read_string(&ctx.host_ecdh_ctx.Qp, 16, 
                                master_QX, master_QY);

                /* compute derived_key */
                memset(ctx.derived_key, 0, sizeof(ctx.derived_key));
                mbedtls_ecdh_calc_secret(&ctx.host_ecdh_ctx, &olen, 
                                ctx.derived_key, sizeof(ctx.derived_key), 
                                genrand, NULL);

                ctx.slave_flag = STS_STEP_2;
                return;
        }

        /* master side, receive RDYACK */
        if (strcmp(msg->header, STS_RDYACK) == 0 && 
                        ctx.master_flag == STS_STEP_2) {
                ctx.master_flag = STS_STEP_3;
                return;
        }
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

        /* if encryption ON */
        if (strcmp(ctx.sts_mode, "master") == 0 || 
                        strcmp(ctx.sts_mode, "slave") == 0) {
                _sts_parse_msg(msg_inc, &msg);
                _sts_handlers(&msg);
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
                if (thrd_msg_type == STS_KILL_THREAD || 
                                ctx.client.isconnected == 0) {
                        INFO("sts: stopping mqttyield thread...\n");
                        INFO("sts: terminating sts client...\n");
                        thrd_msg_type = 0;
                        ctx.status = STS_STOPPED;
                        return NULL;
                }
                if ((ret = MQTTYield(&ctx.client, 1000)) != 0) {
                        ERROR("sts: error while MQTTYield()(%d)\n", ret);
                        thrd_msg_type = STS_KILL_THREAD;
                }
        }
        return NULL;
}

static int _mqtt_connect(void)
{
        int ret = 0;

        /* setting conn params */
        MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
        data.MQTTVersion = ctx.mqtt_version;
        data.clientID.cstring = ctx.clientid;
        data.keepAliveInterval = ctx.keep_alive;
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

static void _mqtt_disconnect(void)
{
        int ret = 0;

        ret = MQTTDisconnect(&ctx.client);
        if (ret < 0) {
                ERROR("sts: couldn't disconnect client, "
                                "forcing network disconnection\n");
                NetworkDisconnect(&ctx.network);
                INFO("sts: disconnected from broker\n");
                return;
        }
        NetworkDisconnect(&ctx.network);
        INFO("sts: disconnected from broker\n");
}

static int _mqtt_subscribe(void)
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

static int _mqtt_unsubscribe(void)
{
        int ret = 0;
        ret = MQTTUnsubscribe(&ctx.client, ctx.topic_pub);
        if (ret < 0) {
                return -1;
        }
        INFO("sts: unsubscribed from topic %s\n", ctx.topic_sub);
        return 0;
}

static int _mqtt_publish(char *message)
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
                _mqtt_disconnect();
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
static int _sts_init_sec(void)
{
        int ret = 0;
        int count = 0;
        size_t olen = 0;
        char msg_out[STS_MSG_MAXLEN];
        char slave_QX[MPI_STRING_SIZE];
        char slave_QY[MPI_STRING_SIZE];
        char master_QX[MPI_STRING_SIZE];
        char master_QY[MPI_STRING_SIZE];

        memset(msg_out, 0, sizeof(msg_out));
        memset(slave_QX, 0, sizeof(slave_QX));
        memset(slave_QY, 0, sizeof(slave_QY));
        memset(master_QX, 0, sizeof(master_QX));
        memset(master_QY, 0, sizeof(master_QY));

        mbedtls_ecdh_init(&ctx.host_ecdh_ctx);
        ret = mbedtls_ecdh_setup(&ctx.host_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
        if (ret < 0) {
                return -1;
        }
        ret = mbedtls_ecdh_gen_public(&ctx.host_ecdh_ctx.grp, 
                        &ctx.host_ecdh_ctx.d, &ctx.host_ecdh_ctx.Q, genrand, 
                        NULL);
        if (ret < 0) {
                return -1;
        }

        INFO("sts: ecdh keypair generated\n");

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, "master") == 0) {
                /* send AUTHREQ to slave 5 times every 5 sec */
                INFO("sts: Sending authentification request to slave...\n");
                ctx.master_flag = STS_STEP_1;
                while (ctx.master_flag == STS_STEP_1 && count < 5) {
                        memset(msg_out, 0, sizeof(msg_out));
                        _concatenate(msg_out, STS_AUTHREQ);
                        _concatenate(msg_out, ctx.id_slave);
                        ctx.no_print = 1;
                        ret = _mqtt_publish(msg_out);
                        if (ret < 0) {
                                ERROR("sts: authentification failed\n");
                                return -1;
                        }
                        count++;
                        sleep(5);
                        if (count == 5) {
                                count = 0;
                                ERROR("sts: authentification request failed "
                                                "after 5 attempts\n");
                                return -1;
                        }
                }

                /* wait for master handling AUTHACK */
                while (ctx.master_flag != STS_STEP_2) {};
                INFO("sts: Authentification SUCCESS!\n");

                /* send RDYREQ + pubkey to slave */
                INFO("sts: Sending ready request...\n");
                memset(msg_out, 0, sizeof(msg_out));
                mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.X, 16, master_QX, 
                                MPI_STRING_SIZE, &olen);
                mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.Y, 16, master_QY, 
                                MPI_STRING_SIZE, &olen);
                _concatenate(msg_out, STS_RDYREQ);
                _concatenate(msg_out, "X");
                _concatenate(msg_out, master_QX);
                _concatenate(msg_out, "Y");
                _concatenate(msg_out, master_QY);

                ctx.no_print = 1;
                ret = _mqtt_publish(msg_out);
                if (ret < 0) {
                        ERROR("sts: publish failed\n");
                        return -1;
                }

                /* wait for master to handle RDYHACK */
                while (ctx.master_flag != STS_STEP_3) {};
                INFO("sts: Encryption established with slave\n");
        }

        /* SLAVE SIDE */
        if (strcmp(ctx.sts_mode, "slave") == 0) {
                INFO("sts: Waiting for authentification request from master\n");
                /* wait for master to send auth request */
                while (ctx.slave_flag == STS_STEP_0) {};
                INFO("sts: Authentification request received from master\n");
                INFO("sts: Authentification SUCCESS!\n");

                /* TODO should also send id for verification on master side 
                 * before pubkey */
                /* send AUTHACK + pubkey to master */
                INFO("sts: Sending authentification acknowledgement...\n");
                memset(msg_out, 0, sizeof(msg_out));
                mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.X, 16, slave_QX, 
                                MPI_STRING_SIZE, &olen);
                mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.Y, 16, slave_QY, 
                                MPI_STRING_SIZE, &olen);
                _concatenate(msg_out, STS_AUTHACK);
                _concatenate(msg_out, "X");
                _concatenate(msg_out, slave_QX);
                _concatenate(msg_out, "Y");
                _concatenate(msg_out, slave_QY);

                ctx.no_print = 1;
                ret = _mqtt_publish(msg_out);
                if (ret < 0) {
                        ctx.slave_flag = STS_STEP_0;
                        ERROR("sts: publish failed\n");
                        return -1;
                }

                /* wait for slave to handle RDYREQ */
                while (ctx.slave_flag != STS_STEP_2) {}
                INFO("sts: Ready request received from slave\n");

                /* send RDYACK to slave */
                memset(msg_out, 0, sizeof(msg_out));
                _concatenate(msg_out, STS_RDYACK);

                ctx.no_print = 1;
                ret = _mqtt_publish(msg_out);
                if (ret < 0) {
                        ctx.slave_flag = STS_STEP_0;
                        ERROR("sts: publish failed\n");
                        return -1;
                }
                INFO("sts: Encryption established with master\n");
        }
        return 0;
}

static void _sts_free_sec(void)
{
        mbedtls_ecdh_free(&ctx.host_ecdh_ctx);
}

////////////////////////////////////////////////////////////////////////////////
/* STS COMMANDS */
////////////////////////////////////////////////////////////////////////////////
int sts_start_session(char **argv)
{
        (void)argv;
        int ret = 0;
        if (ctx.status == STS_STARTED || ctx.client.isconnected == 1) {
                ERROR("sts: a session has already been started already\n");
                return STS_PROMPT;
        }

        if (argv[1] == NULL) {
                ERROR("sts: config file missing, start [PATH_TO_CONFIG]\n");
                return STS_PROMPT;
        }

        ret = _sts_init(argv[1]);
        if (ret < 0) {
                ERROR("sts: could not initialize session\n");
                return STS_PROMPT;
        }

        ret = _mqtt_connect(); 
        if (ret < 0) {
                ERROR("sts: could not connect to broker\n");
                _mqtt_disconnect();
                _sts_reset_ctx();
                return STS_PROMPT;
        }

        ret = _mqtt_subscribe();
        if (ret < 0) {
                ERROR("sts: could not subscribe to broker, disconnecting...\n");
                _mqtt_disconnect();
                _sts_reset_ctx();
                return STS_PROMPT;
        }

        if (strcmp(ctx.sts_mode, "master") == 0 || 
                        strcmp(ctx.sts_mode, "slave") == 0) {
                ret = _sts_init_sec();
                if (ret < 0) {
                        ERROR("sts: while initializing security\n");
                        _mqtt_disconnect();
                        _sts_free_sec();
                        _sts_reset_ctx();
                        return STS_PROMPT;
                }
        }
        ctx.status = STS_STARTED;
        return STS_PROMPT;
}

int sts_stop_session(char **argv)
{
        (void)argv;
        int ret;
        if (ctx.status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return STS_PROMPT;
        }

        /* kill thread and give it time to close up */
        thrd_msg_type = STS_KILL_THREAD;
        sleep(1);

        ret = _mqtt_unsubscribe();
        if (ret < 0) {
                ERROR("sts: could not unsubscribe from topic '%s'\n",
                                ctx.topic_sub);
        }
        _mqtt_disconnect();
        _sts_free_sec();
        _sts_reset_ctx();
        return STS_PROMPT;
}

int sts_send_test(char **message)
{
        int ret = 0;
        int i = 1;
        size_t msg_size = 0;
        char msg_out[STS_MSG_MAXLEN];
        MQTTMessage msg;
        memset(msg_out, 0, sizeof(msg_out));

        /* compute size of msg */
        while (message[i] != NULL) {
                msg_size += strlen(message[i] + 1);
                i++;
        }

        if (ctx.status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return STS_PROMPT;
        }

        if (message[1] == NULL) {
                ERROR("sts: missing param -> 'sendtest [MSG]'\n");
                return STS_PROMPT;
        }

        if (msg_size > STS_MSG_MAXLEN) {
                ERROR("sts: message is too big, size <= %d\n", STS_MSG_MAXLEN);
                return STS_PROMPT;
        }

        /* copy */
        i = 1;
        while (message[i] != NULL) {
                _concatenate(msg_out, message[i]);
                _concatenate(msg_out, " ");
                i++;
        }

        msg.qos = ctx.qos;
        msg.payload = (void*)msg_out;
        msg.payloadlen = strlen(msg_out);
        msg.retained = ctx.is_retained;

        ret = MQTTPublish(&ctx.client, ctx.topic_pub, &msg);
        if (ret < 0) {
                _mqtt_disconnect();
                return STS_PROMPT;
        }
        /* echo */
        INFO("[MQTT_OUT]: %s\n", msg_out);
        ctx.msg_sent++;
        return STS_PROMPT;
}

int sts_help(char **argv)
{
        (void)argv;
        int i;
        printf("+--------------------------------------------------------------+\n");
        printf("| Commands        | Description                                |\n");
        printf("+--------------------------------------------------------------+\n");

        for (i = 0; i < sts_num_builtins(); i++) {
                printf("| %s\n",
                                builtin_cmd_desc[i]);
        }
        printf("+--------------------------------------------------------------+\n");
        return STS_PROMPT;
}

int sts_exit(char **argv)
{
        (void)argv;
        return STS_EXIT;
}

/* TODO make a beautiful status with more info on security */
int sts_status(char **argv)
{
        (void)argv;

        if (ctx.client.isconnected == 0 && ctx.status == STS_STOPPED) {
                INFO("sts: status:          OFFLINE\n");
                return STS_PROMPT;
        }

        INFO("sts: status:          ONLINE\n");
        INFO("sts: id_master:       %s\n", ctx.id_master);
        INFO("sts: id_slave:        %s\n", ctx.id_slave);
        INFO("sts: sts_mode:        %s\n", ctx.sts_mode);
        INFO("sts: mqtt version:    %u\n", ctx.mqtt_version);
        INFO("sts: broker_ip:       %s\n", ctx.ip);
        INFO("sts: broker_port:     %u\n", ctx.port);
        INFO("sts: client_id:       %s\n", ctx.clientid);
        INFO("sts: username:        %s\n", ctx.username);
        INFO("sts: password:        %s\n", ctx.password);
        INFO("sts: qos:             %u\n", ctx.qos);
        INFO("sts: keep_alive:      %u\n", ctx.keep_alive);
        INFO("sts: clean_session:   %u\n", ctx.clean_session);
        INFO("sts: is_retained      %u\n", ctx.is_retained);
        INFO("sts: pub_topic:       %s\n", ctx.topic_pub);
        INFO("sts: sub_topic:       %s\n", ctx.topic_sub);
        INFO("sts: msg sent:        %u\n", ctx.msg_sent);
        INFO("sts: msg recv:        %u\n", ctx.msg_recv);
        if (strcmp(ctx.sts_mode, "master") == 0) {
                _print_derived_key(ctx.derived_key, sizeof(ctx.derived_key));

        }
        if (strcmp(ctx.sts_mode, "slave") == 0) {
                _print_derived_key(ctx.derived_key, sizeof(ctx.derived_key));
        }
        return STS_PROMPT;
}

////////////////////////////////////////////////////////////////////////////////
/* CORE SHELL */
////////////////////////////////////////////////////////////////////////////////
static void sts_welcome(void)
{
        printf("+--------------------------------------------------------------+\n");
        printf("|                    Secure Telemetry Shell                    |\n");
        printf("+--------------------------------------------------------------+\n");
        printf("|                                                              |\n");
        printf("| 'help' to display command list                               |\n");
        printf("|                                                              |\n");
        printf("| https://github.com/nisennenmondai                            |\n");
        printf("|                                                              |\n");
        printf("+--------------------------------------------------------------+\n");
}

static char *sts_read_line(void)
{
        int buffsize = STS_RL_BUFFSIZE;
        int position = 0;
        char *buffer = (char*)malloc(buffsize * sizeof(char));
        int c;

        /* check if buffer has been allocated */
        if (!buffer) {
                fprintf(stderr, "sts: allocation error\n");
                exit(EXIT_FAILURE);
        }

        /* read line */
        while (1) {
                /* use of function getline is much easier */
                c = getchar();

                /* if we hit EOF, replace it with a null character and return */
                if (c == EOF || c == '\n') {
                        buffer[position] = '\0';
                        return buffer;
                } else {
                        buffer[position] = c;
                }
                position++;

                /* if we have exceeded the buffer, reallocate */
                if (position >= buffsize) {
                        buffsize += STS_RL_BUFFSIZE;
                        buffer = realloc(buffer, buffsize);

                        if (!buffer) {
                                fprintf(stderr, "sts: allocation error\n");
                        }
                }
        }
}

static char **sts_split_line(char *line)
{
        int buffsize = STS_TOK_BUFFSIZE;
        int position = 0;
        char **tokens = malloc(buffsize * sizeof(char*));
        char *token;

        /* check if buffer has been allocated */
        if (!tokens) {
                fprintf(stderr, "sts: allocation error\n");
                exit(EXIT_FAILURE);
        }

        /* get the first argument (char*) */
        token = strtok(line, STS_TOK_DELIM);
        while (token != NULL) {
                /* put the token inside the array of pointers */
                tokens[position] = token;
                /* go to next index */
                position++;

                /* check if buffer overflow, then allocate more memory */
                if (position >= buffsize) {
                        buffsize += STS_TOK_BUFFSIZE;
                        tokens = realloc(tokens, buffsize);

                        if (!tokens) {
                                fprintf(stderr, "sts: allocation error\n");
                                exit(EXIT_FAILURE);
                        }
                }
                /* parse the next argument and jump back to the top of while 
                 * loop */
                token  = strtok(NULL, STS_TOK_DELIM);
        }
        /* parsing is done end the array with a NULL pointer */
        tokens[position] = NULL;
        return tokens;
}

/* this function launches a process */
static int sts_launch(char **argv)
{
        pid_t pid, wpid;
        (void)wpid;
        int status;

        pid = fork();
        if (pid == 0) {
                /* child process, execute program by providing filename, vector 
                 * argv */
                if (execvp(argv[0], argv) == -1) {
                        perror("sts");
                }
                exit(EXIT_FAILURE);
        } else if (pid < 0) {
                /* forking error */
                perror("sts");
        } else {
                /* parent process */
                do {
                        /* wait for child process to finish by checking 
                         * status */
                        wpid = waitpid(pid, &status, WUNTRACED);
                } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        }
        /* returns a 1 as a signal to the calling func that we should prompt for
         * input again */
        return STS_PROMPT;
}

/* this function execute a builtin function */
static int sts_execute(char **argv)
{
        int i;

        if (argv[0] == NULL) {
                /* An empty command was entered. */
                return 1;
        }

        /* check if command equals a builtin function and execute it, if not 
         * then launch a process */
        for (i = 0; i < sts_num_builtins(); i++) {
                if (strcmp(argv[0], builtin_cmd[i]) == 0) {
                        return (*builtin_func[i])(argv);
                }
        }

        return sts_launch(argv);
}

/* loop getting input and executing it */
static void sts_loop(void)
{
        char *line;
        char **argv;
        int status;

        do {
                printf("> ");
                line = sts_read_line();
                argv = sts_split_line(line);
                status = sts_execute(argv);

                free(line);
                free(argv);
        } while (status);
        return;
}

////////////////////////////////////////////////////////////////////////////////
/* STS MAIN */
////////////////////////////////////////////////////////////////////////////////
int main(void)
{
        sts_welcome();
        sts_loop();
        return 0;
}
