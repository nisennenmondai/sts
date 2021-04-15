#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "sts.h"

////////////////////////////////////////////////////////////////////////////////
/* VARIABLES */
////////////////////////////////////////////////////////////////////////////////
static struct sts_context ctx = {
        .status     = STS_STOPPED,
        .msg_sent     = 0,
        .msg_recv     = 0,
        .master_flag  = 0,
        .slave_flag   = 0,
};

static unsigned char sendbuff[SENDBUFFSIZE];
static unsigned char readbuff[READBUFFSIZE];

static unsigned int thrd_msg_type = 0;
static pthread_t _mqttyield_thrd_pid;

/* TODO think about more appropriate naming with those var */
static char *sts_msg_inc = NULL;
static char *sts_msg_out = NULL;
static char sts_msg_header[10]; /* max header length */
static char sts_msg_data[STS_MSG_MAXLEN];

////////////////////////////////////////////////////////////////////////////////
/* STS COMMANDS LISTS */
////////////////////////////////////////////////////////////////////////////////
char *builtin_cmd[] = {
        "help",
        "exit",
        "start",
        "stop",
        "status",
        "sendtest",
        "sectest",
};

char *builtin_cmd_desc[] = {
        "help              prints all commands                        |",
        "exit              exit shell                                 |",
        "start [CONFIG]    start STS session                          |",
        "stop              stop STS session                           |",
        "                  example: 'send blah1 blah2 blah3'          |\n| "
                "status            display status of current session          |",
        "sendtest [MSG]    send a message to the broker               |",
        "sectest [MSG]     ecdh aes enc/dec test (no space)           |",
};

int (*builtin_func[]) (char **argv) = {
        &sts_help,
        &sts_exit,
        &sts_start_session,
        &sts_stop_session,
        &sts_status,
        &sts_send_test,
        &sts_ecdh_aes_test,
};

int sts_num_builtins(void) {
        return sizeof(builtin_cmd) / sizeof(char *);
}

////////////////////////////////////////////////////////////////////////////////
/* STS CLIENT */
////////////////////////////////////////////////////////////////////////////////

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

static void *_mqttyield(void *argv)
{
        (void)argv;
        int ret = 0;
        printf("sts: starting mqttyield thread...\n");
        while (1) {
                if (thrd_msg_type == STS_KILL_THREAD || ctx.client.isconnected == 0) {
                        printf("sts: stopping mqttyield thread...\n");
                        printf("sts: terminating sts client...\n");
                        thrd_msg_type = 0;
                        ctx.status = STS_STOPPED;
                        return NULL;
                }
                if ((ret = MQTTYield(&ctx.client, 1000)) != 0) {
                        printf("sts: error while MQTTYield()(%d)\n", ret);
                        thrd_msg_type = STS_KILL_THREAD;
                }
        }
        return NULL;
}

static void _prep_msg_inc(MessageData *data)
{
        sts_msg_inc = calloc((size_t)data->message->payloadlen + 1, sizeof(char));
        memcpy(sts_msg_inc, data->message->payload, data->message->payloadlen);
}

/* TODO think about a better name for this function as it seems to be only for
 * sendtest() */
static void _prep_msg_out(char **message)
{
        int i = 1;
        size_t msg_size = 0;

        /* compute size of msg */
        while (message[i] != NULL) {
                msg_size += strlen(message[i] + 1);
                i++;
        }
        sts_msg_out = malloc(sizeof(msg_size));
        memset(sts_msg_out, 0, sizeof(msg_size));

        /* copy */
        i = 1;
        while (message[i] != NULL) {
                _concatenate(sts_msg_out, message[i]);
                _concatenate(sts_msg_out, " ");
                i++;
        }
}

/* TODO temporary for debug */
static void _print_derived_key(const unsigned char *buf, size_t size, int client) 
{
        size_t i;
        if (client == 0) {
                printf("sts: host derived shared_key:   ");
        }

        if (client == 1) {
                printf("\nsts: remote derived shared_key: ");
        }

        for (i = 0 ; i < size; i++) {
                if (buf[i] == '\0') {
                        break;
                }
                printf("%02X", buf[i]);
        }
}

static int _encryption_handlers(char *msg)
{
        size_t i;
        int index = 0;

        /* TODO header and data should stay local to this function */
        memset(sts_msg_header, 0, sizeof(sts_msg_header));
        memset(sts_msg_data, 0, sizeof(sts_msg_data));

        /* extract header */
        for (i = 0; i < sizeof(sts_msg_header); i++) {
                sts_msg_header[i] = msg[i];
                if (sts_msg_header[i] == ':') {
                        index = i + 1;
                        break;
                }
        }

        /* extract data */
        for (i = 0; i < STS_MSG_MAXLEN; i++) {
                if (msg[index + i] != '\0') {
                        sts_msg_data[i] = msg[index + i];
                } 
                if (msg[index + i] == '\0') {
                        break;
                }
        }

        /* slave side, AUTHREQ handler */
        if (strcmp(sts_msg_header, STS_AUTHREQ) == 0) {
                ctx.slave_flag = 1;
                ctx.msg_recv++;
                free(sts_msg_inc);
                return 0;
        }
        /* TODO master side, AUTHACK handler */
        if (strcmp(sts_msg_header, STS_AUTHACK) == 0) {
                int index_X = 0;
                int index_Y = 0;
                char slave_QX[21];
                char slave_QY[21];
                memset(slave_QX, 0, sizeof(slave_QX));
                memset(slave_QY, 0, sizeof(slave_QY));
                /* extract slave public key X */
                for (i = 0; i < STS_MSG_MAXLEN; i++) {
                        if (sts_msg_data[i] == 'Y') {
                                index_X = index_X - 1;
                                break;
                        }
                        index_X++;
                }
                memcpy(slave_QX, &sts_msg_data[1], index_X * sizeof(char));

                /* extract slave public key Y */
                for (i = index_X + 2; i < STS_MSG_MAXLEN; i++) {
                        if (sts_msg_data[i] == '\0') {
                                index_Y = index_Y + 1;
                                break;
                        }
                        index_Y++;
                }
                memcpy(slave_QY, &sts_msg_data[index_X + 2], index_Y * sizeof(char));

                /* copy public key */
                size_t olen;
                unsigned char host_derived_key[ECDH_SHARED_KEYSIZE_BYTES];
                mbedtls_ecp_point Q;
                mbedtls_ecp_point_init(&Q);

                /* problem */
                mbedtls_mpi_read_string(&Q.X, 10, slave_QX);
                mbedtls_mpi_read_string(&Q.Y, 10, slave_QY);
                mbedtls_mpi_lset(&Q.Z, 1);
                printf("read_string Q X: %lu\n", *Q.X.p);
                printf("read_string Q Y: %lu\n", *Q.Y.p);

                mbedtls_ecp_copy(&ctx.host_ecdh_ctx.Qp, &Q);
                printf("ecp_copy X: %lu\n", *ctx.host_ecdh_ctx.Qp.X.p);
                printf("ecp_copy Y: %lu\n", *ctx.host_ecdh_ctx.Qp.Y.p);
                mbedtls_ecdh_calc_secret(&ctx.host_ecdh_ctx, &olen, host_derived_key, 
                                sizeof(host_derived_key), genrand, NULL);
                
                _print_derived_key(host_derived_key, sizeof(host_derived_key), 0);
                mbedtls_ecp_point_free(&Q);

                ctx.master_flag = 1;
                ctx.msg_recv++;
                free(sts_msg_inc);
                return 0;
        }


        /* TODO slave side, handle RDYREQ */
        /* TODO master side, handle RDYACK */
        return -1;
}

static void _on_msg_recv(MessageData *data)
{
        int ret = -1;
        _prep_msg_inc(data);

        /* handlers if encryption ON */
        if (strcmp(ctx.sts_mode, "master") == 0 || strcmp(ctx.sts_mode, "slave") == 0) {
                ret = _encryption_handlers(sts_msg_inc);
        }

        if (ret < 0) {
                printf("[INC]: %s\n", sts_msg_inc);
                ctx.msg_recv++;
                free(sts_msg_inc);
        }
}

static int _load_config(const char *config)
{
        FILE *fp;
        fp = fopen(config, "r");
        if (fp == NULL)
        {
                printf("sts: error! while opening config file -> start [FILE]\n");
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
                                printf("sts: error! wrong value for sts_mode "
                                                "set to nosec by default\n");
                                strcpy(ctx.sts_mode, "nosec");
                        }
                } else if (strcmp(key, "id_master") == 0) {
                        strcpy(ctx.id_master, value);
                } else if (strcmp(key, "id_slave") == 0) {
                        strcpy(ctx.id_slave, value);
                } else {
                        printf("sts: error! wrong key in config file, please "
                                        "see 'template_config'\n");
                        return STS_PROMPT;
                }
        }
        fclose(fp);
        config = NULL;
        return 0;
}

static int _init(const char *config)
{
        int ret = _load_config(config);
        if (ret < 0) {
                return -1;
        }

        NetworkInit(&ctx.network);
        MQTTClientInit(&ctx.client, &ctx.network, COMMAND_TIMEOUT_MS,
                        sendbuff, SENDBUFFSIZE, readbuff, READBUFFSIZE);
        printf("sts: network and client initialized\n");
        return 0;
}

static int _connect(void)
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
                printf("sts: error! could not connect to the network\n");
                return -1;
        }

        ret = MQTTConnect(&ctx.client, &data);
        if (ret < 0) {
                printf("sts: error! could not connect to mqtt\n");
                return -1;
        }
        printf("sts: connected to broker %s\n", ctx.ip);
        return 0;
}

static void _disconnect(void)
{
        int ret = 0;

        ret = MQTTDisconnect(&ctx.client);
        if (ret < 0) {
                printf("sts: error! couldn't disconnect client\n");
                printf("sts: forcing network disconnection\n");
                NetworkDisconnect(&ctx.network);
                printf("sts: disconnected from broker\n");
                return;
        }
        NetworkDisconnect(&ctx.network);
        ctx.status = STS_STOPPED;
        ctx.msg_sent = 0;
        ctx.msg_recv = 0;
        printf("sts: disconnected from broker\n");
}

static int _subscribe(void)
{
        int ret = 0;
        ret = MQTTSubscribe(&ctx.client, ctx.topic_sub, ctx.qos, _on_msg_recv);
        if (ret < 0) {
                return -1;
        }
        /* start mqttyield thread to receive msg */
        _mqttyield_thrd_pid = pthread_create(&_mqttyield_thrd_pid, NULL, _mqttyield, NULL);
        printf("sts: subscribed to topic %s\n", ctx.topic_sub);
        return 0;
}

static int _unsubscribe(void)
{
        int ret = 0;
        ret = MQTTUnsubscribe(&ctx.client, ctx.topic_pub);
        if (ret < 0) {
                return -1;
        }
        printf("sts: unsubscribed from topic %s\n", ctx.topic_sub);
        return 0;
}

static int _publish(char *message)
{
        int ret = 0;
        MQTTMessage msg;
        msg.qos = ctx.qos;
        msg.payload = (void*)message;
        msg.payloadlen = strlen(message);
        msg.retained = ctx.is_retained;

        ret = MQTTPublish(&ctx.client, ctx.topic_pub, &msg);
        if (ret < 0) {
                free(message);
                _disconnect();
                return -1;
        }

        /* echo */
        printf("> [OUT]: %s\n", message);
        free(message);
        ctx.msg_sent++;
        return 0;
}

static int _init_sec(void)
{
        int ret = 0;
        int count = 0;
        char slave_QX[20];
        char slave_QY[20];
        mbedtls_ecdh_init(&ctx.host_ecdh_ctx);
        ret = mbedtls_ecdh_setup(&ctx.host_ecdh_ctx, MBEDTLS_ECP_DP_SECP256K1);
        if (ret < 0) {
                return -1;
        }
        ret = mbedtls_ecdh_gen_public(&ctx.host_ecdh_ctx.grp, &ctx.host_ecdh_ctx.d, 
                        &ctx.host_ecdh_ctx.Q, genrand, NULL);
        if (ret < 0) {
                return -1;
        }

        printf("sts: ecdh keypair generated\n");

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, "master") == 0) {

                /* send AUTHREQ to slave 5 times every 5 sec */
                while (ctx.master_flag != 1 && count < 5) {
                        sts_msg_out = malloc(sizeof(STS_MSG_MAXLEN));
                        memset(sts_msg_out, 0, sizeof(STS_MSG_MAXLEN));
                        _concatenate(sts_msg_out, STS_AUTHREQ);
                        _concatenate(sts_msg_out, ctx.id_slave);
                        ret = _publish(sts_msg_out);
                        if (ret < 0) {
                                free(sts_msg_out);
                                printf("sts: error! auth failed\n");
                                return -1;
                        }
                        count++;
                        sleep(5);
                        if (count == 5) {
                                count = 0;
                                printf("sts: error! auth failed after 5 attempts\n");
                                return -1;
                        }
                }

                /* receive AUTHACK from slave */
                printf("sts: Received AUTHACK + Public Key from Slave\n");
                ctx.master_flag = 0;
        }

        /* SLAVE SIDE */
        if (strcmp(ctx.sts_mode, "slave") == 0) {
                /* receive AUTHREQ from master */
                while (1) {
                        if (ctx.slave_flag == 1) {
                                printf("sts: Authentification request received from master\n");
                                printf("sts: Verifying ID...\n");
                                if (strcmp(sts_msg_data, ctx.id_slave) == 0) {
                                        printf("sts: Verification OK!\n");
                                        ctx.slave_flag = 0;
                                        memset(sts_msg_data, 0, sizeof(sts_msg_data));
                                        break;

                                } else {
                                        printf("sts: Verification FAILURE! wrong ID\n");
                                        ctx.slave_flag = 0;
                                        memset(sts_msg_data, 0, sizeof(sts_msg_data));
                                        continue;
                                }
                        }
                }

                /* send AUTHACK + pubkey to master */
                printf("sts: Sending AUTHACK + Public Key...\n");
                sts_msg_out = malloc(sizeof(STS_MSG_MAXLEN));
                memset(sts_msg_out, 0, sizeof(STS_MSG_MAXLEN));
                sprintf(slave_QX, "%lu" , (uint64_t)*ctx.host_ecdh_ctx.Q.X.p);
                sprintf(slave_QY, "%lu" , (uint64_t)*ctx.host_ecdh_ctx.Q.Y.p);
                _concatenate(sts_msg_out, STS_AUTHACK);
                _concatenate(sts_msg_out, "X");
                _concatenate(sts_msg_out, slave_QX);
                _concatenate(sts_msg_out, "Y");
                _concatenate(sts_msg_out, slave_QY);

                ret = _publish(sts_msg_out);
                if (ret < 0) {
                        free(sts_msg_out);
                        printf("sts: error! Sending AUTHACK failed\n");
                        return -1;
                }
        }
        return 0;
}

static void _free_sec(void)
{
        mbedtls_ecdh_free(&ctx.host_ecdh_ctx);
}

int sts_start_session(char **argv)
{
        (void)argv;
        int ret = 0;
        if (ctx.status == STS_STARTED || ctx.client.isconnected == 1) {
                printf("sts: an sts session has already been started\n");
                return STS_PROMPT;
        }

        if (argv[1] == NULL) {
                printf("sts: error! config file missing\n");
                return STS_PROMPT;
        }

        ret = _init(argv[1]);
        if (ret < 0) {
                printf("sts: error! could not initialize\n");
                return STS_PROMPT;
        }

        ret = _connect(); 
        if (ret < 0) {
                printf("sts: error! could not connect to broker\n");
                _disconnect();
                return STS_PROMPT;
        }

        ret = _subscribe();
        if (ret < 0) {
                printf("sts: error! could not subscribe to broker, disconnecting...\n");
                _disconnect();
                return STS_PROMPT;
        }

        if (strcmp(ctx.sts_mode, "master") == 0 || strcmp(ctx.sts_mode, "slave") == 0) {
                ret = _init_sec();
                if (ret < 0) {
                        printf("sts: error! while initialization of security\n");
                        _disconnect();
                        _free_sec();
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
                printf("sts: error! no sts session currently active\n");
                return STS_PROMPT;
        }

        /* kill thread and give it time to close up */
        thrd_msg_type = STS_KILL_THREAD;
        sleep(1);

        ret = _unsubscribe();
        if (ret < 0) {
                printf("sts: error! could not unsubscribe from topic '%s'\n",ctx.topic_sub);
        }
        _disconnect();
        _free_sec();
        return STS_PROMPT;
}

int sts_send_test(char **message)
{
        int ret = 0;

        if (ctx.status == STS_STOPPED) {
                printf("sts: error! start an sts session first\n");
                return STS_PROMPT;
        }

        if (message[1] == NULL) {
                printf("sts: error! missing param -> 'send [MSG]'\n");
                return STS_PROMPT;
        }

        _prep_msg_out(message);

        MQTTMessage msg;
        msg.qos = ctx.qos;
        msg.payload = (void*)sts_msg_out;
        msg.payloadlen = strlen(sts_msg_out);
        msg.retained = ctx.is_retained;

        ret = MQTTPublish(&ctx.client, ctx.topic_pub, &msg);
        if (ret < 0) {
                free(sts_msg_out);
                _disconnect();
                return STS_PROMPT;
        }

        /* echo */
        printf("> [OUT]: %s\n", sts_msg_out);
        free(sts_msg_out);
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

int sts_status(char **argv)
{
        (void)argv;

        if (ctx.client.isconnected == 0 && ctx.status == STS_STOPPED) {
                printf("sts: status:          OFFLINE\n");
                return STS_PROMPT;
        }

        printf("sts: status:          ONLINE\n");
        printf("sts: id_master:       %s\n", ctx.id_master);
        printf("sts: id_slave:        %s\n", ctx.id_slave);
        printf("sts: sts_mode:        %s\n", ctx.sts_mode);
        printf("sts: mqtt version:    %u\n", ctx.mqtt_version);
        printf("sts: broker_ip:       %s\n", ctx.ip);
        printf("sts: broker_port:     %u\n", ctx.port);
        printf("sts: client_id:       %s\n", ctx.clientid);
        printf("sts: username:        %s\n", ctx.username);
        printf("sts: password:        %s\n", ctx.password);
        printf("sts: qos:             %u\n", ctx.qos);
        printf("sts: keep_alive:      %u\n", ctx.keep_alive);
        printf("sts: clean_session:   %u\n", ctx.clean_session);
        printf("sts: is_retained      %u\n", ctx.is_retained);
        printf("sts: publish_topic:   %s\n", ctx.topic_pub);
        printf("sts: subscribe_topic: %s\n", ctx.topic_sub);
        printf("sts: msg sent:        %u\n", ctx.msg_sent);
        printf("sts: msg received:    %u\n", ctx.msg_recv);

        return STS_PROMPT;
}

////////////////////////////////////////////////////////////////////////////////
/* STS CORE FUNCTIONS */
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
                /* parse the next argument and jump back to the top of while loop */
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
                /* child process, execute program by providing filename, vector argv */
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
                        /* wait for child process to finish by checking status */
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

        /* check if command equals a builtin function and execute it, if not then
         * launch a process */
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
