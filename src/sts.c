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
        .msg_sent       = 0,
        .msg_recv       = 0,
};

static unsigned char sendbuff[SENDBUFFSIZE];
static unsigned char readbuff[READBUFFSIZE];

static unsigned int thrd_msg_type = 0;
static pthread_t _mqttyield_thrd_pid;

static char *sts_msg_inc = NULL;
static char *sts_msg_out = NULL;


////////////////////////////////////////////////////////////////////////////////
/* STS COMMANDS LISTS */
////////////////////////////////////////////////////////////////////////////////
char *builtin_cmd[] = {
        "help",
        "exit",
        "start",
        "stop",
        "send",
        "status",
        "sectest",
};

char *builtin_cmd_desc[] = {
        "help              prints all commands                        |",
        "exit              exit shell                                 |",
        "start [CONFIG]    start STS session                          |",
        "stop              stop STS session                           |",
        "send [MSG]        send a message to the broker               |",
        "                  example: 'send blah1 blah2 blah3'          |\n| "
                "status            display status of current session          |",
        "sectest [MSG]     ecdh aes enc/dec test (no space)           |",
};

int (*builtin_func[]) (char **argv) = {
        &sts_help,
        &sts_exit,
        &sts_start_session,
        &sts_stop_session,
        &sts_send,
        &sts_status,
        &sts_ecdh_aes_test,
};

int sts_num_builtins(void) {
        return sizeof(builtin_cmd) / sizeof(char *);
}

////////////////////////////////////////////////////////////////////////////////
/* STS COMMANDS */
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

static void _on_msg_recv(MessageData *data)
{
        _prep_msg_inc(data);
        printf("[INC]: %s\n", sts_msg_inc);
        ctx.msg_recv++;
        free(sts_msg_inc);
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
        char comp[2] = {0};
        char value[CONFIG_VALUE_MAXLENGTH] = {0};

        while (fscanf(fp, "%s %s %s ", key, comp, value) != EOF) {
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
                                printf("sts: error! wrong value for sts_mode set to nosec by default\n");
                                strcpy(ctx.sts_mode, "nosec");
                        }
                } else if (strcmp(key, "sts_id") == 0) {
                        strcpy(ctx.sts_id, value);
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

static int _init_sec(void)
{
        int ret;
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
         /* TODO establish authentification protocole between master slave using
          * sts_id */
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

int sts_send(char **message)
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
        printf("sts: sts_id:          %s\n", ctx.sts_id);
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
