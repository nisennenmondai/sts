#include <sys/wait.h>

#include "sts.h"
#include "log.h"
#include "tools.h"

////////////////////////////////////////////////////////////////////////////////
/* CORE SHELL */
////////////////////////////////////////////////////////////////////////////////
static char *builtin_cmd[] = {
        "start",
        "stop",
        "status",
        "send",
        "sendenc",
        "help",
        "exit",
};

static char *builtin_cmd_desc[] = {
        "start [CONFIG]    start STS session                          |",
        "stop              stop STS session                           |",
        "status            display status of current session          |",
        "send [MSG]        test send mqtt message                     |\n|"
                "                   example: 'send blah1 blah2 blah3'          |",
        "sendenc [MSG]     test send encrypted mqtt message           |\n|"
                "                   example: 'sendenc blah1 blah2'             |",
        "help              prints all commands                        |",
        "exit              exit shell                                 |",
};

static int (*builtin_func[]) (char **argv) = {
        &sts_start_session,
        &sts_stop_session,
        &sts_status,
        &sts_test_send_nosec,
        &sts_test_send_sec,
        &sts_help,
        &sts_exit,
};

static int sts_num_builtins(void) {
        return sizeof(builtin_cmd) / sizeof(char *);
}

static void _sig_hander(int signum)
{
        struct sts_context *ctx = sts_get_ctx();

        if (signum == SIGINT) {
                INFO("sts: SIGINT Ctrl-C\n");
                if (ctx->status == STS_STARTED) {
                        sts_stop_session(NULL);
                }
                exit(0);
        }

        if (signum == SIGUSR1) {
                INFO("sts: closing session now\n");
                if (ctx->status == STS_STARTED) {
                        sts_stop_session(NULL);
                }
        }
}

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
        int c;
        int position = 0;
        int buffsize = STS_RL_BUFFSIZE;
        char *buffer = (char*)malloc(buffsize * sizeof(char));

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
        int position = 0;
        int buffsize = STS_TOK_BUFFSIZE;
        char *token;
        char **tokens = malloc(buffsize * sizeof(char*));

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
        int status;
        (void)wpid;

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
        int status;
        char *line;
        char **argv;

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
/* STS COMMANDS */
////////////////////////////////////////////////////////////////////////////////
int sts_start_session(char **argv)
{
        (void)argv;
        int ret;
        struct sts_context *ctx = sts_get_ctx();
        ctx->pid = getpid();

        if (ctx->status == STS_STARTED) {
                ERROR("sts: a session has already been started already\n");
                return STS_PROMPT;
        }

        if (argv[1] == NULL) {
                ERROR("sts: config file missing, start [PATH_TO_CONFIG]\n");
                return STS_PROMPT;
        }

        ret = sts_init(argv[1]);
        if (ret < 0) {
                ERROR("sts: could not initialize session\n");
                return STS_PROMPT;
        }

        ret = mqtt_connect(); 
        if (ret < 0) {
                ERROR("sts: could not connect to broker\n");
                mqtt_disconnect();
                sts_reset_ctx();
                return STS_PROMPT;
        }

        ret = mqtt_subscribe();
        if (ret < 0) {
                ERROR("sts: could not subscribe to broker, disconnecting...\n");
                mqtt_disconnect();
                sts_reset_ctx();
                return STS_PROMPT;
        }

        if (strcmp(ctx->sts_mode, "master") == 0 || 
                        strcmp(ctx->sts_mode, "slave") == 0) {
                ret = sts_init_sec();
                if (ret < 0) {
                        ERROR("sts: while initializing security\n");
                        mqtt_disconnect();
                        sts_free_sec();
                        sts_reset_ctx();
                        return STS_PROMPT;
                }
        }
        ctx->status = STS_STARTED;
        return STS_PROMPT;
}

int sts_stop_session(char **argv)
{
        (void)argv;
        int ret;
        struct sts_context *ctx = sts_get_ctx();

        if (ctx->status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return STS_PROMPT;
        }

        /* flag -> if host rcv KILL msg from remote then no need to send KILL */
        if (ctx->encryption == 0 && strcmp(ctx->sts_mode, "nosec") == 0 && 
                        ctx->kill_flag == 0) {
                INFO("sts: Sending KILL to remote client\n");
                ctx->kill_flag = 1;
                ret = sts_send_nosec(STS_KILL);
                if (ret < 0) {
                        ERROR("sts: could not send KILL to remote client\n");
                }
        }

        if (ctx->encryption == 1 && ctx->kill_flag == 0) {
                INFO("sts: Sending KILL to remote client\n");
                ctx->kill_flag = 1;
                ret = sts_send_sec(STS_KILL);
                if (ret < 0) {
                        ERROR("sts: could not send KILL to remote client\n");
                }
        }

        /* kill thread and give it time to close up */
        ctx->thrd_msg_type = STS_KILL_THREAD;
        sleep(1);

        ret = mqtt_unsubscribe();
        if (ret < 0) {
                ERROR("sts: could not unsubscribe from topic '%s'\n",
                                ctx->topic_sub);
        }
        mqtt_disconnect();
        sts_free_sec();
        sts_reset_ctx();
        return STS_PROMPT;
}

int sts_send_nosec(char *str)
{
        int ret;
        struct sts_context *ctx = sts_get_ctx();

        if (ctx->status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return -1;
        }

        if (ctx->encryption == 1) {
                ERROR("sts: encryption ON, use 'send_sec()' instead\n");
                return -1;
        }

        ret = mqtt_publish(str);
        if (ret < 0) {
                ERROR("sts: mqtt_publish()\n");
                return -1;
        }
        return 0;
}


int sts_send_sec(char *str)
{
        int ret;
        size_t ecb_len = 0;
        unsigned char msg[STS_MSG_MAXLEN];
        unsigned char enc[STS_MSG_MAXLEN];
        struct sts_context *ctx = sts_get_ctx();

        if (ctx->status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return -1;
        }

        if(ctx->encryption == 0) {
                ERROR("sts: encryption OFF, use 'send_nosec()' instead\n");
                return -1;
        }

        memset(msg, 0, sizeof(msg));
        memset(enc, 0, sizeof(enc));

        memcpy(msg, str, strlen((char*)str));

        sts_encrypt_aes_ecb(&ctx->host_aes_ctx_enc, msg, enc, 
                        strlen((char*)msg), &ecb_len);

        ret = mqtt_publish_aes_ecb(enc, ecb_len);
        if (ret < 0) {
                ERROR("sts: mqtt_publish_aes_ecb()\n");
                return -1;
        }
        return 0;
}

int sts_test_send_nosec(char **message)
{
        int ret;
        int i = 1;
        size_t msg_size = 0;
        char msg_out[STS_MSG_MAXLEN];
        struct sts_context *ctx = sts_get_ctx();

        memset(msg_out, 0, sizeof(msg_out));

        if (message[1] == NULL) {
                ERROR("sts: missing param -> 'send [MSG]'\n");
                return STS_PROMPT;
        }

        if (ctx->status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return -1;
        }

        if (ctx->encryption == 1) {
                ERROR("sts: encryption ON, use 'sendenc' instead\n");
                return -1;
        }

        /* compute size of msg */
        while (message[i] != NULL) {
                msg_size += strlen(message[i] + 1);
                i++;
        }

        if (msg_size > STS_MSG_MAXLEN) {
                ERROR("sts: message too big, size <= %d\n", STS_MSG_MAXLEN);
                return STS_PROMPT;
        }

        /* copy */
        i = 1;
        while (message[i] != NULL) {
                concatenate(msg_out, message[i]);
                concatenate(msg_out, " ");
                i++;
        }

        ret = sts_send_nosec(msg_out);
        if (ret < 0) {
                ERROR("sts: sts_send_nosec() failed\n");
                return STS_PROMPT;
        }
        return STS_PROMPT;
}

int sts_test_send_sec(char **message)
{
        int ret;
        size_t i = 1;
        size_t size = 0;
        char str[STS_MSG_MAXLEN];
        struct sts_context *ctx = sts_get_ctx();

        memset(str, 0, sizeof(str));

        if (ctx->status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return STS_PROMPT;
        }

        if(ctx->encryption == 0) {
                ERROR("sts: encryption OFF, use 'send' instead\n");
                return STS_PROMPT;
        }

        if (message[1] == NULL) {
                ERROR("sts: missing param -> 'sendenc [MSG]'\n");
                return STS_PROMPT;
        }

        /* compute size of msg */
        while (message[i] != NULL) {
                size += strlen(message[i]);
                i++;
        }

        if (size > STS_MSG_MAXLEN) {
                ERROR("sts: message too big, size <= %d\n", STS_MSG_MAXLEN);
                return STS_PROMPT;
        }

        i = 1;
        while (message[i] != NULL) {
                concatenate(str, message[i]);
                concatenate(str, " ");
                i++;
        }

        ret = sts_send_sec(str);
        if (ret < 0) {
                ERROR("sts: sts_send_sec() failed\n");
                return STS_PROMPT;
        }
        return STS_PROMPT;
}

int sts_status(char **argv)
{
        (void)argv;
        struct sts_context *ctx = sts_get_ctx();

        if (ctx->status == STS_STOPPED) {
                INFO("sts: status:          OFFLINE\n");
                return STS_PROMPT;
        }

        INFO("sts: status:            ONLINE\n");
        INFO("sts: +==========================================+\n");
        INFO("sts: | MQTT                                     |\n");
        INFO("sts: +==========================================+\n");
        INFO("sts: | mqtt version:    %u\n", ctx->mqtt_version);
        INFO("sts: | broker_ip:       %s\n", ctx->ip);
        INFO("sts: | broker_port:     %u\n", ctx->port);
        INFO("sts: | username:        %s\n", ctx->username);
        INFO("sts: | password:        %s\n", ctx->password);
        INFO("sts: | sub_topic:       %s\n", ctx->topic_sub);
        INFO("sts: | pub_topic:       %s\n", ctx->topic_pub);
        INFO("sts: | qos:             %u\n", 0);
        INFO("sts: | clean_session:   %u\n", 1);
        INFO("sts: | client_id:       %s\n", ctx->clientid);
        INFO("sts: +==========================================+\n");
        INFO("sts: | STS                                      |\n");
        INFO("sts: +==========================================+\n");
        INFO("sts: | sts_mode:        %s\n", ctx->sts_mode);

        if (ctx->encryption == 1) {
                INFO("sts: | id_master:       %s\n", ctx->id_master);
                INFO("sts: | id_slave:        %s\n", ctx->id_slave);
        }
        INFO("sts: | msg sent:        %u\n", ctx->msg_sent);
        INFO("sts: | msg recv:        %u\n", ctx->msg_recv);

        if (ctx->encryption == 1) {
                INFO("sts: +==========================================+\n");
                INFO("sts: | ENCRYPTION                               |\n");
                INFO("sts: +==========================================+\n");
                INFO("sts: | key agreement protocole: ECDH\n");
                INFO("sts: | elliptic curve:          SECP256K1\n");
                INFO("sts: | encryption:              AES-ECB-256\n");
                INFO("sts: +==========================================+\n");
        } else {
                INFO("sts: +==========================================+\n");
        }
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

int main(void)
{
        signal(SIGINT, _sig_hander);
        signal(SIGUSR1, _sig_hander);
        sts_welcome();
        sts_loop();
        return 0;
}

////////////////////////////////////////////////////////////////////////////////
/* IMPLEMENT YOUR FUNCTIONS HERE  -- read_sensor_x() ... */
////////////////////////////////////////////////////////////////////////////////
