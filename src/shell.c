#include <stdio.h>
#include <sys/wait.h>

#include "sts.h"
#include "log.h"

////////////////////////////////////////////////////////////////////////////////
/* VARIABLES */
////////////////////////////////////////////////////////////////////////////////
static char *builtin_cmd[] = {
        "help",
        "exit",
        "start",
        "stop",
        "status",
        "send",
};

static char *builtin_cmd_desc[] = {
        "help              prints all commands                        |",
        "exit              exit shell                                 |",
        "start [CONFIG]    start STS session                          |",
        "stop              stop STS session                           |",
        "                  example: 'send blah1 blah2 blah3'          |\n| "
                "status            display status of current session          |",
        "send [MSG]        send a message to the broker               |",
};

static int (*builtin_func[]) (char **argv) = {
        &sts_help,
        &sts_exit,
        &sts_start_session,
        &sts_stop_session,
        &sts_status,
        &sts_send,
};

static int sts_num_builtins(void) {
        return sizeof(builtin_cmd) / sizeof(char *);
}

////////////////////////////////////////////////////////////////////////////////
/* COMMANDS */
////////////////////////////////////////////////////////////////////////////////
int sts_start_session(char **argv)
{
        struct sts_context *ctx = sts_get_ctx();
        (void)argv;
        int ret = 0;
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

int sts_send(char **message)
{
        int ret = 0;
        int i = 1;
        size_t msg_size = 0;
        char msg_out[STS_MSG_MAXLEN];
        MQTTMessage msg;
        memset(msg_out, 0, sizeof(msg_out));
        struct sts_context *ctx = sts_get_ctx();

        /* compute size of msg */
        while (message[i] != NULL) {
                msg_size += strlen(message[i] + 1);
                i++;
        }

        if (ctx->status == STS_STOPPED) {
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
                sts_concatenate(msg_out, message[i]);
                sts_concatenate(msg_out, " ");
                i++;
        }

        msg.qos = ctx->qos;
        msg.payload = (void*)msg_out;
        msg.payloadlen = strlen(msg_out);
        msg.retained = ctx->is_retained;

        ret = MQTTPublish(&ctx->client, ctx->topic_pub, &msg);
        if (ret < 0) {
                mqtt_disconnect();
                return STS_PROMPT;
        }
        /* echo */
        INFO("[MQTT_OUT]: %s\n", msg_out);
        ctx->msg_sent++;
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
        struct sts_context *ctx = sts_get_ctx();

        if (ctx->status == STS_STOPPED) {
                INFO("sts: status:          OFFLINE\n");
                return STS_PROMPT;
        }

        INFO("sts: status:          ONLINE\n");
        INFO("sts: id_master:       %s\n", ctx->id_master);
        INFO("sts: id_slave:        %s\n", ctx->id_slave);
        INFO("sts: sts_mode:        %s\n", ctx->sts_mode);
        INFO("sts: mqtt version:    %u\n", ctx->mqtt_version);
        INFO("sts: broker_ip:       %s\n", ctx->ip);
        INFO("sts: broker_port:     %u\n", ctx->port);
        INFO("sts: client_id:       %s\n", ctx->clientid);
        INFO("sts: username:        %s\n", ctx->username);
        INFO("sts: password:        %s\n", ctx->password);
        INFO("sts: qos:             %u\n", ctx->qos);
        INFO("sts: keep_alive:      %u\n", ctx->keep_alive);
        INFO("sts: clean_session:   %u\n", ctx->clean_session);
        INFO("sts: is_retained      %u\n", ctx->is_retained);
        INFO("sts: pub_topic:       %s\n", ctx->topic_pub);
        INFO("sts: sub_topic:       %s\n", ctx->topic_sub);
        INFO("sts: msg sent:        %u\n", ctx->msg_sent);
        INFO("sts: msg recv:        %u\n", ctx->msg_recv);
        if (strcmp(ctx->sts_mode, "master") == 0) {
               sts_print_derived_key(ctx->derived_key, sizeof(ctx->derived_key));

        }
        if (strcmp(ctx->sts_mode, "slave") == 0) {
                sts_print_derived_key(ctx->derived_key, sizeof(ctx->derived_key));
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

int main(void)
{
        sts_welcome();
        sts_loop();
        return 0;
}