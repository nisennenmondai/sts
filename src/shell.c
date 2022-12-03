#include <sys/wait.h>

#include "log.h"
#include "sts.h"
#include "shell.h"
#include "shell_commands.h"

#define STS_TOK_BUFFSIZE 64
#define STS_RL_BUFFSIZE  1024
#define STS_TOK_DELIM    " \t\r\n\a"

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

static int sts_num_builtins(void) 
{
        return sizeof(builtin_cmd) / sizeof(char *);
}

static int sts_help(char **argv)
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

static int sts_exit(char **argv)
{
        (void)argv;
        return STS_EXIT;
}

static int (*builtin_func[]) (char **argv) = {
        &sts_start_session,
        &sts_stop_session,
        &sts_status,
        &sts_test_send_nosec,
        &sts_test_send_sec,
        &sts_help,
        &sts_exit,
};

static char *sts_read_line(void)
{
        int c;
        int position = 0;
        int buffsize = STS_RL_BUFFSIZE;
        char *buffer = (char*)malloc(buffsize * sizeof(char));

        if (!buffer) {
                fprintf(stderr, "sts: allocation error\n");
                exit(EXIT_FAILURE);
        }

        /* read line */
        while (1) {
                c = getchar();

                if (c == EOF) {
                        fprintf(stderr, "sts: EOF, exiting...\n");
                        exit(EXIT_FAILURE);
                }

                if (c == '\n') {
                        buffer[position] = '\0';
                        return buffer;

                } else 
                        buffer[position] = c;

                position++;

                /* if we have exceeded the buffer, reallocate */
                if (position >= buffsize) {
                        buffsize += STS_RL_BUFFSIZE;
                        buffer = realloc(buffer, buffsize);

                        if (!buffer)
                                fprintf(stderr, "sts: allocation error\n");
                }
        }
}

static char **sts_split_line(char *line)
{
        int position;
        int buffsize;
        char *token;
        char **tokens;

        position = 0;
        buffsize = STS_TOK_BUFFSIZE;
        tokens = malloc(buffsize * sizeof(char*));

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
        pid_t pid;
        pid_t wpid;
        int status;
        (void)wpid;

        pid = fork();

        if (pid == 0) {
                /* child process, execute program by providing filename, vector 
                 * argv */
                if (execvp(argv[0], argv) == -1)
                        perror("sts");

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

        if (argv[0] == NULL)
                /* An empty command was entered. */
                return 1;

        /* check if command equals a builtin function and execute it, if not 
         * then launch a process */
        for (i = 0; i < sts_num_builtins(); i++) {
                if (strcmp(argv[0], builtin_cmd[i]) == 0) 
                        return (*builtin_func[i])(argv);
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

static void sts_sig_handler(int signum)
{
        struct sts_context *ctx;

        ctx = sts_get_ctx();

        if (signum == SIGINT) {
                INFO("sts: SIGINT Ctrl-C\n");

                if (ctx->status == STS_STARTED)
                        sts_stop_session(NULL);

                INFO("sts: exiting sts...\n");
                exit(EXIT_SUCCESS);
        }

        if (signum == SIGUSR1) {
                INFO("sts: closing session...\n");

                if (ctx->status == STS_STARTED)
                        sts_stop_session(NULL);
        }

        if (signum == SIGALRM) {
                INFO("sts: timer's up, exiting sts...\n");
                exit(EXIT_SUCCESS);
        }
}

void sts_shell(void)
{
        signal(SIGINT, sts_sig_handler);
        signal(SIGUSR1, sts_sig_handler);
        signal(SIGALRM, sts_sig_handler);

        sts_welcome();
        sts_loop();
}
