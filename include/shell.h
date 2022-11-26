#ifndef SHELL_H
#define SHELL_H

#include <sys/wait.h>

#define STS_TOK_BUFFSIZE 64
#define STS_RL_BUFFSIZE  1024
#define STS_TOK_DELIM    " \t\r\n\a"

#define STS_EXIT   0
#define STS_PROMPT 1

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
 * @brief               shell sig handler
 * @param signum        linux signal type
 * @return              null
 */
void sts_sig_handler(int signum);

/*
 * @brief               shell welcome message
 * @param               null
 * @return              null
 */
void sts_welcome(void);

/*
 * @brief               shell loop
 * @param               null
 * @return              null
 */
void sts_loop(void);

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

#endif /* SHELL_H */
