#ifndef SHELL_COMMANDS_H
#define SHELL_COMMANDS_H

/*
 * @brief               print sts status in shell.
 * @param argv          null.
 * @return              STS_PROMPT.
 */
int sts_status(char **argv);

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

#endif /* SHELL_COMMANDS_H */
