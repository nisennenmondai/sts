#ifndef SHELL_H
#define SHELL_H

#include <sys/wait.h>

#define STS_TOK_BUFFSIZE 64
#define STS_RL_BUFFSIZE  1024
#define STS_TOK_DELIM    " \t\r\n\a"

#define STS_EXIT   0
#define STS_PROMPT 1

/*
 * @brief               shell
 * @param               null
 * @return              null
 */
void sts_shell(void);

#endif /* SHELL_H */
