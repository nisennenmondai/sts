#include "shell.h"

int main(void)
{
        signal(SIGINT, sts_sig_handler);
        signal(SIGUSR1, sts_sig_handler);
        signal(SIGALRM, sts_sig_handler);

        sts_welcome();
        sts_loop();

        return 0;
}
