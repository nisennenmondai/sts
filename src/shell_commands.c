#include "log.h"
#include "mqtt.h"
#include "shell.h"
#include "sts.h"
#include "tools.h"

int sts_start_session(char **argv)
{
        (void)argv;
        int ret;
        struct sts_context *ctx;
        ctx = sts_get_ctx();

        if (ctx->status == STS_STARTED) {
                ERROR("sts: a session has already been started already\n");
                return STS_PROMPT;
        }

        if (argv[1] == NULL) {
                ERROR("sts: config file missing, start [PATH_TO_CONFIG]\n");
                return STS_PROMPT;
        }

        alarm(30); /* 30 seconds to start session or exit */
        sts_reset_ctx();
        ctx->pid = getpid();

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

        if (strcmp(ctx->sts_mode, STS_SECMASTER) == 0 || 
                        strcmp(ctx->sts_mode, STS_SECSLAVE) == 0) {
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
        alarm(0);
        return STS_PROMPT;
}

int sts_stop_session(char **argv)
{
        alarm(10); /* 10 seconds to stop session or exit */
        (void)argv;
        int ret;
        struct sts_context *ctx = sts_get_ctx();

        if (ctx->status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return STS_PROMPT;
        }

        /* flag -> if host rcv KILL msg from remote then no need to send KILL */
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
        sleep(2);

        ret = mqtt_unsubscribe();
        if (ret < 0) {
                ERROR("sts: could not unsubscribe from topic '%s'\n",
                                ctx->topic_sub);
        }
        mqtt_disconnect();
        sts_free_sec();
        sts_reset_ctx();
        alarm(0);
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
        INFO("sts: | broker_url:      %s\n", ctx->url);
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
                INFO("sts: | symmetric cipher:        AES-%s-256\n", ctx->aes);
                INFO("sts: +==========================================+\n");
        } else {
                INFO("sts: +==========================================+\n");
        }
        return STS_PROMPT;
}



int sts_test_send_nosec(char **message)
{
        int ret;
        int i = 1;
        size_t msg_size = 0;
        char msg_out[STS_MSG_MAXLEN];
        struct sts_context *ctx = sts_get_ctx();

        memset(msg_out, 0, sizeof(msg_out));

        if (ctx->status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return -1;
        }

        if (ctx->encryption == 1) {
                ERROR("sts: encryption ON, use 'sendenc' instead\n");
                return -1;
        }

        if (message[1] == NULL) {
                ERROR("sts: missing param -> 'send [MSG]'\n");
                return STS_PROMPT;
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
        char str[STS_DATASIZE];
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

        if (size > STS_DATASIZE) {
                ERROR("sts: message too big, size <= %d\n", STS_DATASIZE);
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

////////////////////////////////////////////////////////////////////////////////
/* IMPLEMENT YOUR FUNCTIONS HERE  -- read_sensor_x() ... */
////////////////////////////////////////////////////////////////////////////////
