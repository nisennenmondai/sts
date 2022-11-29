#include "log.h"
#include "sec.h"
#include "mqtt.h"
#include "tools.h"

static struct sts_context ctx = {
        .port           = 0,
        .no_print_out   = 0,
        .no_print_inc   = 0,
        .msg_sent       = 0,
        .msg_recv       = 0,
        .thrd_msg_type  = 0,
        .encryption     = 0,
        .kill_flag      = 0,
        .status         = STS_STOPPED,
        .master_flag    = STS_STEP_0,
        .slave_flag     = STS_STEP_0,
};

static void _extract_pubkey(char *X, char *Y, struct sts_message *msg)
{
        int i;
        int idx_X;
        int idx_Y;

        idx_X = 0;
        idx_Y = 0;

        /* extract slave public key X */
        for (i = 0; i < STS_DATASIZE; i++) {
                if (msg->data[i] == 'Y') {
                        idx_X = idx_X - 1;
                        break;
                }
                idx_X++;
        }
        memcpy(X, &msg->data[1], idx_X * sizeof(char));

        /* extract slave public key Y */
        for (i = idx_X + 2; i < STS_DATASIZE; i++) {
                if (msg->data[i] == '\0') {
                        idx_Y = idx_Y + 1;
                        break;
                }
                idx_Y++;
        }
        memcpy(Y, &msg->data[idx_X + 2], idx_Y * sizeof(char));
}

int sts_load_config(const char *config)
{
        FILE *fp;
        char cmp[2] = {0};
        char key[CONF_KEY_MAXLEN] = {0};
        char value[CONF_VAL_MAXLEN] = {0};

        fp = fopen(config, "r");

        if (fp == NULL) {
                ERROR("sts: while opening config file -> start [FILE]\n");
                return -1;
        }

        while (fscanf(fp, "%s %s %s ", key, cmp, value) != EOF) {

                if (strcmp(key, "url") == 0) {
                        strcpy(ctx.url, value);
                } else if (strcmp(key, "port") == 0) {
                        ctx.port = atoi(value);

                } else if (strcmp(key, "username") == 0) {
                        strcpy(ctx.username, value);

                } else if (strcmp(key, "password") == 0) {
                        strcpy(ctx.password, value);

                } else if (strcmp(key, "subtop") == 0) {
                        strcpy(ctx.topic_sub, value);

                } else if (strcmp(key, "pubtop") == 0) {
                        strcpy(ctx.topic_pub, value);

                } else if (strcmp(key, "clientid") == 0) {
                        strcpy(ctx.clientid, value);

                } else if (strcmp(key, "sts_mode") == 0) {

                        /* if nosec mode then aes = null */
                        if (strcmp(value,STS_NOSEC) == 0) {
                                strcpy(ctx.sts_mode, value);
                                strcpy(ctx.aes, AES_NULL);
                                fclose(fp);
                                config = NULL;
                                return 0;

                        } else if (strcmp(value, STS_SECMASTER) == 0) {
                                strcpy(ctx.sts_mode, value);

                        } else if (strcmp(value, STS_SECSLAVE) == 0) {
                                strcpy(ctx.sts_mode, value);

                        } else {
                                ERROR("sts: wrong value for sts_mode "
                                                "nosec | master | slave\n");
                                fclose(fp);
                                config = NULL;
                                return -1;
                        }

                } else if (strcmp(key, "aes") == 0) {

                        if (strcmp(value, AES_NULL) == 0) {
                                strcpy(ctx.aes, value);

                        } else if (strcmp(value, AES_ECB) == 0) {
                                strcpy(ctx.aes, value);

                        } else if (strcmp(value, AES_CBC) == 0) {
                                strcpy(ctx.aes, value);

                        } else {
                                ERROR("sts: wrong value for aes "
                                                "null | ecb | cbc\n");
                                fclose(fp);
                                config = NULL;
                                return -1;
                        }

                } else {
                        ERROR("sts: wrong key(s) in config file, please "
                                        "check 'config_' examples\n");
                        fclose(fp);
                        config = NULL;
                        return -1;
                }
        }
        fclose(fp);
        config = NULL;
        return 0;
}

void sts_parse_msg(char *inc, struct sts_message *msg)
{
        size_t i;
        int idx;

        idx = 0;

        /* extract header */
        for (i = 0; i < STS_HEADERSIZE; i++) {
                msg->header[i] = inc[i];
                if (msg->header[i] == ':') {
                        idx = i + 1;
                        break;
                }
        }

        /* extract data */
        for (i = 0; i < STS_DATASIZE; i++) {
                if (inc[idx + i] != '\0')
                        msg->data[i] = inc[idx + i];

                if (inc[idx + i] == '\0') 
                        break;
        }
}

void sts_msg_handlers(struct sts_message *msg)
{
        int ret;

        /* SLAVE SIDE */
        if (strcmp(ctx.sts_mode, STS_SECSLAVE) == 0) {

                /* receive KILL from master */
                if (strcmp(msg->header, STS_KILL) == 0 && ctx.encryption == 1) {
                        ctx.kill_flag = 1;
                        ctx.no_print_inc = 1;
                        INFO("sts: Received KILL from master\n");
                        kill(ctx.pid, SIGUSR1);
                }

                /* receive INITREQ from master */
                if (strcmp(msg->header, STS_INITREQ) == 0 && 
                                strcmp(msg->data, "request") == 0 &&
                                ctx.slave_flag == STS_STEP_0) {
                        TRACE("sts: Received INITREQ from master\n");
                        ctx.slave_flag = STS_STEP_1;
                        return;
                }

                /* receive KEYREQ from master */
                if (strcmp(msg->header, STS_KEYREQ) == 0 && 
                                ctx.slave_flag == STS_STEP_1) {
                        char master_QX[MPI_STRING_SIZE];
                        char master_QY[MPI_STRING_SIZE];

                        memset(master_QX, 0, sizeof(master_QX));
                        memset(master_QY, 0, sizeof(master_QY));

                        _extract_pubkey(master_QX, master_QY, msg);
                        ret = sts_compute_shared_secret(master_QX, master_QY, 
                                        &ctx);
                        if (ret != 0) {
                                ERROR("sts: _sts_compute_shared_secret()\n");
                                return;
                        }

                        TRACE("sts: Received KEYREQ from master\n");
                        ctx.slave_flag = STS_STEP_2;
                        return;
                }

                /* receive KEYACK from master */
                if (strcmp(msg->header, STS_KEYACK) == 0 && 
                                ctx.slave_flag == STS_STEP_2 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Received KEYACK from master\n");
                        ctx.slave_flag = STS_STEP_3;
                        return;
                }
        }

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, STS_SECMASTER) == 0) {

                /* receive KILL from slave */
                if (strcmp(msg->header, STS_KILL) == 0 && ctx.encryption == 1) {
                        ctx.kill_flag = 1;
                        ctx.no_print_inc = 1;
                        INFO("sts: Received KILL from slave\n");
                        kill(ctx.pid, SIGUSR1);
                        return;
                }

                /* receive INITACK from slave */
                if (strcmp(msg->header, STS_INITACK) == 0 && 
                                ctx.master_flag == STS_STEP_0 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Receive INITACK from slave\n");
                        ctx.master_flag = STS_STEP_1;
                        return;
                }

                /* receive KEYACK from slave */
                if (strcmp(msg->header, STS_KEYACK) == 0 && 
                                ctx.master_flag == STS_STEP_1 && 
                                msg->data[0] == '\0') {
                        TRACE("sts: Received KEYACK from slave\n");
                        ctx.master_flag = STS_STEP_2;
                        return;
                }

                /* receive KEYREQ from slave */
                if (strcmp(msg->header, STS_KEYREQ) == 0 && 
                                ctx.master_flag == STS_STEP_2) {
                        char slave_QX[MPI_STRING_SIZE];
                        char slave_QY[MPI_STRING_SIZE];

                        memset(slave_QX, 0, sizeof(slave_QX));
                        memset(slave_QY, 0, sizeof(slave_QY));

                        _extract_pubkey(slave_QX, slave_QY, msg);
                        ret = sts_compute_shared_secret(slave_QX, slave_QY, 
                                        &ctx);
                        if (ret != 0) {
                                ERROR("sts: _sts_compute_shared_secret()\n");
                                return;
                        }

                        TRACE("sts: Received KEYREQ from slave\n");
                        ctx.master_flag = STS_STEP_3;
                        return;
                }
        }
}

int sts_init(const char *config)
{
        int ret;

        sts_reset_ctx();
        ret = sts_load_config(config);

        if (ret < 0)
                return -1;

        mqtt_init();
        return 0;
}

int sts_init_sec(void)
{
        int ret;
        size_t olen;
        char msg_out[STS_MSG_MAXLEN];
        char slave_QX[MPI_STRING_SIZE];
        char slave_QY[MPI_STRING_SIZE];
        char master_QX[MPI_STRING_SIZE];
        char master_QY[MPI_STRING_SIZE];

        ctx.master_flag = STS_STEP_0;
        ctx.slave_flag = STS_STEP_0;

        olen = 0;

        memset(msg_out, 0, sizeof(msg_out));
        memset(slave_QX, 0, sizeof(slave_QX));
        memset(slave_QY, 0, sizeof(slave_QY));
        memset(master_QX, 0, sizeof(master_QX));
        memset(master_QY, 0, sizeof(master_QY));

        mbedtls_aes_init(&ctx.host_aes_ctx_dec);
        mbedtls_aes_init(&ctx.host_aes_ctx_enc);
        mbedtls_ecdh_init(&ctx.host_ecdh_ctx);

        ret = mbedtls_ecdh_setup(&ctx.host_ecdh_ctx, MBEDTLS_ECP_DP_CURVE25519);

        if (ret != 0) {
                ERROR("sts: mbedtls_ecdh_setup()\n");
                return -1;
        }

        ret = mbedtls_ecdh_gen_public(&ctx.host_ecdh_ctx.grp, 
                        &ctx.host_ecdh_ctx.d, &ctx.host_ecdh_ctx.Q, 
                        sts_drbg, NULL);
        if (ret != 0) {
                ERROR("sts: mbedtls_ecdh_gen_public()\n");
                return -1;
        }

        /* MASTER SIDE */
        if (strcmp(ctx.sts_mode, STS_SECMASTER) == 0) {
                /* send INITREQ to slave */
                TRACE("sts: Sending INITREQ to slave\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_INITREQ);
                concatenate(msg_out, "request");

                ctx.no_print_out = 1;
                ret = mqtt_publish(msg_out);

                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait INITACK from slave */
                TRACE("sts: Waiting INITACK from slave\n");
                while (ctx.master_flag == STS_STEP_0);


                /* send KEYREQ to slave */
                TRACE("sts: Sending KEYREQ to slave...\n");
                memset(msg_out, 0, sizeof(msg_out));
                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.X, 16, 
                                master_QX, MPI_STRING_SIZE, &olen);

                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }

                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.Y, 16, 
                                master_QY, MPI_STRING_SIZE, &olen);
                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }
                concatenate(msg_out, STS_KEYREQ);
                concatenate(msg_out, "X");
                concatenate(msg_out, master_QX);
                concatenate(msg_out, "Y");
                concatenate(msg_out, master_QY);

                ctx.no_print_out = 1;
                ret = mqtt_publish(msg_out);

                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait KEYACK from slave */
                TRACE("sts: Waiting KEYACK from slave\n");
                while (ctx.master_flag == STS_STEP_1);

                /* wait KEYREQ from slave */
                TRACE("sts: Waiting KEYREQ from slave\n");
                while (ctx.master_flag == STS_STEP_2);

                /* send KEYACK to slave */
                TRACE("sts: Sending KEYACK to slave\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_KEYACK);

                ctx.no_print_out = 1;
                ret = mqtt_publish(msg_out);

                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                ctx.encryption = 1;
                INFO("sts: Encryption established with slave\n");
                return 0;
        }

        /* SLAVE SIDE */
        if (strcmp(ctx.sts_mode, STS_SECSLAVE) == 0) {
                /* wait INITREQ from master */
                TRACE("sts: Waiting INITREQ from master\n");
                while (ctx.slave_flag == STS_STEP_0);

                /* send INITACK to master */
                TRACE("sts: Sending INITACK to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_INITACK);

                ctx.no_print_out = 1;
                ret = mqtt_publish(msg_out);

                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait KEYREQ from master */
                TRACE("sts: Waiting KEYREQ from master\n");
                while (ctx.slave_flag == STS_STEP_1);

                /* send KEYACK to master */
                TRACE("sts: Sending KEYACK to master\n");
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_KEYACK);

                ctx.no_print_out = 1;
                ret = mqtt_publish(msg_out);

                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* send KEYREQ */
                TRACE("sts: Sending KEYREQ to master\n");
                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.X, 16, 
                                slave_QX, MPI_STRING_SIZE, &olen);
                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }

                ret = mbedtls_mpi_write_string(&ctx.host_ecdh_ctx.Q.Y, 16, 
                                slave_QY, MPI_STRING_SIZE, &olen);

                if (ret != 0) {
                        ERROR("sts: mbedtls_mpi_write_string()\n");
                        return -1;
                }
                memset(msg_out, 0, sizeof(msg_out));
                concatenate(msg_out, STS_KEYREQ);
                concatenate(msg_out, "X");
                concatenate(msg_out, slave_QX);
                concatenate(msg_out, "Y");
                concatenate(msg_out, slave_QY);

                ctx.no_print_out = 1;
                ret = mqtt_publish(msg_out);

                if (ret < 0) {
                        ERROR("sts: mqtt_publish()\n");
                        return -1;
                }

                /* wait KEYACK from master */
                TRACE("sts: Waiting KEYACK from master\n");
                while (ctx.slave_flag == STS_STEP_2);

                /* wait for master to finish */
                sleep(1);
                ctx.encryption = 1;
                INFO("sts: Encryption established with master\n");
                return 0;
        }
        return 0;
}

void sts_free_sec(void)
{
        mbedtls_aes_free(&ctx.host_aes_ctx_enc);
        mbedtls_aes_free(&ctx.host_aes_ctx_dec);
        mbedtls_ecdh_free(&ctx.host_ecdh_ctx);
}

void sts_reset_ctx(void)
{
        ctx.port          = 0;
        ctx.no_print_out  = 0;
        ctx.no_print_inc  = 0;
        ctx.msg_sent      = 0;
        ctx.msg_recv      = 0;
        ctx.thrd_msg_type = 0;
        ctx.encryption    = 0;
        ctx.kill_flag     = 0;
        ctx.status        = STS_STOPPED;
        ctx.master_flag   = STS_STEP_0;
        ctx.slave_flag    = STS_STEP_0;
        memset(ctx.derived_key, 0, sizeof(ctx.derived_key));
        memset(ctx.topic_sub,   0, sizeof(ctx.topic_sub));
        memset(ctx.topic_pub,   0, sizeof(ctx.topic_pub));
        memset(ctx.clientid,    0, sizeof(ctx.clientid));
        memset(ctx.username,    0, sizeof(ctx.username));
        memset(ctx.password,    0, sizeof(ctx.password));
        memset(ctx.sts_mode,    0, sizeof(ctx.sts_mode));
        memset(ctx.aes,         0, sizeof(ctx.aes));
        memset(ctx.url,         0, sizeof(ctx.url));
}

int sts_send_nosec(char *str)
{
        int ret;

        if (ctx.status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return -1;
        }

        if (ctx.encryption == 1) {
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
        size_t ecb_len;
        size_t cbc_len;
        unsigned char msg[STS_MSG_MAXLEN];
        unsigned char enc[STS_MSG_MAXLEN];

        ecb_len = 0;
        cbc_len = 0;

        memset(msg, 0, sizeof(msg));
        memset(enc, 0, sizeof(enc));

        if (ctx.status == STS_STOPPED) {
                ERROR("sts: session not started\n");
                return -1;
        }

        if(ctx.encryption == 0) {
                ERROR("sts: encryption OFF, use 'send_nosec()' instead\n");
                return -1;
        }

        if (ctx.kill_flag == 1) {
                ctx.no_print_out = 1;
                /* if sending a KILL msg, don't add ENC header */
                concatenate((char*)msg, str);

        } else {
                concatenate((char*)msg, STS_ENC);
                concatenate((char*)msg, str);
        }

        if (strcmp(ctx.aes, AES_ECB) == 0) {
                ret = sts_encrypt_aes_ecb(&ctx.host_aes_ctx_enc, msg,
                                enc, strlen((char*)msg), &ecb_len);
                if (ret != 0) {
                        ERROR("sts: sts_encrypt_aes_ecb()\n");
                        return -1;
                }

                ret = mqtt_publish_aes_ecb(enc, ecb_len, strlen((char*)msg));

                if (ret < 0) {
                        ERROR("sts: mqtt_publish_aes_ecb()\n");
                        return -1;
                }
        }

        if (strcmp(ctx.aes, AES_CBC) == 0) {
                ret = sts_encrypt_aes_cbc(&ctx.host_aes_ctx_enc,
                                ctx.derived_key, msg, enc,
                                strlen((char*)msg), &cbc_len);
                if (ret != 0) {
                        ERROR("sts: sts_encrypt_aes_cbc()\n");
                        return -1;
                }

                ret = mqtt_publish_aes_cbc(enc, cbc_len, strlen((char*)msg));

                if (ret < 0) {
                        ERROR("sts: mqtt_publish_aes_cbc()\n");
                        return -1;
                }
        }
        return 0;
}

struct sts_context *sts_get_ctx(void)
{
        return &ctx;
}
