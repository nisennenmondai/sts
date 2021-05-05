#include "log.h"
#include "mqtt.h"
#include "sts.h"

#define NUMBER_TESTS 5

void mqtt_test(void)
{
        TESTS("+================================================+\n");
        TESTS("|                     MQTT                       |\n");
        TESTS("+================================================+\n");

        int ret;
        int count = 0;
        struct sts_context *ctx;

        ctx = sts_get_ctx();
        ctx->no_print = 1;
        ctx->pid = getpid();

        sts_load_config("config_nosec");
        mqtt_init();
        ret = mqtt_connect();
        if (ret == 0) {
                count++;
                TESTS("test 1.0: mqtt_connect() OK!\n");
        } else {
                TESTS("test 1.0: mqtt_connect() FAILED!\n");

        }

        ret = mqtt_subscribe();
        if (ret == 0) {
                count++;
                TESTS("test 2.0: mqtt_subscribe() OK!\n");
        } else {
                TESTS("test 2.0: mqtt_subscribe() FAILED!\n");

        }

        ret = mqtt_publish("Hello World!");
        if (ret == 0) {
                count++;
                TESTS("test 3.0: mqtt_publish() OK!\n");
        } else {
                TESTS("test 3.0: mqtt_publish() FAILED!\n");

        }

        /* kill thread and give it time to close up */
        ctx->thrd_msg_type = STS_KILL_THREAD;
        sleep(2);

        ret = mqtt_unsubscribe();
        if (ret == 0) {
                count++;
                TESTS("test 4.0: mqtt_unsubscribe() OK!\n");
        } else {
                TESTS("test 4.0: mqtt_unsubscribe() FAILED!\n");

        }

        ret = mqtt_disconnect();
        if (ret == 0) {
                count++;
                TESTS("test 5.0: mqtt_disconnect() OK!\n\n");
        } else {
                TESTS("test 5.0: mqtt_disconnect() FAILED!\n\n");

        }

        if (count == NUMBER_TESTS) {
                TESTS("TESTS PASSED: %d/%d\n", count, NUMBER_TESTS);
        } else {
                TESTS("TESTS FAILED: %d/%d\n", count, NUMBER_TESTS);
        }
}

int main(void)
{
        mqtt_test();
}
