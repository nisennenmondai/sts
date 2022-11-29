#ifndef MQTT_H
#define MQTT_H

#include <stdlib.h>

#define STS_KILL_THREAD 1

#define READBUFFSIZE       1024
#define SENDBUFFSIZE       1024
#define COMMAND_TIMEOUT_MS 10000

/*
 * @brief       initialize network.
 */
void mqtt_init(void);

/*
 * @brief       connect to a mqtt broker.
 * @return      -1 if connection fails.
 */
int mqtt_connect(void);

/*
 * @brief       disconnect from a mqtt broker.
 * @return      -1 if disconnection fails.
 */
int mqtt_disconnect(void);

/*
 * @brief       subscribe to a topic.
 * @return      -1 if subscription fails.
 */
int mqtt_subscribe(void);

/*
 * @brief       unsubscribe from a topic.
 * @return      -1 if unsubscription fails.
 */
int mqtt_unsubscribe(void);

/*
 * @brief               publish to a topic.
 * @param string        message to publish.
 * @return              -1 if publish fails.
 */
int mqtt_publish(char *string);

/*
 * @brief               publish to a topic with aes-ecb mode
 * @param enc           encrypted data.
 * @param ecb_len       encrypted data length aligned with ecb blocksize.
 * @param str_size      size of original msg for the bin to hex func
 * @return              -1 if publish fails.
 */
int mqtt_publish_aes_ecb(unsigned char *enc, size_t ecb_len, int str_size);

/*
 * @brief               publish to a topic with aes-cbc mode
 * @param enc           encrypted data.
 * @param cbc_len       encrypted data length aligned with cbc blocksize.
 * @param str_size      size of original msg for the bin to hex func
 * @return              -1 if publish fails.
 */
int mqtt_publish_aes_cbc(unsigned char *enc, size_t cbc_len, int str_size);

#endif /* MQTT_H */
