SRC_DIR += ../../src
SRC_TST += ../ecdh_aes_ecp_256/ecdh_aes_ecp_256.c
SRC_STS += $(filter-out $(SRC_DIR)/shell.c, $(wildcard $(SRC_DIR)/*.c))

CFLAGS += -Wall
CFLAGS += -I../../include/
CFLAGS += -I../../lib/paho-mqtt/MQTTClient-C/src/
CFLAGS += -I../../lib/paho-mqtt/MQTTClient-C/src/linux/
CFLAGS += -I../../lib/paho-mqtt/MQTTPacket/src/
CFLAGS += -I../../lib/mbedtls/include/mbedtls/

LDLIBS += -lpaho-embed-mqtt3cc
LDLIBS += -lmbedcrypto
LDLIBS += -lpthread
LDLIBS += -lm

all:
	gcc $(SRC_STS) $(SRC_TST) $(CFLAGS) $(LDLIBS) -o ecdh_aes_ecp_256
