SRC_DIR += ../../src
SRC += ../enc_dec/tests.c
SRC_STS += $(filter-out $(SRC_DIR)/main.c, $(wildcard $(SRC_DIR)/*.c))

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
	gcc $(SRC_STS) $(SRC) $(CFLAGS) $(LDLIBS) -o enc_dec
