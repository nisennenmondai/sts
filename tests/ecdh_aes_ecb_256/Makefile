SRC_DIR += ../../src
OBJ_DIR += obj

EXE += ecdh_aes_ecb_256
SRC += $(filter-out $(SRC_DIR)/shell.c, $(wildcard $(SRC_DIR)/*.c))
SRC += ecdh_aes_ecb_256.c

OBJ += $(SRC:.c=.o)

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


.PHONY: all clean

all: $(EXE)
	mv $(SRC_DIR)/sec.o $(OBJ_DIR)
	mv $(SRC_DIR)/sts.o $(OBJ_DIR)
	mv $(SRC_DIR)/tools.o $(OBJ_DIR)
	mv $(SRC_DIR)/mqtt.o $(OBJ_DIR)
	mv $(SRC_DIR)/shell_commands.o $(OBJ_DIR)
	mv $(EXE).o $(OBJ_DIR)

$(EXE): $(OBJ) | $(OBJ_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rf $(OBJ_DIR) $(OBJ) $(EXE)

-include $(OBJ:.o=.d)
