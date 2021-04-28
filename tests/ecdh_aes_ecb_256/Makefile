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

LDLIBS += -L../../lib/paho-mqtt/MQTTClient-C/src/ -lpaho-embed-mqtt3cc
LDLIBS += -L../../lib/mbedtls/library/ -lmbedcrypto
LDLIBS += -lpthread
LDLIBS += -lm


.PHONY: all clean

all: $(EXE)
	mv $(SRC_DIR)/*.o $(OBJ_DIR)
	mv *.o $(OBJ_DIR)

$(EXE): $(OBJ) | $(OBJ_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rf $(OBJ_DIR) $(OBJ) $(EXE) 

-include $(OBJ:.o=.d)
