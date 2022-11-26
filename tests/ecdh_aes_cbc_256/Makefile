SRC1_DIR += ../../src
SRC2_DIR += src
OBJ_DIR += obj
BIN_DIR += bin

EXE += $(BIN_DIR)/ecdh_aes_cbc_256
SRC1 += $(filter-out $(SRC1_DIR)/main.c, $(wildcard $(SRC1_DIR)/*.c))
SRC2 += $(SRC2_DIR)/ecdh_aes_cbc_256.c

OBJ += $(SRC1:$(SRC1_DIR)/%.c=$(OBJ_DIR)/%.o)
OBJ += $(SRC2:$(SRC2_DIR)/%.c=$(OBJ_DIR)/%.o)

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

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC2_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC1_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rv $(BIN_DIR) $(OBJ_DIR)

-include $(OBJ:.o=.d)
