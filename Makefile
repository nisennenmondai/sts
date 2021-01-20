SRC_DIR += src
OBJ_DIR += obj
BIN_DIR += bin

EXE += $(BIN_DIR)/sts
SRC += $(wildcard $(SRC_DIR)/*.c)
OBJ += $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CFLAGS += -Wall
CFLAGS += -Iinclude/
CFLAGS += -Ilib/paho-mqtt/MQTTClient-C/src/
CFLAGS += -Ilib/paho-mqtt/MQTTClient-C/src/linux/
CFLAGS += -Ilib/paho-mqtt/MQTTPacket/src/
CFLAGS += -Ilib/mbedtls/include/mbedtls/
LDLIBS += -lpaho-embed-mqtt3cc
LDLIBS += -lmbedcrypto
LDLIBS += -lpthread

.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

clean:
	@$(RM) -rv $(BIN_DIR) $(OBJ_DIR)

-include $(OBJ:.o=.d)
