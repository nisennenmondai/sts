SRC_DIR += src
OBJ_DIR += obj
BIN_DIR += bin

EXE += $(BIN_DIR)/sts
SRC += $(wildcard $(SRC_DIR)/*.c)
OBJ += $(SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

CFLAGS += -g
CFLAGS += -MD
CFLAGS += -Wall
CFLAGS += -Iinclude/
CFLAGS += -Ilib/paho-mqtt/MQTTClient-C/src/
CFLAGS += -Ilib/paho-mqtt/MQTTClient-C/src/linux/
CFLAGS += -Ilib/paho-mqtt/MQTTPacket/src/
CFLAGS += -Ilib/mbedtls/include/

LDLIBS += -lm
LDLIBS += -lpthread
LDLIBS += -L$(PWD)/lib/paho-mqtt/MQTTClient-C/src -lpaho-embed-mqtt3cc
LDLIBS += -L$(PWD)/lib/mbedtls/library -lmbedcrypto
LDLIBS += -Wl,-rpath=$(PWD)/lib/mbedtls/library
LDLIBS += -Wl,-rpath=$(PWD)/lib/paho-mqtt/MQTTClient-C/src


.PHONY: all clean

all: $(EXE)

$(EXE): $(OBJ) | $(BIN_DIR)
	$(CC) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR) $(OBJ_DIR):
	mkdir -p $@

build-tests:
	cd tests/; make

run-tests:
	cd tests/ecdh_aes_ecb_256/bin; ./ecdh_aes_ecb_256
	cd tests/ecdh_aes_cbc_256/bin; ./ecdh_aes_cbc_256
	cd tests/sha256/bin; ./sha256
	cd tests/mqtt/bin; ./tests_mqtt

deps:
	git submodule update --init --recursive
	cd lib/paho-mqtt/; cmake .; make
	cd lib/mbedtls/; cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .; make

install:
	cd lib/paho-mqtt; make install
	cd lib/mbedtls; make install

clean:
	@$(RM) -rv $(BIN_DIR) $(OBJ_DIR)

-include $(OBJ:.o=.d)
