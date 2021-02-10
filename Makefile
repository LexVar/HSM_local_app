SOURCE_DIR = ./src
CLIENT_DIR = ./src/client
SERVER_DIR = ./src/server
LIBS_DIR = $(SERVER_DIR)/libs
MBEDTLS_DIR = $(LIBS_DIR)/mbedtls
BIN_DIR = ./bin

# Include all precompiled libtomcrypt object files
# SRCS := $(shell find $(MBEDTLS_DIR) -name *.c)

CC = gcc
# CFLAGS = -Wall -I$(MBEDTLS_DIR)/include
CFLAGS = -Wall #-Wextra -Werror -pedantic

LIBS = -lcrypto -lssl

server: $(SERVER_DIR)/server.c $(LIBS_DIR)/crypto.c $(LIBS_DIR)/keys.c $(SOURCE_DIR)/comms.c $(LIBS_DIR)/openssl_ecdsa.c #$(LIBS_DIR)/openssl_ecdh.c #$(LIBS_DIR)/mbed_ecdh.c $(LIBS_DIR)/mbed_ecdsa.c $(SRCS)
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/server $(LIBS) 

client: $(CLIENT_DIR)/client.c $(SOURCE_DIR)/comms.c 
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/client

clean:
	rm data.txt data.enc key.enc signature.txt
