SOURCE_DIR = ./src
CLIENT_DIR = ./src/client
SERVER_DIR = ./src/server
LIBS_DIR = $(SERVER_DIR)/libs
MBEDTLS_DIR = $(LIBS_DIR)/mbedtls

CC = gcc
CFLAGS = -Wall
# CFLAGS = -Wall #-Wextra -Werror -pedantic

LIBS = -lcrypto -lssl -lmbedtls -lmbedcrypto

server: $(SERVER_DIR)/server.c $(LIBS_DIR)/crypto.c $(LIBS_DIR)/keys.c $(SOURCE_DIR)/comms.c $(LIBS_DIR)/openssl_ecdsa.c $(LIBS_DIR)/mbedtls_crypto.c #$(LIBS_DIR)/openssl_ecdh.c #$(LIBS_DIR)/mbed_ecdh.c $(LIBS_DIR)/mbed_ecdsa.c
	$(CC) $(CFLAGS) $^ -o server $(LIBS) 

client: $(CLIENT_DIR)/client.c $(SOURCE_DIR)/comms.c $(LIBS_DIR)/mbedtls_crypto.c $(SRCS)
	$(CC) $(CFLAGS) $^ -o client $(LIBS)

clean:
	rm data.txt data.enc key.enc signature.txt
