SOURCE_DIR = ./src
CLIENT_DIR = ./src/client
SERVER_DIR = ./src/server
LIBS_DIR = $(SERVER_DIR)/libs
OPENSSL_DIR = $(LIBS_DIR)/openssl
BIN_DIR = ./bin

# Include all precompiled libtomcrypt object files
OBJS := $(shell find $(OPENSSL_DIR) -name *.o)

CC = gcc
CFLAGS = -Wall -I$(OPENSSL_DIR)/include
# CFLAGS = -Wall -Wextra -Werror -pedantic

LIBS = -L$(OPENSSL_DIR) -lcrypto -lssl

server: $(SERVER_DIR)/server.c $(LIBS_DIR)/crypto.c $(LIBS_DIR)/sign.c $(SOURCE_DIR)/comms.c 
	$(CC) $(CFLAGS) $(OBJS) $^ -o $(BIN_DIR)/server $(LIBS) 

client: $(CLIENT_DIR)/client.c $(SOURCE_DIR)/comms.c 
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/client

clean:
	rm data.txt data.enc key.enc signature.txt
