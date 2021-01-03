CLIENT_DIR = ./src/client
SERVER_DIR = ./src/server
LIBS_DIR = $(SERVER_DIR)/libs
# LIBTOMCRYPT = $(LIBS_DIR)/libtomcrypt
BIN_DIR = ./bin

# Include all precompiled libtomcrypt object files
# OBJS := $(shell find $(LIBTOMCRYPT) -name *.o)

CC = gcc
CFLAGS = -Wall
# CFLAGS = -Wall -Wextra -Werror -pedantic
LIBS =  -lssl -lcrypto

server: $(SERVER_DIR)/server.c $(LIBS_DIR)/crypto.c $(LIBS_DIR)/sign.c
	$(CC) $(CFLAGS) $(LIBS) $^ -o $(BIN_DIR)/server

client: $(CLIENT_DIR)/client.c
	$(CC) $(CFLAGS) $^ -o $(BIN_DIR)/client

clean:
	rm data.txt data.enc key.enc signature.txt
