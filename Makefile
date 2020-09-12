CC = gcc
LIBS =  -lssl -lcrypto
CFLAGS = -Wall
CLIENT_DIR = ./client-source
SERVER_DIR = ./server-source
CRYPTO_DIR = ${SERVER_DIR}/crypto

server:  ${SERVER_DIR}/server.c ${CRYPTO_DIR}/crypto.c
	${CC} ${CFLAGS} ${LIBS} ${SERVER_DIR}/server.c ${CRYPTO_DIR}/crypto.c -o server.bin

client: ${CLIENT_DIR}/client.c
	${CC} ${CFLAGS} ${CLIENT_DIR}/client.c -o client.bin
