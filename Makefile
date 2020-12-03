CC = gcc
LIBS =  -lssl -lcrypto
CFLAGS = -Wall
# CFLAGS = -Wall -Wextra -Werror -pedantic
CLIENT_DIR = ./src/client
SERVER_DIR = ./src/server
CRYPTO_DIR = ${SERVER_DIR}/crypto
BIN_DIR = ./bin

server:  ${SERVER_DIR}/server.c ${CRYPTO_DIR}/crypto.c
	${CC} ${CFLAGS} ${LIBS} ${SERVER_DIR}/server.c ${CRYPTO_DIR}/crypto.c -o ${BIN_DIR}/server

client: ${CLIENT_DIR}/client.c
	${CC} ${CFLAGS} ${CLIENT_DIR}/client.c -o ${BIN_DIR}/client

clean:
	rm data.txt data.enc signature.txt bin/sign.txt
