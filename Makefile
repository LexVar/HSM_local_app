server: server.h pipe.h protocol.h crypto.h server.c crypto.c
	gcc -Wall -lssl -lcrypto server.c crypto.c -o server

client: client.h pipe.h protocol.h client.c
	gcc -Wall client.c -o client
