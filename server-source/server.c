#include "server.h"
#include "protocol.h"
#include "crypto/crypto.h"
#include "pipe.h"

/* pipe file descriptor */
int pipe_fd;

/* request structure */
struct composed_request request;

/* response structure */
struct composed_response response;

int main (void)
{
	int bytes;
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	// Redirects SIGINT (CTRL-V) to sigint()
	signal(SIGINT, cleanup);

	// Creates the named pipe if it doesn't exist yet
        if ((mkfifo(PIPE_NAME, O_CREAT|O_EXCL|0600)<0) && (errno!= EEXIST))
        {
                perror("[SERVER] Cannot create pipe: ");
                exit(0);
        }

		/* 2. Change PIN\n"); */
		/* 3. Encrypt and authenticate message\n"); */
		/* 4. Decrypt and authenticate message\n"); */
		/* 5. Sign message\n"); */
		/* 6. Verify message signature\n"); */
		/* 7. Import public key\n"); */
		/* 8. Share symmetric key\n"); */
		/* 9. Save shared symmetric key\n"); */
		/* 0. Quit\n"); */

		/* 1-cifrar mensagem\n"); */
		/* 2-decifrar mensagem\n"); */
		/* 3-nova chave para cifra\n"); */
		/* 4-nova chave para mac\n"); */
		/* 0-sair\n\nSelect Option: "); */

	while(1)
	{
		/* --------------------------------------------------- */
		/* Receive request from client */

		if ((pipe_fd = open(PIPE_NAME, O_RDONLY)) < 0) {
			perror("[SERVER] Cannot open pipe for reading: ");
			exit(0);
		}

		if ((bytes = read(pipe_fd, &request, sizeof(request))) == -1) {
			perror("[SERVER] Error reading from pipe: ");
			close(pipe_fd);
			exit(0);
		}

		close(pipe_fd);

		printf("[SERVER] Received Operation %d....\n", request.request.type);

		if (request.request.type == 0)
		{
			printf("\n[SERVER] Quitting...\n");
			break;
		}
		else if (request.request.type < 2 || request.request.type > 9)
		{
			printf("\n[SERVER] %d. Is not a valid operation\n", request.request.type);
			sleep (2);
			continue;
		}

		/* --------------------------------------------------- */
		/* Perform operation */
		switch (request.request.type)
		{
			case 1:
				encrypt("messages/text.msg", "messages/out.enc", "keys/aes.key", "keys/mac.key");
				break;
			case 2:
				decrypt("messages/out.enc", "messages/original.msg", "keys/aes.key", "keys/mac.key");
				break;
			case 3:
				new_key("keys/aes.key");
				break;
			case 4:
				new_key("keys/mac.key");
				break;
			case 0:
				printf("[SERVER] Stopping server..\n");
				cleanup();
				exit(0);
				break;
			default:
				printf("Wrong choice, try again\n");
		}

		printf("\n[SERVER] Op %d done\n\n", request.request.type);

		/* --------------------------------------------------- */
		/* Send response back to client */

		if ((pipe_fd = open(PIPE_NAME, O_WRONLY)) < 0) {
			perror("[SERVER] Cannot open pipe for writing: ");
			exit(0);
		}

		/* set requests attributes */
		response.response.status = 0;
		response.response.type = request.request.type;

		if ((bytes = write(pipe_fd, &response, sizeof(response))) == -1) {
			perror("[SERVER] Error writing to pipe: ");
			close(pipe_fd);
			exit(0);
		}

		close(pipe_fd);
	}

	return 0;
}

// Generates new AES key, saves to aes.key file
void new_key(char * key_file)
{
	FILE *fout;
	unsigned char key[KEY_SIZE];

	if ( !RAND_bytes(key, sizeof(key)) )
		exit(-1);

	fout = fopen(key_file, "w");
	if (fout != NULL)
	{
		fwrite(key, sizeof(char), sizeof(key), fout);
		fclose(fout);
	}
	else
		printf("Error generating key.\n");
}

void print_hexa(unsigned char * string, int length)
{
	int i = 0;
	for (i = 0; i < length; i++)
		printf("%x ",string[i] & 0xff);

	printf("\n");
}

void cleanup()
{
	/* place all cleanup operations here */
	close(pipe_fd);
}
