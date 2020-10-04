#include "server.h"
#include "../protocol.h"
#include "crypto/crypto.h"
#include "../pipe.h"

/* pipe file descriptor */
int pipe_fd;

/* request structure */
struct composed_request request;

/* response structure */
struct composed_response response;

int main (void)
{
	int bytes;

	// load cryptography libraries
	init_crypto_state();

	// Redirects SIGINT (CTRL-c) to sigint()
	signal(SIGINT, cleanup);

	// Creates the named pipe if it doesn't exist yet
        if ((mkfifo(PIPE_NAME, O_CREAT|O_EXCL|0600)<0) && (errno!= EEXIST))
        {
                perror("[SERVER] Cannot create pipe: ");
                exit(0);
        }

	while(1)
	{
		/* --------------------------------------------------- */
		/* Receive request from client */
		receive_from_connection(&request);

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
			case 3:
				write_to_file ("messages/text.msg", request.msg_req.msg, request.msg_req.msg_size);
				printf ("[SERVER] message to encrypt: \"%s\"\n", request.msg_req.msg);
				encrypt("messages/text.msg", "messages/out.enc", "keys/aes.key", "keys/mac.key");
				read_from_file ("messages/out.enc", request.msg_req.msg, request.msg_req.msg_size);
				// TODO - Set status according to operation success
				response.response.status = 0;
				break;
			case 4:
				write_to_file ("messages/out.enc", request.msg_req.msg, request.msg_req.msg_size);
				decrypt("messages/out.enc", "messages/original.msg", "keys/aes.key", "keys/mac.key");
				read_from_file ("messages/original.msg", request.msg_req.msg, request.msg_req.msg_size);
				// TODO - Set status according to operation success
				response.response.status = 0;
				break;
			case 5:
				// Encrypt(sign) with private key
				// bytes = encrypt_private(enc_out, msg_size, signature);
				break;
			case 6:
				// Verify signature
				// bytes = decrypt_public(bytes, signature, to);

				// if (bytes == -1)
				// {
				//         response.response.status = -1;
				//         printf ("Error verifying signature..\n");
				//         break;
				// }
				// else
				//         printf("Signature verified..\n");
			case 7:
				// Import public key
			case 8:
				new_key("keys/aes.key");
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

		/* set requests attributes */
		response.response.type = request.request.type;

		/* --------------------------------------------------- */
		/* Send response back to client */
		send_to_connection(&response);

		sleep (2);
	}

	return 0;
}

void receive_from_connection (struct composed_request * request)
{
	int bytes;

	if ((pipe_fd = open(PIPE_NAME, O_RDONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for reading: ");
		exit(0);
	}

	if ((bytes = read(pipe_fd, request, sizeof(struct composed_request))) == -1) {
		perror("[SERVER] Error reading from pipe: ");
		close(pipe_fd);
		exit(0);
	}

	close(pipe_fd);

}

void send_to_connection (struct composed_response * response)
{
	int bytes;

	if ((pipe_fd = open(PIPE_NAME, O_WRONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for writing: ");
		exit(0);
	}

	if ((bytes = write(pipe_fd, response, sizeof(struct composed_response))) == -1) {
		perror("[SERVER] Error writing to pipe: ");
		close(pipe_fd);
		exit(0);
	}

	close(pipe_fd);
}

void * write_to_file (char * filename, char * content, int fsize)
{
	FILE *f = fopen(filename, "wb");

	if (f != NULL)
	{
		fwrite(content, 1, fsize, f);
		fclose(f);

		content[fsize] = 0;
	}

	return f;
}

void * read_from_file (char * filename, char * content, int fsize)
{
	FILE *f = fopen(filename, "rb");

	if (f != NULL)
	{
		fread(content, 1, fsize, f);
		fclose(f);

		content[fsize] = 0;
	}

	return f;
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
	printf ("[SERVER] Received SIGINT, shutting down server after cleanup\n");

	/* place all cleanup operations here */
	close(pipe_fd);
	exit(0);
}
