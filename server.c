#include "server.h"
#include "protocol.h"
#include "crypto.h"
#include "pipe.h"

/* pipe file descriptor */
int pipe_fd;

int main (void)
{
	int op, bytes;
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

	do {
		 /* 2. Change PIN\n"); */
		 /* 3. Encrypt and authenticate message\n"); */
		 /* 4. Decrypt and authenticate message\n"); */
		 /* 5. Sign message\n"); */
		 /* 6. Verify message signature\n"); */
		 /* 7. Import public key\n"); */
		 /* 8. Share symmetric key\n"); */
		 /* 9. Save shared symmetric key\n"); */
		 /* 0. Quit\n"); */

		if ((pipe_fd = open(PIPE_NAME, O_RDONLY)) < 0) {
			perror("[SERVER] Cannot open pipe for reading: ");
			exit(0);
		}

		if ((bytes = read(pipe_fd, &op, sizeof(op))) == -1) {
			perror("[SERVER] Error reading from pipe: ");
			close(pipe_fd);
			exit(0);
		}

		close(pipe_fd);

		printf("[SERVER] Received Operation %d....\n", op);

		if (op == 0)
		{
			printf("\n[SERVER] Quitting...\n");
			break;
		}
		else if (op < 2 || op > 9)
		{
			printf("\n[SERVER] %d. Is not a valid operation\n", op);
			sleep (2);
			continue;
		}

		if (op == 1)
			encrypt("messages/text.msg", "messages/out.enc", "keys/aes.key", "keys/mac.key");
		else if (op == 2)
			decrypt("messages/out.enc", "messages/original.msg", "keys/aes.key", "keys/mac.key");
		else if (op == 3)
			new_key("keys/aes.key");
		else if (op == 4)
			new_key("keys/mac.key");
		else if (op != 0)
			printf("Wrong choice, try again\n");
		else
		{
			printf("[SERVER] Stopping server..\n");
			exit(0);
		}

		printf("\n[SERVER] Op %d done\n\n", op);

		/* system("clear"); */

		if ((pipe_fd = open(PIPE_NAME, O_WRONLY)) < 0) {
			perror("[SERVER] Cannot open pipe for writing: ");
			exit(0);
		}

		if ((bytes = write(pipe_fd, &op, sizeof(op))) == -1) {
			perror("[SERVER] Error writing to pipe: ");
			close(pipe_fd);
			exit(0);
		}

		close(pipe_fd);
		/* printf("1-cifrar mensagem\n"); */
		/* printf("2-decifrar mensagem\n"); */
		/* printf("3-nova chave para cifra\n"); */
		/* printf("4-nova chave para mac\n"); */
		/* printf("0-sair\n\nSelect Option: "); */

	} while (op != 0);

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

void concatenate(unsigned char * dest, unsigned char * src, int start, int length)
{
	int i;
	for (i = 0; i < length; i++)
		dest[i+start] = src[i];
}

/* return 0 if equal, 1 if different */
int compare_mac(unsigned char * mac1, unsigned char * mac2, int length)
{
	int i, different = 0;
	for (i = 0; i < length && !different; i++)
		if (mac1[i] != mac2[i])
			different = 1;
	return different;
}

// Read key from aes.key file
void read_key(unsigned char * key, char * key_file)
{
	FILE *fin;

	fin = fopen(key_file, "r");
	if (fin != NULL)
	{
		fread(key, KEY_SIZE, 1, fin);
		fclose(fin);
	}
	else
		printf("Error reading key.\n");
}

void cleanup()
{
	/* place all cleanup operations here */
	close(pipe_fd);
}
