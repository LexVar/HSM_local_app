#include "server.h"

int pipe_fd;		// pipe file descriptor
struct request req;	// request structure
struct response resp;	// response structure

int main (void)
{
	char keyfile[ID_SIZE];
	// Redirects SIGINT (CTRL-c) to cleanup()
	signal(SIGINT, cleanup);

	// Creates the named pipe if it doesn't exist yet
        if ((mkfifo(PIPE_NAME, S_IFIFO|0660)<0) && (errno!= EEXIST))
        {
                perror("[SERVER] Cannot create pipe: ");
                exit(-1);
        }

	// load cryptography libraries
	init_crypto_state();

	while(1)
	{
		// Receive request from client
		receive_from_connection(pipe_fd, &req, sizeof(struct request));

		printf("[SERVER] Received Operation %d....\n", req.op_code);

		if (req.op_code == 0)
		{
			printf("\n[SERVER] Quitting...\n");
			break;
		}
		else if (req.op_code < 2 || req.op_code > 9)
		{
			printf("n[SERVER] %d. Is not a valid operation\n", req.op_code);
			continue;
		}

		/* --------------------------------------------------- */
		/* Perform operation */
		switch (req.op_code)
		{
			case 3: // Encrypt + authenticate data
				// TEMPORARY
				// write data to file to pass as argument
				write_to_file ("messages/plaintext.txt", req.data.data, req.data.data_size);
				// Encrypt and authenticate data
				encrypt("messages/plaintext.txt", "messages/ciphertext.enc", "keys/aes.key", "keys/mac.key");
				// Read ciphertext from file
				resp.data.data_size = read_from_file ("messages/ciphertext.enc", resp.data.data);
				// TODO - Set status according to operation success
				resp.status = 0;
				break;
			case 4: // Decrypt + authenticate data
				// TEMPORARY
				// write data to file to pass as argument
				write_to_file ("messages/ciphertext.enc", req.data.data, req.data.data_size);
				// Decrypt and authenticate data
				decrypt("messages/ciphertext.enc", "messages/plaintext.txt", "keys/aes.key", "keys/mac.key");
				// Read plaintext from file
				resp.data.data_size = read_from_file ("messages/plaintext.txt", resp.data.data);
				// TODO - Set status according to operation success
				resp.status = 0;
				break;
			case 5: // Encrypt(sign) with private key
				resp.status = sign_data((unsigned char *)req.sign.data, req.sign.data_size, PRIVATE_KEY, (unsigned char *)resp.sign.signature);
				if (resp.status == 0)
					printf ("[SERVER] Data succesfully signed\n");
				else
					printf ("[SERVER] Error signing data\n");

				break;
			case 6: // Verify signature
				// Get key path from secure storage
				get_cert_path(req.verify.entity_id, keyfile);

				resp.status = verify_data((unsigned char *)req.verify.data, req.verify.data_size, keyfile, (unsigned char *)req.verify.signature, SIGNATURE_SIZE);
				if (resp.status != 0)
					printf ("[SERVER] Signature verified successfully\n");
				else
					printf ("[SERVER] Error verifying signature\n");
				break;
			case 7: // Import public key
				get_cert_path(req.import_pub.entity_id, keyfile);
				if (write_to_file(keyfile, req.import_pub.public_key, PUB_KEY_SIZE) != NULL)
					resp.status = 0;
				else
					resp.status = 1;
				break;
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

		printf("\n[SERVER] Finished Op. %d\n", req.op_code);

		/* set requests attributes */
		resp.op_code = req.op_code;

		// wait for client to open pipe for reading
		sleep (1);
		/* --------------------------------------------------- */
		/* Send response back to client */
		send_to_connection(pipe_fd, &resp, sizeof(struct request));

		printf("[SERVER] Sent response to op. %d....\n", resp.op_code);
	}

	return 0;
}

void get_cert_path (char * entity, char * cert_path)
{
	strcpy(cert_path, "keys/");
	strncat(cert_path, entity, strlen(entity)-1);
	strcat(cert_path, ".cert");
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

void cleanup()
{
	printf ("\n[SERVER] Received SIGINT, cleaning up...\n");
	printf ("\n[SERVER] Shutting down...\n");

	/* place all cleanup operations here */
	close(pipe_fd);
	exit(0);
}
