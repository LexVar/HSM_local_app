#include "server.h"

int pipe_fd;		// pipe file descriptor
struct request req;	// request structure
struct response resp;	// response structure

int main (void)
{
	char keyfile[ID_SIZE];
	char key[CIPHER_SIZE];
	unsigned char signature[SIGNATURE_SIZE];
	// Redirects SIGINT (CTRL-c) to cleanup()
	signal(SIGINT, cleanup);

	// Creates the named pipe if it doesn't exist yet
        if ((mkfifo(PIPE_NAME, S_IFIFO|0600)<0) && (errno!= EEXIST))
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

		if (req.op_code < 1 || req.op_code > 10)
		{
			printf("n[SERVER] %d. Is not a valid operation\n", req.op_code);
			continue;
		}

		printf("[SERVER] Received Operation %d....\n", req.op_code);

		/* --------------------------------------------------- */
		/* Perform operation */
		switch (req.op_code)
		{
			case 1: // Authentication
				// authenticate(req.auth.PIN);
				break;
			case 2: // Change PIN
				// set_PIN(req.admin.PIN);
				break;
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
				get_key_path(req.verify.entity_id, keyfile, ".cert");

				resp.status = verify_data((unsigned char *)req.verify.data, req.verify.data_size, keyfile, (unsigned char *)req.verify.signature, SIGNATURE_SIZE);
				if (resp.status != 0)
					printf ("[SERVER] Signature verified successfully\n");
				else
					printf ("[SERVER] Error verifying signature\n");
				break;
			case 7: // Import public key
				get_key_path(req.import_pub.entity_id, keyfile, ".cert");
				if (write_to_file(keyfile, req.import_pub.public_key, PUB_KEY_SIZE) != NULL)
					resp.status = 0;
				else
					resp.status = 1;
				break;
			case 8: // Share key

				// Generate new symmetric key
				get_key_path(req.gen_key.key_id, keyfile, ".key");
				new_key(keyfile);
				printf("keyfile: %s\n", keyfile);

				// Read key from file
				resp.gen_key.msg_size = read_from_file (keyfile, key);

				// Sign key
				resp.status = sign_data((unsigned char *)keyfile, resp.gen_key.msg_size, PRIVATE_KEY, (unsigned char *)signature);
				// Concatenate signature and key
				strncat(key, (char *)signature, SIGNATURE_SIZE);
				
				// Entities certificate path
				strncpy(keyfile, req.gen_key.entity_id, strlen(req.gen_key.entity_id));
				printf("cert: %s\n", keyfile);
				strcat(keyfile, ".cert");
				printf("cert: %s\n", keyfile);

				pub_encrypt (keyfile, (unsigned char *)key, (size_t)(KEY_SIZE+SIGNATURE_SIZE), (unsigned char *)resp.gen_key.msg, (size_t *)(&resp.gen_key.msg_size));

				print_hex (resp.gen_key.msg, resp.gen_key.msg_size);
				break;
			case 9: // Save key
				private_decrypt (PRIVATE_KEY, (unsigned char *)key, CIPHER_SIZE, (unsigned char *)req.save_key.msg, (size_t)CIPHER_SIZE);
				break;
			case 10: // List avaiable secure comm keys
				get_list_comm_keys (resp.list.list);
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

// .cert -> certificate
// .key  -> private/symmetric key
void get_key_path (char * entity, char * key_path, char * extension)
{
	key_path[0] = '\0';
	strcpy(key_path, "keys/");
	strncat(key_path, entity, strlen(entity)-1);
	strcat(key_path, extension);
}

void print_hex (char * data, int data_size)
{
	int i;
	for (i = 0; i < data_size; i++)
		printf("%x", data[i] & 0xff);
	printf("\n");
}

int get_list_comm_keys(char * list)
{
	DIR *d;
	struct dirent *dir;
	d = opendir("./keys");
	if (d)
	{
		list[0] = '\0';
		while ((dir = readdir(d)) != NULL)
		{
			if (strstr(dir->d_name, ".key") != NULL)
			{
				strncat (list, dir->d_name, strlen(dir->d_name));
				strncat (list, "\n", 1);
			}
		}
		closedir(d);
	}
	return 0;
}

void cleanup()
{
	printf ("\n[SERVER] Received SIGINT, cleaning up...\n");
	printf ("\n[SERVER] Shutting down...\n");

	/* place all cleanup operations here */
	close(pipe_fd);
	exit(0);
}
