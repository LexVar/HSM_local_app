#include "server.h"

int pipe_fd;		// pipe file descriptor
struct request req;	// request structure
struct response resp;	// response structure

int main (void)
{
	char keyfile[ID_SIZE];
	unsigned char key[CIPHER_SIZE];
	unsigned char signature[SIGNATURE_SIZE];
	size_t msg_size;
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

				get_key_path(req.data.key_id, keyfile, ".key");
				// Encrypt and authenticate data
				resp.status = resp.data.data_size = encrypt(req.data.data, req.data.data_size, resp.data.data, keyfile);
				break;
			case 4: // Decrypt + authenticate data

				get_key_path(req.data.key_id, keyfile, ".key");

				// Decrypt and authenticate data
				resp.status = resp.data.data_size = decrypt(req.data.data, req.data.data_size, resp.data.data, keyfile);
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
				if (resp.status > 0)
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

				// Read key from file
				msg_size = read_from_file (keyfile, (char *)key);
				// Sign key
				resp.status = sign_data(key, KEY_SIZE, PRIVATE_KEY, signature);
				if (resp.status >= 0)
				{
					// Entities certificate path
					get_key_path(req.gen_key.entity_id, keyfile, ".cert");
					// Encrypt with recipient's public key
					resp.status = pub_encrypt (keyfile, key, KEY_SIZE, resp.gen_key.msg, &msg_size);

					// Concatenate signature and encrypted key
					concatenate(resp.gen_key.msg, signature, CIPHER_SIZE, SIGNATURE_SIZE);
				}
				break;
			case 9: // Save key
				// Decrypt key + signature
				resp.status = private_decrypt (PRIVATE_KEY, req.save_key.msg, CIPHER_SIZE, key, &msg_size);
				if (resp.status > 0)
				{
					// Verify signature with public key
					get_key_path(req.save_key.entity_id, keyfile, ".cert");
					resp.status = verify_data(key, KEY_SIZE, keyfile, &(req.save_key.msg[CIPHER_SIZE]), SIGNATURE_SIZE);
					// save key in storage
					get_key_path(req.save_key.key_id, keyfile, ".key");
					write_to_file (keyfile, (char *)key, KEY_SIZE);
				}
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

void print_chars (unsigned char * data, int data_size)
{
	int i;
	for (i = 0; i < data_size; i++)
		printf("%c", data[i]);
	printf("\n");
}

int get_list_comm_keys(char * list)
{
	DIR *d;
	struct dirent *dir;
	char newline[] = "\n";
	d = opendir("./keys");
	if (d)
	{
		list[0] = '\0';
		while ((dir = readdir(d)) != NULL)
		{
			if (strstr(dir->d_name, ".key") != NULL)
			{
				strncat (list, dir->d_name, strlen(dir->d_name));
				strncat (list, newline, strlen(newline));
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
