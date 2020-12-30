#include "server.h"

uint8_t AUTH_PIN[PIN_SIZE];
uint32_t pipe_fd;		// pipe file descriptor
struct request req;	// request structure
struct response resp;	// response structure
uint8_t authenticated = 0;  // Flag, 1-authenticated, 0-not authenticated

int main (void)
{
	init();

	// load cryptography libraries
	init_crypto_state();

	while(1)
	{
		// Check authentication
		// authenticate();

		// if (!authenticated)
		//         continue;

		display_greeting();

		// Receive request from client
		// receive_from_connection(pipe_fd, &req, sizeof(struct request));
		receive_from_connection(pipe_fd, &req.op_code, sizeof(uint8_t));
		printf("[SERVER] Received Operation %d....\n", req.op_code);

		/* --------------------------------------------------- */
		/* Perform operation */
		switch (req.op_code)
		{
			case 1: // Authentication
				break;
			case 2: // Change PIN
				// set_PIN(req.admin.PIN);
				break;
			case 3: // Encrypt + authenticate data
			case 4: // Decrypt + authenticate data
				// Get data size
				receive_from_connection(pipe_fd, &req.data.data_size, sizeof(uint16_t));
				sendOK((uint8_t *)"OK");

				// Get data
				receive_from_connection(pipe_fd, req.data.data, req.data.data_size);
				sendOK((uint8_t *)"OK");

				// Get key ID
				receive_from_connection(pipe_fd, req.data.key_id, ID_SIZE);
				encrypt_authenticate();

				// Send result
				send_to_connection(pipe_fd, &resp.data.data_size, sizeof(uint16_t));
				send_to_connection(pipe_fd, resp.data.data, resp.data.data_size);
				break;
			case 5: // Encrypt(sign) with private key
				sign_operation();
				break;
			case 6: // Verify signature
				verify_operation();
				break;
			case 7: // Import public key
				import_pubkey_operation();
				break;
			case 8: // Share key
				share_key_operation();
				break;
			case 9: // Save key
				save_key_operation();
				break;
			case 10: // List avaiable secure comm keys
				get_list_comm_keys (resp.list.list);
				break;
			case 11:
				authenticated = 0;
				printf("[SERVER] User logged out..\n");
				resp.status = 1;
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
		// send_to_connection(pipe_fd, &resp, sizeof(struct response));

		printf("[SERVER] Sent response to op. %d....\n", resp.op_code);
	}

	return 0;
}

void sendOK(uint8_t * msg)
{
	send_to_connection(pipe_fd, msg, ID_SIZE);
}

// .cert -> certificate
// .key  -> private/symmetric key
void get_key_path (uint8_t * entity, uint8_t * key_path, uint8_t * extension)
{
	entity[strlen((char *)entity)-1] = 0;
	snprintf((char*)key_path, ID_SIZE, "%s%s%s", "keys/", entity, extension);
}

void print_chars (uint8_t * data, uint32_t data_size)
{
	uint32_t i;
	for (i = 0; i < data_size; i++)
		printf("%c", data[i]);
	printf("\n");
}

// Get it from: MSS_SYS_puf_get_number_of_keys()
// slot number from 2-57 is used as key_id
uint32_t get_list_comm_keys(uint8_t * list)
{
	DIR *d;
	struct dirent *dir;
	uint32_t len=0;
	d = opendir("./keys");
	if (d)
	{
		list[0] = 0;
		while ((dir = readdir(d)) != NULL)
		{
			if (strstr(dir->d_name, ".key") != NULL)
			{
				snprintf((char *)list+len, DATA_SIZE, "%s\n", dir->d_name);
				len += strlen(dir->d_name)+1;
			}
		}
		closedir(d);
	}
	return 0;
}

void authenticate()
{
	// Send authentication status
	resp.status = authenticated;
	resp.op_code = 1;
	send_to_connection(pipe_fd, &resp, sizeof(struct response));

	printf("PIN:%s\n",AUTH_PIN);
	if (!authenticated)
	{
		receive_from_connection(pipe_fd, &req, sizeof(struct request));

		authenticated = resp.status = !compare_strings(req.auth.pin, AUTH_PIN, sizeof(AUTH_PIN));

		if (authenticated)
			printf("[SERVER] Authentication succesfull\n");
		else
			printf("[SERVER] Authentication failed\n");

		sleep (1);
		send_to_connection(pipe_fd, &resp, sizeof(struct response));
	}
}

void encrypt_authenticate()
{
	uint8_t keyfile[ID_SIZE];

	get_key_path(req.data.key_id, keyfile, (uint8_t *)".key");

	if (req.op_code == 3)
		resp.status = resp.data.data_size = encrypt(req.data.data, req.data.data_size, resp.data.data, keyfile);
	// Decrypt and authenticate data
	else
		resp.status = resp.data.data_size = decrypt(req.data.data, req.data.data_size, resp.data.data, keyfile);
	resp.data.data[resp.data.data_size] = 0;
}

void sign_operation ()
{
	resp.status = sign_data(req.sign.data, req.sign.data_size, (uint8_t *)PRIVATE_KEY, resp.sign.signature);
	if (resp.status == 0)
		printf ("[SERVER] Data succesfully signed\n");
	else
		printf ("[SERVER] Error signing data\n");
}

void verify_operation()
{
	uint8_t keyfile[ID_SIZE];

	// Get key path from secure storage
	get_key_path(req.verify.entity_id, keyfile, (uint8_t *)".cert");

	resp.status = verify_data(req.verify.data, req.verify.data_size, keyfile, req.verify.signature, SIGNATURE_SIZE);
	if (resp.status > 0)
		printf ("[SERVER] Signature verified successfully\n");
	else
		printf ("[SERVER] Error verifying signature\n");
}

void import_pubkey_operation()
{
	uint8_t keyfile[ID_SIZE];
	get_key_path(req.import_pub.entity_id, keyfile, (uint8_t *)".cert");
	if (write_to_file(keyfile, req.import_pub.public_key, PUB_KEY_SIZE) != NULL)
		resp.status = 0;
	else
		resp.status = 1;
}

void share_key_operation()
{
	uint8_t keyfile[ID_SIZE];
	uint8_t key[CIPHER_SIZE];
	uint8_t signature[SIGNATURE_SIZE];
	size_t msg_size;

	// Generate new symmetric key
	get_key_path(req.gen_key.key_id, keyfile, (uint8_t *)".key");
	new_key(keyfile);

	// Read key from file
	msg_size = read_from_file (keyfile, key);
	// Sign key
	resp.status = sign_data(key, 2*KEY_SIZE, (uint8_t *)PRIVATE_KEY, signature);
	if (resp.status >= 0)
	{
		// Entities certificate path
		get_key_path(req.gen_key.entity_id, keyfile, (uint8_t *)".cert");
		// Encrypt with recipient's public key
		resp.status = pub_encrypt (keyfile, key, 2*KEY_SIZE, resp.gen_key.msg, &msg_size);

		// Concatenate signature and encrypted key
		concatenate(resp.gen_key.msg, signature, CIPHER_SIZE, SIGNATURE_SIZE);
	}
}

void save_key_operation()
{
	uint8_t keyfile[ID_SIZE];
	uint8_t key[CIPHER_SIZE];
	size_t msg_size;

	// Decrypt key + signature
	resp.status = private_decrypt ((uint8_t *)PRIVATE_KEY, req.save_key.msg, CIPHER_SIZE, key, &msg_size);
	if (resp.status > 0)
	{
		// Verify signature with public key
		get_key_path(req.save_key.entity_id, keyfile, (uint8_t *)".cert");
		resp.status = verify_data(key, 2*KEY_SIZE, keyfile, &(req.save_key.msg[CIPHER_SIZE]), SIGNATURE_SIZE);
		// save key in storage
		get_key_path(req.save_key.key_id, keyfile, (uint8_t *)".key");
		write_to_file (keyfile, key, 2*KEY_SIZE);
	}
}

void init()
{
	memcpy(AUTH_PIN, "1234", sizeof("1234"));
	// Redirects SIGINT (CTRL-c) to cleanup()
	signal(SIGINT, cleanup);

	// Creates the named pipe if it doesn't exist yet
        if ((mkfifo(PIPE_NAME, S_IFIFO|0600)<0) && (errno!= EEXIST))
        {
                perror("[SERVER] Cannot create pipe: ");
                exit(-1);
        }
}

void display_greeting ()
{
	uint8_t greeting [] ="\n--CLIENT OPERATIONS--\n\
1. Authentication\n\
2. Change PIN\n\
3. Encrypt message\n\
4. Decrypt message\n\
5. Sign message\n\
6. Verify signature\n\
7. Import public key\n\
8. Share key\n\
9. Save key\n\
10. List comm keys\n\
0. Quit\n\
--------------------\n\n\
Operation: ";
	send_to_connection(pipe_fd, greeting, sizeof(greeting));
}

void cleanup()
{
	printf ("\n[SERVER] Received SIGINT, cleaning up...\n");
	printf ("\n[SERVER] Shutting down...\n");

	/* place all cleanup operations here */
	close(pipe_fd);
	exit(0);
}
