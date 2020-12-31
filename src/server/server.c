#include "server.h"

uint8_t AUTH_PIN[PIN_SIZE];
uint32_t pipe_fd;		// pipe file descriptor
struct request req;		// request structure
struct response resp;		// response structure
uint8_t authenticated = 0;	// Flag, 1-authenticated, 0-not authenticated

int main (void)
{
	init();

	// load cryptography libraries
	init_crypto_state();

	while(1)
	{
		display_greeting();

		// Receive operation request
		receive_from_connection(pipe_fd, &req.op_code, sizeof(uint8_t));
		printf("[SERVER] Received Operation %d....\n", req.op_code);

		resp.op_code = req.op_code; // same op_code for response

		// Check authentication
		if (req.op_code > 1 && !authenticated)
		{
			sendOK((uint8_t *)"NO"); // send not authorized response
			continue;
		}
		else
			sendOK((uint8_t *)"OK"); // send not authorized response

		/* --------------------------------------------------- */
		/* Perform operation */
		switch (req.op_code)
		{
			case 1: // Authentication
				authenticate();
				break;
			case 2: // Change PIN
				set_pin();
				break;
			case 3: // Encrypt + authenticate data
			case 4: // Decrypt + authenticate data
				// Get data size
				receive_from_connection(pipe_fd, &req.data.data_size, sizeof(uint16_t));
				if (send_status(req.data.data_size) == 0)
					continue;

				// Get data
				receive_from_connection(pipe_fd, req.data.data, req.data.data_size);
				if (send_status(req.data.data[0]) == 0)
					continue;

				// Get key ID
				receive_from_connection(pipe_fd, req.data.key_id, ID_SIZE);
				sendOK((uint8_t *)"OK");

				encrypt_authenticate();

				// Send result
				send_to_connection(pipe_fd, &resp.data.data_size, sizeof(uint16_t));
				waitOK();
				send_to_connection(pipe_fd, resp.data.data, resp.data.data_size);
				waitOK();
				break;
			case 5: // Encrypt(sign) with private key
				receive_from_connection(pipe_fd, &req.sign.data_size, sizeof(uint16_t));
				if (send_status(req.sign.data_size) == 0)
					continue;

				// Get data
				receive_from_connection(pipe_fd, req.sign.data, req.sign.data_size);
				sendOK((uint8_t *)"OK");

				sign_operation();

				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK();
				if (resp.status == 0)
					continue;
				send_to_connection(pipe_fd, resp.sign.signature, SIGNATURE_SIZE);
				waitOK();
				break;
			case 6: // Verify signature
				receive_from_connection(pipe_fd, &req.verify.data_size, sizeof(uint16_t));
				// sendOK((uint8_t *)"OK");
				if (send_status(req.verify.data_size) == 0)
					continue;

				receive_from_connection(pipe_fd, req.verify.data, req.verify.data_size);
				sendOK((uint8_t *)"OK");

				receive_from_connection(pipe_fd, req.verify.signature, SIGNATURE_SIZE);
				sendOK((uint8_t *)"OK");

				receive_from_connection(pipe_fd, req.verify.entity_id, ID_SIZE);
				if (send_status(req.verify.entity_id[0]) == 0)
					continue;

				verify_operation();

				// Send status
				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK();
				break;
			case 7: // Import public key
				receive_from_connection(pipe_fd, req.import_pub.entity_id, ID_SIZE);
				if (send_status(req.import_pub.entity_id[0]) == 0)
					continue;
				receive_from_connection(pipe_fd, &req.import_pub.cert_size, sizeof(uint16_t));
				if (send_status(req.import_pub.cert_size) == 0)
					continue;
				receive_from_connection(pipe_fd, req.import_pub.public_key, req.import_pub.cert_size);
				if (send_status(req.import_pub.public_key[0]) == 0)
					continue;
				import_pubkey_operation();

				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK();
				break;
			case 8: // Share key
				receive_from_connection(pipe_fd, req.gen_key.entity_id, ID_SIZE);
				if (send_status(req.gen_key.entity_id[0]) == 0)
					continue;
				receive_from_connection(pipe_fd, req.gen_key.key_id, ID_SIZE);
				if (send_status(req.gen_key.key_id[0]) == 0)
					continue;
				share_key_operation();

				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK();
				if (resp.status == 0)
					continue;

				send_to_connection(pipe_fd, resp.gen_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);
				waitOK();
				break;
			case 9: // Save key
				receive_from_connection(pipe_fd, req.save_key.entity_id, ID_SIZE);
				if (send_status(req.save_key.entity_id[0]) == 0)
					continue;
				receive_from_connection(pipe_fd, req.save_key.key_id, ID_SIZE);
				if (send_status(req.save_key.key_id[0]) == 0)
					continue;
				receive_from_connection(pipe_fd, req.save_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);

				save_key_operation();

				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				break;
			case 10: // List avaiable secure comm keys
				get_list_comm_keys (resp.list.list);

				send_to_connection(pipe_fd, resp.list.list, DATA_SIZE);
				waitOK();
				break;
			case 11:
				authenticated = 0;
				sendOK((uint8_t *)"OK");
				printf("[SERVER] User logged out..\n");
				break;
			case 0:
				break;
			default:
				sendOK((uint8_t *)"NO");
				printf("Wrong choice, try again\n");
		}
		printf("\n[SERVER] Finished Op. %d\n", req.op_code);
	}

	return 0;
}

uint8_t send_status(uint8_t status)
{
	if (status == 0)
		send_to_connection(pipe_fd, (uint8_t *)"NO", sizeof("NO"));
	else
		send_to_connection(pipe_fd, (uint8_t *)"OK", sizeof("OK"));
	return status;
}

void sendOK(uint8_t * msg)
{
	send_to_connection(pipe_fd, msg, sizeof(msg));
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

void set_pin()
{
	receive_from_connection(pipe_fd, req.admin.pin, PIN_SIZE);

	memcpy(AUTH_PIN, req.admin.pin, PIN_SIZE);

	sendOK((uint8_t *)"OK");
}

void authenticate()
{
	// get PIN from user
	receive_from_connection(pipe_fd, req.auth.pin, PIN_SIZE);

	printf("PIN:%s\n", AUTH_PIN);
	// check PIN
	authenticated = resp.status = !compare_strings(req.auth.pin, AUTH_PIN, PIN_SIZE);

	if (!authenticated)
		printf("[SERVER] Authentication failed\n");
	else
		printf("[SERVER] Authentication succesfull\n");

	// send resonse back
	send_to_connection(pipe_fd, &authenticated, sizeof(uint8_t));
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

	if (write_to_file(keyfile, req.import_pub.public_key, req.import_pub.cert_size) != NULL)
		resp.status = 1;
	else
		resp.status = 0;
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

uint8_t waitOK()
{
	uint8_t msg[ID_SIZE];
	receive_from_connection(pipe_fd, msg, ID_SIZE);

	printf ("%s\n", msg);

	if (msg[0] != 'O' || msg[1] != 'K')
		resp.status = 0;
	else
		resp.status = 1;
	return resp.status;
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
11. Logout\n\
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
