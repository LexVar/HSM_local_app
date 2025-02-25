#include "server.h"

uint8_t AUTH_PIN[PIN_SIZE];
struct request req;		// request structure
struct response resp;		// response structure
uint8_t authenticated = 0;	// Flag, 1-authenticated, 0-not authenticated
uint32_t pipe_fd;		// Pipe descriptor
uint8_t key_set[DATA_SIZE], key[DATA_SIZE];
uint16_t keylen, keyl;

void trade_keys()
{
	uint8_t pub[96], peer[96], priv[48];
	uint8_t buf[128], gen_key[HASH_SIZE], ret;
	uint8_t buf_len, pub_len;

	// Generate public key pair
	if ((ret = mbed_gen_pair_scalar(priv, pub)) != 0)
		printf ("Error generating pair: %d\n", ret);
	
	// Receive client's public key: size+pub
	receive_plain(pipe_fd, &pub_len, 1);
	receive_plain(pipe_fd, peer, pub_len);

	// Send generated public key: size+pub
	send_plain(pipe_fd, &pub_len, 1);
	send_plain(pipe_fd, pub, pub_len);

	if ((ret = mbed_ecdh_scalar(priv, peer, buf, (size_t *)&buf_len)) != 0)
		printf ("Error ECDH: %d\n", ret);

	if ((ret = mbed_sha256(buf, buf_len, gen_key)) != 0)
		printf ("Error SHA256: %d\n", ret);

	// Save key in buffer
	init_key (gen_key);

	printf ("Symmetric Key: %s\n", (char *)gen_key);
}

int main (void)
{
	init();

	// trade_keys();
	
	// ----------------- Key set stuff -----------------
	// init_keys((uint8_t *)"41203491263490123428136482364iub", 32);

	// read_key_set(key_set, &keylen);
	
	// add_key((uint8_t *)"i11111111111111122222222222222233333333f", 40);
	// add_key((uint8_t *)"i11111111111111122242rrrrrrrr2233333333f", 40);
	// read_key_set(key_set, &keylen);

	// fetch_key_from_set(key_set, keylen, 2, key, &keyl);
	// ----------------- Key set stuff -----------------

	while(1)
	{
		// display_greeting(); // Send greeting string

		// Receive operation code
		receive_from_connection(pipe_fd, &req.op_code, sizeof(uint8_t));
		printf("[SERVER] Received Operation %d....\n", req.op_code);

		resp.op_code = req.op_code; // same op_code for response

		// Check authentication
		if (req.op_code > 1 && !authenticated)
		{
			sendOK(pipe_fd, (uint8_t *)"NO"); // Not authenticated
			continue;
		}
		else
			sendOK(pipe_fd, (uint8_t *)"OK"); // Authenticated

		/* --------------------------------------------------- */
		/* Perform operation */
		switch (req.op_code)
		{
			case 1: // Authentication
				authenticate();
				break;
			case 2: // Change PIN
				// authenticate old PIN
				// receive_from_connection(pipe_fd, req.auth.pin, PIN_SIZE-2);

				// resp.status = !compare_strings(req.auth.pin, AUTH_PIN, PIN_SIZE-2);
				// if it was not authenticated for change, return
				// send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				// if (!resp.status)
					// continue;
				// if (send_status(pipe_fd, resp.status) == 0)
				//         continue;

				// Get new PIN and change it
				receive_from_connection(pipe_fd, req.admin.pin, PIN_SIZE-2);
				memcpy(AUTH_PIN, req.admin.pin, PIN_SIZE-2); // Save PIN
				sendOK(pipe_fd, (uint8_t *)"OK");
				break;
			case 3: // Encrypt + authenticate data
			case 4: // Decrypt + authenticate data
				// Get data size
				receive_from_connection(pipe_fd, &req.data.data_size, sizeof(req.data.data_size));
				// Check if size is 0
				if (send_status(pipe_fd, req.data.data_size) == 0)
					continue;

				// Get data
				receive_from_connection(pipe_fd, req.data.data, req.data.data_size);
				sendOK(pipe_fd, (uint8_t *)"OK");

				// Get key ID
				receive_from_connection(pipe_fd, req.data.key_id, ID_SIZE);
				sendOK(pipe_fd, (uint8_t *)"OK");

				encrypt_authenticate();

				// Send data result size
				send_to_connection(pipe_fd, &resp.data.data_size, sizeof(resp.data.data_size));
				waitOK(pipe_fd);
				// Send data
				send_to_connection(pipe_fd, resp.data.data, resp.data.data_size);
				waitOK(pipe_fd);
				break;
			case 5: // Sign with private key
				// Get data size
				receive_from_connection(pipe_fd, &req.sign.data_size, sizeof(req.sign.data_size));
				// Check if size is 0
				if (send_status(pipe_fd, req.sign.data_size) == 0)
					continue;

				// Get data
				receive_from_connection(pipe_fd, req.sign.data, req.sign.data_size);
				// printf ("data: %s\n", req.sign.data);
				// sendOK(pipe_fd, (uint8_t *)"OK");

				if (req.sign.data[0] != 0)
					sign_operation(); // Sign with private key
				else
					resp.status = 1;

				// Send op status
				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK(pipe_fd);

				if (resp.status != 0)
					continue;

				// Send signature size
				send_to_connection(pipe_fd, &resp.sign.signlen, sizeof(resp.sign.signlen));
				waitOK(pipe_fd);
				// if status is good, send signature
				send_to_connection(pipe_fd, resp.sign.signature, resp.sign.signlen);
				waitOK(pipe_fd);
				break;
			case 6: // Verify signature
				// Get data size
				receive_from_connection(pipe_fd, &req.verify.data_size, sizeof(req.verify.data_size));
				// Check if size is 0
				if (send_status(pipe_fd, req.verify.data_size) == 0)
					continue;

				// Get data
				receive_from_connection(pipe_fd, req.verify.data, req.verify.data_size);
				sendOK(pipe_fd, (uint8_t *)"OK");

				// Get signature size
				receive_from_connection(pipe_fd, &req.verify.signlen, sizeof(req.verify.signlen));
				sendOK(pipe_fd, (uint8_t *)"OK");

				// Get signature
				receive_from_connection(pipe_fd, req.verify.signature, req.verify.signlen);
				sendOK(pipe_fd, (uint8_t *)"OK");

				// Get entity ID who signed the data
				receive_from_connection(pipe_fd, req.verify.entity_id, ID_SIZE);
				// Check if entity ID is empty
				if (req.verify.entity_id[0] != 0)
					verify_operation(); // verifies signature
				else
					resp.status = 0;

				// Send op status
				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK(pipe_fd);
				break;
			case 7: // Import public key
				// Get entity ID
				receive_from_connection(pipe_fd, req.import_pub.entity_id, ID_SIZE);
				// Check if entity ID is empty
				if (send_status(pipe_fd, req.import_pub.entity_id[0]) == 0)
					continue;
				// get certificate size
				receive_from_connection(pipe_fd, &req.import_pub.cert_size, sizeof(req.import_pub.cert_size));
				// Check if certificate size is 0
				if (send_status(pipe_fd, req.import_pub.cert_size) == 0)
					continue;

				// get certificate data
				receive_from_connection(pipe_fd, req.import_pub.public_key, req.import_pub.cert_size);
				// Check if certificate is empty
				if (send_status(pipe_fd, req.import_pub.public_key[0]) == 0)
					continue;

				// Save certificate in HSM
				import_pubkey_operation();

				// Send op status
				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK(pipe_fd);
				break;
			case 8:
				// Get key ID, will be generated
				receive_from_connection(pipe_fd, req.gen_key.entity_id, ID_SIZE);
				// Check if key ID is empty
				if (send_status(pipe_fd, req.gen_key.entity_id[0]) == 0)
					continue;

				new_comms_key();

				// Send op status
				send_to_connection(pipe_fd, &resp.status, sizeof(uint8_t));
				waitOK(pipe_fd);

				break;
			case 9: // List avaiable secure comm keys
				get_list_comm_keys (resp.list.list);

				// Send list of available keys
				send_to_connection(pipe_fd, resp.list.list, DATA_SIZE);
				waitOK(pipe_fd);
				break;
			case 10:
				// mark user as logged out
				authenticated = 0;
				sendOK(pipe_fd, (uint8_t *)"OK");
				printf("[SERVER] User logged out..\n");
				break;
			case 0:
				break;
			default:
				sendOK(pipe_fd, (uint8_t *)"NO");
				printf("Wrong choice, try again\n");
		}
		printf("\n[SERVER] Finished Op. %d\n", req.op_code);
	}

	return 0;
}

// .cert -> certificate
// .key  -> private/symmetric key
void get_key_path (uint8_t * entity, uint8_t * key_path, uint8_t * extension)
{
	uint8_t c = strlen((char *)entity)-1;
	// Remove newline from end of string
	if (entity[c] == '\n')
		entity[c] = '\0';

	snprintf((char*)key_path, ID_SIZE, "keys/%s%s", entity, extension);
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
	// get PIN from user
	receive_from_connection(pipe_fd, req.auth.pin, PIN_SIZE);
	printf ("PIN: ");
	printf ("%c %c %c %c", req.auth.pin[0], req.auth.pin[1], req.auth.pin[2], req.auth.pin[3]);

	// check PIN 
	authenticated = resp.status = !strncmp ((char *)req.auth.pin, (char *)AUTH_PIN, 4);
	// authenticated = resp.status = !compare_strings(req.auth.pin, AUTH_PIN, PIN_SIZE);

	if (!authenticated)
		printf("[SERVER] Authentication failed\n");
	else
		printf("[SERVER] Authentication succesfull\n");

	// send resonse back
	send_to_connection(pipe_fd, &authenticated, sizeof(uint8_t));
}

// Operation 3: encrypt + authenticate
// Operation 4: decrypt + authenticate
void encrypt_authenticate()
{
	uint8_t keyfile[ID_SIZE];

	get_key_path(req.data.key_id, keyfile, (uint8_t *)".key");

	// Encrypt/Decrypte data
	if (req.op_code == 3)
		resp.status = resp.data.data_size = encrypt(req.data.data, req.data.data_size, resp.data.data, keyfile);
	// Decrypt and authenticate data
	else
		resp.status = resp.data.data_size = decrypt(req.data.data, req.data.data_size, resp.data.data, keyfile);
	resp.data.data[resp.data.data_size] = 0;
}

// Operation 5: sign data
void sign_operation ()
{
	// -----------------------------
	// uint8_t private[ECC_KEY_SIZE];

	// Read private key from file
	// read_from_file ((uint8_t *)PRIVATE_KEY, private);

	// Sign data
	// resp.status = sign_data(private, req.sign.data, req.sign.data_size, resp.sign.signature, (size_t *)&resp.sign.signlen);
	// -----------------------------
	resp.status = sign_data(req.sign.data, req.sign.data_size, (uint8_t *)PRIVATE_KEY, resp.sign.signature, &resp.sign.signlen);
	if (resp.status == 0)
		printf ("[SERVER] Data succesfully signed\n");
	else
		printf ("[SERVER] Error signing data\n");
}

// Operation 6: verify signature from data
void verify_operation()
{
	uint8_t keyfile[ID_SIZE];

	// -----------------------------
	// uint8_t pub[PUB_KEY_SIZE];
	// Get certificate path from secure storage
	// get_key_path(req.verify.entity_id, keyfile, (uint8_t *)".pub");
	// Read certificate
	// read_from_file (keyfile, pub);
	// Verify signature
	// resp.status = verify_signature(pub, req.verify.data, req.verify.data_size, req.verify.signature, (size_t)req.verify.signlen);

	// -----------------------------
	get_key_path(req.verify.entity_id, keyfile, (uint8_t *)".cert");

	resp.status = !verify_data(req.verify.data, req.verify.data_size, keyfile, req.verify.signature, req.verify.signlen);
	if (resp.status == 0)
		printf ("[SERVER] Signature verified successfully\n");
	else
		printf ("[SERVER] Error verifying signature\n");
}

// Operation 7: import public key certificate
void import_pubkey_operation()
{
	uint8_t keyfile[ID_SIZE];
	get_key_path(req.import_pub.entity_id, keyfile, (uint8_t *)".pub");

	if (write_to_file(keyfile, req.import_pub.public_key, req.import_pub.cert_size) != NULL)
		resp.status = 1;
	else
		resp.status = 0;
}

// Operation 8: Generate new key from private key, and an entities public key
/*
void new_comms_key ()
{
	uint8_t secret[128u];
	uint8_t keyfile[ID_SIZE];
	uint8_t private[ECC_KEY_SIZE];
	uint8_t pub[PUB_KEY_SIZE];
	// TODO exchange salt, or agree salt beforehand
	// uint8_t salt[16u] = "3234567890123456";
	// uint8_t key[KEY_SIZE*2];
	size_t secret_len;

	// Read private key from file
	read_from_file ((uint8_t *)PRIVATE_KEY, private);
	// Get pub key path
	get_key_path(req.gen_key.entity_id, keyfile, (uint8_t *)".pub");

	// Read certificate
	read_from_file (keyfile, pub);

	resp.status = ecdh(private, pub, secret, &secret_len);

	// If key was successfully derived, store it
	if (resp.status == 0)
	{
		// resp.status = kdf (salt, 16u, secret, secret_len, key);
		// if (resp.status == 0)
		// {
		get_key_path(req.gen_key.entity_id, keyfile, (uint8_t *)".key");
		write_to_file (keyfile, secret, KEY_SIZE*2);
		// }
	}
}
*/

// Operation 8: Generate new key from private key, and an entities public key
void new_comms_key ()
{
	uint8_t key[HASH_SIZE];
	size_t len;
	uint8_t * secret;
	uint8_t keyfile[ID_SIZE];

	get_key_path(req.gen_key.entity_id, keyfile, (uint8_t *)".cert");

	secret = ecdh((uint8_t *)PRIVATE_KEY, keyfile, &len);

	if (secret == NULL)
	{
		resp.status = 1;
		return;
	}

	// Key derivation function from secret
	// resp.status = simpleSHA256(secret, len, key);
	resp.status = mbed_sha256 (secret, len, key);

	free(secret);
	// If key was successfully derived, store it
	if (resp.status == 0)
	{
		get_key_path(req.gen_key.entity_id, keyfile, (uint8_t *)".key");
		write_to_file (keyfile, key, HASH_SIZE);
	}
}

void init()
{
	memcpy(AUTH_PIN, "1234", 4);
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
8. New comms key\n\
9. List comm keys\n\
10. Logout\n\
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
	// release_drbg_service(drbg_handle);
	close(pipe_fd);
	exit(0);
}
