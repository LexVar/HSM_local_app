#include "client.h"

uint32_t pipe_fd;	// pipe file descriptor
struct request req;	// request structure
struct response resp;	// response structure

int main(void)
{
	uint8_t greetings[DATA_SIZE];
	// Redirects SIGINT (CTRL-c) to cleanup()
	signal(SIGINT, cleanup);

	while (1) {
		printf ("Press ENTER to continue...\n");
		if (fgets((char *)greetings, DATA_SIZE, stdin) == NULL)
			continue;

		// Get greetings message
		receive_from_connection(pipe_fd, greetings, sizeof(greetings));
		printf ("%s", greetings);

		// Input op code from stdin
		scanf("%hhd", &(req.op_code));

		flush_stdin();

		// Send op code and wait for confirmation
		// If error occurs, user must choose code:1 and authenticate with PIN
		send_to_connection(pipe_fd, &req.op_code, sizeof(uint8_t));
		if (!waitOK())
		{
			printf ("NOT AUTHENTICATED\n");
			continue;
		}

		// ------------------------------
		// set request attributes depending on op. code
		switch (req.op_code)
		{
			case 1: // Authentication request
				authenticate();
				break;
			case 2:	// Change authentication PIN
				set_pin();
				break;
			case 3: // Encrypt and authenticate data
				encrypt_authenticate((uint8_t *)"data.enc");
				break;
			case 4: // Decrypt and authenticate data
				encrypt_authenticate((uint8_t *)"data.txt");
				break;
			case 5:	// Sign message
				sign_operation();
				break;
			case 6:	// Sign message
				verify_operation();
				break;
			case 7:	// Import public key
				import_pubkey_operation();
				break;
			case 8:	// Share key
				share_key_operation();
				break;
			case 9:	// Save key
				save_key_operation();
				break;
			case 10: // Get available symmetric key list
				receive_from_connection(pipe_fd, resp.list.list,DATA_SIZE);
				sendOK((uint8_t *)"OK");

				printf ("List of keys:\n");
				printf("%s", resp.list.list);
				break;
			case 11: // Logout request
				printf ("[CLIENT] Sending logout request\n");
				waitOK();
				break;
			case 0:
				printf("[CLIENT] Stopping client..\n");
				exit(0);
				break;
			default:
				waitOK();
				printf("\n[CLIENT] %d. Is not a valid operation\n", req.op_code);
		}
	}
	return 0;
}

// Operation 2: Set new authentication PIN
uint8_t set_pin()
{
	printf("New PIN: ");
	if (fgets((char *)req.admin.pin, PIN_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting PIN, try again..\n");
		return 0;
	}
	send_to_connection(pipe_fd, req.admin.pin, PIN_SIZE);

	return waitOK();
}

// Operation 1: Authenticate
uint8_t authenticate()
{
	printf("PIN: ");

	if (fgets((char *)req.auth.pin, PIN_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting PIN, try again..\n");
		return 0;
	}
	send_to_connection(pipe_fd, req.auth.pin, PIN_SIZE);

	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	if (resp.status == 0)
		printf("[CLIENT] Authentication failed\n");
	else
		printf("[CLIENT] Authentication SUCCESS\n");

	return resp.status;
}

// Operation 3: encrypt + authenticate
// Operation 4: decrypt + authenticate
void encrypt_authenticate(uint8_t * file)
{
	printf("Data filename: ");
	if ((req.data.data_size = get_attribute_from_file(req.data.data)) == 0)
	{
		printf ("Some error\n");
	}

	// send data size
	send_to_connection(pipe_fd, &req.data.data_size, sizeof(uint16_t));
	if (!waitOK())
		return;

	// send data
	send_to_connection(pipe_fd, req.data.data, req.data.data_size);
	if (!waitOK())
		return;

	printf("Key ID to use to encrypt/decrypt data: ");
	if (fgets((char *)req.data.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID\n");
		req.data.key_id[0] = 0; // marks it's invalid
	}

	send_to_connection(pipe_fd, req.data.key_id, ID_SIZE); // send key ID
	if (!waitOK())
		return;

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &resp.data.data_size, sizeof(uint16_t));
	sendOK((uint8_t *)"OK");
	receive_from_connection(pipe_fd, resp.data.data, resp.data.data_size);
	sendOK((uint8_t *)"OK");

	if (resp.data.data_size <= 0)
		printf ("Some error ocurred data\n");
	else
	{
		// If success, data in resp.data.data
		resp.data.data[resp.data.data_size] = 0;
		printf ("[CLIENT] Data (\"%s\"):\n%s\n", file, resp.data.data);
		write_to_file ((uint8_t *)file, resp.data.data, resp.data.data_size);
	}
}

// Operation 5: sign data
void sign_operation()
{
	printf("Data filename: ");
	if ((req.sign.data_size = get_attribute_from_file(req.sign.data)) == 0)
	{
		printf ("Some error\n");
		req.sign.data[0] = 0;
	}

	// send data size
	send_to_connection(pipe_fd, &req.sign.data_size, sizeof(uint16_t));
	if(!waitOK())
		return;

	// send data
	send_to_connection(pipe_fd, req.sign.data, req.sign.data_size);
	if(!waitOK())
		return;

	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK((uint8_t *)"OK");
	if (resp.status != 0)
		return;
	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, resp.sign.signature, SIGNATURE_SIZE);
	sendOK((uint8_t *)"OK");

	printf ("[CLIENT] Signature: (\"signature.txt\"):\n%s\n", resp.sign.signature);
	write_to_file ((uint8_t *)"signature.txt", resp.sign.signature, SIGNATURE_SIZE);
}

// Operation 6: verify signature from data
void verify_operation()
{
	printf("Data filename: ");
	if ((req.verify.data_size = get_attribute_from_file(req.verify.data)) == 0)
	{
		printf ("Some error\n");
		req.verify.data[0] = 0;
	}

	// send data size
	send_to_connection(pipe_fd, &req.verify.data_size, sizeof(uint16_t));
	if(!waitOK())
		return;

	// send data
	send_to_connection(pipe_fd, req.verify.data, req.verify.data_size);
	if(!waitOK())
		return;

	printf("Signature filename: ");
	if (get_attribute_from_file(req.verify.signature) == 0)
		printf ("Some error\n");

	// send data size
	send_to_connection(pipe_fd, req.verify.signature, SIGNATURE_SIZE);
	if(!waitOK())
		return;

	printf("Entity's ID: ");
	if (fgets((char *)req.verify.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.verify.entity_id[0] = 0;
	}

	// send entity ID
	send_to_connection(pipe_fd, req.verify.entity_id, ID_SIZE);
	if(!waitOK())
		return;

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK((uint8_t *)"OK");

	if (resp.status != 0)
		printf ("[CLIENT] Signature successfully verified\n");
	else
		printf ("[CLIENT] Signature failed verification\n");
}
// Operation 7: import public key certificate
void import_pubkey_operation()
{
	printf("Entity's ID: ");
	if (fgets((char *)req.import_pub.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.verify.entity_id[0] = 0;
	}
	// send entity ID
	send_to_connection(pipe_fd, req.import_pub.entity_id, ID_SIZE);
	if(!waitOK())
		return;

	printf("Public key filename: ");
	if ((req.import_pub.cert_size = get_attribute_from_file(req.import_pub.public_key)) == 0)
		printf ("Some error\n");

	// Send certificate size
	send_to_connection(pipe_fd, &req.import_pub.cert_size, sizeof(uint16_t));
	if(!waitOK())
		return;

	// send entity ID
	send_to_connection(pipe_fd, req.import_pub.public_key, req.import_pub.cert_size);
	if(!waitOK())
		return;

	// Receives status
	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK((uint8_t *)"OK");

	if (resp.status != 0)
		printf ("[CLIENT] Public key successfully saved\n");
}
// Operation 8: Generate new key for sharing
void share_key_operation()
{
	printf("Entity's ID (to share key with): ");
	if (fgets((char *)req.gen_key.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.gen_key.entity_id[0] = 0;
	}
	// send entity ID
	send_to_connection(pipe_fd, req.gen_key.entity_id, ID_SIZE);
	if(!waitOK())
		return;

	printf("New Key's ID: ");
	if (fgets((char *)req.gen_key.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.gen_key.key_id[0] = 0;
	}
	// Send key ID
	send_to_connection(pipe_fd, req.gen_key.key_id, ID_SIZE);
	if(!waitOK())
		return;

	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK((uint8_t *)"OK");
	if (resp.status == 0)
		return;

	// Receives key
	receive_from_connection(pipe_fd, resp.gen_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);
	sendOK((uint8_t *)"OK");

	printf ("[CLIENT] Generated encrypted key (\"new_key.enc\"): \n%s\n", resp.gen_key.msg);
	write_to_file ((uint8_t *)"key.enc", resp.gen_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);
}
// Operation 9: Save generated key from other entity
void save_key_operation()
{
	printf("Sender entity's ID: ");
	if (fgets((char *)req.save_key.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.save_key.entity_id[0] = 0;
	}
	// Send entity id
	send_to_connection(pipe_fd, req.save_key.entity_id, ID_SIZE);
	if(!waitOK())
		return;

	printf("New Key's ID: ");
	if (fgets((char *)req.save_key.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.save_key.key_id[0] = 0;
	}
	// Send key size
	send_to_connection(pipe_fd, req.save_key.key_id, ID_SIZE);
	if(!waitOK())
		return;

	printf("Message (encrypted key): ");
	if (get_attribute_from_file(req.save_key.msg) == 0)
		printf ("Some error\n");
	// Send message
	send_to_connection(pipe_fd, req.save_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);

	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));

	if (resp.status != 0)
		printf ("[CLIENT] Saved new symmetric key\n");
	else
		printf ("[CLIENT] Some error ocurred\n");
}

uint32_t get_attribute_from_file (uint8_t * attribute)
{
	uint8_t filename[ID_SIZE];

	if (fgets((char *)filename, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting filename, try again..\n");
		return 0;
	}
	filename[strlen((char *)filename)-1] = 0; // Remove newline from filename

	// get data and size from file
	return read_from_file (filename, attribute);
}

void sendOK(uint8_t * msg)
{
	send_to_connection(pipe_fd, msg, sizeof(msg));
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

void cleanup()
{
	printf ("\n[CLIENT] Cleaning up...\n");
	/* place all cleanup operations here */
	close(pipe_fd);
	exit (0);
}
