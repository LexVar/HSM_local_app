#include "client.h"

struct request req;	// request structure
struct response resp;	// response structure

int main(void)
{
	uint8_t greetings[DATA_SIZE];
	// Redirects SIGINT (CTRL-c) to cleanup()
	signal(SIGINT, cleanup);

	while (1) {
		// if (C_Initialize(NULL) == CKR_FUNCTION_NOT_SUPPORTED)
		//         printf("not suppoerted\n");
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
		if (!waitOK(pipe_fd))
		{
			printf ("NOT AUTHENTICATED\n");
			continue;
		}

		// ------------------------------
		// set request attributes depending on op. code
		switch (req.op_code)
		{
			case 1: // Authentication request
				printf("PIN: ");

				if (fgets((char *)req.auth.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					return 0;
				}
				flush_stdin();

				if (C_Login(0, 0, req.auth.pin, PIN_SIZE) == CKR_OK)
					printf("[CLIENT] Authentication SUCCESS\n");
				else
					printf("[CLIENT] Authentication failed\n");

				break;
			case 2:	// Change authentication PIN
				printf("Old PIN: ");
				if (fgets((char *)req.auth.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					return 0;
				}
				flush_stdin();

				printf("New PIN: ");
				if (fgets((char *)req.admin.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					return 0;
				}
				flush_stdin();

				if (C_SetPIN(0, req.auth.pin, PIN_SIZE, req.admin.pin, PIN_SIZE) == CKR_OK)
					printf("[CLIENT] PIN succesfully set\n");
				else
					printf("[CLIENT] Operation failed \n");

				// C_SetPIN,
				// set_pin();
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
			case 8: // New communications key
				new_comms_key();
				break;
			case 9: // Get available symmetric key list
				receive_from_connection(pipe_fd, resp.list.list,DATA_SIZE);
				sendOK(pipe_fd, (uint8_t *)"OK");

				printf ("List of keys:\n");
				printf("%s", resp.list.list);
				break;
			case 10: // Logout request
				printf ("[CLIENT] Sending logout request\n");
				waitOK(pipe_fd);
				break;
			case 0:
				printf("[CLIENT] Stopping client..\n");
				exit(0);
				break;
			default:
				waitOK(pipe_fd);
				printf("\n[CLIENT] %d. Is not a valid operation\n", req.op_code);
		}
	}
	return 0;
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
	if (!waitOK(pipe_fd))
		return;

	// send data
	send_to_connection(pipe_fd, req.data.data, req.data.data_size);
	if (!waitOK(pipe_fd))
		return;

	printf("Key ID to use to encrypt/decrypt data: ");
	if (fgets((char *)req.data.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID\n");
		req.data.key_id[0] = 0; // marks it's invalid
	}

	send_to_connection(pipe_fd, req.data.key_id, ID_SIZE); // send key ID
	if (!waitOK(pipe_fd))
		return;

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &resp.data.data_size, sizeof(uint16_t));
	sendOK(pipe_fd, (uint8_t *)"OK");
	receive_from_connection(pipe_fd, resp.data.data, resp.data.data_size);
	sendOK(pipe_fd, (uint8_t *)"OK");

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
	if(!waitOK(pipe_fd))
		return;

	// send data
	send_to_connection(pipe_fd, req.sign.data, req.sign.data_size);
	if(!waitOK(pipe_fd))
		return;

	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK(pipe_fd, (uint8_t *)"OK");
	if (resp.status != 0)
		return;
	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, resp.sign.signature, SIGNATURE_SIZE);
	sendOK(pipe_fd, (uint8_t *)"OK");

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
	if(!waitOK(pipe_fd))
		return;

	// send data
	send_to_connection(pipe_fd, req.verify.data, req.verify.data_size);
	if(!waitOK(pipe_fd))
		return;

	printf("Signature filename: ");
	if (get_attribute_from_file(req.verify.signature) == 0)
		printf ("Some error\n");

	// send data size
	send_to_connection(pipe_fd, req.verify.signature, SIGNATURE_SIZE);
	if(!waitOK(pipe_fd))
		return;

	printf("Entity's ID: ");
	if (fgets((char *)req.verify.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.verify.entity_id[0] = 0;
	}

	// send entity ID
	send_to_connection(pipe_fd, req.verify.entity_id, ID_SIZE);
	if(!waitOK(pipe_fd))
		return;

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK(pipe_fd, (uint8_t *)"OK");

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
	if(!waitOK(pipe_fd))
		return;

	printf("Public key filename: ");
	if ((req.import_pub.cert_size = get_attribute_from_file(req.import_pub.public_key)) == 0)
		printf ("Some error\n");

	// Send certificate size
	send_to_connection(pipe_fd, &req.import_pub.cert_size, sizeof(uint16_t));
	if(!waitOK(pipe_fd))
		return;

	// send entity ID
	send_to_connection(pipe_fd, req.import_pub.public_key, req.import_pub.cert_size);
	if(!waitOK(pipe_fd))
		return;

	// Receives status
	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK(pipe_fd, (uint8_t *)"OK");

	if (resp.status != 0)
		printf ("[CLIENT] Public key successfully saved\n");
}

// Operation 8: Generate new key for sharing
void new_comms_key()
{
	printf("Entity's ID (to share key with): ");
	if (fgets((char *)req.gen_key.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		req.gen_key.entity_id[0] = 0;
	}
	// send entity ID
	send_to_connection(pipe_fd, req.gen_key.entity_id, ID_SIZE);
	if(!waitOK(pipe_fd))
		return;

	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	sendOK(pipe_fd, (uint8_t *)"OK");
	if (resp.status == 0)
		printf ("[CLIENT] Key successfully generated and saved with key_id: %s\n", req.gen_key.entity_id);
	else
		printf ("[CLIENT] Some error ocurred deriving shared secret\n");
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

void cleanup()
{
	printf ("\n[CLIENT] Cleaning up...\n");
	/* place all cleanup operations here */
	close(pipe_fd);
	exit (0);
}
