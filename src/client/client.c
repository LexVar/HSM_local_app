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
		{
			printf ("[CLIENT] Error stdin..\n");
			continue;
		}

		// send_to_connection(pipe_fd, (uint8_t *)"ACK", sizeof("ACK"));
                //
		// waitOK("OK");

		// if (check_authentication() != 1)
		// {
		//         printf("[CLIENT] Authentication failed\n");
		//         continue;
		// }

		// printf("[CLIENT] Authentication succesfull\n");

		receive_from_connection(pipe_fd, greetings, sizeof(greetings));

		printf ("%s", greetings);
		scanf("%hhd", &(req.op_code));

		flush_stdin();

		send_to_connection(pipe_fd, &req.op_code, sizeof(uint8_t));
		// ------------------------------
		// set request attributes depending on op. code
		switch (req.op_code)
		{
			case 2:	// Change authentication PIN
				printf("New PIN: ");
				if (fgets((char *)req.admin.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					continue;
				}
				if (resp.status == 0)
					printf ("[CLIENT] PIN was changed succesfully\n");
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
			case 10:
				receive_from_connection(pipe_fd, resp.list.list,DATA_SIZE);
				printf ("List of keys:\n");
				printf("%s", resp.list.list);
				break;
			case 11:
				printf ("[CLIENT] Sending logout request\n");
				send_to_connection(pipe_fd, &req.op_code, sizeof(uint8_t));
				break;
			case 0:
				printf("[CLIENT] Stopping client..\n");
				exit(0);
				break;
			default:
				printf("\n[CLIENT] %d. Is not a valid operation\n", req.op_code);
				sleep (0.5);
				continue;
		}

		// Wait before printing the menu again
		sleep(0.5);
	}
	return 0;
}

void waitOK()
{
	uint8_t msg[ID_SIZE];
	receive_from_connection(pipe_fd, msg, ID_SIZE);

	if (msg[0] != 'O' && msg[1] != 'K')
		printf ("%s", msg);
}

void sign_operation()
{
	printf("Data filename: ");
	if ((req.sign.data_size = get_attribute_from_file(req.sign.data)) == 0)
		return;

	// send data size
	send_to_connection(pipe_fd, &req.sign.data_size, sizeof(uint16_t));
	waitOK();

	// send data
	send_to_connection(pipe_fd, req.sign.data, req.sign.data_size);
	waitOK();

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, resp.sign.signature, SIGNATURE_SIZE);

	printf ("[CLIENT] Signature: (\"signature.txt\"):\n%s\n", resp.sign.signature);
	write_to_file ((uint8_t *)"signature.txt", resp.sign.signature, SIGNATURE_SIZE);
}

void verify_operation()
{
	printf("Data filename: ");
	if ((req.verify.data_size = get_attribute_from_file(req.verify.data)) == 0)
		return;

	// send data size
	send_to_connection(pipe_fd, &req.verify.data_size, sizeof(uint16_t));
	waitOK();

	// send data
	send_to_connection(pipe_fd, req.verify.data, req.verify.data_size);
	waitOK();

	printf("Signature filename: ");
	if (get_attribute_from_file(req.verify.signature) == 0)
		return;

	// send data size
	send_to_connection(pipe_fd, req.verify.signature, SIGNATURE_SIZE);
	waitOK();

	printf("Entity's ID: ");
	if (fgets((char *)req.verify.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		return;
	}

	// send entity ID
	send_to_connection(pipe_fd, req.verify.entity_id, ID_SIZE);

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));

	if (resp.status != 0)
		printf ("[CLIENT] Signature successfully verified\n");
	else
		printf ("[CLIENT] Signature failed verification\n");
}
void import_pubkey_operation()
{
	printf("Entity's ID: ");
	if (fgets((char *)req.import_pub.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		return;
	}
	// send entity ID
	send_to_connection(pipe_fd, req.import_pub.entity_id, ID_SIZE);

	printf("Public key filename: ");
	if ((req.import_pub.cert_size = get_attribute_from_file(req.import_pub.public_key)) == 0)
		return;

	// Send certificate size
	send_to_connection(pipe_fd, &req.import_pub.cert_size, sizeof(uint16_t));
	waitOK();

	// send entity ID
	send_to_connection(pipe_fd, req.import_pub.public_key, req.import_pub.cert_size);

	// Receives status
	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));

	if (resp.status == 0)
		printf ("[CLIENT] Public key successfully saved\n");
}
void share_key_operation()
{
	printf("Entity's ID (to share key with): ");
	if (fgets((char *)req.gen_key.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		return;
	}
	// send entity ID
	send_to_connection(pipe_fd, req.gen_key.entity_id, ID_SIZE);

	printf("New Key's ID: ");
	if (fgets((char *)req.gen_key.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		return;
	}
	// Send key ID
	send_to_connection(pipe_fd, &req.gen_key.key_id, ID_SIZE);

	// Receives key
	receive_from_connection(pipe_fd, resp.gen_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);

	printf ("[CLIENT] Generated encrypted key (\"new_key.enc\"): \n%s\n", resp.gen_key.msg);
	write_to_file ((uint8_t *)"key.enc", resp.gen_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);
}
void save_key_operation()
{
	printf("Entity's ID (to share key with): ");
	if (fgets((char *)req.save_key.entity_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		return;
	}
	// Send entity id
	send_to_connection(pipe_fd, req.save_key.entity_id, ID_SIZE);

	printf("New Key's ID: ");
	if (fgets((char *)req.save_key.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		return;
	}
	// Send key size
	send_to_connection(pipe_fd, req.save_key.key_id, ID_SIZE);

	printf("Message (encrypted key): ");
	if (get_attribute_from_file(req.save_key.msg) == 0)
		return;
	// Send message
	send_to_connection(pipe_fd, req.save_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);

	receive_from_connection(pipe_fd, &resp.status, sizeof(uint8_t));
	if (resp.status == 0)
		printf ("[CLIENT] Saved new symmetric key\n");
}
void encrypt_authenticate(uint8_t * file)
{
	printf("Data filename: ");
	if ((req.data.data_size = get_attribute_from_file(req.data.data)) == 0)
		return;

	// send data size
	send_to_connection(pipe_fd, &req.data.data_size, sizeof(uint16_t));
	waitOK();

	// send data
	send_to_connection(pipe_fd, req.data.data, req.data.data_size);
	waitOK();

	printf("Key ID to use to encrypt/decrypt data: ");
	if (fgets((char *)req.data.key_id, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting ID, try again..\n");
		return;
	}
	send_to_connection(pipe_fd, req.data.key_id, ID_SIZE); // send key ID

	// Receives encrypt and authenticated data
	receive_from_connection(pipe_fd, &resp.data.data_size, sizeof(uint16_t));
	receive_from_connection(pipe_fd, resp.data.data, resp.data.data_size);

	if (resp.data.data_size <= 0)
		printf ("Some error ocurred data\n");
	else
	{
		printf ("[CLIENT] Data (\"%s\"):\n%s\n", file, resp.data.data);
		write_to_file ((uint8_t *)file, resp.data.data, resp.data.data_size);
	}
}

uint8_t check_authentication ()
{
	receive_from_connection(pipe_fd, &resp, sizeof(struct response));
	if (resp.status != 1)
	{
		req.op_code = 1;
		printf("PIN: ");

		if (fgets((char *)req.auth.pin, PIN_SIZE, stdin) == NULL)
		{
			printf ("[CLIENT] Error getting PIN, try again..\n");
			return 0;
		}
		send_to_connection(pipe_fd, &req, sizeof(struct request));
		printf("[CLIENT] Sent Auth request\n");

		receive_from_connection(pipe_fd, &resp, sizeof(struct response));
	}
	return resp.status;
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
