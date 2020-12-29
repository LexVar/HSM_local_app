#include "client.h"

int pipe_fd;		// pipe file descriptor
struct request req;	// request structure
struct response resp;	// response structure

int main(void)
{
	char greetings[DATA_SIZE];
	// Redirects SIGINT (CTRL-c) to cleanup()
	signal(SIGINT, cleanup);

	while (1) {

		printf ("Press ENTER to continue...\n");
		if (fgets(greetings, DATA_SIZE, stdin) == NULL)
		{
			printf ("[CLIENT] Error stdin..\n");
			continue;
		}
		if (check_authentication() != 1)
		{
			printf("[CLIENT] Authentication failed\n");
			continue;
		}

		printf("[CLIENT] Authentication succesfull\n");

		receive_from_connection(pipe_fd, greetings, sizeof(greetings));

		printf ("%s", greetings);
		scanf("%hhd", &(req.op_code));

		flush_stdin();

		// ------------------------------
		// set request attributes depending on op. code
		switch (req.op_code)
		{
			case 2:	// Change authentication PIN
				printf("New PIN: ");
				if (fgets(req.admin.pin, PIN_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting PIN, try again..\n");
					continue;
				}
				break;
			case 3: // Encrypt and authenticate data
				printf("Data filename: ");
				if ((req.data.data_size = get_attribute_from_file((char *)req.data.data)) == 0)
					continue;
				printf("Key ID to encrypt data: ");
				if (fgets(req.data.key_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}
				break;
			case 4: // Decrypt and authenticate data
				printf("Data filename: ");
				if ((req.data.data_size = get_attribute_from_file((char *)req.data.data)) == 0)
					continue;
				printf("Key ID to decrypt data: ");
				if (fgets(req.data.key_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}
				break;
			case 5:	// Sign message
				printf("Data filename: ");
				if ((req.sign.data_size = get_attribute_from_file(req.sign.data)) == 0)
					continue;

				break;
			case 6:	// Sign message
				printf("Data filename: ");
				if ((req.verify.data_size = get_attribute_from_file(req.verify.data)) == 0)
					continue;

				printf("Signature filename: ");
				if (get_attribute_from_file(req.verify.signature) == 0)
					continue;

				printf("Entity's ID: ");
				if (fgets(req.verify.entity_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}
				break;
			case 7:	// Import public key
				printf("Public key filename: ");
				if (get_attribute_from_file(req.import_pub.public_key) == 0)
					continue;

				printf("Entity's ID: ");
				if (fgets(req.import_pub.entity_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}
				break;
			case 8:	// Share key
				printf("Entity's ID (to share key with): ");
				if (fgets(req.gen_key.entity_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}

				printf("New Key's ID: ");
				if (fgets(req.gen_key.key_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}
				break;
			case 9:	// Save key
				printf("Entity's ID (to share key with): ");
				if (fgets(req.save_key.entity_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}

				printf("New Key's ID: ");
				if (fgets(req.save_key.key_id, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting ID, try again..\n");
					continue;
				}

				printf("Message (encrypted key): ");
				if (get_attribute_from_file((char *)req.save_key.msg) == 0)
					continue;
				break;
			case 10:
				break;
			case 11:
				printf ("[CLIENT] Sending logout request\n");
				break;
			case 0:
				printf("[CLIENT] Stopping client..\n");
				exit(0);
				break;
			default:
				printf("\n[CLIENT] %d. Is not a valid operation\n", req.op_code);
				sleep (2);
				continue;
		}

		// ----------------------------------------------------
		// Send the request
		send_to_connection(pipe_fd, &req, sizeof(struct request));

		printf("[CLIENT] Sent Operation %d....\n", req.op_code);

		// ----------------------------------------------------
		// Receiving the response
		receive_from_connection(pipe_fd, &resp, sizeof(struct response));

		printf("[CLIENT] Received response: status %d\n", resp.status);

		// ----------------------------------------------------
		// Treat the response
		if (resp.status == -1)
		{
			printf ("[CLIENT] !!!! Some error ocurred on the server\n");
		}

		switch (resp.op_code)
		{
			case 2: // Change PIN
				if (resp.status == 0)
					printf ("[CLIENT] PIN was changed succesfully\n");
				break;
			case 3: // Encrypt + authenticate data
				if (resp.status <= 0)
					printf ("Error encrypting data\n");
				else
				{
					printf ("[CLIENT] Encrypted data (\"data.enc\"):\n%s\n", resp.data.data);
					write_to_file ("data.enc", (char *)resp.data.data, resp.data.data_size);
				}
				break;
			case 4: // Decrypt + authenticate data
				if (resp.status <= 0)
					printf ("Error decrypting data\n");
				else
				{
					printf ("[CLIENT] Decrypted data (\"data.txt\"):\n%s\n", resp.data.data);
					write_to_file ("data.txt", (char *)resp.data.data, resp.data.data_size);
				}
				break;
			case 5: // Sign data
				printf ("[CLIENT] Signature: (\"signature.txt\"):\n%s\n", resp.sign.signature);
				write_to_file ("signature.txt", resp.sign.signature, SIGNATURE_SIZE);
				break;
			case 6: // Verify signature
				if (resp.status != 0)
					printf ("[CLIENT] Signature successfully verified\n");
				else
					printf ("[CLIENT] Signature failed verification\n");
				break;
			case 7: // Import public key
				if (resp.status == 0)
					printf ("[CLIENT] Public key successfully saved\n");
				break;
			case 8: // Generate new key
				printf ("[CLIENT] Generated encrypted key (\"new_key.enc\"): \n%s\n", resp.gen_key.msg);
				write_to_file ("key.enc", (char *)resp.gen_key.msg, CIPHER_SIZE+SIGNATURE_SIZE);
				break;
			case 9: // Save key
				if (resp.status == 0)
					printf ("[CLIENT] Saved new symmetric key\n");
				break;
			case 10:
				printf ("List of keys:\n");
				printf("%s", resp.list.list);
				break;
			default:
				break;
		}

		// Wait before printing the menu again
		sleep(2);
	}
	return 0;
}

int check_authentication ()
{
	receive_from_connection(pipe_fd, &resp, sizeof(struct response));
	if (resp.status != 1)
	{
		req.op_code = 1;
		printf("PIN: ");

		if (fgets(req.auth.pin, PIN_SIZE, stdin) == NULL)
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

int get_attribute_from_file (char * attribute)
{
	char filename[ID_SIZE];

	if (fgets(filename, ID_SIZE, stdin) == NULL)
	{
		printf ("[CLIENT] Error getting filename, try again..\n");
		return 0;
	}
	filename[strlen(filename)-1] = 0; // Remove newline from filename

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
