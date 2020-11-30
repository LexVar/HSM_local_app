#include "client.h"

// pipe file descriptor
int pipe_fd;

// request structure
struct request req;

// response structure
struct response resp;

int main(void)
{
	// Opens the pipe for writing
	int op;

	char filename[ID_SIZE];

	// Do some work
	while (1) {

		printf("\n----------CLIENT OPERATIONS---------\n");
		printf(" 2. Change PIN\n");
		printf(" 3. Encrypt and authenticate message\n");
		printf(" 4. Decrypt and authenticate message\n");
		printf(" 5. Sign message\n");
		printf(" 6. Verify message signature\n");
		printf(" 7. Import public key\n");
		printf(" 8. Share symmetric key\n");
		printf(" 9. Save shared symmetric key\n");
		printf(" 0. Quit\n");
		printf("------------------------------------\n\n");

		printf("Operation: ");
		scanf("%d", &op);

		flush_stdin();

		// ------------------------------
		// set request attributes
		req.op_code = op;

		switch (req.op_code)
		{
			// CHANGE PIN TODO
			case 3:
				printf("Data filename: ");

				if (fgets(filename, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting filename from stdin, try again..\n");
					continue;
				}
				filename[strlen(filename)-1] = 0; // Remove newline
				req.data.data_size = read_from_file (filename, req.data.data);
				printf("[CLIENT] Sending data:\n%s\n", req.data.data);
				break;
			case 4:
				printf("Encrypted filename: ");

				if (fgets(filename, ID_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error getting filename from stdin, try again..\n");
					continue;
				}
				filename[strlen(filename)-1] = 0; // Remove newline
				req.data.data_size = read_from_file (filename, req.data.data);

				printf("[CLIENT] Sending data:\n%s\n", req.data.data);
				break;
			case 0:
				printf("[CLIENT] Stopping client..\n");
				exit(0);
				break;
			default:
				printf("\n[CLIENT] %d. Is not a valid operation\n", op);
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

		printf("[CLIENT] Received Op. %d, status %d\n", resp.op_code, resp.status);

		// ----------------------------------------------------
		// Treat the response
		if (resp.status == -1)
		{
			printf ("[CLIENT] Some error ocurred on the server performing the operation\n");
		}
		else
		{
			switch (resp.op_code)
			{
				// CHANGE PIN TODO
				case 3:
					printf ("[CLIENT] Encrypted message:\n%s\n", resp.data.data);
					write_to_file ("data.enc", resp.data.data, resp.data.data_size);

					break;
				case 4:
					printf ("[CLIENT] Decrypted message:\n%s\n", resp.data.data);
					write_to_file ("data.txt", resp.data.data, resp.data.data_size);

					break;
				default:
					break;
			}
		}


		sleep(2);
	}
	return 0;
}

void cleanup()
{
	/* place all cleanup operations here */
	close(pipe_fd);
}
