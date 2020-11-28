#include "client.h"
#include "../pipe.h"
#include "../protocol.h"

/* pipe file descriptor */
int pipe_fd;

/* request structure */
struct request req;

/* response structure */
struct response resp;

int main()
{
	// Opens the pipe for writing
	int op;

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
		req.base.op_code = op;

		switch (req.base.op_code)
		{
			// CHANGE PIN TODO
			case 2:
				break;
			case 3:
				printf("Enter the message: ");

				if (fgets(req.data.data, DATA_SIZE, stdin) == NULL)
				{
					printf ("[CLIENT] Error reading message from input, try again..\n");
					continue;
				}
				// request.msg_req.msg_size = strlen(request.msg_req.msg);

				break;
			case 4:
				break;
			case 0:
				printf("[CLIENT] Sending message to stop server..\n");
				exit(0);
				break;
			default:
				printf("\n[CLIENT] %d. Is not a valid operation\n", op);
				sleep (2);
				continue;
		}

		// ----------------------------------------------------
		// Send the request
		send_to_connection(&req);

		// ----------------------------------------------------
		// Receiving the response
		receive_from_connection(&resp);

		// ----------------------------------------------------
		// Treat the response
		if (resp.base.status == -1)
		{
			printf ("[CLIENT] Some error ocurred on the server performing the operation\n");
		}
		else
		{
			switch (req.base.op_code)
			{
				// CHANGE PIN TODO
				case 2:
					break;
				case 3:
					printf ("[CLIENT] Encrypted message: \"%s\"\n", resp.data.data);

					break;
				case 4:
					printf ("[CLIENT] Decrypted message: \"%s\"\n", resp.data.data);

					break;
				default:
					break;
			}
		}


		sleep(2);
	}
	return 0;
}

void send_to_connection (struct request * request)
{
	int bytes;

	if ((pipe_fd = open(PIPE_NAME, O_WRONLY)) < 0) {
		perror("[CLIENT] Cannot open pipe for writing: ");
		exit(0);
	}

	printf("[CLIENT] Sending %d operation\n", request->base.op_code);

	if ((bytes = write(pipe_fd, request, sizeof(struct request))) == -1) {
		perror("[CLIENT] Error writing to pipe: ");
		close(pipe_fd);
		exit(0);
	}
	close(pipe_fd);
}

void receive_from_connection (struct response * response)
{
	int bytes;

	if ((pipe_fd = open(PIPE_NAME, O_RDONLY)) < 0) {
		perror("[CLIENT] Cannot open pipe for reading: ");
		exit(0);
	}

	if ((bytes = read(pipe_fd, response, sizeof(struct response))) == -1) {
		perror("[CLIENT] Error reading from pipe: ");
		close(pipe_fd);
		exit(0);
	}
	printf("[CLIENT] Received operation %d result with status %d\n", response->base.op_code, response->base.status);

	close(pipe_fd);
}


void flush_stdin ()
{
	int c;
	while ((c = getchar()) != EOF && c != '\n') ;
}

void cleanup()
{
	/* place all cleanup operations here */
	close(pipe_fd);
}
