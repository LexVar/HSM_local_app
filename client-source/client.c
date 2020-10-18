#include "client.h"
#include "../pipe.h"
#include "../protocol.h"

/* pipe file descriptor */
int pipe_fd;

/* request structure */
struct composed_request request;

/* response structure */
struct composed_response response;

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
		request.request.type = op;

		switch (request.request.type)
		{
			// CHANGE PIN TODO
			case 2:
				break;
			case 3:
				printf("Enter the message: ");

				if (fgets(request.msg_req.msg, MSG_SIZE, stdin) == NULL)
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
		send_to_connection(&request);

		// ----------------------------------------------------
		// Receiving the response
		receive_from_connection(&response);

		// ----------------------------------------------------
		// Treat the response
		if (response.response.status == -1)
		{
			printf ("[CLIENT] Some error ocurred on the server performing the operation\n");
		}
		else
		{
			switch (request.request.type)
			{
				// CHANGE PIN TODO
				case 2:
					break;
				case 3:
					printf ("[CLIENT] Encrypted message: \"%s\"\n", response.msg_res.msg);

					break;
				case 4:
					printf ("[CLIENT] Decrypted message: \"%s\"\n", response.msg_res.msg);

					break;
				default:
					break;
			}
		}


		sleep(2);
	}
	return 0;
}

void send_to_connection (struct composed_request * request)
{
	int bytes;

	if ((pipe_fd = open(PIPE_NAME, O_WRONLY)) < 0) {
		perror("[CLIENT] Cannot open pipe for writing: ");
		exit(0);
	}

	printf("[CLIENT] Sending %d operation\n", request->request.type);

	if ((bytes = write(pipe_fd, request, sizeof(struct composed_request))) == -1) {
		perror("[CLIENT] Error writing to pipe: ");
		close(pipe_fd);
		exit(0);
	}
	close(pipe_fd);
}

void receive_from_connection (struct composed_response * response)
{
	int bytes;

	if ((pipe_fd = open(PIPE_NAME, O_RDONLY)) < 0) {
		perror("[CLIENT] Cannot open pipe for reading: ");
		exit(0);
	}

	if ((bytes = read(pipe_fd, response, sizeof(struct composed_response))) == -1) {
		perror("[CLIENT] Error reading from pipe: ");
		close(pipe_fd);
		exit(0);
	}
	printf("[CLIENT] Received operation %d result with status %d\n", response->response.type, response->response.status);

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
