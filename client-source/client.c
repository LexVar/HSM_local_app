#include "client.h"
#include "pipe.h"
#include "protocol.h"

int pipe_fd;

int main()
{
	// Opens the pipe for writing
	int op, bytes;

	/* request structure */
	struct composed_request request;

	/* response structure */
	struct composed_response response;

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

		printf("%d\n", op);
		if (op == 0)
		{
			printf("\n[CLIENT] Quitting...\n");
			break;
		}
		else if (op < 2 || op > 9)
		{
			printf("\n[CLIENT] %d. Is not a valid operation\n", op);
			sleep (2);
			continue;
		}

		/* set request attributes */
		request.request.type = op;

		if ((pipe_fd = open(PIPE_NAME, O_WRONLY)) < 0) {
			perror("[CLIENT] Cannot open pipe for writing: ");
			exit(0);
		}

		printf("[CLIENT] Sending %d operation\n", op);

		if ((bytes = write(pipe_fd, &request, sizeof(request))) == -1) {
			perror("[CLIENT] Error writing to pipe: ");
			close(pipe_fd);
			exit(0);
		}
		close(pipe_fd);

		switch (request.request.type)
		{
			case 1:
				break;
			case 2:
				break;
			case 3:
				break;
			case 4:
				break;
			case 0:
				printf("[SERVER] Stopping server..\n");
				exit(0);
				break;
			default:
				printf("Wrong choice, try again\n");
		}

		if ((pipe_fd = open(PIPE_NAME, O_RDONLY)) < 0) {
			perror("[CLIENT] Cannot open pipe for reading: ");
			exit(0);
		}

		if ((bytes = read(pipe_fd, &response, sizeof(response))) == -1) {
			perror("[CLIENT] Error reading from pipe: ");
			close(pipe_fd);
			exit(0);
		}
		printf("[CLIENT] Received operation %d result with status %d\n", response.response.type, response.response.status);

		close(pipe_fd);

		sleep(2);
	}
	return 0;
}


void cleanup()
{
	/* place all cleanup operations here */
	close(pipe_fd);
}
