#include "comms.h"

static uint8_t global_key[32];

void init_key (uint8_t * key)
{
	memcpy (global_key, key, KEY_SIZE);
}

// Receive a message from the other process
// fd - pipe file descriptor
// structure - pointer to structure where to save information
// struct_size - structure size in bytes sizeof(..)
uint32_t receive_from_connection (uint32_t fd, void * structure, uint32_t struct_size)
{
	uint32_t bytes;
	/* uint8_t iv[16]; */
	/* uint8_t * in; */

	if ((fd = open(PIPE_NAME, O_RDONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for reading: ");
		exit(0);
	}

	/* in = malloc(struct_size); */
	if ((bytes = read(fd, structure, struct_size)) == -1) {
		perror("Error reading from pipe: ");
		close(fd);
		/* free (in); */
		exit(0);
	}

	/* mbed_aes_crypt(iv, in, structure, struct_size, global_key); */
	/* printf ("decrypted data: %s\n", (char *)structure); */

	/* free (in); */
	sleep(0.3);
	close(fd);
	return bytes;
}
uint32_t receive_plain (uint32_t fd, void * structure, uint32_t struct_size)
{
	uint32_t bytes;

	if ((fd = open(PIPE_NAME, O_RDONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for reading: ");
		exit(0);
	}

	if ((bytes = read(fd, structure, struct_size)) == -1) {
		perror("Error reading from pipe: ");
		close(fd);
		exit(0);
	}

	sleep(0.3);
	close(fd);
	return bytes;
}

// Send a message from the other process
// fd - pipe file descriptor
// structure - pointer to structure to send through pipe
// struct_size - structure size in bytes sizeof(..)
uint32_t send_to_connection (uint32_t fd, void * structure, uint32_t struct_size)
{
	uint32_t bytes;
	/* uint8_t iv[16]; */
	/* uint8_t * out; */

	if ((fd = open(PIPE_NAME, O_WRONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for writing: ");
		exit(0);
	}
	/* out = malloc(struct_size); */
	/* mbed_aes_crypt(iv, structure, out, struct_size, global_key); */
	/* printf ("encrypted data: %s\n", out); */
	sleep (0.3);
	if ((bytes = write(fd, structure, struct_size)) == -1) {
		perror("Error writing to pipe: ");
		close(fd);
		/* free(out); */
		exit(0);
	}

	/* free(out); */
	sleep (0.3);
	close(fd);
	sleep (0.3);
	return bytes;
}
uint32_t send_plain (uint32_t fd, void * structure, uint32_t struct_size)
{
	uint32_t bytes;

	if ((fd = open(PIPE_NAME, O_WRONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for writing: ");
		exit(0);
	}
	sleep (0.3);
	if ((bytes = write(fd, structure, struct_size)) == -1) {
		perror("Error writing to pipe: ");
		close(fd);
		exit(0);
	}

	sleep (0.3);
	close(fd);
	sleep (0.3);
	return bytes;
}

uint8_t send_status(uint32_t pipe_fd, uint8_t status)
{
	if (status == 0)
		send_to_connection(pipe_fd, (uint8_t *)"NO", sizeof("NO"));
	else
		send_to_connection(pipe_fd, (uint8_t *)"OK", sizeof("OK"));
	return status;
}

void sendOK(uint32_t pipe_fd, uint8_t * msg)
{
	send_to_connection(pipe_fd, msg, sizeof(msg));
}

uint8_t waitOK(uint32_t pipe_fd)
{
	uint8_t msg[ID_SIZE];
	uint8_t status;
	receive_from_connection(pipe_fd, msg, ID_SIZE);

	printf ("%s\n", msg);

	if (msg[0] != 'O' || msg[1] != 'K')
		status = 0;
	else
		status = 1;
	return status;
}

void * write_to_file (uint8_t * filename, uint8_t * content, uint32_t fsize)
{
	FILE *f = fopen((char *)filename, "wb");

	if (f != NULL)
	{
		fwrite(content, 1, fsize, f);
		fclose(f);

		// content[fsize] = 0;
	}

	return f;
}

uint32_t read_from_file (uint8_t * filename, uint8_t * content)
{
	FILE *f = fopen((char *)filename, "rb");
	uint32_t fsize = 0;

	if (f != NULL)
	{
		// Seek to end to read size
		fseek(f, 0L, SEEK_END);
		fsize = ftell(f);

		// Go back to begginning of file
		fseek(f, 0L, SEEK_SET);

		fread(content, 1, fsize, f);
		fclose(f);

		// content[fsize] = 0;
	}

	return fsize;
}

void flush_stdin ()
{
	uint8_t c;
	while ((c = getchar()) != EOF && c != '\n') ;
}

void print_hexa(uint8_t * string, uint32_t length)
{
	uint32_t i = 0;
	for (i = 0; i < length; i++)
		printf("%x ",string[i] & 0xff);

	printf("\n");
}

void print_chars (uint8_t * data, uint32_t data_size)
{
	uint32_t i;
	for (i = 0; i < data_size; i++)
		printf("%c", data[i]);
	printf("\n");
}
