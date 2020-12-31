#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <inttypes.h>

#define PIPE_NAME "/tmp/connection" // Pipe name

// Receive a message from the other process
// fd - pipe file descriptor
// structure - pointer to structure where to save information
// struct_size - structure size in bytes sizeof(..)
uint32_t receive_from_connection (uint32_t fd, void * structure, uint32_t struct_size)
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

	sleep(0.1);
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

	if ((fd = open(PIPE_NAME, O_WRONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for writing: ");
		exit(0);
	}

	sleep (0.1);
	if ((bytes = write(fd, structure, struct_size)) == -1) {
		perror("Error writing to pipe: ");
		close(fd);
		exit(0);
	}

	sleep (0.1);
	close(fd);
	return bytes;
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
