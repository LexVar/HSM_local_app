#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>           /* Definition of AT_* constants */
#include <sys/stat.h>
#include <errno.h>

#define PIPE_NAME "/tmp/connection" // Pipe name

// Reiceve a message from the other process
// fd - pipe file descriptor
// structure - pointer to structure where to save information
// struct_size - structure size in bytes sizeof(..)
int receive_from_connection (int fd, void * structure, size_t struct_size)
{
	int bytes;

	if ((fd = open(PIPE_NAME, O_RDONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for reading: ");
		exit(0);
	}

	if ((bytes = read(fd, structure, struct_size)) == -1) {
		perror("Error reading from pipe: ");
		close(fd);
		exit(0);
	}

	close(fd);
	return bytes;
}

// Send a message from the other process
// fd - pipe file descriptor
// structure - pointer to structure to send through pipe
// struct_size - structure size in bytes sizeof(..)
int send_to_connection (int fd, void * structure, size_t struct_size)
{
	int bytes;

	if ((fd = open(PIPE_NAME, O_WRONLY)) < 0) {
		perror("[SERVER] Cannot open pipe for writing: ");
		exit(0);
	}

	sleep (1);
	if ((bytes = write(fd, structure, struct_size)) == -1) {
		perror("Error writing to pipe: ");
		close(fd);
		exit(0);
	}

	close(fd);
	return bytes;
}

void * write_to_file (char * filename, char * content, int fsize)
{
	FILE *f = fopen(filename, "wb");

	if (f != NULL)
	{
		fwrite(content, 1, fsize, f);
		fclose(f);

		// content[fsize] = 0;
	}

	return f;
}

int read_from_file (char * filename, char * content)
{
	FILE *f = fopen(filename, "rb");
	int fsize = 0;

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
	int c;
	while ((c = getchar()) != EOF && c != '\n') ;
}

void print_hexa(unsigned char * string, int length)
{
	int i = 0;
	for (i = 0; i < length; i++)
		printf("%x ",string[i] & 0xff);

	printf("\n");
}
