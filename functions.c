#include <stdio.h>

void * write_to_file (char * filename, char * content, int fsize)
{
	FILE *f = fopen(filename, "wb");

	if (f != NULL)
	{
		fwrite(content, 1, fsize, f);
		fclose(f);

		content[fsize] = 0;
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

		content[fsize] = 0;
	}

	return fsize;
}
