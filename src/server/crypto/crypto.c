#include "crypto.h"
#include "aes/aes_ctr.c"
#include "sign.c"

void init_crypto_state ()
{
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();
}

void concatenate(unsigned char * dest, unsigned char * src, int start, int length)
{
	int i;
	for (i = 0; i < length; i++)
		dest[i+start] = src[i];
}

/* return 0 if equal, 1 if different */
int compare_mac(unsigned char * mac1, unsigned char * mac2, int length)
{
	int i, different = 0;
	for (i = 0; i < length && !different; i++)
		if (mac1[i] != mac2[i])
			different = 1;
	return different;
}

// Read key from aes.key file
void read_key(unsigned char * key, char * key_file)
{
	FILE *fin;

	fin = fopen(key_file, "r");
	if (fin != NULL)
	{
		fread(key, KEY_SIZE, 1, fin);
		fclose(fin);
	}
	else
		printf("Error reading key.\n");
}

void init_ctr_state (ctr_state * state, unsigned char iv[AES_BLOCK_SIZE], unsigned char key_bytes[KEY_SIZE])
{
	/* save key bytes */
	memcpy(state->key_bytes, key_bytes, KEY_SIZE);

	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call. */
	state->num = 0;
	memset(state->ecount_buf, 0, AES_BLOCK_SIZE);

	/* Initialise counter with 64 bits of 0's */
	memset(state->iv + 8, 0, 8);

	/* Copy 64 bits of IV to the upper part */
	memcpy(state->iv, iv, 8);
}

int ctr_encryption(unsigned char * plaintext, int size, unsigned char * iv, unsigned char * ciphertext, unsigned char * key_bytes)
{
	AES_KEY key;
	int bytes_read = AES_BLOCK_SIZE;
	// is at least the size of the iv
	int total_bytes = 0;
	
	/* Buffers for Encryption */
	unsigned char enc_in[DATA_SIZE];
	unsigned char enc_out[DATA_SIZE];

	ctr_state state;

	/* Initialize state structure */
	init_ctr_state (&state, iv, key_bytes);

	/* set encryption key */
	AES_set_encrypt_key(state.key_bytes, KEY_SIZE*8, &key);

	while (bytes_read >= AES_BLOCK_SIZE)
	{
		// Read 1 block size at a time to buffer
		if (AES_BLOCK_SIZE > size)
			bytes_read = size;
		else
			bytes_read = AES_BLOCK_SIZE;
		concatenate (enc_in, plaintext, 0, bytes_read);
		enc_in[bytes_read] = 0;

		plaintext = &plaintext[bytes_read];
		size -= bytes_read;

		/* AES CTR Encryption */
		AES_ctr128_encrypt(enc_in, enc_out, bytes_read, &key, state.iv, state.ecount_buf, &(state.num));
		/* enc_out[bytes_read] = 0; */

		/* Add block to the result string */
		/* strncat((char *) ciphertext, (char *) enc_out, bytes_read); */
		concatenate (ciphertext, enc_out, total_bytes, bytes_read);

		/* number of bytes written to ciphertext */
		total_bytes += bytes_read;
	}

	/* ciphertext[total_bytes] = '\0'; */
	return total_bytes;
}

void encrypt(char * input_file, char * output_file, char * key_file, char * mac_file)
{
	unsigned char * mac;
	unsigned char ciphertext[DATA_SIZE], plaintext[DATA_SIZE];
	unsigned char iv_cipher[DATA_SIZE];
	unsigned char buffer[AES_BLOCK_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char key[KEY_SIZE], mac_key[KEY_SIZE];

	int size, bytes_read = AES_BLOCK_SIZE, total_bytes = 0;
	FILE * fout, * fin;

	// read key from file
	read_key(mac_key, mac_file);
	read_key(key, key_file);

	// Generate random IV
	if ( !RAND_bytes(iv, sizeof(iv)) )
		exit(-1);

	/* Read plaintext from file using buffer */
	fin = fopen (input_file, "rb");

	if (fin != NULL)
	{
		while (bytes_read >= AES_BLOCK_SIZE)
		{
			bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, fin);
			concatenate (plaintext, buffer, total_bytes, bytes_read);
			total_bytes += bytes_read;
		}
		fclose(fin);
	}
	else
		printf("Error opening input file...\n");

	/* perform ctr encryption, return cipher/plaintext */
	size = ctr_encryption(plaintext, total_bytes, iv, ciphertext, key);

	/* Concatenate iv+ciphertet to compute mac */
	concatenate (iv_cipher, iv, 0, AES_BLOCK_SIZE);
	concatenate (iv_cipher, ciphertext, AES_BLOCK_SIZE, size);

	/* compute mac from IV+CIPHER/PLAINTEXT */
	mac = compute_hmac(mac_key, iv_cipher, AES_BLOCK_SIZE+size);

	fout = fopen (output_file, "wb");

	/* write MAC+IV+MESSAGE to file */
	if (fout != NULL)
	{
		fwrite (mac, sizeof(char), SIGNATURE_SIZE, fout);
		fwrite (iv, sizeof(char), AES_BLOCK_SIZE, fout);
		fwrite (ciphertext, sizeof(char), size, fout);
		fclose(fout);
		printf ("Output successfully written..\n");
	}
	else
		printf ("Error opening output file..\n");
}

void decrypt(char * input_file, char * output_file, char * key_file, char * mac_file)
{
	unsigned char mac[SIGNATURE_SIZE];
	unsigned char * computed_mac;
	unsigned char ciphertext[DATA_SIZE], plaintext[DATA_SIZE];
	unsigned char iv_cipher[DATA_SIZE];
	unsigned char buffer[AES_BLOCK_SIZE];
	int bytes_read, total_bytes = 0;
	FILE *fout, *fin;
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char key[KEY_SIZE], mac_key[KEY_SIZE];

	// read key from file
	read_key(key, key_file);
	read_key(mac_key, mac_file);

	fin = fopen (input_file, "rb");

	if (fin != NULL)
	{
		fread(mac, SIGNATURE_SIZE, 1, fin);

		// Read the IV first
		bytes_read = fread(iv, 1, AES_BLOCK_SIZE, fin);

		while (bytes_read >= AES_BLOCK_SIZE)
		{
			bytes_read = fread(buffer, 1, AES_BLOCK_SIZE, fin);
			concatenate (ciphertext, buffer, total_bytes, bytes_read);
			total_bytes += bytes_read;
		}
		fclose(fin);
	}
	else
		printf("Error opening input file...\n");

	/* Concatenate iv+ciphertet to compute mac */
	concatenate (iv_cipher, iv, 0, AES_BLOCK_SIZE);
	concatenate (iv_cipher, ciphertext, AES_BLOCK_SIZE, total_bytes);

	/* compute mac from IV+CIPHER */
	computed_mac = compute_hmac(mac_key, iv_cipher, AES_BLOCK_SIZE+total_bytes);

	/* verify if macs are the same */
	if (compare_mac(mac, computed_mac, SIGNATURE_SIZE) == 0)
	{
		printf ("MAC successfully verified, proceding to decryption...\n");

		/* perform ctr encryption, return IV+CIPHER/PLAINTEXT */
		total_bytes = ctr_encryption(ciphertext, total_bytes, iv, plaintext, key);

		fout = fopen (output_file, "wb");

		/* write Plaintext message to file */
		if (fout != NULL)
		{
			fwrite (plaintext, 1, total_bytes, fout);
			fclose(fout);
			printf ("Output successfully written..\n");
		}
		else
			printf ("Error opening output file..\n");

	}
	else
		printf ("Error verifing the mac!\n");
}

unsigned char * compute_hmac(unsigned char * key, unsigned char * message, int size)
{
	unsigned char * md;

	/* don't change the hash function without changing SIGNATURE_SIZE */
	md = HMAC(EVP_sha256(), key, KEY_SIZE, message, size, NULL, NULL);

	if (md == NULL)
		printf ("Error computing HMAC...\n");

	return md;
}
