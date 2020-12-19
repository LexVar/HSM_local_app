#include "crypto.h"
#include "aes/aes_ctr.c"

void print_chars2 (unsigned char * data, int data_size)
{
	int i;
	for (i = 0; i < data_size; i++)
		printf("%c", data[i]);
	printf("\n");
}

// Generates new AES key, saves to aes.key file
void new_key(char * key_file)
{
	FILE *fout;
	unsigned char key[2*KEY_SIZE];

	if ( !RAND_bytes(key, sizeof(key)) )
		exit(-1);

	fout = fopen(key_file, "w");
	if (fout != NULL)
	{
		fwrite(key, sizeof(char), sizeof(key), fout);
		fclose(fout);
	}
	else
		printf("Error generating key.\n");
}

void init_crypto_state ()
{
	OpenSSL_add_all_digests();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();
}

int simpleSHA256(void * input, unsigned long length, unsigned char * md)
{
	SHA256_CTX context;
	if(!SHA256_Init(&context))
	{
		fprintf(stderr, "[CRYPTO] SHA256_Init failed\n");
		return -1;
	}

	if(!SHA256_Update(&context, (unsigned char*)input, length))
	{
		fprintf(stderr, "[CRYPTO] SHA256_Update failed\n");
		return -1;
	}

	if(!SHA256_Final(md, &context))
	{
		fprintf(stderr, "[CRYPTO] SHA256_Final failed\n");
		return -1;
	}

	return 0;
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
void read_key(unsigned char * key, char * key_file, int key_size)
{
	FILE *fin;

	fin = fopen(key_file, "r");
	if (fin != NULL)
	{
		fread(key, key_size, 1, fin);
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

int encrypt(unsigned char * in, int inlen, unsigned char * out, char * key_file)
{
	unsigned char * mac;
	unsigned char * mac_key;
	unsigned char ciphertext[DATA_SIZE];
	unsigned char iv_cipher[DATA_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char key[2*KEY_SIZE];
	int size;

	// read key from file
	read_key(key, key_file, 2*KEY_SIZE);
	mac_key = &key[KEY_SIZE];

	// Generate random IV
	if ( !RAND_bytes(iv, sizeof(iv)) )
		exit(-1);

	/* perform ctr encryption, return cipher/plaintext */
	size = ctr_encryption(in, inlen, iv, ciphertext, key);

	/* Concatenate iv+ciphertet to compute mac */
	concatenate (iv_cipher, iv, 0, AES_BLOCK_SIZE);
	concatenate (iv_cipher, ciphertext, AES_BLOCK_SIZE, size);

	/* compute mac from IV+CIPHER/PLAINTEXT */
	mac = compute_hmac(mac_key, iv_cipher, AES_BLOCK_SIZE+size);
	printf("ciphertext:\n");
	printf("size:%d\n", size);
	print_chars2 (ciphertext, size);

	/* write MAC+IV+MESSAGE to file */
	concatenate (out, mac, 0, MAC_SIZE);
	concatenate (out, iv, MAC_SIZE, AES_BLOCK_SIZE);
	concatenate (out, ciphertext, MAC_SIZE+AES_BLOCK_SIZE, size);

	printf ("Output successfully written..\n");
	return size+AES_BLOCK_SIZE+MAC_SIZE;
}

int decrypt(unsigned char * in, size_t inlen, unsigned char * out, char * key_file)
{
	unsigned char mac[MAC_SIZE];
	unsigned char * computed_mac;
	unsigned char ciphertext[DATA_SIZE], plaintext[DATA_SIZE];
	unsigned char iv_cipher[DATA_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char key[2*KEY_SIZE];
	unsigned char * mac_key;
	int total_bytes = 0;

	// read key from file
	read_key(key, key_file, 2*KEY_SIZE);
	mac_key = &key[KEY_SIZE];

	// Read the MAC
	concatenate (mac, in, 0, MAC_SIZE);

	// Read the IV
	concatenate (iv, &in[MAC_SIZE], 0, AES_BLOCK_SIZE);

	total_bytes = inlen - MAC_SIZE - AES_BLOCK_SIZE;
	printf("total_bytes:%d\n", total_bytes);
	/* Concatenate iv+ciphertet to compute mac */
	concatenate (iv_cipher, iv, 0, AES_BLOCK_SIZE);
	concatenate (iv_cipher, &in[MAC_SIZE+AES_BLOCK_SIZE], AES_BLOCK_SIZE, total_bytes);

	/* compute mac from IV+CIPHER */
	computed_mac = compute_hmac(mac_key, iv_cipher, AES_BLOCK_SIZE+total_bytes);

	/* verify if macs are the same */
	if (compare_mac(mac, computed_mac, MAC_SIZE) == 0)
	{
		/* perform ctr encryption, return IV+CIPHER/PLAINTEXT */
		total_bytes = ctr_encryption(ciphertext, total_bytes, iv, plaintext, key);

		printf("plaintext:\n");
		printf("size:%d\n", total_bytes);
		print_chars2 (plaintext, total_bytes);
		printf ("MAC successfully verified, proceding to decryption...\n");

		concatenate(out, plaintext, 0, total_bytes);
		printf ("Output successfully written..\n");
	}
	else
		printf ("Error verifing the mac!\n");

	return total_bytes;
}

unsigned char * compute_hmac(unsigned char * key, unsigned char * message, int size)
{
	unsigned char * md;

	/* don't change the hash function without changing MAC_SIZE */
	md = HMAC(EVP_sha256(), key, KEY_SIZE, message, size, NULL, NULL);

	if (md == NULL)
		printf ("Error computing HMAC...\n");

	return md;
}
