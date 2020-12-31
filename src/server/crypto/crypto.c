#include "crypto.h"
#include "aes/aes_ctr.c"

// Generates new AES key, saves to aes.key file
void new_key(uint8_t * key_file)
{
	FILE *fout;
	uint8_t key[2*KEY_SIZE];

	if ( !RAND_bytes(key, sizeof(key)) )
		exit(-1);

	fout = fopen((char *)key_file, "w");
	if (fout != NULL)
	{
		fwrite(key, sizeof(uint8_t), sizeof(key), fout);
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

void concatenate(uint8_t * dest, uint8_t * src, uint32_t start, uint32_t length)
{
	uint32_t i;
	for (i = 0; i < length; i++)
		dest[i+start] = src[i];
}

/* return 0 if equal, 1 if different */
uint32_t compare_strings(uint8_t * m1, uint8_t * m2, uint32_t length)
{
	uint32_t i, different = 0;
	for (i = 0; i < length && !different && m1[i] != '\0' && m2[i] != '\0'; i++)
		if (m1[i] != m2[i])
			different = 1;
	return different;
}

// Read key from aes.key file
void read_key(uint8_t * key, uint8_t * key_file, uint32_t key_size)
{
	FILE *fin;

	fin = fopen((char *)key_file, "r");
	if (fin != NULL)
	{
		fread(key, key_size, 1, fin);
		fclose(fin);
	}
	else
		printf("Error reading key.\n");
}

void init_ctr_state (ctr_state * state, uint8_t iv[AES_BLOCK_SIZE], uint8_t key_bytes[KEY_SIZE])
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

uint32_t ctr_encryption(uint8_t * plaintext, uint32_t size, uint8_t * iv, uint8_t * ciphertext, uint8_t * key_bytes)
{
	AES_KEY key;
	uint32_t bytes_read = AES_BLOCK_SIZE;
	// is at least the size of the iv
	uint32_t total_bytes = 0;
	
	/* Buffers for Encryption */
	uint8_t enc_in[DATA_SIZE];
	uint8_t enc_out[DATA_SIZE];

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
		/* strncat((uint8_t *) ciphertext, (uint8_t *) enc_out, bytes_read); */
		concatenate (ciphertext, enc_out, total_bytes, bytes_read);

		/* number of bytes written to ciphertext */
		total_bytes += bytes_read;
	}

	/* ciphertext[total_bytes] = '\0'; */
	return total_bytes;
}

uint32_t encrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file)
{
	uint8_t * mac;
	uint8_t * mac_key;
	uint8_t ciphertext[DATA_SIZE];
	uint8_t iv_cipher[DATA_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t key[2*KEY_SIZE];
	uint32_t size;

	// read keys from file
	read_key(key, key_file, 2*KEY_SIZE);
	// set mac key
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

	// concatenate the 3 components for final result
	if (mac != NULL && size > 0)
	{
		/* write MAC+IV+MESSAGE to file */
		concatenate (out, mac, 0, MAC_SIZE);
		concatenate (out, iv, MAC_SIZE, AES_BLOCK_SIZE);
		concatenate (out, ciphertext, MAC_SIZE+AES_BLOCK_SIZE, size);

		printf ("Message succesfully encrypted..\n");
		size = size+AES_BLOCK_SIZE+MAC_SIZE;
	}
	else 
	{
		printf ("Error computing the MAC..\n");
		size = 0;
	}

	return size;
}

uint32_t decrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file)
{
	uint8_t mac[MAC_SIZE];
	uint8_t * computed_mac;
	uint8_t * ciphertext = in+MAC_SIZE+AES_BLOCK_SIZE;
	uint8_t plaintext[DATA_SIZE];
	uint8_t iv_cipher[DATA_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t key[2*KEY_SIZE];
	uint8_t * mac_key;
	uint32_t total_bytes = 0;

	// read key from file
	read_key(key, key_file, 2*KEY_SIZE);
	mac_key = &key[KEY_SIZE];

	// Read the MAC
	concatenate (mac, in, 0, MAC_SIZE);

	// Read the IV
	concatenate (iv, in+MAC_SIZE, 0, AES_BLOCK_SIZE);

	total_bytes = inlen - MAC_SIZE - AES_BLOCK_SIZE;
	/* Concatenate iv+ciphertext to compute mac */
	concatenate (iv_cipher, iv, 0, AES_BLOCK_SIZE);
	concatenate (iv_cipher, ciphertext, AES_BLOCK_SIZE, total_bytes);

	/* compute mac from IV+CIPHER */
	computed_mac = compute_hmac(mac_key, iv_cipher, AES_BLOCK_SIZE+total_bytes);

	/* verify if macs are the same */
	if (compare_strings(mac, computed_mac, MAC_SIZE) == 0)
	{
		printf ("MAC successfully verified, proceding to decryption...\n");

		/* perform ctr encryption, return IV+CIPHER/PLAINTEXT */
		total_bytes = ctr_encryption(ciphertext, total_bytes, iv, plaintext, key);

		// Copy plaintext to out string and add null terminate uint8_t
		concatenate(out, plaintext, 0, total_bytes);
		out[total_bytes] = 0;

		if (total_bytes > 0)
			printf ("Message decrypted..\n");
	}
	else
		printf ("Error verifing the mac!\n");

	return total_bytes;
}

uint8_t * compute_hmac(uint8_t * key, uint8_t * message, uint32_t size)
{
	uint8_t * md;

	/* don't change the hash function without changing MAC_SIZE */
	md = HMAC(EVP_sha256(), key, KEY_SIZE, message, size, NULL, NULL);

	if (md == NULL)
		printf ("Error computing HMAC...\n");

	return md;
}
