#include "crypto.h"
#include "aes/aes_ctr.c"

uint16_t padd_block(uint8_t * buf, uint16_t len)
{
	uint8_t padding;

	if (len%BLOCK_SIZE == 0)
		padding = 0;
	else
		padding = BLOCK_SIZE - len%BLOCK_SIZE;

	memset (buf + len, 0, padding);

	return len + padding;
}

uint8_t simpleSHA256(void * input, uint64_t length, uint8_t * md)
{
	SHA256_CTX context;
	if(!SHA256_Init(&context))
	{
		fprintf(stderr, "[CRYPTO] SHA256_Init failed\n");
		return -1;
	}

	if(!SHA256_Update(&context, input, length))
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
	for (i = 0; i < length && !different; i++)
		if (m1[i] != m2[i])
			different = 1;
	return different;
}

uint8_t read_key(uint8_t * key, uint8_t * key_file, uint32_t key_size)
{
	FILE *fin;

	fin = fopen((char *)key_file, "r");
	if (fin != NULL)
	{
		fread(key, key_size, 1, fin);
		fclose(fin);
		return 1;
	}
	else
	{
		printf("Error reading key.\n");
		return 0;
	}
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

// Encrypts in buffer of inlen size, with key in key_file. Stores ciphertext in out buffer.
// in  - input plaintext
// inlen - plaintext size
// out - output ciphertext
// key_file - file of symmetric key (for AES and HMAC)
uint32_t encrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file)
{
	uint8_t * mac_key;
	uint8_t * ciphertext = out + MAC_SIZE + AES_BLOCK_SIZE;
	uint8_t * iv = out + MAC_SIZE;
	uint8_t * iv_cipher = out + MAC_SIZE;
	uint8_t * mac = out;
	uint8_t key[3*KEY_SIZE];
	uint8_t iv2[AES_BLOCK_SIZE];
	int ret;

	// Padd input buffer block with zeros if needed
	inlen = padd_block(in, inlen);

	// read keys from file
	if(read_key(key, key_file, 2*KEY_SIZE) == 0)
		return 0;

	memset (key+2*KEY_SIZE, 0, KEY_SIZE);

	// set mac key pointer
	mac_key = &key[KEY_SIZE];

	// Generate random IV
	// USE NRGB HERE
	if ( !RAND_bytes(iv2, AES_BLOCK_SIZE) )
		return 0;
	memcpy (iv, iv2, AES_BLOCK_SIZE);

	// perform ctr encryption, return cipher/plaintext
	// inlen = ctr_encryption(in, inlen, iv, ciphertext, key);
	ret = mbed_aes_crypt(iv2, in, ciphertext, inlen, key);

	// compute mac from IV+PLAINTEXT
	ret = mbed_hmac (mac_key, iv_cipher, AES_BLOCK_SIZE+inlen, mac);

	if (ret == 0)
	{
		printf ("Message encrypted..\n");
		inlen = inlen+AES_BLOCK_SIZE+MAC_SIZE;
	}
	else 
	{
		printf ("Error..\n");
		inlen = 0;
	}

	return inlen;
}

// Decrypts in buffer of inlen size, with key in key_file. Stores plaintext at out buffer.
// in  - ciphertext
// inlen - ciphertext size
// out - output plaintext
// key_file - file of key used to encrypt ciphertext
uint32_t decrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file)
{
	uint8_t * mac = in;
	uint8_t * iv = in + MAC_SIZE;
	uint8_t * ciphertext = in + MAC_SIZE + AES_BLOCK_SIZE;
	uint8_t * iv_cipher = in + MAC_SIZE;
	uint8_t computed_mac[MAC_SIZE];
	uint8_t key[3*KEY_SIZE];
	uint8_t * mac_key;
	int ret;

	if (inlen <= (AES_BLOCK_SIZE+MAC_SIZE))
		return 0;

	// read key from file
	if (read_key(key, key_file, 2*KEY_SIZE) == 0)
		return 0;

	memset (key+2*KEY_SIZE, 0, KEY_SIZE);
	mac_key = &key[KEY_SIZE];

	inlen = inlen - MAC_SIZE - AES_BLOCK_SIZE;

	// compute mac from IV+CIPHER
	ret = mbed_hmac (mac_key, iv_cipher, AES_BLOCK_SIZE+inlen, computed_mac);

	// verify if macs are the same
	if (strncmp((char *)mac, (char *)computed_mac, MAC_SIZE) == 0)
	{
		printf ("MAC verified...\n");
		// perform ctr encryption, return IV+CIPHER/PLAINTEXT
		// total_bytes = ctr_encryption(ciphertext, total_bytes, iv, plaintext, key);
		ret = mbed_aes_crypt(iv, ciphertext, out, inlen, key);
		out[inlen] = 0;
		printf ("Plain: %s\n", out);
		printf ("length: %d\n", inlen);

		// Copy plaintext to out string and add null terminate uint8_t

		if (ret == 0)
			printf ("Message decrypted..\n");
		else
			inlen = 0;
	}
	else
	{
		inlen = 0;
		printf ("Error verifing the mac!\n");
	}

	return inlen;
}

// Compute HMAC with SHA256 hashing, from ciphertext and IV
// key - key info of KEY_SIZE
// message - ciphertext+IV
// size - size of message
uint8_t * compute_hmac(uint8_t * key, uint8_t * message, uint32_t size)
{
	uint8_t * md;

	/* don't change the hash function without changing MAC_SIZE */
	md = HMAC(EVP_sha256(), key, KEY_SIZE, message, size, NULL, NULL);

	if (md == NULL)
		printf ("Error computing HMAC...\n");

	return md;
}
