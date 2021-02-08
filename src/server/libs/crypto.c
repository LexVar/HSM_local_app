#include "crypto.h"
#include "aes/aes_ctr.c"

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
	uint8_t * mac;
	uint8_t * mac_key;
	uint8_t ciphertext[DATA_SIZE];
	uint8_t iv_cipher[DATA_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t key[2*KEY_SIZE], padded_key[KEY_SIZE*3];
	uint32_t size;

	// read keys from file
	if(read_key(key, key_file, 2*KEY_SIZE) == 0)
		return 0;

	memcpy (padded_key, key, 2*KEY_SIZE);
	memset (padded_key+2*KEY_SIZE, 0, KEY_SIZE);

	// set mac key pointer
	mac_key = &key[KEY_SIZE];

	// Generate random IV
	// USE NRGB HERE
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
		/* MAC+IV+MESSAGE to out ptr */
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

// Decrypts in buffer of inlen size, with key in key_file. Stores plaintext at out buffer.
// in  - ciphertext
// inlen - ciphertext size
// out - output plaintext
// key_file - file of key used to encrypt ciphertext
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

	if (inlen <= AES_BLOCK_SIZE+MAC_SIZE)
		return 0;

	// read key from file
	if (read_key(key, key_file, 2*KEY_SIZE) == 0)
		return 0;

	mac_key = &key[KEY_SIZE];

	// Read the MAC
	concatenate (mac, in, 0, MAC_SIZE);

	// Read the IV
	concatenate (iv, in+MAC_SIZE, 0, AES_BLOCK_SIZE);

	total_bytes = inlen - MAC_SIZE - AES_BLOCK_SIZE;

	/* Concatenate iv+ciphertext to compute mac */
	concatenate (iv_cipher, iv, 0, AES_BLOCK_SIZE);
	printf ("ivc %s...\n", iv_cipher);
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
	{
		total_bytes = 0;
		printf ("Error verifing the mac!\n");
	}

	return total_bytes;
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

uint8_t encrypt_keyset (uint8_t *set, uint16_t setlen)
{
	uint8_t * mac, * mac_key;
	uint8_t ciphertext[DATA_SIZE], out[DATA_SIZE];
	uint8_t iv[AES_BLOCK_SIZE], key[3*KEY_SIZE];
	uint16_t cipherlen, outlen;
	uint8_t status = 1;

	// fetch pre defined key
	if(read_key(key, (uint8_t*)"keys/hsm.key", 2*KEY_SIZE) == 0)
		return status;

	// set mac key pointer
	mac_key = &key[KEY_SIZE];
	// padd mac key with zeros
	memset(&key[2*KEY_SIZE], 0, KEY_SIZE);

	// Generate random IV
	if ( !RAND_bytes(iv, sizeof(iv)) )
		exit(-1);

	// Encrypt Key Set with CTR mode -> ciphertext
	cipherlen = ctr_encryption(set, setlen, iv, ciphertext, key);

	// concatenate the 3 components for final result
	if (cipherlen > 0)
	{
		// Concatenate size + IV + ciphertext of key set
		outlen = cipherlen+AES_BLOCK_SIZE;
		memcpy(out,(uint16_t *)&outlen, sizeof(uint16_t));
		memcpy(out+sizeof(uint16_t), iv, AES_BLOCK_SIZE);
		memcpy(out+sizeof(uint16_t)+AES_BLOCK_SIZE, ciphertext, cipherlen);

		// total size of output
		outlen += sizeof(uint16_t);
		// compute mac from LENGTH+IV+CIPHER
		mac = compute_hmac(mac_key, out, outlen);

		if (mac != NULL)
		{
			printf ("Message succesfully encrypted..\nMAC Generated..\n");
			// Write output to memory
			write_to_file((uint8_t *)"keys/keys.enc", out, outlen);
			// Write MAC in PUF slot
			write_to_file((uint8_t *)"keys/keys.mac", mac, MAC_SIZE);
			status = 0;
		}
		else
			printf ("Error Decrypting key set..\n");
	}
	else 
		printf ("Error Decrypting key set..\n");

	return status;
}

uint8_t init_keys(uint8_t * new_key, uint16_t keylen)
{
	uint8_t plaintext[DATA_SIZE];

	// Set number of keys
	plaintext[0] = 1;
	// Set 1st key ID
	plaintext[1] = 1;
	// Set Key length (multiple of 8 bytes)
	plaintext[2] = keylen/8;
	// concatenate key
	memcpy(&plaintext[3], new_key, keylen);

	// Encrypt and write key set, also writes MAC
	return encrypt_keyset(plaintext, keylen+3);
}

uint8_t read_key_set(uint8_t * out, uint16_t *keylen)
{
	uint8_t * computed_mac, * iv, *ciphertext, * mac_key, *keyptr;
	uint8_t set[DATA_SIZE], mac[MAC_SIZE];
	uint8_t key[3*KEY_SIZE];
	uint16_t len;
	uint8_t i, status = 1;

	// fetch pre defined key
	if(read_key(key, (uint8_t*)"keys/hsm.key", 2*KEY_SIZE) == 0)
		return status;

	// set mac key pointer
	mac_key = &key[KEY_SIZE];
	// Padd mac key with zeros
	memset(&key[2*KEY_SIZE], 0, KEY_SIZE);

	// fetch key set
	if(read_from_file((uint8_t*)"keys/keys.enc", set) == 0)
		return status;

	// Read key set length (IV + ciphertext)
	memcpy(&len, (uint16_t *)set, sizeof(uint16_t));
	printf ("SET LENGTH: %d\n",len);

	// Compute MAC of set
	computed_mac = compute_hmac(mac_key, set, 2+len);

	// Read MAC from PUF slot
	if(read_from_file((uint8_t*)"keys/keys.mac", mac) == 0)
		return status;

	// Compare computed MAC and MAC from PUF
	if (computed_mac != NULL && strncmp((char *)mac, (char *)computed_mac, MAC_SIZE) == 0)
	{
		printf ("MAC validated..\nDecrypting keys..\n");

		iv = &set[2]; // Iv ptr
		printf ("IV: %s\n", iv);

		ciphertext = set+2+AES_BLOCK_SIZE;

		// Decrypt Key Set with CTR mode -> out
		*keylen = ctr_encryption(ciphertext, len-AES_BLOCK_SIZE, iv, out, key);
		
		if (keylen > 0)
		{
			// DEBUG PRINT
			printf ("NUMKEYS: %d\n", out[0]);
			// ptr to 1st key
			keyptr = out+1;
			// Print keys
			for (i = 0; i < out[0]; i++)
			// for (keyptr = set+1; keyptr < (set+*keylen); keyptr += (2+keyptr[1]*8))
			{
				printf ("ID: %d\n", keyptr[0]);
				printf ("LENGTH: %d\n", keyptr[1]*8);
				printf ("KEY: ");
				print_chars(keyptr+2, keyptr[1]*8);

				keyptr += 2+keyptr[1]*8;
			}
			status = 0;
		}
		else
			printf ("Error deciphering key set..\n");
	}
	else 
		printf ("Error computing the MAC..\n");

	return status;
}

void fetch_key_from_set(uint8_t *set, uint16_t setlen, uint8_t id, uint8_t *key, uint16_t *keylen)
{
	uint8_t *keyptr;
	uint8_t found = 0;

	// ptr to 1st key
	for (keyptr = (set+1); keyptr < (set+setlen) && !found; keyptr += (2+*keylen))
	{
		printf ("ID: %d\n", keyptr[0]);
		printf ("LENGTH: %d\n", keyptr[1]*8);
		// Current key length
		*keylen = keyptr[1]*8;

		if (keyptr[0] == id)
		{
			memcpy(key, keyptr+2, *keylen);
			found = 1;
		}
	}
	if (!found)
		*keylen = 0;
}

uint8_t add_key(uint8_t *new_key, uint16_t keylen)
{
	uint8_t *plaintext;
	uint8_t set[DATA_SIZE];
	uint16_t setlen;

	if (read_key_set(set, &setlen) != 0)
		return 0;

	plaintext = set+setlen;

	// Increment number of keys in set
	set[0]++;
	// Set new key ID
	plaintext[0] = set[0];
	// Set Key length (multiple of 8 bytes)
	plaintext[1] = keylen/8;
	// Concatenate new key to set
	memcpy(plaintext+2, new_key, keylen);

	// Encrypt and write key set, also writes MAC
	return encrypt_keyset(set, setlen+keylen+2);
}
