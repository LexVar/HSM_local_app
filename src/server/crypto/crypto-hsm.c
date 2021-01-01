#include "crypto-hsm.h"

// Generates new AES key, saves to aes.key file
// Generate both AES and HMAC key, ence 2*
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
	for (i = 0; i < length && !different ; i++)
		if (m1[i] != m2[i] || m1[i] == '\0' || m2[i] == '\0')
			different = 1;
	return different;
}

// Read key from aes.key file
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
	uint8_t key[2*KEY_SIZE];
	uint32_t size;
	// uint8_t nrbg_handle;
	// const uint8_t personalization_str[4] = {0x12, 0x34, 0x56, 0x78};

	// read keys from file
	if(read_key(key, key_file, 2*KEY_SIZE) == 0)
		return 0;
	// set mac key pointer
	mac_key = &key[KEY_SIZE];

	// Generate random IV
	// USE NRGB HERE
	if ( !RAND_bytes(iv, sizeof(iv)) )
		exit(-1);

	// MSS_SYS_nrbg_instantiate(person, ,nrbg_handle);
	// status = MSS_SYS_nrbg_instantiate(personalization_str, 0, &nrbg_handle);
        // if(MSS_SYS_SUCCESS == status)
        //     MSS_UART_polled_tx_string( gp_my_uart,(const uint8_t*)"\n\rNRBG reserve successful.");
        //  else
        //     MSS_UART_polled_tx_string( gp_my_uart,(const uint8_t*)"\n\rNRBG reserve failure.");


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
