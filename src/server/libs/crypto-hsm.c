#include "crypto-hsm.h"

#define AES_BLOCK_SIZE 16

uint8_t drbg_handler;

// Generates new AES key, saves to aes.key file
// Generate both AES and HMAC key, ence 2*
void new_key(uint8_t * key)
{
	uint8_t nkeys;
	uint8_t key_data[KEY_SIZE*2];

	if (MSS_SYS_puf_get_number_of_keys(&nkeys) != MSS_SYS_SUCCESS)
		return 0;

	// Generate random bits
	if (generate_random_bits(drbg_handler, KEY_SIZE*2, key_data) != MSS_SYS_SUCCESS)
		return 0;

	if (MSS_SYS_puf_enroll_key(nkeys, KEY_SIZE*2, key_data, key) != MSS_SYS_SUCCESS)
		return 0;

	if(MSS_SYS_puf_fetch_key(nkeys, &key) != MSS_SYS_SUCCESS)
		return 0;

	return 1;
}

void init_crypto_state ()
{
	// Intantiate random number generator
	if (reserve_drbg_service(&drbg_handler) != MSS_SYS_SUCCESS)
	{
		printf ("Error instantiating NRBG\n");
		exit(0);
	}
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
	uint32_t size, status;

	// read keys from puf
	MSS_SYS_puf_fetch_key(key_file, &key);

	// set mac key pointer
	mac_key = &key[KEY_SIZE];

	// Generate random IV
	if (generate_random_bits(drbg_handler, AES_BLOCK_SIZE, iv) != MSS_SYS_SUCCESS)
		return 0;

	/* perform ctr encryption, return cipher/plaintext */
	size = MSS_SYS_128bit_aes(key, iv, inlen/AES_BLOCK_SIZE, MSS_SYS_CTR_ENCRYPT, ciphertext, in);

	/* Concatenate iv+ciphertet to compute mac */
	concatenate (iv_cipher, iv, 0, AES_BLOCK_SIZE);
	concatenate (iv_cipher, ciphertext, AES_BLOCK_SIZE, size);

	/* compute mac from IV+CIPHER/PLAINTEXT */
	status = MSS_SYS_hmac ((const uint8_t *) mac_key, (const uint8_t *) iv_cipher, AES_BLOCK_SIZE+size, mac);

	// concatenate the 3 components for final result
	if (status == MSS_SYS_SUCCESS && size == MSS_SYS_SUCCESS)
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
	uint32_t total_bytes = 0, status;

	// read keys from puf
	MSS_SYS_puf_fetch_key(key_file, &key);

	// set mac key pointer
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
	status = MSS_SYS_hmac ((const uint8_t *) mac_key, (const uint8_t *) iv_cipher, AES_BLOCK_SIZE+total_bytes, computed_mac);

	/* verify if macs are the same */
	if (status == MSS_SYS_SUCCESS && compare_strings(mac, computed_mac, MAC_SIZE) == 0)
	{
		printf ("MAC successfully verified, proceding to decryption...\n");

		/* perform ctr encryption, return IV+CIPHER/PLAINTEXT */
		status = MSS_SYS_128bit_aes(key, iv, total_bytes/AES_BLOCK_SIZE, MSS_SYS_CTR_DECRYPT, plaintext, ciphertext);

		if (status != MSS_SYS_SUCCESS)
			total_bytes = 0;

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
