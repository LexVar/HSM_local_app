#include "crypto.h"

uint8_t random_bytes(uint8_t * buffer, uint16_t len)
{
	FILE * fd = fopen("/dev/urandom", "r");
	int ret = 0;

	if (fd != NULL)
	{
		fread(buffer, len, 1, fd);
		fclose(fd);
	}
	else ret = 1;

	return ret;
}

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
uint32_t encrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key)
{
	uint8_t * mac_key;
	uint8_t * ciphertext = out + MAC_SIZE + BLOCK_SIZE;
	uint8_t * iv = out + MAC_SIZE;
	uint8_t * iv_cipher = out + MAC_SIZE;
	uint8_t * mac = out;
	uint8_t iv2[BLOCK_SIZE];
	int ret;

	// Padd input buffer block with zeros if needed
	inlen = padd_block(in, inlen);

	memset (key+2*KEY_SIZE, 0, KEY_SIZE);

	// set mac key pointer
	mac_key = &key[KEY_SIZE];

	// Generate random IV
	// USE NRGB HERE
	if( random_bytes(iv2, sizeof(iv)) )
		return 0;
	memcpy (iv, iv2, BLOCK_SIZE);

	// perform ctr encryption, return cipher/plaintext
	// inlen = ctr_encryption(in, inlen, iv, ciphertext, key);
	ret = mbed_aes_crypt(iv2, in, ciphertext, inlen, key);

	// compute mac from IV+PLAINTEXT
	ret = mbed_hmac (mac_key, iv_cipher, BLOCK_SIZE+inlen, mac);

	if (ret == 0)
	{
		printf ("Message encrypted..\n");
		inlen = inlen+BLOCK_SIZE+MAC_SIZE;
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
uint32_t decrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key)
{
	uint8_t * mac = in;
	uint8_t * iv = in + MAC_SIZE;
	uint8_t * ciphertext = in + MAC_SIZE + BLOCK_SIZE;
	uint8_t * iv_cipher = in + MAC_SIZE;
	uint8_t computed_mac[MAC_SIZE];
	uint8_t * mac_key;
	int ret;

	if (inlen <= (BLOCK_SIZE+MAC_SIZE))
		return 0;

	memset (key+2*KEY_SIZE, 0, KEY_SIZE);
	mac_key = &key[KEY_SIZE];

	inlen = inlen - MAC_SIZE - BLOCK_SIZE;

	// compute mac from IV+CIPHER
	ret = mbed_hmac (mac_key, iv_cipher, BLOCK_SIZE+inlen, computed_mac);

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
