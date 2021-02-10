#include "keys.h"

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
