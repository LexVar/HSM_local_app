#ifndef CRYPTO_H
#define CRYPTO_H

#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/hmac.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include <inttypes.h>

#include "../../protocol.h"
#include "../../comms.h"

typedef struct
{
	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t key_bytes[KEY_SIZE];
	uint32_t num;
	uint8_t ecount_buf[AES_BLOCK_SIZE];
} ctr_state;

void init_crypto_state ();
uint8_t simpleSHA256(void * input, uint64_t length, uint8_t * md);
void concatenate(uint8_t * dest, uint8_t * src, uint32_t start, uint32_t length);
uint32_t compare_strings(uint8_t * m1, uint8_t * m2, uint32_t length);
uint8_t read_key(uint8_t * key, uint8_t * key_file, uint32_t key_size);
uint32_t encrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file);
uint32_t ctr_encryption(uint8_t * plaintext, uint32_t size, uint8_t * iv, uint8_t * ciphertext, uint8_t * key_bytes);
uint32_t decrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file);
uint8_t * compute_hmac(uint8_t * key, uint8_t * message, uint32_t size);
void init_ctr_state (ctr_state * state, uint8_t iv[AES_BLOCK_SIZE], uint8_t key_bytes[KEY_SIZE]);

#endif 
