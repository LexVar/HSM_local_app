#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "../../protocol.h"

typedef struct
{
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char key_bytes[KEY_SIZE];
	unsigned int num;
	unsigned char ecount_buf[AES_BLOCK_SIZE];
} ctr_state;

void new_key(char * key_file);
void init_crypto_state ();
int simpleSHA256(void * input, unsigned long length, unsigned char * md);
void concatenate(unsigned char * dest, unsigned char * src, int start, int length);
int compare_mac(unsigned char * mac1, unsigned char * mac2, int length);
void read_key(unsigned char * key, char * key_file, int key_size);
int encrypt(unsigned char * in, int inlen, unsigned char * out, char * key_file);
int ctr_encryption(unsigned char * plaintext, int size, unsigned char * iv, unsigned char * ciphertext, unsigned char * key_bytes);
int decrypt(unsigned char * in, int inlen, unsigned char * out, char * key_file);
unsigned char * compute_hmac(unsigned char * key, unsigned char * message, int size);
void init_ctr_state (ctr_state * state, unsigned char iv[AES_BLOCK_SIZE], unsigned char key_bytes[KEY_SIZE]);

#endif 
