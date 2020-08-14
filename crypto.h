#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/aes.h>
/* #include <openssl/modes.h> */
/* #include <openssl/crypto.h> */
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#define SIZE 99
// Key size - 128 bit
#define KEY_SIZE 16
// MAC code size
#define MAC_SIZE 32
// Max message size
#define MESSAGE_SIZE 512

typedef struct
{
	unsigned char iv[AES_BLOCK_SIZE];
	unsigned char key_bytes[KEY_SIZE];
	unsigned int num;
	unsigned char ecount_buf[AES_BLOCK_SIZE];
} ctr_state;

void encrypt(char * input_file, char * output_file, char * key_file, char * mac_file);
int ctr_encryption(unsigned char * plaintext, int size, unsigned char * iv, unsigned char * ciphertext, unsigned char * key_bytes);
void decrypt(char * input_file, char * output_file, char * key_file, char * mac_file);
unsigned char * compute_hmac(unsigned char * key, unsigned char * message, int size);
void init_ctr_state (ctr_state * state, unsigned char iv[AES_BLOCK_SIZE], unsigned char key_bytes[KEY_SIZE]);

#endif 
