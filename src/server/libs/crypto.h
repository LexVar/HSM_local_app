#ifndef CRYPTO_H
#define CRYPTO_H

#include <inttypes.h>

#include "mbedtls_crypto.h"
#include "../../protocol.h"
#include "../../comms.h"

// Helper functions
uint8_t random_bytes(uint8_t * buffer, uint16_t len);
uint8_t read_key(uint8_t * key, uint8_t * key_file, uint32_t key_size);

// Encryption/decryption, HMAC functions
uint32_t encrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file);
uint32_t decrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file);

#endif 
