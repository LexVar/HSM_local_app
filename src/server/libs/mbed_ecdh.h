#ifndef MBED_ECDH_H 
#define MBED_ECDH_H 

#include <string.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/config.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

#include "../../protocol.h"
#include "../../comms.h"

// int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

// ECDH - generate shared secret from personal ecc key pair and peer's public key
uint8_t ecdh(uint8_t *privkey, uint8_t * public, uint8_t * secret, size_t * len);

// Key derivation function to generate key from shared secret
// SHA256 hashing
// Uses salt for extra entropy
uint8_t kdf(uint8_t * salt, size_t saltlen, uint8_t * shared_secret, size_t len, uint8_t *key);

#endif /* MBED_ECDH_H */
