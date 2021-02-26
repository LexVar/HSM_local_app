#include <string.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>

#include "../../protocol.h"

int mbed_sha256 (uint8_t * in, uint16_t len, uint8_t * hash);
int mbed_hmac (uint8_t * key, uint8_t * in, uint16_t len, uint8_t * out);
int mbed_aes_crypt(uint8_t * iv, uint8_t * in, uint8_t * out, uint16_t len, uint8_t * key);
int mbed_gen_pair(uint8_t * pri, uint8_t * pub);

// ECDH - generate shared secret from personal ecc key pair and peer's public key
uint8_t mbed_ecdh(uint8_t *privkey, uint8_t * public, uint8_t * secret, size_t * len);
