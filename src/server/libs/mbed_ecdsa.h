#ifndef MBED_ECDSA_H
#define MBED_ECDSA_H

#include <string.h>
#include "mbedtls/ecdh.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"

#include "../../protocol.h"

// int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

// init entropy and pk contexts
int init_ctx(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg, const char * pers, uint8_t loadGroup);

// Sign data
// SHA256 -> ECDSA
uint8_t sign_data(uint8_t * private, uint8_t * data, size_t data_len, uint8_t * signature, size_t * signature_len);
// verify signature
int verify_signature(uint8_t * cert, uint8_t * data, size_t data_len, uint8_t * signature, size_t signature_len);

// Free contexts
void free_ctx(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg);

#endif /* MBED_ECDSA_H */
