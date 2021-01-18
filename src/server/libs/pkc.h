/*
 * PKC.h
 *
 *  Created on: 10/02/2017
 *      Author: diogo
 */

#ifndef PKC_H_
#define PKC_H_

#include "mbedtls/ecdh.h"
#include "mbedtls/config.h"

#include "mbedtls/platform.h"

#include "mbedtls/pkcs5.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ecdh.h"
#include "../../protocol.h"

// int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);
int PKC_init(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg, const char * pers, uint8_t loadGroup);
uint8_t PKC_genKeyPair(uint8_t * public, uint8_t * private);
uint8_t PKC_signData(uint8_t * private, uint8_t * data, size_t data_len, uint8_t * signature, size_t * signature_len);
int PKC_verifySignature(uint8_t * cert, uint8_t * data, size_t data_len, uint8_t * signature, size_t signature_len);
uint8_t PKC_createCertificate(uint8_t* public, uint8_t * subject_name, uint16_t key_usage, uint8_t* certificate, uint32_t bufsize);
void PKC_free(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg);

// ECDH - generate shared secret from personal ecc key pair and peer's public key
uint8_t ecdh(uint8_t *privkey, uint8_t * public, uint8_t * secret, size_t * len);

// Key derivation function to generate key from shared secret
// SHA256 hashing
// Uses salt for extra entropy
uint8_t kdf(uint8_t * salt, size_t saltlen, uint8_t * shared_secret, size_t len, uint8_t *key);

#endif /* PKC_H_ */
