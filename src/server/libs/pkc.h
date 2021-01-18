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

// uint8_t SecComm();
// int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);
int PKC_init(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg, const char * pers, uint8_t loadGroup);
uint8_t PKC_genKeyPair(uint8_t * public, uint8_t * private);
uint8_t PKC_signData(uint8_t * private, uint8_t * data, size_t data_len, uint8_t * signature, size_t * signature_len);
int PKC_verifySignature(uint8_t * cert, uint8_t * data, size_t data_len, uint8_t * signature, size_t signature_len);
// int PKC_verifySignature(uint8_t * cert, size_t cert_size, uint8_t * data, size_t data_len, uint8_t * signature, size_t signature_len);
uint8_t PKC_createCertificate(uint8_t* public, uint8_t * subject_name, uint16_t key_usage, uint8_t* certificate, uint32_t bufsize);
void PKC_free(mbedtls_pk_context *ctx, mbedtls_entropy_context * entropy, mbedtls_ctr_drbg_context * ctr_drbg);

#endif /* PKC_H_ */
