#ifndef SIGN_H
#define SIGN_H

#include <string.h>
#include <sys/mman.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <inttypes.h>

uint8_t *simple_digest(uint8_t *buf, uint32_t len, uint32_t *olen);
uint8_t *simple_sign(uint8_t *keypath, uint8_t *data, uint32_t len, uint32_t *olen);
void *map_file(FILE *fp, size_t len);
uint32_t sign_data(uint8_t * data, uint32_t data_size, uint8_t * privkey, uint8_t * signature);
uint32_t simple_verify(uint8_t *certpath, uint8_t *sig, uint32_t sigsz, uint8_t *buf, uint32_t len);
uint32_t verify_data(uint8_t * data, uint32_t data_size, uint8_t * certfile, uint8_t * signature, uint32_t siglen);

#endif
