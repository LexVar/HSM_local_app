#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <inttypes.h>

#include "drivers/mss_sys_services/mss_sys_services.h"
#include "drivers/mss_uart/mss_uart.h"
#include "../../protocol.h"

void new_key(uint8_t * key_file);
void init_crypto_state ();
void concatenate(uint8_t * dest, uint8_t * src, uint32_t start, uint32_t length);
uint32_t compare_strings(uint8_t * m1, uint8_t * m2, uint32_t length);
uint8_t read_key(uint8_t * key, uint8_t * key_file, uint32_t key_size);
uint32_t encrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file);
uint32_t decrypt(uint8_t * in, uint32_t inlen, uint8_t * out, uint8_t * key_file);
uint8_t * compute_hmac(uint8_t * key, uint8_t * message, uint32_t size);

#endif 
