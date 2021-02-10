#ifndef KEYS_H
#define KEYS_H

#include <string.h>
#include <stdlib.h>
#include "crypto.h"

// Key set management functions in memory
uint8_t encrypt_keyset (uint8_t *set, uint16_t setlen);
uint8_t init_keys(uint8_t * new_key, uint16_t keylen);
uint8_t read_key_set(uint8_t * out, uint16_t *keylen);
uint8_t add_key(uint8_t * new_key, uint16_t keylen);
void fetch_key_from_set(uint8_t *set, uint16_t setlen, uint8_t id, uint8_t *key, uint16_t *keylen);

#endif 
