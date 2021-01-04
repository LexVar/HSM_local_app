#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include "../protocol.h"
#include "../functions.c"

void encrypt_authenticate();
void sendOK(uint8_t * msg);
uint8_t waitOK();
uint32_t get_attribute_from_file (uint8_t * attribute);
uint8_t authenticate();
uint8_t set_pin();
void cleanup();
void encrypt_authenticate(uint8_t * file);
void sign_operation();
void verify_operation();
void import_pubkey_operation();
void new_comms_key();
void share_key_operation();
void save_key_operation();

#endif 
