#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include "../protocol.h"
#include "../functions.c"
#include "libs/sign.h"
#include "libs/crypto.h"
#include "libs/pubkey.c"
#include <inttypes.h>
// #include "pkcs11.h"

#define PRIVATE_KEY "keys/test.pem"

uint8_t send_status(uint8_t status);
uint8_t waitOK();
void sendOK(uint8_t * msg);
uint32_t get_list_comm_keys(uint8_t * list);
void print_hex (uint8_t * data, uint32_t data_size);
void print_chars (uint8_t * data, uint32_t data_size);
void get_key_path (uint8_t * entity, uint8_t * key_path, uint8_t * extension);
void authenticate();
void encrypt_authenticate();
void sign_operation();
void verify_operation();
void import_pubkey_operation();
void share_key_operation();
void save_key_operation();
void init();
void display_greeting ();
void cleanup();

#endif 
