#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include "../protocol.h"
#include "../comms.h"
// #include "libs/sign.h"
#include "libs/crypto.h"
#include "libs/ecdh.c"
#include "libs/pkc.h"
#include <inttypes.h>

#define PRIVATE_KEY "keys/alice.pem"
#define PRIVATE_KEY_RSA "keys/test.pem"

uint32_t get_list_comm_keys(uint8_t * list);
void get_key_path (uint8_t * entity, uint8_t * key_path, uint8_t * extension);
void authenticate();
void encrypt_authenticate();
void sign_operation();
void verify_operation();
void import_pubkey_operation();
void new_comms_key ();
void init();
void display_greeting ();
void cleanup();

#endif 
