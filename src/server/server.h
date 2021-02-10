#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <inttypes.h>

#include "../comms.h"
#include "../protocol.h"

#include "libs/crypto.h"
#include "libs/keys.h"
// #include "libs/mbed_ecdsa.h"
// #include "libs/mbed_ecdh.h"

// DEPRECATED OPENSSL STUFF
#include "libs/openssl_ecdsa.h"
#include "libs/openssl_ecdh.c"

#define PRIVATE_KEY "keys/alice.pem"

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
