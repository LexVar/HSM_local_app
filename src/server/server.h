#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include "../protocol.h"
#include "../functions.c"
#include "crypto/sign.h"
#include "crypto/crypto.h"
#include "crypto/pubkey.c"
#include <inttypes.h>
// #include "pkcs11.h"

#define PRIVATE_KEY "keys/test.pem"

int get_list_comm_keys(char * list);
void print_hex (unsigned char * data, int data_size);
void print_chars (unsigned char * data, int data_size);
void get_key_path (char * entity, char * key_path, char * extension);
void authenticate();
void encrypt_authenticate();
void decrypt_authenticate();
void sign_operation();
void verify_operation();
void import_pubkey_operation();
void share_key_operation();
void save_key_operation();
void init();
void display_greeting ();
void cleanup();

#endif 
