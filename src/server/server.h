#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "../protocol.h"
#include "../functions.c"
#include "crypto/sign.h"
#include "crypto/crypto.h"
#include "crypto/pubkey.c"
#include "pkcs11.h"

#define PRIVATE_KEY "keys/test.key"

void get_cert_path (char * entity, char * cert_path);
void new_key(char * key_file);
void cleanup();

#endif 
