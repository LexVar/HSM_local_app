#ifndef SERVER_H
#define SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "../protocol.h"
#include "../functions.c"
#include "crypto/crypto.h"

void new_key(char * key_file);
void cleanup();

#endif 
