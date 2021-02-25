#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
// #include "../protocol.h"
// #include "../comms.h"
#include "pkcs11.c"

uint32_t get_attribute_from_file (uint8_t * attribute);
void display_greeting ();
void cleanup();

#endif 
