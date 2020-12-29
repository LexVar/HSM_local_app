#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>
#include "../protocol.h"
#include "../functions.c"


uint32_t get_attribute_from_file (uint8_t * attribute);
uint8_t check_authentication ();
void cleanup();

#endif 
