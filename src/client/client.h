#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "../protocol.h"
#include "../functions.c"

int get_attribute_from_file (char * attribute);
int check_authentication ();
void cleanup();

#endif 
