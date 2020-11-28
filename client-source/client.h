#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../protocol.h"
#include "../functions.c"

void send_to_connection (struct request * request);
void receive_from_connection (struct response * response);
void flush_stdin ();
void cleanup();

#endif 
