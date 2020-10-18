#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../protocol.h"
#include "../functions.h"

void send_to_connection (struct composed_request * request);
void receive_from_connection (struct composed_response * response);
void flush_stdin ();
void cleanup();

#endif 
