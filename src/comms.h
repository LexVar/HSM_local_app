#ifndef COMMS_H
#define COMMS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include "protocol.h"
#include "server/libs/mbedtls_crypto.h"
#include "server/libs/crypto.h"

#define PIPE_NAME "/tmp/connection" // Pipe name

void init_key (uint8_t * key);
// Receive a message from the other process
// fd - pipe file descriptor
// structure - pointer to structure where to save information
// struct_size - structure size in bytes sizeof(..)
uint32_t receive_from_connection (uint32_t fd, void * structure, uint32_t struct_size);
uint32_t receive_plain (uint32_t fd, void * structure, uint32_t struct_size);

// Send a message from the other process
// fd - pipe file descriptor
// structure - pointer to structure to send through pipe
// struct_size - structure size in bytes sizeof(..)
uint32_t send_to_connection (uint32_t fd, void * structure, uint32_t struct_size);
uint32_t send_plain (uint32_t fd, void * structure, uint32_t struct_size);

uint8_t send_status(uint32_t  pipe_fd, uint8_t status);
void sendOK(uint32_t pipe_fd, uint8_t * msg);
uint8_t waitOK(uint32_t pipe_fd);
void * write_to_file (uint8_t * filename, uint8_t * content, uint32_t fsize);
uint32_t read_from_file (uint8_t * filename, uint8_t * content);
void flush_stdin ();
void print_hexa(uint8_t * string, uint32_t length);
void print_chars (uint8_t * data, uint32_t data_size);

#endif
