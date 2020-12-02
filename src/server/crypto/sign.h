#ifndef SIGN_H
#define SIGN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

unsigned char *simple_digest(unsigned char *buf, unsigned int len, unsigned int *olen);
unsigned char *simple_sign(char *keypath, unsigned char *data, unsigned int len, unsigned int *olen);
void *map_file(FILE *fp, size_t len);
int sign_data(char * file, char * privkey);
int simple_verify(char *certpath, unsigned char *sig, unsigned int sigsz, unsigned char *buf, unsigned int len);
int verify_data(char * file, char * certfile, char * sigfile);

#endif
