#ifndef SIGN_H
#define SIGN_H

#include <string.h>
#include <sys/mman.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

unsigned char *simple_digest(unsigned char *buf, unsigned int len, unsigned int *olen);
unsigned char *simple_sign(char *keypath, unsigned char *data, unsigned int len, unsigned int *olen);
void *map_file(FILE *fp, size_t len);
int sign_data(unsigned char * data, int data_size, char * privkey, unsigned char * signature);
int simple_verify(char *certpath, unsigned char *sig, unsigned int sigsz, unsigned char *buf, unsigned int len);
int verify_data(unsigned char * data, int data_size, char * certfile, unsigned char * signature, int siglen);

#endif
