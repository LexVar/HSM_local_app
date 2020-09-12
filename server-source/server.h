#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

void new_key(char * key_file);
void read_key(unsigned char * key, char * key_file);
void print_hexa(unsigned char * string, int length);
void concatenate(unsigned char * dest, unsigned char * src, int start, int length);
int compare_mac(unsigned char * mac1, unsigned char * mac2, int length);
void cleanup();

#endif 
