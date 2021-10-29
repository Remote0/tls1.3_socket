#ifndef __CHACHA_POLY_FUNC_H__
#define __CHACHA_POLY_FUNC_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

//#define DEBUG

int chacha_poly_set_key(int fd, uint32_t* key);
int chacha_poly_set_nonce(int fd, uint32_t* nonce);
int chacha_poly_set_input(int fd, uint32_t* input, uint32_t input_len);
int chacha_poly_set_aad(int fd, uint32_t* aad);
int chacha_poly_set_mac(int fd, uint32_t* mac) ;
int chacha_poly_start_encrypt(int fd);
int chacha_poly_start_decrypt(int fd);

int chacha_poly_encrypt(int fd, uint32_t* output, uint32_t* mac, uint32_t* input, uint32_t input_len, uint32_t* key, uint32_t* nonce, uint32_t* aad);
int chacha_poly_decrypt(int fd, uint32_t* output, uint32_t* input, uint32_t input_len, uint32_t* key, uint32_t* iv, uint32_t* aad, uint32_t* mac);

#endif //__CHACHA_POLY_FUNC_H__