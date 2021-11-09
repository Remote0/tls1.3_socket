#ifndef __HMAC_SHA_FUNC_H__
#define __HMAC_SHA_FUNC_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "hmac_sha_regs.h"
//#define DEBUG

int hmac_sha_set_key(int fd, uint64_t* key);
int hmac_sha_set_input(int fd, uint64_t* input, uint32_t input_len) ;
int hmac_sha_set_mode(int fd, uint32_t mode, uint32_t submode);
int hmac_sha_start(int fd);

int hmac_sha_hashing(int fd, uint32_t* mac, uint64_t* input, uint32_t input_len, uint64_t* key, uint32_t mode, uint32_t submode);

#endif //__HMAC_SHA_FUNC_H__