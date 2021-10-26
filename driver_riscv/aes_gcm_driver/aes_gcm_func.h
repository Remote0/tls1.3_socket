#ifndef __AES_GCM_FUNC_H__
#define __AES_GCM_FUNC_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

//#define DEBUG

int aes_gcm_set_key(int fd, uint32_t* key, uint32_t key_len);
int aes_gcm_set_iv(int fd, uint32_t* iv);
int aes_gcm_set_input(int fd, uint32_t* input, uint32_t input_len);
int aes_gcm_set_aad(int fd, uint32_t* aad, uint32_t aad_len);
int aes_gcm_set_tag(int fd, uint32_t* tag);
int aes_gcm_start_encrypt(int fd);
int aes_gcm_start_decrypt(int fd);

int aes_gcm_encrypt(int fd, uint32_t* output, uint32_t* tag, uint32_t* input, uint32_t input_len, uint32_t* key, const uint32_t key_len, uint32_t* iv, uint32_t* aad, const size_t aad_len);
int aes_gcm_decrypt(int fd, uint32_t* output, uint32_t* input, uint32_t input_len, uint32_t* key, const uint32_t key_len, uint32_t* iv, uint32_t* aad, const size_t aad_len,  uint32_t* tag);

#endif //__AES_GCM_FUNC_H__