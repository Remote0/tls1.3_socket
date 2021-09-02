#ifndef ULT_H
#define ULT_H

#pragma once
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <math.h>
#include <stdio.h>

void print_key(const EC_GROUP* ec_group, const EC_POINT* key){
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if(EC_POINT_get_affine_coordinates_GFp(ec_group, key, x, y, NULL)) {
        printf("\n Print Key:\n");
        BN_print_fp(stdout, x);
        putc('\n', stdout);
        BN_print_fp(stdout, y);
        putc('\n', stdout);
    }
}

void Base64Encode( const unsigned char* buffer,
                   size_t length,
                   char** base64Text) {
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  *base64Text=(*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

int find_pos(const char* haystack, const char* needle) {
  char* ptr = strstr(haystack, needle);
  return ptr-haystack;
}


#endif //ULT_H