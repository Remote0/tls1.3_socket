#ifndef ULT_H
#define ULT_H

#pragma once
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

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



#endif //ULT_H