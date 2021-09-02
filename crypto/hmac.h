#ifndef HMAC_H
#define HMAC_H

#pragma once
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

unsigned char* hmac_sha256(const void* key,
                           int keylen,
                           const unsigned char* data,
                           int datalen,
                           unsigned char* result,
                           unsigned int* resultlen
                           ) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

int hash_key(const EVP_MD* hashFunc, const unsigned char* key, const size_t keylen, unsigned char** hased_key, size_t* out_keylen) {
        EVP_PKEY_CTX* ctx;
        *hased_key = (unsigned char*)malloc(sizeof(unsigned char) * *out_keylen); 
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if(EVP_PKEY_derive_init(ctx) <= 0)
                return -1;
        if(EVP_PKEY_CTX_set_hkdf_md(ctx, hashFunc) <= 0)
                return -1;
        if(EVP_PKEY_CTX_set1_hkdf_salt(ctx, "salt", 4) <= 0)
                return -1;
        if(EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen) <= 0)
                return -1;
        if(EVP_PKEY_derive(ctx, *hased_key, out_keylen) <= 0)
                return -1;
        EVP_PKEY_CTX_free(ctx);
        return 0;
}



//Example use in main
/* char* keytest = strdup("security is awesome");
        int keylen = strlen(keytest);
        const unsigned char* data = (const unsigned char*) strdup("this is highly sensitive user data");
        int datalen = strlen((char*)data);
        unsigned char* result = NULL;
        unsigned int resultlen = -1;

        result = hmac_sha256((const void*)keytest, keylen, data, datalen, result, &resultlen);

        unsigned int i;
        for(i = 0; i < resultlen; i = i + 1) {
                printf("%02X", result[i]);
        }
        printf("\n"); */


#endif //HMAC_H