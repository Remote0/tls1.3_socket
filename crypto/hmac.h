#ifndef HMAC_H
#define HMAC_H

#pragma once
#include <openssl/evp.h>
#include <openssl/hmac.h>

unsigned char* hmac_sha256(const void* key,
                           int keylen,
                           const unsigned char* data,
                           int datalen,
                           unsigned char* result,
                           unsigned int* resultlen
                           ) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
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