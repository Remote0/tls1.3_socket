#ifndef ECDH_H
#define ECDH_H

#pragma once
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include "sha.h"

EC_KEY *create_key(void) {
    EC_KEY* key;
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(key == NULL)
        handleErrors("Error create key curve");

    if(1 != EC_KEY_generate_key(key))
        handleErrors("Error generate key");

    return key;
}

/* unsigned char* get_secret(EC_KEY* key, const EC_POINT *peer_pub_key, size_t *secret_len) {
    int field_size;
    unsigned char* secret;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    *secret_len = (field_size + 7) / 8;

    secret = OPENSSL_malloc(*secret_len);
    if(secret == NULL)
        handleErrors("Error allocate memory for secret");

    *secret_len = ECDH_compute_key(secret, *secret_len, peer_pub_key, key, NULL);

    if(*secret_len <= 0) {
        OPENSSL_free(secret);
        return NULL;
    }

    return secret;
} */

size_t compute_key(EC_KEY* key, const EC_POINT *peer_pub_key, unsigned char** secret) {
    int field_size;
    //unsigned char* secret;
    size_t secret_len;

    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    secret_len = (field_size + 7) / 8;

    *secret = OPENSSL_malloc(secret_len);
    if(*secret == NULL)
        handleErrors("Error allocate memory for secret");

    secret_len = ECDH_compute_key(*secret, secret_len, peer_pub_key, key, NULL);

    if(secret_len <= 0) {
        OPENSSL_free(*secret);
        return 0;
    }

    return secret_len;
}

#endif //ECDH_H