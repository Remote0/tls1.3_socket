#ifndef RSA_H
#define RSA_H

#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "sha.h"

char* privateKey = 
"-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEA2lxfKK1UNmKhFX1K2QUbNTJGtt6oqRwLNQY15JqawIVi/2UV\n"\
"96IQdk8A+UcfS9DS11CgsPEsM6VUPNYYeJ3dJtPR8IW3mJ83RqlYGLIat4EBByyW\n"\
"fH/4UrWvdsUmpYSvks39iqLh5WPbkjOugJH8rOYuVL31+HvRmdrlXfBUUlqgrhJJ\n"\
"PTDaAKe8Cyax77/wzMnFJo/O7Dps84N2esf4O5Siw6jYPiQ4c+pgTWTV1AVCPsmv\n"\
"pP76IJSxo7iGVoyq/bCrnOtSBRl2d7M6HAh+P6Tn3Uxm6oTmrathtQqKWsYcy0gv\n"\
"MksRvXnM/6gl4Nd2v0eLCUz6SXZ14LiOsGnxGwIDAQABAoIBAFyaSdzFTO5Xe3rS\n"\
"jLhmWvh/Xs/Us3AsLXCKNrbA/hnhN2+Z3ewLtbGGpaIRkGslnxSi49LGJHmuhn/a\n"\
"R7x3Lj92GxVGj+rQsq9rx6mJdp0Vv2rcdOFNn/DrjgLvbwlIsPCwHPL7SpNuesKQ\n"\
"2lM6Fg74+vMDMFn1oJj/5L+m2QunDGEgOeeDb6xGq1ueJyQk/m6daZFXVGAkR6Wl\n"\
"6peEiiRduciGN5yqNIqpC1icuCaSxP9vFVrCdSV5fQ2Lb3VMKi+kDDo1fT1ilAC7\n"\
"15OhDSkTaJm9vAbetxDFUNA6YI+watwIjdxfCt8UGJOwACinazPPFOmY9EVKhH+O\n"\
"TN10P9ECgYEA/p39kVpRBFK8Dros0SCLFcKMnUq69GzdFqT6FgUFAeUp6LIfJ8R+\n"\
"ow+2w3AdAfHTWcUKXr2I+KQCLL5oUzKYoje9K9/hkfT5YUry6pYucrRYInTFQA/T\n"\
"7+Nbu06Lw58HXReRmYHw/2c537N43LWO4vckXfeqosIks0Ba07S3XGMCgYEA24v4\n"\
"zLSTtFagEVOBH/KfD9KF9RcYffzSKV4Bfp8zT7ZZpfokW8EBeFm7ielRlZGb68C3\n"\
"iz9tYp3h7AC602LGgmDGojZw6KXJW6d2AMYqgTQj/0ne7NHXh+eD+zNasJI7Rp6w\n"\
"pQaapbq9005oj5llJqX4q4nIdUJgmd4GrtrJKekCgYEA1sKQFD/nwgu+z3U9RA99\n"\
"ARed3zYfRvdj7CuvPU9yj8ypcrp7COH2JrekYmh4LyG4MSm/u3WGyKIdq3vXJwWw\n"\
"NHNrPkySSLgmeGftSOzvtJRlGnr/vS8chmRxBSYVQSUr4tt0VdSCYArDh+orcY46\n"\
"PTpUFGZIKQw0RHVtps/xMR0CgYAT3l/+zpzLZkeIKeF2rbNdcDT1UEjEJhwy6DIE\n"\
"bo3rOdp1HeUqdJYYeS5yta3PdmUA+ejibjQNB7LJc+t0c+z5IZ74USr4swA9DjOs\n"\
"sEJqfPiBAwNstTTnNLmKA0TC1AkPRA9CcA2Q0Ayb0e2+iShRThXqGEcO7ZnmcuRx\n"\
"8JTh+QKBgFIeMGUwVb2vsivz3H5l/SkHe0yXUxCyaZOu87h6FtXvHQqfDeBVdUPG\n"\
"sF5FTzmeZc1PCY3D9zFkafkvCGMTEGo+g5jVfSBG7OHoH4ncrsQAgnkk9AFnQBxh\n"\
"INYWj1RtKp2xo6xZ+xfmkUR8DWWwvu1QKvy+zXkAqxUh78F1m4Bq\n"\
"-----END RSA PRIVATE KEY-----\0";

char* publicKey =
"-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2lxfKK1UNmKhFX1K2QUb\n"\
"NTJGtt6oqRwLNQY15JqawIVi/2UV96IQdk8A+UcfS9DS11CgsPEsM6VUPNYYeJ3d\n"\
"JtPR8IW3mJ83RqlYGLIat4EBByyWfH/4UrWvdsUmpYSvks39iqLh5WPbkjOugJH8\n"\
"rOYuVL31+HvRmdrlXfBUUlqgrhJJPTDaAKe8Cyax77/wzMnFJo/O7Dps84N2esf4\n"\
"O5Siw6jYPiQ4c+pgTWTV1AVCPsmvpP76IJSxo7iGVoyq/bCrnOtSBRl2d7M6HAh+\n"\
"P6Tn3Uxm6oTmrathtQqKWsYcy0gvMksRvXnM/6gl4Nd2v0eLCUz6SXZ14LiOsGnx\n"\
"GwIDAQAB\n"\
"-----END PUBLIC KEY-----\n\0";

RSA* createPrivateRSA(char* key) {
    RSA *rsa = NULL;
    BIO * keybio = BIO_new_mem_buf((void*)key, -1);
    if (keybio==NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    return rsa;
}

RSA* createPublicRSA(char* key) {
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf((void*)key, -1);
    if (keybio==NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    return rsa;
}

int RSASign(RSA* rsa,
            const EVP_MD *hashFunc,
            const unsigned char* Msg,
            size_t MsgLen,
            unsigned char** EncMsg,
            size_t* MsgLenEnc) {

    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    if (EVP_DigestSignInit(m_RSASignCtx,NULL, hashFunc, NULL, priKey)<=0) {
        return 0;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        return 0;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
        return 0;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
        return 0;
    }
    EVP_MD_CTX_free(m_RSASignCtx);
    return 1;
}

int RSAVerifySignature(RSA* rsa,
                       const EVP_MD *hashFunc,
                       unsigned char* MsgHash,
                       size_t MsgHashLen,
                       const char* Msg,
                       size_t MsgLen,
                       int* Authentic
) {
    *Authentic = 0;
    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, hashFunc, NULL,pubKey)<=0) {
    return 0;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return 0;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus==1) {
    *Authentic = 1;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return 1;
    } else if(AuthStatus==0){
    *Authentic = 0;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return 1;
    } else{
    *Authentic = 0;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return 0;
    }
}

size_t signMessage(const EVP_MD *hashFunc, char* privateKey, char* plainText, unsigned char** encMessage) {
  RSA* privateRSA = createPrivateRSA(privateKey); 
  size_t encMessageLength;
  unsigned char* temp;
  RSASign(privateRSA, hashFunc, (unsigned char*) plainText, strlen(plainText), &temp, &encMessageLength);
  *encMessage = temp;
  return encMessageLength;
}

int verifySignature(const EVP_MD *hashFunc, char* publicKey, char* plainText, unsigned char* encMessage, size_t encMessageLength) {
  RSA* publicRSA = createPublicRSA(publicKey);
  int authentic;
  int result = RSAVerifySignature(publicRSA, hashFunc, encMessage, encMessageLength, plainText, strlen(plainText), &authentic);
  return result & authentic;
}


#endif //RSA_H