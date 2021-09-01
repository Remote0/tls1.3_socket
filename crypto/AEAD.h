#ifndef AEAD_H
#define AEAD_H

#pragma once
#include "sha.h"
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <string.h>

/*void handleErrors(char* error) {
        printf("%s\n", error);
        exit(-1);
}*/

int encrypt(char* cipherName,
            unsigned char* plaintext, int plaintext_len,
            unsigned char* aad, int aad_len,
            unsigned char* key,
            unsigned char* iv, int iv_len,
            unsigned char* ciphertext,
            unsigned char* tag) {

        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;


	const EVP_CIPHER *cipher;
        if (cipherName == NULL) {
                printf("Usage: cipher name\n");
                exit(-1);
        }
        cipher = EVP_get_cipherbyname(cipherName);
        if (cipher == NULL) {
                printf("Unknown cipher %s\n", cipherName);
                exit(-1);
        }

        /*Create context*/
        if(!(ctx = EVP_CIPHER_CTX_new()))
                handleErrors("Error create context");

        /*If IV length is different from 12 bytes (96 bits)
         *  Do this first
         */
        /*if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL))
                handleErrors("Error change iv length");*/

        /*Initialize the encryption*/
        if(!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
                handleErrors("Error Initialize encryption");
	
	/* Provide AAD data.
         * Can be get rid of if there is no AAD data
         */
        if(!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
                EVP_CIPHER_CTX_free(ctx);
                handleErrors("Error computing AAD data");
        }

        /*Provide message to be encrypted, and obtain the encrypted output
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if(!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
                EVP_CIPHER_CTX_free(ctx);
                handleErrors("Error encrypting message");
        }

        ciphertext_len = len;

        /*Finalize the encryption
         *Buffer passed to EVP_EncryptFinal() must be after data just encrypted to avoid overwriting it
         */
        if(!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
                EVP_CIPHER_CTX_free(ctx);
                handleErrors("Error finalize the encryption");
        }
        ciphertext_len += len;

        /*Get the tag*/
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
                handleErrors("Errot can not get tag");

        /*Clean up*/
        EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}


int decrypt(char* cipherName,
            unsigned char* ciphertext, int ciphertext_len,
            unsigned char* aad, int aad_len,
            unsigned char* key,
            unsigned char* tag,
            unsigned char* iv, int iv_len,
            unsigned char* plaintext) {
        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;
        int ret;

	const EVP_CIPHER *cipher;
        if (cipherName == NULL) {
                printf("Usage: cipher name\n");
                exit(-1);
        }
        cipher = EVP_get_cipherbyname(cipherName);
        if (cipher == NULL) {
                printf("Unknown cipher %s\n", cipherName);
                exit(-1);
        }

        /*Create context*/
        if(!(ctx = EVP_CIPHER_CTX_new()))
                handleErrors("Error create context");

        /* Can be set IV length here as similar as in the encryption*/

        /*Initialize the decryption operation*/
        if(!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
                handleErrors("Error initialize the decryption");

        /*Provide AAD data*/
        if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
                EVP_CIPHER_CTX_free(ctx);
                handleErrors("Error computing AAD data");
        }

        /*Provide message to be decrypted*/
        if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
                EVP_CIPHER_CTX_free(ctx);
                handleErrors("Error decrypting message");
        }
        plaintext_len = len;
	
	/*Set the expected tag value*/
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
                handleErrors("Error set expected tag");

        /*Finalize the decryption.
         * A positive return value indicates success, 
         * anything else is a failure - the plaintext is not trustworthy.
         */
        ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        if(ret > 0) {
                /*Success*/
                plaintext_len += len;
                return plaintext_len;
        } else {
                /*Verify failed*/
                return -1;
        }
}


#endif // AEAD_H
