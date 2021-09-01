#ifndef SHA_H
#define SHA_H

#pragma once
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <string.h>

void handleErrors(const char* error) {
        printf("%s\n", error);
        exit(-1);
}

int computeHash(char* hashName, char* unhashed, unsigned char* hashed){
        EVP_MD_CTX* ctx;
        unsigned int lenOfHash = 0;
	
	const EVP_MD *md;
        if (hashName == NULL) 
                handleErrors("Usage: mdtest digestname\n");

        md = EVP_get_digestbyname(hashName);
        if (md == NULL) {
                printf("Unknown message digest %s\n", hashName);
                exit(-1);
        }

        if(!(ctx = EVP_MD_CTX_new()))
                handleErrors("Error create context");

        if(!EVP_DigestInit_ex(ctx, md, NULL))
		handleErrors("Error Initialize sha256");

	if(!EVP_DigestUpdate(ctx, unhashed, strlen(unhashed)))
		handleErrors("Error digest unhashed data");

	if(!EVP_DigestFinal_ex(ctx, hashed, &lenOfHash))
		handleErrors("Error finalize digest");
	return lenOfHash;
}


#endif //SHA_H
