#include <stdio.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include "crypto/ECDH.h"
#include "crypto/sha.h"
#include "crypto/rsa.h"
#include "crypto/AEAD.h"
#include <openssl/kdf.h>
//#include "hmac.h"

//#define DEBUG
#define KEY_LEN 48

/* Data Exchange Initial Setup*/ 
unsigned char *iv = (unsigned char*)"0123456789ab"; /* 96 bits IV*/
size_t iv_len = 12;
unsigned char *plaintext = (unsigned char*)"Test cipher program"; /* Message to be encrypted */
unsigned char *additional = (unsigned char*)"additional data example"; /* Additional data*/

/* Ciphersuite Selection */
char* cipherName = NULL;
int cipher_key_len = 0;
char* hashName = NULL;

typedef struct{
    char* cipherSuite;

    /*Key Exchange*/
    EC_KEY* private_key;
    const EC_POINT* shared_key;
    unsigned char* master_key;
    unsigned char* hashed_master_key;
    /*Cert Verification*/
    char* cert;
    char* jammed_cert;
    char* RSA_private_key;

    /*Functions*/
    int (*func_enc_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, int, unsigned char*, unsigned char*);
    int (*func_dec_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, unsigned char*, int, unsigned char*);
    int (*func_hash_ptr)(char*, char*, unsigned char*);
    size_t (*func_sign_cert)(const EVP_MD*, char*, char*, unsigned char**);
}server;

typedef struct {
    char* cipherSuite[3];
    
    /*Key Exchange*/
    EC_KEY* private_key;
    const EC_POINT* shared_key;
    unsigned char* master_key;
    unsigned char* hashed_master_key;
    /*Cert Verification*/
    char* RSA_public_key;

    /*Functions -- later on change these function to test hardware*/
    int (*func_dec_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, unsigned char*, int, unsigned char*);
    int (*func_hash_ptr)(char*, char*, unsigned char*);
    int (*func_verf_cert)(const EVP_MD*, char*, char*, unsigned char*, size_t);
}client;


int main(int argc, char** argv) {

/*Init server*/
server S;
S.master_key = NULL;
S.jammed_cert = "This is the server's certification message. However it has been jammed\n";
S.func_enc_ptr = &encrypt;
S.func_dec_ptr = &decrypt;
S.func_hash_ptr = &computeHash;
S.func_sign_cert = &signMessage;

/*Init client*/
client C;
C.master_key = NULL;
C.func_dec_ptr = &decrypt;
C.func_hash_ptr = &computeHash;
C.func_verf_cert = &verifySignature;

int opt;
if(argc == 1)
        handleErrors("Require selecting cipherName and hashName");
while((opt = getopt(argc, argv, "c:h:")) != -1) {
        switch(opt) {
                case 'c':
                        cipherName = optarg;
        if(!strcmp(cipherName, "aes-128-gcm"))
                cipher_key_len = 16;
        else if((!strcmp(cipherName, "aes-256-gcm")) | (!strcmp(cipherName, "chacha20-poly1305")))
                cipher_key_len = 32;
        break;
                case 'h':
                        hashName = optarg;
                        break;
        }
}

if(!(cipherName == NULL))
        printf("Selected Cipher: %s\n", cipherName);
else
        handleErrors("Error selecting Cipher");

if(!(hashName == NULL))
        printf("Selected Hash function: %s\n", hashName);
else	
        handleErrors("Error selecting Hash");

//Choose hash function based on input
const EVP_MD *hashFunc;
hashFunc = EVP_get_digestbyname(hashName);
/*------------------------------*/
/*         CLIENT HELLO         */
/*------------------------------*/
/* 1. List of cipher suites */
printf("\n------CLIENT HELLO------\n");
printf("1. Create list of Cipher:\n");
C.cipherSuite[0] = "aes-128-gcm_sha256";
C.cipherSuite[1] = "aes-256-gcm_sha384";
C.cipherSuite[2] = "chacha20-poly1305_sha384";
int i;
for(i = 0; i < 3; i = i + 1)
printf("\t- %s\n", C.cipherSuite[i]);


/* 2. Key share extension */
printf("2. Key share extension:\n");
printf("\t- ECDHE\n");
printf("Generating Client's Private and Share Keys...");
C.private_key = create_key();
if(C.private_key == NULL)
handleErrors("Error creating client key");
C.shared_key = EC_KEY_get0_public_key(C.private_key);
printf("\t***DONE***\n");

/* 3. Signature algorithms extension */
printf("3. Signature algorithms extension:\n");
printf("\t- RSASSA-PCKS1-v1_5\n");

/*------------------------------*/
/*         SERVER HELLO         */
/*------------------------------*/
printf("\n------SERVER HELLO------\n");
/* 1. Select cipher suite */
printf("1. Select cipher suite:\n");
S.cipherSuite = malloc(strlen(cipherName) + 1 + 6);
strcpy(S.cipherSuite, cipherName);
strcat(S.cipherSuite, "_");
strcat(S.cipherSuite, hashName);
//S.cipherSuite = cipherName + "_" + hashName;
printf("\t- %s\n", S.cipherSuite);

/* 2. Select key share extension */
printf("2. Select key share extension:\n");
printf("\t- ECDHE\n");
printf("Generating Server's Private and Share Keys...");
S.private_key = create_key();
if(S.private_key == NULL)
handleErrors("Error creating client key");
S.shared_key = EC_KEY_get0_public_key(S.private_key);
printf("\t***DONE***\n");
printf("Generating Master Key...");
size_t S_master_len;
S_master_len = compute_key(S.private_key, C.shared_key, &S.master_key);
if (S.master_key == NULL)
        handleErrors("Error creating Master Key");
printf("\t***GENERATED***\n");
S.master_key[S_master_len] = '\0';
/* It is recommended that using HMAC-based key derivation to derive the password
HMAC(salt, secret key, SHA256)
salt: some random value, which is stored along with the derived key and,
        used later to derive the same key again from the password. */
/*-----------------HKDF Key creation for cipher use-----------------*/
EVP_PKEY_CTX* ctx;
S.hashed_master_key = malloc(sizeof(unsigned char) * cipher_key_len); 
size_t S_hashed_key_len = cipher_key_len; //this decides the length of key
ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
if(EVP_PKEY_derive_init(ctx) <= 0)
        return -1;
if(EVP_PKEY_CTX_set_hkdf_md(ctx, hashFunc) <= 0)
        return -1;
if(EVP_PKEY_CTX_set1_hkdf_salt(ctx, "salt", 4) <= 0)
        return -1;
if(EVP_PKEY_CTX_set1_hkdf_key(ctx, S.master_key, S_master_len) <= 0)
        return -1;
if(EVP_PKEY_derive(ctx, S.hashed_master_key, &S_hashed_key_len) <= 0)
        return -1;
EVP_PKEY_CTX_free(ctx);
S.hashed_master_key[S_hashed_key_len] = '\0';
printf("S key HKDF len: %ldB - %ldbit\n", S_hashed_key_len, S_hashed_key_len*8);
BIO_dump_fp(stdout, (const char*) S.hashed_master_key, S_hashed_key_len);

/* 3. Select signature algorithms */
printf("3. Select signature algorithms:\n");
printf("\t- RSASSA-PCKS1-v1_5\n");
printf("Generating Certificate...\n");
S.cert = "This is the server's certification message.\nThe Server will sign this then send signature and this cert to the Client\n";
printf("Certification text: %s", S.cert);
S.RSA_private_key = privateKey;
printf("Server Signing...");
unsigned char* signature = NULL;
size_t signature_len = S.func_sign_cert(hashFunc, S.RSA_private_key, S.cert, &signature);
printf("\t***SIGNED***\n");
printf("Server FINISHED\n");

//printf("signature length: %ld\n", signature_len);
//BIO_dump_fp(stdout,(const char*) signature, signature_len);

/*-------------------------------*/
/*         CLIENT VERFIY         */
/*-------------------------------*/
printf("\n------CLIENT VERIFY------\n");
C.RSA_public_key = publicKey;
printf("Client verifying...");
int authentic = verifySignature(hashFunc, C.RSA_public_key, S.cert, signature, signature_len);
if ( authentic ) {
        printf("\t***AUTHENTIC***\n");
} else {
        printf("\nNot Authentic\n");
        printf("Abort connection\n");
        exit(-1);
}

printf("Generating Master Key...");
size_t C_master_len;
C_master_len = compute_key(C.private_key, S.shared_key, &C.master_key);
if (C.master_key == NULL)
        handleErrors("Error creating Master Key");
printf("\t***GENERATED***\n");
C.master_key[C_master_len] = '\0';

/* It is recommended that using HMAC-based key derivation to derive the password
HMAC(salt, secret key, SHA256)
salt: some random value, which is stored along with the derived key and,
        used later to derive the same key again from the password. */

/*-----------------HKDF Key creation for cipher use-----------------*/
C.hashed_master_key = malloc(sizeof(unsigned char) * cipher_key_len);
size_t C_hashed_key_len = cipher_key_len; //This decides the length of the key
printf("hashed key len: %ld\n", C_hashed_key_len);
ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
if(EVP_PKEY_derive_init(ctx) <= 0)
        return -1;
if(EVP_PKEY_CTX_set_hkdf_md(ctx, hashFunc) <= 0)
        return -1;
if(EVP_PKEY_CTX_set1_hkdf_salt(ctx, "salt", 4) <= 0)
        return -1;
if(EVP_PKEY_CTX_set1_hkdf_key(ctx, C.master_key, C_master_len) <= 0)
        return -1;
if(EVP_PKEY_derive(ctx, C.hashed_master_key, &C_hashed_key_len) <= 0)
        return -1;
EVP_PKEY_CTX_free(ctx);
C.hashed_master_key[C_hashed_key_len] = '\0';
printf("C key HKDF len: %ldB - %ldbit\n", C_hashed_key_len, C_hashed_key_len*8);
BIO_dump_fp(stdout, (const char*) C.hashed_master_key, C_hashed_key_len);
printf("Client FINISHED\n");
/*------------------------------*/
/*        EXCHANGE DATA         */
/*------------------------------*/
printf("\n------EXCHANGE DATA------\n");
/*Buffer for ciphertext. Ensure the buffer is long enough for the
* ciphertext which may be longer than the plaintext, depending
* on the algorithm and mode.
*/
unsigned char ciphertext[128];
unsigned char decryptedtext[128]; /* Buffer for the decrypted text */
unsigned char tag[16]; /* Buffer for the tag */
int decryptedtext_len, ciphertext_len;

/*--------SERVER--------*/
printf("Server encrypting data and send Ciphertext, AAD, IV, Tag to client...\n");
ciphertext_len = S.func_enc_ptr(cipherName,
                                plaintext, strlen((char*)plaintext),
                                additional, strlen((char*)additional),
                                S.hashed_master_key,
                                iv, iv_len,
                                ciphertext, tag); /* Encrypt the plaintext */
printf("***ENCRYPTED***\n"); /* Do something useful with the ciphertext */
printf("Ciphertext:\n");
BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);
printf("tag: %s\n", (char*)tag);
printf("Tag:\n");
BIO_dump_fp(stdout, (const char*)tag, 16);

/*--------CLIENT--------*/
printf("\nClient decrypt and verify data...\n");
decryptedtext_len = C.func_dec_ptr( cipherName,
                                ciphertext, ciphertext_len,
                                additional, strlen((char*)additional),
                                C.hashed_master_key,
                                tag,
                                iv, iv_len,
                                decryptedtext); /* Decrypt the ciphertext */

if(decryptedtext_len >= 0) {
        decryptedtext[decryptedtext_len] = '\0'; /* Add a NULL terminator. We are expecting printable text*/
        /* Show the decrypted text */
        printf("***DECRYPTION SUCCESS***\n");
        printf("Decrypted text: ");
        printf("%s\n", decryptedtext);
} else {
        printf("Decryption failed\n");
}

/*CLEAN UP*/
EC_KEY_free(S.private_key);
EC_KEY_free(C.private_key);
free(S.master_key);
free(C.master_key);
free(S.hashed_master_key);
free(C.hashed_master_key);
//OPENSSL_free(S.master_key);
//OPENSSL_free(C.master_key);
//free(S.key);
//free(C.key);
return 0;
}
