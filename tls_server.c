/*
	C socket server example
*/

#define BUFF_SIZE 2000

#include<stdio.h>
#include<stdlib.h>
#include<string.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<unistd.h>	//write

/* OPENSSL */
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/kdf.h>
#include "crypto/ECDH.h"
#include "crypto/sha.h"
#include "crypto/rsa.h"
#include "crypto/AEAD.h"
#include "crypto/ult.h"

typedef struct{
    char* cipherSuite;
    char* cipherName;
    char* hashName;
    char keyshare[5];
    char* sign_algorithm;

    /*Client share key*/
    char C_hex_key[130];
    EC_POINT* C_shared_key;

    /*Key Exchange*/
    const EC_KEY* private_key;
    const EC_POINT* shared_key;
    char* hex_key;
    unsigned char* master_key;
    unsigned char* hashed_master_key;
    size_t hashed_key_len;
    /*Cert Verification*/
    char* cert;
    char* RSA_private_key;
    unsigned char* signature;
    size_t signature_len;
    /*Functions*/
    int (*func_enc_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, int, unsigned char*, unsigned char*);
    int (*func_dec_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, unsigned char*, int, unsigned char*);
    int (*func_hash_ptr)(char*, char*, unsigned char*);
    size_t (*func_sign_cert)(const EVP_MD*, char*, char*, unsigned char**);

    /* Utility */
    const EC_GROUP* ec_group;
    BN_CTX* bn_ctx;
}server;

char client_message[BUFF_SIZE];
char message[BUFF_SIZE];

void parsing_hello_message(char* message, server* ser){
    char ID_ciphersuite[3];
    char ID_sign[5];

    strncpy(ID_ciphersuite, &message[15], 2);
    switch(atoi(ID_ciphersuite)) {
    case 1: {
        ser->cipherSuite = "aes-128-gcm_sha256";
        ser->cipherName = "aes-128-gcm";
        ser->hashName = "sha256";
        ser->hashed_key_len = 16;
        break;
    }
    case 2: {
        ser->cipherSuite = "aes-256-gcm_sha384";
        ser->cipherName = "aes-256-gcm";
        ser->hashName = "sha384";
        ser->hashed_key_len = 32;
        break;
    }
    case 3: {
        ser->cipherSuite = "chacha20-poly1305_sha256";
        ser->cipherName = "chacha20-poly1305";
        ser->hashName = "sha256";
        ser->hashed_key_len = 32;
        break;
    }
    }

    strncpy(ser->keyshare, &message[29], 5);

    strncpy(ID_sign, &message[42], 4);
    switch(atoi(ID_sign)) {
    case 401:
        ser->sign_algorithm = "rsa_pkcs1_sha256";
        break;
    
    case 501:
        ser->sign_algorithm = "rsa_pkcs1_sha384";
        break;
    case 601:
        ser->sign_algorithm = "rsa_pkcs1_sha512";
        break;
    }
    
    strncpy(ser->C_hex_key, &message[53], strlen(message) - 53);
}
void create_hello_message(char* hello_message, char* key, char* cert, char* signature){
    strcat(hello_message, "<<KEY>>");
    strcat(hello_message, key);
    strcat(hello_message, "<<CERT>>");
    strcat(hello_message, cert);
    strcat(hello_message, "<<SIGNATURE>>");
    strcat(hello_message, signature);
}


int main(int argc , char *argv[]) {
//---------------------------------------------//
//---------------SERVER CREATION---------------//
//---------------------------------------------//

/*Init server*/
server S;
S.master_key = NULL;
S.func_enc_ptr = &encrypt;
S.func_dec_ptr = &decrypt;
S.func_hash_ptr = &computeHash;
S.func_sign_cert = &signMessage;

S.ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
S.bn_ctx = BN_CTX_new();

//---------------------------------------------//
//------------ESTABLISH CONNECTION-------------//
//---------------------------------------------//
printf("\n*----------------------------------*\n");
printf("*-------Establish connection-------*\n");
printf("*----------------------------------*\n");
int socket_desc , client_sock , c , read_size;
struct sockaddr_in server , client;
//Create socket
socket_desc = socket(AF_INET , SOCK_STREAM , 0);
if (socket_desc == -1)
{
    printf("Could not create socket");
}
printf("Socket created\n");

//Prepare the sockaddr_in structure
server.sin_family = AF_INET;
server.sin_addr.s_addr = INADDR_ANY;
server.sin_port = htons( 8888 );

//Bind
if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
{
    //print the error message
    perror("bind failed. Error");
    return 1;
}
printf("bind done\n");

//Listen
listen(socket_desc , 3);

//Accept and incoming connection
printf("Waiting for incoming connections...\n");
c = sizeof(struct sockaddr_in);

//accept connection from an incoming client
client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
if (client_sock < 0)
{
    perror("accept failed");
    return 1;
}
printf("Connection accepted\n");

//---------------------------------------------//
//--------------START TRANSACTION--------------//
//---------------------------------------------//
printf("\n*----------------------------------*\n");
printf("*---------Start transaction--------*\n");
printf("*----------------------------------*\n");

//Receive a message from client
while( (read_size = recv(client_sock , client_message , BUFF_SIZE, 0)) > 0)
{
    /* Hello message */
    // printf("Received from Client: %s\n", client_message);
    // printf("Message length: %d\n", (int)strlen(client_message));
    parsing_hello_message(client_message, &S);

    printf("Accept Client connection with:\n");
    printf("\t1. Ciphersuite: %s_%s\n", S.cipherName, S.hashName);
    printf("\t2. Key share: %s\n", S.keyshare);
    printf("\t3. Signature algorithm: %s\n", S.sign_algorithm);
    printf("----------------------------------\n");
    const EVP_MD *hashFunc;
    hashFunc = EVP_get_digestbyname(S.hashName);


    printf("Generating Server's Private and Share Keys...");
    S.private_key = create_key();
    if(S.private_key == NULL)
        handleErrors("Error creating client key");
    S.shared_key = EC_KEY_get0_public_key(S.private_key);
    //create hex key for transmitting
    S.hex_key = EC_POINT_point2hex(S.ec_group, S.shared_key, POINT_CONVERSION_UNCOMPRESSED, S.bn_ctx);
    printf("\t***DONE***\n");

    printf("Generating Master Key...");
    //1. Reconstruct Client's shared key
    S.C_shared_key = EC_POINT_hex2point(S.ec_group, S.C_hex_key, NULL, S.bn_ctx);
    //print_key(S.ec_group, S.C_shared_key);
    

    size_t S_master_len;
    S_master_len = compute_key(S.private_key, S.C_shared_key, &S.master_key);
    if (S.master_key == NULL)
            handleErrors("Error creating Master Key");
    printf("\t***GENERATED***\n");
    S.master_key[S_master_len] = '\0';

    EVP_PKEY_CTX* ctx;
    S.hashed_master_key = malloc(sizeof(unsigned char) * S.hashed_key_len); 
    //size_t S_hashed_key_len = cipher_key_len; //this decides the length of key
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if(EVP_PKEY_derive_init(ctx) <= 0)
            return -1;
    if(EVP_PKEY_CTX_set_hkdf_md(ctx, hashFunc) <= 0)
            return -1;
    if(EVP_PKEY_CTX_set1_hkdf_salt(ctx, "salt", 4) <= 0)
            return -1;
    if(EVP_PKEY_CTX_set1_hkdf_key(ctx, S.master_key, S_master_len) <= 0)
            return -1;
    if(EVP_PKEY_derive(ctx, S.hashed_master_key, &S.hashed_key_len) <= 0)
            return -1;
    EVP_PKEY_CTX_free(ctx);
    S.hashed_master_key[S.hashed_key_len] = '\0';
    printf("S key HKDF len: %ldB - %ldbit\n", S.hashed_key_len, S.hashed_key_len*8);
    BIO_dump_fp(stdout, (const char*) S.hashed_master_key, S.hashed_key_len);

    printf("Generating Certificate...\n");
    S.cert = "This is the server's certification message.\nThe Server will sign this then send signature and this cert to the Client\n";
    printf("Certification text: %s", S.cert);
    S.RSA_private_key = privateKey;
    printf("Server Signing...");
    S.signature_len = S.func_sign_cert(hashFunc, S.RSA_private_key, S.cert, &S.signature);
    printf("\t***SIGNED***\n");

    char* hex_key = EC_POINT_point2hex(S.ec_group, S.shared_key, POINT_CONVERSION_UNCOMPRESSED, S.bn_ctx);
    create_hello_message(message, hex_key, S.cert, (char*)S.signature);
    printf("Send to Client: %s\n", message);
    printf("Message length: %d\n", (int)strlen(message));
    write(client_sock , message , strlen(message));
    //memset(client_message, 0, BUFF_SIZE);
}

if(read_size == 0)
{
    printf("Client disconnected\n");
    fflush(stdout);
}
else if(read_size == -1)
{
    perror("recv failed");
}

return 0;
}