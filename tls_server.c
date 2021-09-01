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

typedef struct{
    char* cipherSuite;
    char* cipherName;
    char* hashName;
    char keyshare[5];
    char* sign_algorithm;

    /*Client share key*/
    char C_share_key[130];

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

/* Ciphersuite Selection */
//char* cipherName = NULL;
int cipher_key_len = 0;
//char* hashName = NULL;

char client_message[BUFF_SIZE];


void parsing_hello_message(char* message, server* ser){
    char ID_ciphersuite[3];
    ID_ciphersuite[2] = '\0';
    char ID_keyshare[6];
    ID_keyshare[5] = '\0';
    char ID_sign[5];
    ID_sign[4] = '\0';
    
    //char key[131];
    //key[130] = '\0';
    // strncpy(key, &message[53], strlen(message) - 53);
    // printf("key: %s\n", key);
    // printf("keyshare length: %d\n", (int)strlen(key));

    //*************************//

    strncpy(ID_ciphersuite, &message[15], 2);
    printf("ciphersuite: %s\n", ID_ciphersuite);
    if(strcmp(ID_ciphersuite, "01") == 0){
        ser->cipherSuite = "aes-128-gcm_sha256";
        ser->cipherName = "aes-128-gcm";
        ser->hashName = "sha256";
    }
    else if (strcmp(ID_ciphersuite, "02") == 0) {
        ser->cipherSuite = "aes-256-gcm_sha384";
        ser->cipherName = "aes-256-gcm";
        ser->hashName = "sha384";
    }
    else if(strcmp(ID_ciphersuite, "03") == 0) {
        ser->cipherSuite = "chacha20-poly1305_sha256";
        ser->cipherName = "chacha20-poly1305";
        ser->hashName = "sha256";
    }

    strncpy(ID_keyshare, &message[29], 5);
    strcpy(ser->keyshare, ID_keyshare);
    printf("key share: %s\n", ID_keyshare);


    strncpy(ID_sign, &message[42], 4);
    printf("signature algorithm: %s\n", ID_sign);
    if(strcmp(ID_sign, "0401") == 0)
        ser->sign_algorithm = "rsa_pkcs1_sha256";
    else if(strcmp(ID_sign, "0501") == 0)
        ser->sign_algorithm = "rsa_pkcs1_sha384";
    else if(strcmp(ID_sign, "0601") == 0)
        ser->sign_algorithm = "rsa_pkcs1_sha512";
    
    strncpy(ser->C_share_key, &message[53], strlen(message) - 53);
}


int main(int argc , char *argv[]) {
//---------------------------------------------//
//---------------SERVER CREATION---------------//
//---------------------------------------------//

/*Init server*/
server S;
S.master_key = NULL;
S.jammed_cert = "This is the server's certification message. However it has been jammed\n";
S.func_enc_ptr = &encrypt;
S.func_dec_ptr = &decrypt;
S.func_hash_ptr = &computeHash;
S.func_sign_cert = &signMessage;

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
    printf("Received from Client: %s\n", client_message);
    printf("Message length: %d\n", (int)strlen(client_message));
    parsing_hello_message(client_message, &S);

    printf("Accept Client connection with:\n");
    printf("\t1. Ciphersuite: %s_%s\n", S.cipherName, S.hashName);
    printf("\t2. Key share: %s\n", S.keyshare);
    printf("\t3. Signature algorithm: %s\n", S.sign_algorithm);




    //write(client_sock , client_message , strlen(client_message));
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