/*
	C ECHO client example using sockets
*/

#define BUFF_SIZE 2000

#include <stdio.h>	//printf
#include <stdlib.h>
#include <string.h>	//strlen
#include <sys/socket.h>	//socket
#include <arpa/inet.h>	//inet_addr
#include <unistd.h>

/* OPENSSL */
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/kdf.h>
#include "crypto/ECDH.h"
#include "crypto/sha.h"
#include "crypto/rsa.h"
#include "crypto/AEAD.h"
#include "crypto/ult.h"

typedef struct {
    char* cipherSuite[3];
    char* key_share;
    char* sign_algorithm;
    /*Key Exchange*/
    const EC_KEY* private_key;
    const EC_POINT* shared_key;
    unsigned char* master_key;
    unsigned char* hashed_master_key;
    /*Cert Verification*/
    char* RSA_public_key;

    /*Functions -- later on change these function to test hardware*/
    int (*func_dec_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, unsigned char*, int, unsigned char*);
    int (*func_hash_ptr)(char*, char*, unsigned char*);
    int (*func_verf_cert)(const EVP_MD*, char*, char*, unsigned char*, size_t);

    /* Utility*/
    EC_GROUP *ec_group;
    BN_CTX *bn_ctx;
}client;

/* Ciphersuite Selection */
char* cipherName = NULL;
int cipher_key_len = 0;
char* hashName = NULL;

/* For transmission */ 
char message[1000];
char server_reply[BUFF_SIZE];



void create_hello_message(char* hello_message, char* cipher, char* hash, char* key_gen, char* sign_algorithm, char* hex_key) {
    strcat(hello_message, "<<CIPHERSUITE>>");
    if((strcmp(cipher,"aes-128-gcm") == 0) & (strcmp(hash,"sha256") == 0))
        strcat(hello_message, "01");
    else if((strcmp(cipher,"aes-256-gcm") == 0) & (strcmp(hash,"sha384") == 0))
        strcat(hello_message, "02");
    else if((strcmp(cipher,"chacha20-poly1305") == 0) & (strcmp(hash,"sha256") == 0))
        strcat(hello_message, "03");
    
    //using ECDHE
    strcat(hello_message, "<<KEYSHARE>>");
    strcat(hello_message, key_gen);

    //using RSASSA-PKCS1-v1_5
    strcat(hello_message, "<<SIGN>>");
    if(strcmp(hash,"sha256") == 0)
        strcat(hello_message, "0401");
    else if(strcmp(hash,"sha384") == 0)
        strcat(hello_message, "0501");
    else if(strcmp(hash,"sha512") == 0)
        strcat(hello_message, "0601");

    strcat(hello_message, "<<KEY>>");
    strcat(hello_message, hex_key);
    printf("keyshare length: %d\n", (int)strlen(hex_key));
    return;
}


int main(int argc , char *argv[]) {
//---------------------------------------------//
//---------------CLIENT CREATION---------------//
//---------------------------------------------//

/* Choosing ciphersuite and hash */
client C;
C.master_key = NULL;
C.func_dec_ptr = &decrypt;
C.func_hash_ptr = &computeHash;
C.func_verf_cert = &verifySignature;

C.ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
C.bn_ctx = BN_CTX_new();

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

if((cipherName == NULL) | (hashName == NULL))
    handleErrors("Error selecting Cipher");

/* 1. List of cipher suites */
printf("1. List of available Ciphersuite:\n");
C.cipherSuite[0] = "aes-128-gcm_sha256";
C.cipherSuite[1] = "aes-256-gcm_sha384";
C.cipherSuite[2] = "chacha20-poly1305_sha384";
int i;
for(i = 0; i < 3; i = i + 1)
    printf("\t- %s\n", C.cipherSuite[i]);
/* 2. Key share extension */
printf("2. Key share extension:\n");
printf("\t- ECDHE\n");
C.key_share = "ECDHE";
/* 3. Signature algorithms extension */
printf("3. Signature algorithms extension:\n");
printf("\t- RSASSA-PCKS1-v1_5\n");
C.sign_algorithm = "RSASSA-PCKS1-v1_5";

//Choose hash function based on input
const EVP_MD *hashFunc;
hashFunc = EVP_get_digestbyname(hashName);


//---------------------------------------------//
//------------ESTABLISH CONNECTION-------------//
//---------------------------------------------//
printf("\n*----------------------------------*\n");
printf("*--Establish connection to server--*\n");
printf("*----------------------------------*\n");
int sock;
struct sockaddr_in server;

//Create socket
sock = socket(AF_INET , SOCK_STREAM , 0);
if (sock == -1)
{
    printf("Could not create socket\n");
}
printf("Socket created\n");

server.sin_addr.s_addr = inet_addr("127.0.0.1");
server.sin_family = AF_INET;
server.sin_port = htons( 8888 );

//Connect to remote server
if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
{
    perror("connect failed. Error");
    return 1;
}

printf("Connected to server\n");

//---------------------------------------------//
//--------------START TRANSACTION--------------//
//---------------------------------------------//

printf("\n*----------------------------------*\n");
printf("*---------Start transaction--------*\n");
printf("*----------------------------------*\n");

/* Prepare for Client Hello */
printf("Generating Client's Private and Share Keys...");
C.private_key = create_key();
if(C.private_key == NULL)
    handleErrors("Error creating client key");
C.shared_key = EC_KEY_get0_public_key(C.private_key);
printf("\t***DONE***\n");

printf("Creating Client Hello message with prefer selection:\n");
printf("\t1. Ciphersuite: %s_%s\n", cipherName, hashName);
printf("\t2. Key share: %s\n", C.key_share);
printf("\t3. Signature algorithm: %s\n", C.sign_algorithm);

/* Creating Hello Message */

char* hex_key = EC_POINT_point2hex(C.ec_group, C.shared_key, POINT_CONVERSION_UNCOMPRESSED, C.bn_ctx);
//printf("hex_key length: %d\n", (int)strlen(hex_key));
create_hello_message(message, cipherName, hashName, C.key_share, C.sign_algorithm, hex_key);
printf("Client Hello message: %s\n", message);
printf("Hello message length: %d\n", (int)strlen(message));
//print_key(C.ec_group, C.shared_key);


//Send hello message
if( send(sock , message , strlen(message) , 0) < 0)
{
    printf("Send failed\n");
    return 1;
}


//Receive a reply from the server
if( recv(sock , server_reply , BUFF_SIZE , 0) < 0)
{
    printf("recv failed\n");
    return 1;
}
printf("Server reply: %s\n", server_reply);
printf("Message length: %d\n", (int)strlen(server_reply));
//memset(server_reply, 0, BUFF_SIZE);

close(sock);




return 0;
}