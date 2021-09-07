/*
	C ECHO client example using sockets
*/

#define BUFF_SIZE 1000

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
#include "crypto/hmac.h"

typedef struct {
    char* cipherSuite[3];
    char* key_share;
    char* sign_algorithm;
    char* cipherName;
    char* hashName;

    /*Client share key*/
    EC_POINT* S_shared_key;

    /*Key Exchange*/
    const EC_KEY* private_key;
    const EC_POINT* shared_key;
    
    unsigned char* master_key;
    unsigned char* hashed_master_key;
    size_t hashed_key_len;
    /*Cert Verification*/
    char* RSA_public_key;

    /*Functions -- later on change these function to test hardware*/
    int (*func_dec_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, unsigned char*, int, unsigned char*);
    int (*func_hash_ptr)(char*, char*, unsigned char*);
    int (*func_verf_cert)(const EVP_MD*, char*, char*, unsigned char*, size_t);

    /* Utility*/
    EC_GROUP *ec_group;
    BN_CTX *bn_ctx;
    unsigned char* iv;
    const EVP_MD *hashFunc;
    unsigned char* tag;
    size_t tag_len;
    unsigned char additional[30];
    unsigned char* enc_signature;
    size_t enc_signature_len;

}client;

/* Ciphersuite Selection */


/* For transmission */ 
char message[1000];
char server_hello[BUFF_SIZE];



void create_hello_message(char* hello_message, client* clnt) {
    strcat(hello_message, "<<CIPHERSUITE>>");
    if((strcmp(clnt->cipherName,"aes-128-gcm") == 0) & (strcmp(clnt->hashName,"sha256") == 0))
        strcat(hello_message, "01");
    else if((strcmp(clnt->cipherName,"aes-256-gcm") == 0) & (strcmp(clnt->hashName,"sha384") == 0))
        strcat(hello_message, "02");
    else if((strcmp(clnt->cipherName,"chacha20-poly1305") == 0) & (strcmp(clnt->hashName,"sha256") == 0))
        strcat(hello_message, "03");
    
    //using ECDHE
    strcat(hello_message, "<<KEYSHARE>>");
    strcat(hello_message, clnt->key_share);

    //using RSASSA-PKCS1-v1_5
    strcat(hello_message, "<<SIGN>>");
    if(strcmp(clnt->hashName,"sha256") == 0)
        strcat(hello_message, "0401");
    else if(strcmp(clnt->hashName,"sha384") == 0)
        strcat(hello_message, "0501");
    else if(strcmp(clnt->hashName,"sha512") == 0)
        strcat(hello_message, "0601");

    strcat(hello_message, "<<KEY>>");
    char* hex_key;
    hex_key = EC_POINT_point2hex(clnt->ec_group, clnt->shared_key, POINT_CONVERSION_UNCOMPRESSED, clnt->bn_ctx);
    strcat(hello_message, hex_key);
    //printf("keyshare length: %d\n", (int)strlen(hex_key));
    return;
}
void parsing_hello_message(char* message, client* clnt){
    char S_hex_key[130];
    parse_message(message,"<<KEY>>","<<ENCRYPTED>>", S_hex_key);
    // printf("Server hex key: %s\n", S_hex_key);
    // printf("Server hex key length: %ld\n", strlen(S_hex_key));
    // Reconstruct Server's shared key
    clnt->S_shared_key = EC_POINT_hex2point(clnt->ec_group, S_hex_key, NULL, clnt->bn_ctx);
    //print_key(clnt->ec_group, clnt->S_shared_key);
    

    parse_message(message,"<IV>","<TAG>",(char*)clnt->iv);
    // printf("Server iv: %s\n", (char*)clnt->iv);
    // printf("Server iv length: %ld\n", strlen((char*)clnt->iv));

    char base64_tag[30];
    parse_message(message,"<TAG>","<ADDITIONAL>",base64_tag);
    // printf("Server bs64 tag: %s\n", base64_tag);
    // printf("Server bs64 tag length: %ld\n", strlen(base64_tag));
    Base64Decode(base64_tag, &(clnt->tag), &clnt->tag_len);

    parse_message(message,"<ADDITIONAL>","<SIGNATURE>",(char*)clnt->additional);
    // printf("Server additional: %s\n", (char*)clnt->additional);
    // printf("Server additional length: %ld\n", strlen((char*)clnt->additional));

    char bs64_enc_signature[BUFF_SIZE];
    parse_message(message,"<SIGNATURE>",NULL,bs64_enc_signature);
    Base64Decode(bs64_enc_signature, &clnt->enc_signature, &clnt->enc_signature_len);

    // printf("Server enc_signature: %s\n",clnt->enc_signature);
    // printf("Server enc_signature length: %ld\n", strlen(clnt->enc_signature));
};
void verify(const char* plain_signature, client* clnt) {
    char bs64_signature[BUFF_SIZE];
    parse_message(plain_signature,"<<SIGNATURE>>","<<CERT>>",bs64_signature);
    //printf("Server bs64_signature: %s\n",bs64_signature);
    //printf("Server bs64_signature length: %ld\n", strlen(bs64_signature));
    unsigned char* signature;
    size_t signature_len;
    Base64Decode(bs64_signature, &signature, &signature_len);

    char certification[BUFF_SIZE];
    parse_message(plain_signature,"<<CERT>>",NULL,certification);
    // printf("Server certification: %s\n",certification);
    // printf("Server certification length: %ld\n", strlen(certification));

    printf("\n------CLIENT VERIFY------\n");
    clnt->RSA_public_key = publicKey;
    printf("Client verifying...");
    int authentic = clnt->func_verf_cert(clnt->hashFunc, clnt->RSA_public_key, certification, signature, signature_len);
    if ( authentic ) {
            printf("\t***AUTHENTIC***\n");
    } else {
            printf("***VERIFY FAILED***\n");
    }
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
C.RSA_public_key = publicKey;

C.ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
C.bn_ctx = BN_CTX_new();

C.iv = (unsigned char*)malloc(sizeof(char)*12); //96bits


int opt;
if(argc == 1)
    handleErrors("Require selecting cipherName and hashName");
while((opt = getopt(argc, argv, "c:h:")) != -1) {
    switch(opt) {
        case 'c':
            C.cipherName = optarg;
            if(!strcmp(C.cipherName, "aes-128-gcm"))
                    C.hashed_key_len = 16;
            else if((!strcmp(C.cipherName, "aes-256-gcm")) | (!strcmp(C.cipherName, "chacha20-poly1305")))
                    C.hashed_key_len = 32;
            break;
        case 'h':
            C.hashName = optarg;
            break;
    }
}

if((C.cipherName == NULL) | (C.hashName == NULL))
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
C.hashFunc = EVP_get_digestbyname(C.hashName);


//---------------------------------------------//
//------------SOCKET CONNECTION-------------//
//---------------------------------------------//
printf("\n*----------------------------------*\n");
printf("*----------Connect to server-------*\n");
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
printf("\t1. Ciphersuite: %s_%s\n", C.cipherName, C.hashName);
printf("\t2. Key share: %s\n", C.key_share);
printf("\t3. Signature algorithm: %s\n", C.sign_algorithm);

/* Creating Hello Message */


create_hello_message(message, &C);
// printf("Client Hello message: %s\n", message);
// printf("Hello message length: %d\n", (int)strlen(message));
//print_key(C.ec_group, C.shared_key);
//Send hello message
if( send(sock , message , strlen(message) , 0) < 0)
{
    printf("Send failed\n");
    return 1;
}
printf("Hello Message Sent...\n");
printf("----------------------------------\n");
//Receive a reply from the server
if( recv(sock , server_hello , BUFF_SIZE , 0) < 0)
{
    printf("recv failed\n");
    return 1;
}


printf("ACCEPTED communication to Server\n");
// printf("Server reply: %s\n", server_hello);
// printf("Message length: %d\n", (int)strlen(server_hello));

parsing_hello_message(server_hello, &C);

/* Generating Master Key*/
 printf("Generating Master Key...");

size_t C_master_len;
C_master_len = compute_key(C.private_key, C.S_shared_key, &C.master_key);
if (C.master_key == NULL)
        handleErrors("Error creating Master Key");
if(hash_key(C.hashFunc, C.master_key, C_master_len, &C.hashed_master_key, &C.hashed_key_len) < 0) {
    handleErrors("error generate hashed key\n");
}
printf("\t***GENERATED***\n");
//printf("S key HKDF len: %ldB - %ldbit\n", C.hashed_key_len, C.hashed_key_len*8);
//BIO_dump_fp(stdout, (const char*) C.hashed_master_key, C.hashed_key_len);


/* Verify Server Authentication */
unsigned char plain_signature[BUFF_SIZE];
size_t plain_signature_len;
plain_signature_len = C.func_dec_ptr( C.cipherName,
                            C.enc_signature, C.enc_signature_len,
                            C.additional, strlen((char*)C.additional),
                            C.hashed_master_key,
                            C.tag,
                            C.iv, 12,
                            plain_signature);

printf("dec_signature len: %ld\n", plain_signature_len);
// plain_signature[plain_signature_len] = '\0';                       
// printf("dec_signature: %s\n", plain_signature);

verify((char*)plain_signature, &C);
printf("??????????????\n");
//BIO_dump_fp(stdout, (const char*) dec_signature, dec_signature_len);

// //memset(server_hello, 0, BUFF_SIZE);

close(sock);




return 0;
}