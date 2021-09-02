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
#include "crypto/hmac.h"

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
    unsigned char* iv;
    size_t iv_len;
    unsigned char* additional;

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
void create_hello_message(char* hello_message, server* ser){
    strcat(hello_message, "<<KEY>>");
    strcat(hello_message, ser->hex_key);
    strcat(hello_message, "<<ENCRYPTED>>");

    //Encrypt signature and certificate
    char plain_signature[BUFF_SIZE];
    strcat(plain_signature, "<<SIGNATURE>>");
    //encode signature to base64
    char* base64_signature;
    Base64Encode(ser->signature, ser->signature_len, &base64_signature);
    char base64_signature_len[10];
    sprintf(base64_signature_len, "%d", (int)strlen(base64_signature));
    strcat(plain_signature, base64_signature);
    strcat(plain_signature, "<<CERT>>");
    strcat(plain_signature, ser->cert);


    //encode cert and signature too base64
    unsigned char enc_signature[BUFF_SIZE]; /* Buffer encrypted signature and certificate */
    int enc_signature_len;
    unsigned char tag[16];
    enc_signature_len = ser->func_enc_ptr(ser->cipherName,
                                          (unsigned char*) plain_signature, strlen(plain_signature),
                                          ser->additional, strlen((char*)ser->additional),
                                          ser->hashed_master_key,
                                          ser->iv, ser->iv_len,
                                          enc_signature, tag); /* Encrypt the signature and certificate */
    //printf("decode encrypted len: %d\n", enc_signature_len);                                      
    //BIO_dump_fp(stdout,(const char*) enc_signature, enc_signature_len);
    
    char* base64_enc_signature;
    Base64Encode(enc_signature, (size_t)enc_signature_len, &base64_enc_signature);
    // unsigned char* base64_dec_signature;
    // size_t dec_enc_signature_len;
    // Base64Decode(base64_enc_signature, &base64_dec_signature, &dec_enc_signature_len);
    // printf("decode encrypted len: %ld\n", dec_enc_signature_len);
    // BIO_dump_fp(stdout,(const char*) base64_dec_signature, dec_enc_signature_len);

    strcat(hello_message, "<LENGTH>");
    strcat(hello_message, base64_signature_len);
    strcat(hello_message, "<IV>");
    strcat(hello_message, (char*) ser->iv);
    strcat(hello_message, "<TAG>");
    char* base64_tag;
    Base64Encode(tag, 16, &base64_tag);
    strcat(hello_message, (char*) base64_tag);
    strcat(hello_message, "<SIGNATURE>");
    strcat(hello_message, base64_enc_signature);
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
S.iv = (unsigned char*)"0123456789ab"; /* 96 bits IV*/
S.iv_len = 12;
S.additional = (unsigned char*)"KIET-PC";
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
    if(hash_key(hashFunc, S.master_key, S_master_len, &S.hashed_master_key, &S.hashed_key_len) < 0) {
        handleErrors("error generate hashed key\n");
    }
    printf("\t***GENERATED***\n");
    printf("S key HKDF len: %ldB - %ldbit\n", S.hashed_key_len, S.hashed_key_len*8);
    BIO_dump_fp(stdout, (const char*) S.hashed_master_key, S.hashed_key_len);

    printf("Generating Certificate...\n");
    S.cert = "This is the server's certification message.\nThe Server will sign this then send signature and this cert to the Client\n";
    printf("Certification text: %s", S.cert);
    S.RSA_private_key = privateKey;
    printf("Server Signing...");
    S.signature_len = S.func_sign_cert(hashFunc, S.RSA_private_key, S.cert, &S.signature);
    printf("\t***SIGNED***\n");

    /*Create server hello message*/
    S.hex_key = EC_POINT_point2hex(S.ec_group, S.shared_key, POINT_CONVERSION_UNCOMPRESSED, S.bn_ctx);
    create_hello_message(message, &S);

    // printf("Send to Client: %s\n", message);
    // printf("Message length: %d\n", (int)strlen(message));
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