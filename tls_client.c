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
    int (*func_enc_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, int, unsigned char*, unsigned char*);
    int (*func_dec_ptr)(char*, unsigned char*, int, unsigned char*, int, unsigned char*, unsigned char*, unsigned char*, int, unsigned char*);
    int (*func_hash_ptr)(char*, char*, unsigned char*);
    int (*func_verf_cert)(const EVP_MD*, char*, char*, unsigned char*, size_t);

    /* Utility*/
    EC_GROUP *ec_group;
    BN_CTX *bn_ctx;
    unsigned char* iv;
    const EVP_MD *hashFunc;
    unsigned char* tag;
    unsigned char additional[30];
    unsigned char* enc_signature;
    size_t enc_signature_len;

}client;

/* For transmission */ 
char out_message[BUFF_SIZE];
char in_message[BUFF_SIZE];
unsigned char buff_dec[BUFF_SIZE];
size_t buff_dec_length;


/* Handshake */
void create_hello_message(char* hello_message, client* C) {
    strcat(hello_message, "<<CIPHERSUITE>>");
    if((strcmp(C->cipherName,"aes-128-gcm") == 0) & (strcmp(C->hashName,"sha256") == 0))
        strcat(hello_message, "01");
    else if((strcmp(C->cipherName,"aes-256-gcm") == 0) & (strcmp(C->hashName,"sha384") == 0))
        strcat(hello_message, "02");
    else if((strcmp(C->cipherName,"chacha20-poly1305") == 0) & (strcmp(C->hashName,"sha256") == 0))
        strcat(hello_message, "03");
    
    //using ECDHE
    strcat(hello_message, "<<KEYSHARE>>");
    strcat(hello_message, C->key_share);

    //using RSASSA-PKCS1-v1_5
    strcat(hello_message, "<<SIGN>>");
    if(strcmp(C->hashName,"sha256") == 0)
        strcat(hello_message, "0401");
    else if(strcmp(C->hashName,"sha384") == 0)
        strcat(hello_message, "0501");
    else if(strcmp(C->hashName,"sha512") == 0)
        strcat(hello_message, "0601");

    strcat(hello_message, "<<KEY>>");
    char* hex_key;
    hex_key = EC_POINT_point2hex(C->ec_group, C->shared_key, POINT_CONVERSION_UNCOMPRESSED, C->bn_ctx);
    strcat(hello_message, hex_key);
    return;
}

void parsing_hello_message(char* message, client* C){
    char S_hex_key[130];
    parse_message(message,"<<KEY>>","<<ENCRYPTED>>", S_hex_key);
    // Reconstruct Server's shared key
    C->S_shared_key = EC_POINT_hex2point(C->ec_group, S_hex_key, NULL, C->bn_ctx);

    parse_message(message,"<IV>","<TAG>",(char*)C->iv);

    char bs64_tag[30];
    size_t bs64_tag_len;
    parse_message(message,"<TAG>","<ADDITIONAL>",bs64_tag);
    Base64Decode(bs64_tag, &(C->tag), &bs64_tag_len);

    parse_message(message,"<ADDITIONAL>","<SIGNATURE>",(char*)C->additional);

    char bs64_enc_signature[BUFF_SIZE];
    parse_message(message,"<SIGNATURE>",NULL,bs64_enc_signature);
    Base64Decode(bs64_enc_signature, &C->enc_signature, &C->enc_signature_len);
};

int verify(const char* plain_signature, client* C) {
    char bs64_signature[BUFF_SIZE];
    parse_message(plain_signature,"<<SIGNATURE>>","<<CERT>>",bs64_signature);
    unsigned char* signature;
    size_t signature_len;
    Base64Decode(bs64_signature, &signature, &signature_len);
    //BIO_dump_fp(stdout, (const char*)signature, signature_len);

    char certification[BUFF_SIZE];
    parse_message(plain_signature,"<<CERT>>",NULL,certification);
    C->RSA_public_key = publicKey;
    printf("Verifying signature...");
    int authentic = C->func_verf_cert(C->hashFunc, C->RSA_public_key, certification, signature, signature_len);
    return authentic;
}

/* Transaction */
void create_out_message(char* out_message, client* C, unsigned char* encrypted, int encrypted_len, unsigned char* tag) {
    strcat(out_message, "<<TAG>>");
    char* bs64_tag;
    Base64Encode(tag, 16, &bs64_tag);
    strcat(out_message, bs64_tag);
    strcat(out_message, "<<ENCRYPTED>>");
    char* bs64_encrypted;
    Base64Encode(encrypted, encrypted_len, &bs64_encrypted);
    strcat(out_message, bs64_encrypted);
}

void process_in_message(char* in_message, client* C){
    char bs64_tag[16];
    char bs64_encrypted[100];
    unsigned char* tag;
    size_t tag_len;
    unsigned char* encrypted;
    size_t encrypted_len;

    parse_message(in_message,"<<TAG>>", "<<ENCRYPTED>>", bs64_tag);
    parse_message(in_message,"<<ENCRYPTED>>", NULL , bs64_encrypted);
    Base64Decode(bs64_tag, &tag, &tag_len);
    Base64Decode(bs64_encrypted, &encrypted, &encrypted_len);

    buff_dec_length = C->func_dec_ptr( C->cipherName,
                                    encrypted, encrypted_len,
                                    C->additional, strlen((char*)C->additional),
                                    C->hashed_master_key,
                                    tag,
                                    C->iv, 12,
                                    buff_dec);
    buff_dec[buff_dec_length] = '\0';
}

int main(int argc , char *argv[]) {
//---------------------------------------------//
//---------------CLIENT CREATION---------------//
//---------------------------------------------//

/* Choosing ciphersuite and hash */
client C;
C.master_key = NULL;
C.func_enc_ptr = &encrypt;
C.func_dec_ptr = &decrypt;
C.func_hash_ptr = &computeHash;
C.func_verf_cert = &verifySignature;
C.RSA_public_key = publicKey;

// Utility
C.ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
C.bn_ctx = BN_CTX_new();
C.iv = (unsigned char*)malloc(sizeof(char)*12); //96bits

C.cipherSuite[0] = "aes-128-gcm_sha256";
C.cipherSuite[1] = "aes-256-gcm_sha384";
C.cipherSuite[2] = "chacha20-poly1305_sha256";
C.key_share = "ECDHE";
C.sign_algorithm = "RSASSA-PCKS1-v1_5";

int i;

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
            C.hashFunc = EVP_get_digestbyname(C.hashName);
            break;
    }
}

if((C.cipherName == NULL) | (C.hashName == NULL))
    handleErrors("Error selecting Cipher");

// /* 1. List of cipher suites */
// printf("1. List of available Ciphersuite:\n");

// for(i = 0; i < 3; i = i + 1)
//     printf("\t- %s\n", C.cipherSuite[i]);
// /* 2. Key share extension */
// printf("2. Key share extension:\n");
// printf("\t- ECDHE\n");

// /* 3. Signature algorithms extension */
// printf("3. Signature algorithms extension:\n");
// printf("\t- RSASSA-PCKS1-v1_5\n");


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
//--------------Start Handshake--------------//
//---------------------------------------------//
printf("*----------------------------------*\n");
printf("*---------Start Handshake--------*\n");
printf("*----------------------------------*\n");

/* Prepare for Client Hello */
//printf("Generating Client's Private and Share Keys...");
C.private_key = create_key();
if(C.private_key == NULL)
    handleErrors("Error creating client key");
C.shared_key = EC_KEY_get0_public_key(C.private_key);
//printf("\t***DONE***\n");

printf("Creating Client Hello message with prefer selection:\n");
printf("\t1. Ciphersuite: %s_%s\n", C.cipherName, C.hashName);
printf("\t2. Key share: %s\n", C.key_share);
printf("\t3. Signature algorithm: %s\n", C.sign_algorithm);

create_hello_message(out_message, &C);
if( send(sock , out_message , strlen(out_message) , 0) < 0)
{
    printf("Send failed\n");
    return 1;
}
printf("Hello Message sent & waiting for Server Hello Message...\n");

// Waiting for Server Hello Message
if( recv(sock , in_message , BUFF_SIZE , 0) < 0)
{
    printf("recv failed\n");
    return 1;
}
parsing_hello_message(in_message, &C);

/* Generating Master Key*/
//printf("Generating Master Key...");
size_t C_master_len;
C_master_len = compute_key(C.private_key, C.S_shared_key, &C.master_key);
if (C.master_key == NULL)
        handleErrors("Error creating Master Key");
if(hash_key(C.hashFunc, C.master_key, C_master_len, &C.hashed_master_key, &C.hashed_key_len) < 0) {
    handleErrors("error generate hashed key\n");
}
//printf("\t***GENERATED***\n");
// printf("HKDF key len: %ldB - %ldbit\n", C.hashed_key_len, C.hashed_key_len*8);
// BIO_dump_fp(stdout, (const char*) C.hashed_master_key, C.hashed_key_len);

/* Verify Server Authentication */
buff_dec_length = C.func_dec_ptr( C.cipherName,
                                        C.enc_signature, C.enc_signature_len,
                                        C.additional, strlen((char*)C.additional),
                                        C.hashed_master_key,
                                        C.tag,
                                        C.iv, 12,
                                        buff_dec);
buff_dec[buff_dec_length] = '\0';
if(verify((char*)buff_dec, &C)){
    printf("\t***AUTHENTIC***\n");
    printf("Connection ACCEPTED\n");
}else{
    printf("***VERIFY FAILED***\n");
    printf("Abort Connection\n");
    close(sock);
}

printf("\n==============Ping to Server==============\n");
/* Request time to Server */
struct timespec time_start, time_end, tfe, tfs;
long double rtt_msec=0, total_msec=0;
double timeElapsed;
int loop_cnt = 6;
i = 0;
memset(out_message, 0, BUFF_SIZE);
strcat(out_message, "<<MESSAGE>>PingRequest");
clock_gettime(CLOCK_MONOTONIC, &tfs);

while(i < loop_cnt){
    int rc;
    memset(in_message, 0, BUFF_SIZE);
    memset(buff_dec, 0, BUFF_SIZE);
    /* Mark time here*/
    clock_gettime(CLOCK_MONOTONIC, &time_start);

    // Send request message
    if( send(sock , out_message , strlen(out_message) , 0) < 0)
    {
        printf("Send failed\n");
        close(sock);
        return 1;
    }
    // printf("send: %d\n", rc);
    
    // Receive a reply from the server
    rc = recv(sock , in_message , BUFF_SIZE , 0);
    if( rc < 0)
    {
        printf("recv failed\n");
        return 1;
    }
    // printf("received: %d\n", rc);
    
    /* Mark time here*/
    clock_gettime(CLOCK_MONOTONIC, &time_end);
    timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
    rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

    process_in_message(in_message, &C);
    //printf("received message: %s\n", in_message);
    printf("%ld bytes from local host (127.0.0.1)\n\t\t\t msg_seq=%d   rtt= %Lf ms.\n", strlen((char*)buff_dec),i+1, rtt_msec);
    i = i + 1;

    if(i == loop_cnt){
        char ch;
        printf("Continue(y/n)?: ");
        
        //scanf("%s", sel);
       
        ch = getchar();
        while((getchar()) != '\n');
        if(strcmp(&ch, "y") == 0) {
            i = 0;
            //strcpy(&ch, "");
        }
        else
            break;
    }
}
clock_gettime(CLOCK_MONOTONIC, &tfe);
timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;
total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;
printf("=========127.0.0.1 ping statistics=========\n");
printf("\n%d packets sent, %d packets received, %f percent packet loss.\nTotal time: %Lf ms.\n\n", loop_cnt, i, ((loop_cnt - i)/loop_cnt)*100.0, total_msec);
close(sock);
return 0;
}