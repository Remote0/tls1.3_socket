#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>

#include <arpa/inet.h>	//inet_addr
#include <unistd.h>
#include <string.h>

#define SERVER_PORT  8888
#define WAIT_SEC 30

#define TRUE             1
#define FALSE            0

/*------------------------------*/
#define BUFF_SIZE 1000

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

/* For transmission */ 
char out_message[BUFF_SIZE];
char in_message[BUFF_SIZE];
unsigned char buff_enc[BUFF_SIZE];
size_t buff_enc_length;
unsigned char buff_tag[100];
unsigned char buff_dec[BUFF_SIZE];
size_t buff_dec_length;

/* Handshake */
void parsing_hello_message(char* message, server* S){
    char ID_ciphersuite[3];
    char ID_sign[5];

    parse_message(message,"<<CIPHERSUITE>>","<<KEYSHARE>>", ID_ciphersuite);
    switch(atoi(ID_ciphersuite)) {
    case 1: {
        S->cipherSuite = "aes-128-gcm_sha256";
        S->cipherName = "aes-128-gcm";
        S->hashName = "sha256";
        S->hashed_key_len = 16;
        break;
    }
    case 2: {
        S->cipherSuite = "aes-256-gcm_sha384";
        S->cipherName = "aes-256-gcm";
        S->hashName = "sha384";
        S->hashed_key_len = 32;
        break;
    }
    case 3: {
        S->cipherSuite = "chacha20-poly1305_sha256";
        S->cipherName = "chacha20-poly1305";
        S->hashName = "sha256";
        S->hashed_key_len = 32;
        break;
    }
    }

    // strncpy(S->keyshare, &message[29], 5);
    parse_message(message,"<<KEYSHARE>>","<<SIGN>>", S->keyshare);
    // strncpy(ID_sign, &message[42], 4);
    parse_message(message,"<<SIGN>>","<<KEY>>", ID_sign);
    switch(atoi(ID_sign)) {
    case 401:
        S->sign_algorithm = "rsa_pkcs1_sha256";
        break;
    
    case 501:
        S->sign_algorithm = "rsa_pkcs1_sha384";
        break;
    case 601:
        S->sign_algorithm = "rsa_pkcs1_sha512";
        break;
    }
    
    //strncpy(S->C_hex_key, &message[53], strlen(message) - 53);
    parse_message(message,"<<KEY>>",NULL, S->C_hex_key);
}
void create_hello_message(char* hello_message, server* S){
    strcat(hello_message, "<<KEY>>");
    strcat(hello_message, S->hex_key);
    strcat(hello_message, "<<ENCRYPTED>>");

    //Encrypt signature and certificate
    char plain_signature[BUFF_SIZE] = "<<SIGNATURE>>";
    char* base64_signature;
    Base64Encode(S->signature, S->signature_len, &base64_signature);
    strcat(plain_signature, base64_signature);
    strcat(plain_signature, "<<CERT>>");
    strcat(plain_signature, S->cert);

    //encode cert and signature too base64
    unsigned char enc_signature[BUFF_SIZE]; /* Buffer encrypted signature and certificate */
    int enc_signature_len;
    unsigned char tag[16];
    enc_signature_len = S->func_enc_ptr(S->cipherName,
                                          (unsigned char*) plain_signature, strlen(plain_signature),
                                          S->additional, strlen((char*)S->additional),
                                          S->hashed_master_key,
                                          S->iv, S->iv_len,
                                          enc_signature, tag); /* Encrypt the signature and certificate */
                                        

    char* base64_enc_signature;
    Base64Encode(enc_signature, (size_t)enc_signature_len, &base64_enc_signature);
    strcat(hello_message, "<IV>");
    strcat(hello_message, (char*) S->iv);
    strcat(hello_message, "<TAG>");
    char* base64_tag;
    Base64Encode(tag, 16, &base64_tag);
    strcat(hello_message, (char*) base64_tag);
    strcat(hello_message, "<ADDITIONAL>");
    strcat(hello_message, (char*) S->additional);
    strcat(hello_message, "<SIGNATURE>");
    strcat(hello_message, base64_enc_signature);
}
void parsing_message(const char* message, server* S, unsigned char* plain_text){
    char bs64_tag[100];
    size_t tag_len;
    unsigned char* tag;
    parse_message(message, "<<TAG>>", "<<ENCRYPTED>>", bs64_tag);
    Base64Decode(bs64_tag, &tag, &tag_len);
    
    char bs64_encrypted[BUFF_SIZE];
    size_t encrypted_len;
    unsigned char* encrypted;
    parse_message(message, "<<ENCRYPTED>>", NULL, bs64_encrypted);
    Base64Decode(bs64_encrypted, &encrypted, &encrypted_len);
    
    //unsigned char plain_text[BUFF_SIZE];
    size_t plain_text_length;
    plain_text_length = S->func_dec_ptr( S->cipherName,
                                        encrypted, encrypted_len,
                                        S->additional, strlen((char*)S->additional),
                                        S->hashed_master_key,
                                        tag,
                                        S->iv, S->iv_len,
                                        plain_text);
    plain_text[plain_text_length] = '\0';
    return;
}

/* Transaction */
void create_out_message(char* out_message, server* S, unsigned char* encrypted, int encrypted_len, unsigned char* tag) {
    strcat(out_message, "<<TAG>>");
    char* bs64_tag;
    Base64Encode(tag, 16, &bs64_tag);
    strcat(out_message, bs64_tag);
    strcat(out_message, "<<ENCRYPTED>>");
    char* bs64_encrypted;
    Base64Encode(encrypted, encrypted_len, &bs64_encrypted);
    strcat(out_message, bs64_encrypted);
}

void process_in_message(char* in_message, server* S){
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

    buff_dec_length = S->func_dec_ptr(S->cipherName,
                                    encrypted, encrypted_len,
                                    S->additional, strlen((char*)S->additional),
                                    S->hashed_master_key,
                                    tag,
                                    S->iv, S->iv_len,
                                    buff_dec);
    buff_dec[buff_dec_length] = '\0';

    printf("Received Message: %s\n", (char*)buff_dec);
}

/*------------------------------*/

int main (int argc, char *argv[])
{
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
    S.cert = "This is the server's certification. The Server will sign this then send signature and this cert to the Client";
    S.RSA_private_key = privateKey;

    //---------------------------------------------//
    //---------------Creating socket---------------//
    //---------------------------------------------//
    printf("*----------------------------------*\n");
    printf("*----------Creating socket---------*\n");
    printf("*----------------------------------*\n");
    int    i, len, rc, on = 1;
    int    listen_sd, max_sd, new_sd;
    int    desc_ready, end_server = FALSE;
    int    close_conn;
    char   buffer[80];
    struct sockaddr_in server;
    struct timeval      timeout;
    fd_set              master_set, working_set;

    listen_sd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sd < 0)
    {
        perror("socket() failed");
        exit(-1);
    }

    rc = setsockopt(listen_sd, SOL_SOCKET,  SO_REUSEADDR,
                    (char *)&on, sizeof(on));
    if (rc < 0)
    {
        perror("setsockopt() failed");
        close(listen_sd);
        exit(-1);
    }

    rc = ioctl(listen_sd, FIONBIO, (char *)&on);
    if (rc < 0)
    {
        perror("ioctl() failed");
        close(listen_sd);
        exit(-1);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family      = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port        = htons(SERVER_PORT);
    rc = bind(listen_sd,
                (struct sockaddr *)&server, sizeof(server));
    if (rc < 0)
    {
        perror("bind() failed");
        close(listen_sd);
        exit(-1);
    }
    rc = listen(listen_sd, 32);
    if (rc < 0)
    {
        perror("listen() failed");
        close(listen_sd);
        exit(-1);
    }

    FD_ZERO(&master_set);
    max_sd = listen_sd;
    FD_SET(listen_sd, &master_set);

    /* time out WAIT_SEC seconds*/
    timeout.tv_sec  = WAIT_SEC;
    timeout.tv_usec = 0;

    /* Loop for incomming connect */
    do
    {
        memcpy(&working_set, &master_set, sizeof(master_set));

        /* Call select() and wait for timeout */
        printf("Waiting on select()...\n");
        rc = select(max_sd + 1, &working_set, NULL, NULL, &timeout);
        if (rc < 0)
        {
            perror("  select() failed");
            break;
        }
        /* Check if timeout */
        if (rc == 0)
        {
            printf("  select() timed out.  End program.\n");
            break;
        }

        /**********************************************************/
        /* One or more descriptors are readable.  Need to         */
        /* determine which ones they are.                         */
        /**********************************************************/
        desc_ready = rc;
        for (i=0; i <= max_sd  &&  desc_ready > 0; ++i)
        {
            /*******************************************************/
            /* Check to see if this descriptor is ready            */
            /*******************************************************/
            if (FD_ISSET(i, &working_set))
            {
            desc_ready -= 1;
            if (i == listen_sd)
            {
                printf("  Listening socket is readable\n");
                do
                {
                    new_sd = accept(listen_sd, NULL, NULL);
                    if (new_sd < 0)
                    {
                        if (errno != EWOULDBLOCK)
                        {
                        perror("  accept() failed");
                        end_server = TRUE;
                        }
                        break;
                    }
                    printf("  New incoming connection - %d\n", new_sd);
                    FD_SET(new_sd, &master_set);
                    if (new_sd > max_sd)
                        max_sd = new_sd;
                } while (new_sd != -1);
            }
            else
            {
                printf("  Descriptor %d is readable\n", i);
                printf("Connection accepted\n");
                close_conn = FALSE;

                printf("*----------------------------------*\n");
                printf("*----------Start Handshake---------*\n");
                printf("*----------------------------------*\n");
                /* Receive a message from client */
                rc = recv(i , in_message , BUFF_SIZE, 0);
                if (rc < 0) {
                    if (errno != EWOULDBLOCK)
                    {
                    perror("  recv() failed");
                    close_conn = TRUE;
                    }
                    break;
                }
                if (rc == 0) {
                    printf("  Connection closed\n");
                    close_conn = TRUE;
                    break;
                }                   
                /* Hello message */
                parsing_hello_message(in_message, &S);
                printf("Accept Client connection with:\n");
                printf("\t1. Ciphersuite: %s_%s\n", S.cipherName, S.hashName);
                printf("\t2. Key share: %s\n", S.keyshare);
                printf("\t3. Signature algorithm: %s\n", S.sign_algorithm);
                const EVP_MD *hashFunc;
                hashFunc = EVP_get_digestbyname(S.hashName);

                //printf("Generating Server's Private and Share Keys...");
                S.private_key = create_key();
                if(S.private_key == NULL)
                    handleErrors("Error creating client key");
                S.shared_key = EC_KEY_get0_public_key(S.private_key);
                S.hex_key = EC_POINT_point2hex(S.ec_group, S.shared_key, POINT_CONVERSION_UNCOMPRESSED, S.bn_ctx);
                //printf("\t***DONE***\n");


                //printf("Generating Master Key...");
                //Reconstruct Client's shared key
                S.C_shared_key = EC_POINT_hex2point(S.ec_group, S.C_hex_key, NULL, S.bn_ctx);
                size_t S_master_len;
                S_master_len = compute_key(S.private_key, S.C_shared_key, &S.master_key);
                if (S.master_key == NULL)
                    handleErrors("Error creating Master Key");
                if(hash_key(hashFunc, S.master_key, S_master_len, &S.hashed_master_key, &S.hashed_key_len) < 0) {
                    handleErrors("error generate hashed key\n");
                }
                //printf("\t***GENERATED***\n");
                // printf("HKDF key len: %ldB - %ldbit\n", S.hashed_key_len, S.hashed_key_len*8);
                // BIO_dump_fp(stdout, (const char*) S.hashed_master_key, S.hashed_key_len);

                //printf("Generating Certificate and signing...");
                S.signature_len = S.func_sign_cert(hashFunc, S.RSA_private_key, S.cert, &S.signature);
                //printf("\t***SIGNED***\n");

                /*Create server hello message*/
                S.hex_key = EC_POINT_point2hex(S.ec_group, S.shared_key, POINT_CONVERSION_UNCOMPRESSED, S.bn_ctx);
                memset(out_message, 0, BUFF_SIZE);
                create_hello_message(out_message, &S);
                // printf("hello: %s\n", out_message);
                // printf("hello len: %ld\n", strlen(out_message));
                write(i , out_message , strlen(out_message));

                printf("Hello Message Sent...\n");
                //---------------------------------------------//
                //--------------START TRANSACTION--------------//
                //---------------------------------------------//

                //Process ping request
                int loop = 0;
                memset(in_message, 0, BUFF_SIZE);
                printf("===============Transaction===============\n");
                do
                {
                    // rc = recv(i, buffer, sizeof(buffer), 0);
                    // if (rc < 0)
                    // {
                    //     if (errno != EWOULDBLOCK)
                    //     {
                    //     perror("  recv() failed");
                    //     close_conn = TRUE;
                    //     }
                    //     break;
                    // }
                    // if (rc == 0)
                    // {
                    //     printf("  Connection closed\n");
                    //     close_conn = TRUE;
                    //     break;
                    // }

                    // len = rc;
                    // printf("  %d bytes received\n", len);

                    // /**********************************************/
                    // /* Echo the data back to the client           */
                    // /**********************************************/
                    // rc = send(i, buffer, len, 0);
                    // if (rc < 0)
                    // {
                    //     perror("  send() failed");
                    //     close_conn = TRUE;
                    //     break;
                    // }

                    
                    

                    rc = recv(i , in_message , BUFF_SIZE, 0);
                    
                    if (rc < 0) {
                        if (errno != EWOULDBLOCK)
                        {
                            perror("  recv() failed");
                            close_conn = TRUE;
                        }
                        break;
                    }
                    if (rc == 0) {
                        printf("  Connection closed\n");
                        close_conn = TRUE;
                        break;
                    }    
                    //process_in_message(in_message, &S);
                    printf("Received: %s\n", in_message);

                    unsigned char message[100] = "<<REPLY>>Packet";
                    char packet_num[3];
                    sprintf(packet_num, "%d", loop);
                    strcat((char*)message, packet_num);
                    buff_enc_length = S.func_enc_ptr(S.cipherName,
                                                message, strlen((char*)message),
                                                S.additional, strlen((char*)S.additional),
                                                S.hashed_master_key,
                                                S.iv, S.iv_len,
                                                buff_enc, buff_tag);
                    memset(out_message, 0, BUFF_SIZE);
                    create_out_message(out_message, &S, buff_enc, buff_enc_length, buff_tag);
                    write(i , out_message , strlen(out_message));
                    memset(in_message, 0, BUFF_SIZE);
                    loop = loop + 1;
                    
                    
        
                } while (TRUE);
                printf("==========================================\n");
                if (close_conn)
                {
                    close(i);
                    FD_CLR(i, &master_set);
                    if (i == max_sd)
                    {
                        while (FD_ISSET(max_sd, &master_set) == FALSE)
                        max_sd -= 1;
                    }
                }
            } /* End of existing connection is readable */
            } /* End of if (FD_ISSET(i, &working_set)) */
        } /* End of loop through selectable descriptors */

    } while (end_server == FALSE);

    /*************************************************************/
    /* Clean up all of the sockets that are open                 */
    /*************************************************************/
    for (i=0; i <= max_sd; ++i)
    {
        if (FD_ISSET(i, &master_set))
            close(i);
    }

    return 0;
}