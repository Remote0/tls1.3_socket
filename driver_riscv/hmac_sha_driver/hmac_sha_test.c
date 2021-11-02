#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "hmac_sha_func.h"

// #define BUFFER_LENGTH 4
// static char receive[BUFFER_LENGTH]; //32b-reg


uint64_t msg[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // multiple of msg - process 1024bit each time
uint64_t key[8] = {1, 2, 3, 4, 5, 6, 7, 8}; //512bit - before padding

uint64_t msg384[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint64_t key384[8] = {1, 2, 3, 4, 5, 6, 7, 8};

uint64_t msg256[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint64_t key256[8] = {1, 2, 3, 4, 5, 6, 7, 8};

uint32_t mac[16];

int main(){
    int ret, fd;
    int i;
    printf("Starting hmac-sha test code example...\n");
    fd = open("/dev/hmac-sha", O_RDWR); //Open the device with read/write access
    if(fd < 0){
        printf("Error(%d): ", fd);
        perror("Failed to open the module...");
        return errno;
    }

    //hmac sha 512
    printf("HMAC SHA512 start test\n");
    ret = hmac_sha_hashing(fd, mac, msg, /*bytes*/128, key, HMAC, SHA512);
    if(ret<0){
        perror("Failed hashing");
        return errno;
    }
    printf("result:\n");
    for (i = 0; i < 16; i=i+2)
    {
        printf("hmac-sha512: (%d)- 0x%08x%08x\n", i, mac[i], mac[i+1]);
    }

    //hmac sha 384
    printf("HMAC SHA384 start test\n");
    ret = hmac_sha_hashing(fd, mac, msg384, /*bytes*/128, key384, HMAC, SHA384);
    if(ret<0){
        perror("Failed hashing");
        return errno;
    }
    printf("result:\n");
    for (i = 0; i < 12; i=i+2)
    {
        printf("hmac-sha384: (%d)- 0x%08x%08x\n", i, mac[i], mac[i+1]);
    }

    //hmac sha 256
    printf("HMAC SHA256 start test\n");
    ret = hmac_sha_hashing(fd, mac, msg256, /*bytes*/128, key256, HMAC, SHA256);
    if(ret<0){
        perror("Failed hashing");
        return errno;
    }
    printf("result:\n");
    for (i = 0; i < 8; i=i+2)
    {
        printf("hmac-sha256: (%d)- 0x%08x%08x\n", i, mac[i], mac[i+1]);
    }

    printf("End of the program\n");
    return 0;
}