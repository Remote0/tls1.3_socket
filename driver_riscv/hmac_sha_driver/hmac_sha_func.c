#include "hmac_sha_func.h"
//Set function
int hmac_sha_set_key(int fd, uint64_t* key){
    #ifdef DEBUG
    printf("Set key - 0x%lx%lx\n", *(key), *(key+1));
    printf("Set key - 0x%lx%lx\n", *(key+2), *(key+3));
    printf("Set key - 0x%lx%lx\n", *(key+4), *(key+5));
    printf("Set key - 0x%lx%lx\n", *(key+6), *(key+7));
    #endif //DEBUG

    int ret;
    uint32_t sel = 0;
    ret = write(fd, &sel, 4);
    ret = write(fd, key, 8*8);
    return ret;
}

int hmac_sha_set_input(int fd, uint64_t* input, uint32_t input_len) {
    #ifdef DEBUG
    int i;
    printf("Write input to hmac-sha module...\n");
    for(i=0; i<16; i=i+2){
        printf("Set input - 0x%lx%lx\n", input[i], input[i+1]);
    }
    printf("input_len: %d\n", input_len);
    #endif //DEBUG

    //input[input_len/4] = input[input_len/4] >> ((input_len%4)*8); 
    int ret;
    uint32_t sel = 1;
    ret = write(fd, &sel, 4);
    ret = write(fd, input, input_len);
    return ret;
}

int hmac_sha_set_mode(int fd, uint32_t mode, uint32_t submode){
    int ret;
    uint32_t sel;
    if(mode == SHA){
        sel = 2;
        ret = write(fd, &sel, 4);
    }

    if(mode == HMAC){
        sel = 3;
        ret = write(fd, &sel, 4);
    }

    switch (submode)
    {
    case SHA512:
        sel = 4;
        ret = write(fd, &sel, 4);
        break;
    case SHA384:
        sel = 5;
        ret = write(fd, &sel, 4);
        break;
    case SHA256:
        sel = 6;
        ret = write(fd, &sel, 4);
        break;
    }

    return ret;
}

int hmac_sha_start(int fd) {
    #ifdef DEBUG
    printf("Start hashing...\n");
    #endif //DEBUG

    int ret;
    uint32_t sel = 7;
    ret = write(fd, &sel, 4);

    return ret;
}


//Start function
int hmac_sha_hashing(int fd, uint32_t* mac, uint64_t* input, uint32_t input_len, uint64_t* key, uint32_t mode, uint32_t submode) {
    int ret;

    //set key
    ret = hmac_sha_set_key(fd, key);
    //set input
    ret = hmac_sha_set_input(fd, input, input_len);
    //set mode
    ret = hmac_sha_set_mode(fd, mode, submode);
    ret = hmac_sha_start(fd);
    
    //Read ready
    uint32_t sel = 9;
    ret = write(fd, &sel, 4);
    uint32_t status = 0;
    while(status == 0) {
        ret = read(fd, &status, 4);
    }

    sel = 8; //read mac
    ret = write(fd, &sel, 4);
    switch (submode)
    {
    case SHA512:
        ret = read(fd, mac, 64);
        break;
    case SHA384:
        ret = read(fd, mac, 48);
        break;
    case SHA256:
        ret = read(fd, mac, 32);
        break;
    }

    return ret;
}
