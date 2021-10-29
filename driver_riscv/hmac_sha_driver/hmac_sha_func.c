#include "chacha_poly_func.h"
//Set function
int chacha_poly_set_key(int fd, uint32_t* key){
    #ifdef DEBUG
    printf("Write key to chacha-poly module...\n");
    printf("Set key - 0x%08x%08x%08x%08x\n", *(key), *(key+1), *(key+2), *(key+3));
    printf("Set key - 0x%08x%08x%08x%08x\n", *(key+4), *(key+5), *(key+6), *(key+7));
    #endif //DEBUG

    int ret;
    uint32_t sel = 0;
    ret = write(fd, &sel, 4);
    ret = write(fd, key, 8*4);
    return ret;
}

int chacha_poly_set_nonce(int fd, uint32_t* nonce){
    #ifdef DEBUG
    printf("Write iv to chacha-poly module...\n");
    printf("Set iv - 0x%08x%08x%08x\n", *(nonce), *(nonce+1), *(nonce+2));
    #endif //DEBUG

    int ret;
    uint32_t sel = 1;
    ret = write(fd, &sel, 4);
    ret = write(fd, nonce, 3*4);
    return ret;
}

int chacha_poly_set_input(int fd, uint32_t* input, uint32_t input_len) {
    #ifdef DEBUG
    printf("Write input to chacha-poly module...\n");
    int i;
    for (i = 0; i < input_len; i++)
    {
        printf("input - 0x%08x%08x%08x%08x\n", input[i], input[i+1], input[i+2], input[i+3]);
        i = i + 3;
    }
    printf("input_len: %d\n", input_len);
    #endif //DEBUG
    //input[input_len/4] = input[input_len/4] >> ((input_len%4)*8); 
    int ret;
    uint32_t sel = 2;
    ret = write(fd, &sel, 4);
    ret = write(fd, input, input_len);
    return ret;
}

int chacha_poly_set_aad(int fd, uint32_t* aad) {
    #ifdef DEBUG
    printf("Write aad to chacha-poly module...\n");
    int i;
    for (i = 0; i < 4; i++)
    {
        printf("aad - 0x%08x%08x%08x%08x\n", aad[i], aad[i+1], aad[i+2], aad[i+3]);
        i = i + 3;
    }
    #endif //DEBUG
    
    int ret;
    uint32_t sel = 3;
    ret = write(fd, &sel, 4);
    ret = write(fd, aad, 4*4);
    return ret;
}

int chacha_poly_set_mac(int fd, uint32_t* mac) {
    #ifdef DEBUG
    printf("Write mac to chacha-poly module...\n");
    printf("Set mac - 0x%08x%08x%08x%08x\n", *(mac), *(mac+1), *(mac+2), *(mac+3));
    #endif //DEBUG
    
    int ret;
    uint32_t sel = 4;
    ret = write(fd, &sel, 4);
    ret = write(fd, mac, 4*4);
    return ret;
}

int chacha_poly_start_encrypt(int fd) {
    #ifdef DEBUG
    printf("Start encryption...\n");
    #endif //DEBUG

    int ret;
    uint32_t sel = 5;
    ret = write(fd, &sel, 4);

    return ret;
}

int chacha_poly_start_decrypt(int fd) {
    #ifdef DEBUG
    printf("Start decryption...\n");
    #endif //DEBUG

    int ret;
    uint32_t sel = 6;
    ret = write(fd, &sel, 4);
    return ret;
}


//Start function
int chacha_poly_encrypt(int fd, uint32_t* output, uint32_t* mac, uint32_t* input, uint32_t input_len, uint32_t* key, uint32_t* nonce, uint32_t* aad) {
    int ret;

    //set key
    ret = chacha_poly_set_key(fd, key);
    //set iv
    ret = chacha_poly_set_nonce(fd, nonce);
    //set input
    ret = chacha_poly_set_input(fd, input, input_len);
    //set aad
    ret = chacha_poly_set_aad(fd, aad);
    //do encryption
    ret = chacha_poly_start_encrypt(fd);

    //Read result
    uint32_t sel = 10; //read ready
    ret = write(fd, &sel, 4);
    uint32_t status = 0;
    while(status == 0) {
        ret = read(fd, &status, 4);
    }

    sel = 7; //read output
    ret = write(fd, &sel, 4);
    ret = read(fd, output, input_len);
    

    sel = 8; //read mac
    ret = write(fd, &sel, 4);
    ret = read(fd, mac, 4*4);
    
    return ret;
}

int chacha_poly_decrypt(int fd, uint32_t* output, uint32_t* input, uint32_t input_len, uint32_t* key, uint32_t* nonce, uint32_t* aad, uint32_t* mac) {
    int ret;

    //set key
    ret = chacha_poly_set_key(fd, key);
    //set iv
    ret = chacha_poly_set_nonce(fd, nonce);
    //set input
    ret = chacha_poly_set_input(fd, input, input_len);
    //set aad
    ret = chacha_poly_set_aad(fd, aad);
    //set tag
    ret = chacha_poly_set_mac(fd, mac);
    //do decryption
    ret = chacha_poly_start_decrypt(fd);

    //Read result
    uint32_t sel = 10; //read ready
    ret = write(fd, &sel, 4);
    uint32_t status = 0;
    while(status == 0) {
        ret = read(fd, &status, 4);
    }

    sel = 7; //read output
    ret = write(fd, &sel, 4);
    ret = read(fd, output, input_len);

    int auth = 0;
    sel = 9; //read authentic
    ret = write(fd, &sel, 4);
    ret = read(fd, &auth, 4);

    if(auth < 0)
        printf("Authentication failed\n");
    else
        printf("Authentic result\n");
        

    return ret;
}