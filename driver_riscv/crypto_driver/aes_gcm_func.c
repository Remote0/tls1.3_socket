#include "aes_gcm_func.h"


int aes_gcm_set_key(int fd, uint32_t* key, uint32_t key_len) {
    #ifdef DEBUG
    printf("Write key to aes-gcm module...\n");
    printf("Set key - 0x%08x%08x%08x%08x\n", *(key), *(key+1), *(key+2), *(key+3));
    printf("Set key - 0x%08x%08x%08x%08x\n", *(key+4), *(key+5), *(key+6), *(key+7));
    printf("key_len: %d\n", key_len);
    #endif //DEBUG

    int ret;
    uint32_t sel = 0;
    ret = write(fd, &sel, 4);
    ret = write(fd, key, key_len*4);
    return ret;
}

int aes_gcm_set_iv(int fd, uint32_t* iv) {
    #ifdef DEBUG
    printf("Write iv to aes-gcm module...\n");
    printf("Set iv - 0x%08x%08x%08x\n", *(iv), *(iv+1), *(iv+2));
    #endif //DEBUG

    int ret;
    uint32_t sel = 1;
    ret = write(fd, &sel, 4);
    ret = write(fd, iv, 3*4);
    return ret;
}

int aes_gcm_set_input(int fd, uint32_t* input, uint32_t input_len) {
    #ifdef DEBUG
    printf("Write input to aes-gcm module...\n");
    int i;
    for (i = 0; i < input_len; i++)
    {
        printf("input - 0x%08x%08x%08x%08x\n", input[i], input[i+1], input[i+2], input[i+3]);
        i = i + 3;
    }
    printf("input_len: %d\n", input_len);
    #endif //DEBUG

    int ret;
    uint32_t sel = 2;
    ret = write(fd, &sel, 4);
    ret = write(fd, input, input_len*4);
    return ret;
}

int aes_gcm_set_aad(int fd, uint32_t* aad, uint32_t aad_len) {
    #ifdef DEBUG
    printf("Write aad to aes-gcm module...\n");
    int i;
    for (i = 0; i < aad_len; i++)
    {
        printf("aad - 0x%08x%08x%08x%08x\n", aad[i], aad[i+1], aad[i+2], aad[i+3]);
        i = i + 3;
    }
    printf("aad_len: %d\n", aad_len);
    #endif //DEBUG
    
    int ret;
    uint32_t sel = 3;
    ret = write(fd, &sel, 4);
    ret = write(fd, aad, aad_len*4);
    return ret;
}

int aes_gcm_set_tag(int fd, uint32_t* tag) {
    #ifdef DEBUG
    printf("Write tag to aes-gcm module...\n");
    printf("Set tag - 0x%08x%08x%08x%08x\n", *(tag), *(tag+1), *(tag+2), *(tag+3));
    #endif //DEBUG

    int ret;
    uint32_t sel = 4;
    ret = write(fd, &sel, 4);
    ret = write(fd, tag, 4*4);
    return ret;
}

int aes_gcm_start_encrypt(int fd) {
    #ifdef DEBUG
    printf("Start encryption...\n");
    #endif //DEBUG

    int ret;
    uint32_t sel = 5;
    ret = write(fd, &sel, 4);
    return ret;
}

int aes_gcm_start_decrypt(int fd) {
    #ifdef DEBUG
    printf("Start decryption...\n");
    #endif //DEBUG

    int ret;
    uint32_t sel = 6;
    ret = write(fd, &sel, 4);
    return ret;
}

int aes_gcm_encrypt(int fd, uint32_t* output, uint32_t* tag, uint32_t* input, uint32_t input_len, uint32_t* key, const uint32_t key_len, uint32_t* iv, uint32_t* aad, const size_t aad_len) {
    int ret;

    //set key
    ret = aes_gcm_set_key(fd, key, key_len);
    //set iv
    ret = aes_gcm_set_iv(fd, iv);
    //set input
    ret = aes_gcm_set_input(fd, input, input_len);
    //set aad
    ret = aes_gcm_set_aad(fd, aad, aad_len);
    //do encryption
    ret = aes_gcm_start_encrypt(fd);

    return ret;
}

int aes_gcm_decrypt(int fd, uint32_t* output, uint32_t* input, uint32_t input_len, uint32_t* key, const uint32_t key_len, uint32_t* iv, uint32_t* aad, const size_t aad_len,  uint32_t* tag) {
    int ret;

    //set key
    ret = aes_gcm_set_key(fd, key, key_len);
    //set iv
    ret = aes_gcm_set_iv(fd, iv);
    //set input
    ret = aes_gcm_set_input(fd, input, input_len);
    //set aad
    ret = aes_gcm_set_aad(fd, aad, aad_len);
    //set tag
    ret = aes_gcm_set_tag(fd, tag);
    //do decryption
    ret = aes_gcm_start_decrypt(fd);

    return ret;
}