#include "aes_gcm_func.h"
#include "aes_gcm_regs.h"
#include "chacha_poly_func.h"
#include "chacha_poly_regs.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>

int drv_encrypt(char* device, char* cipherName, uint32_t* output, uint32_t* tag, uint32_t* input, uint32_t input_len, uint32_t* key, uint32_t* iv, uint32_t* aad, const size_t aad_len){
     int fd;
     int ret;
     fd = open(device, O_RDWR); //Open the device with read/write access
     if(fd < 0){
        printf("Error(%d): ", fd);
        perror("Failed to open the module...");
        return errno;
     }
     uint32_t additional_len = 4; //4*8*4 = 128-bit

    if(!strcmp(cipherName, "aes-128-gcm")) {
        printf("do encryption using aes 128\n");
        //do encryption
        ret = aes_gcm_encrypt(fd, output, tag, input, input_len, key, 4, iv, aad, additional_len);
        if(ret<0){
            perror("Failed to do encryption to module");
            return errno;
        }
    }

    if(!strcmp(cipherName, "aes-256-gcm")) {
        //do encryption
        printf("do encryption using aes 256\n");
        ret = aes_gcm_encrypt(fd, output, tag, input, input_len, key, 8, iv, aad, additional_len);
        if(ret<0){
            perror("Failed to do encryption to module");
            return errno;
        }
    }
    
    if(!strcmp(cipherName, "chacha20-poly1305")) {
        //do encryption
        printf("do encryption using chacha\n");
        ret = chacha_poly_encrypt(fd, output, tag, input, input_len*4, key, iv, aad);
        if(ret<0){
            perror("Failed to do encryption to module");
            return errno;
        }
    }
    close(fd);
    return ret;
}

int drv_decrypt(char* device, char* cipherName, uint32_t* output, uint32_t* input, uint32_t input_len, uint32_t* key, uint32_t* iv, uint32_t* aad, const size_t aad_len, uint32_t* tag){
    int ret;
    int fd;
    fd = open(device, O_RDWR); //Open the device with read/write access
        if(fd < 0){
            printf("Error(%d): ", fd);
            perror("Failed to open the module...");
            return errno;
        }
    if(!strcmp(cipherName, "aes-128-gcm")) {
        uint32_t key_len = 4; // 4 or 8 == 128 or 256 bit
        printf("do decryption using aes 128\n");
        //do encryptions
        ret = aes_gcm_decrypt(fd, output,  input, input_len, key, key_len, iv,  aad, aad_len,  tag);
        if(ret<0){
            perror("Failed to do decryption to module");
            return errno;
        }
    }
    if(!strcmp(cipherName, "aes-256-gcm")) {
        uint32_t key_len = 8; // 4 or 8 == 128 or 256 bit
        printf("do decryption using aes 256\n");
        //do encryptions
        ret = aes_gcm_decrypt(fd, output, input, input_len, key, key_len, iv,  aad, aad_len,  tag);
        if(ret<0){
            perror("Failed to do decryption to module");
            return errno;
        }
    }
    if(!strcmp(cipherName, "chacha20-poly1305")) {
        printf("do decryption using chacha\n");
        //do encryptions
        ret = chacha_poly_decrypt(fd, output, input, input_len*4, key, iv, aad, tag);
        if(ret<0){
            perror("Failed to do decryption to module");
            return errno;
        }
    }
    close(fd);
    return ret;
}