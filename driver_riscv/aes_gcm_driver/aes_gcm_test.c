#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "aes_gcm_regs.h"
#include "aes_gcm_func.h"

// #define BUFFER_LENGTH 4
// static char receive[BUFFER_LENGTH]; //32b-reg


//for encryption test
const uint32_t key_len = 8; //number of bytes
uint32_t key[8] = {0xE3C08A8F,0x06C6E3AD,0x95A70557,0xB23F7548,0x3CE33021,0xA9C72B70,0x25666204,0xC69C0B72}; //fix with 8 elements = 32*8 = 256 bits
const uint32_t input_len = 12;
uint32_t input[12] = {0x08000F10,0x11121314,0x15161718,0x191A1B1C,0x1D1E1F20,0x21222324,0x25262728,0x292A2B2C,0x2D2E2F30,0x31323334,0x35363738,0x393A0002}; //should be large enough to store input data, or can be just a pointer
const uint32_t aad_len = 7;
uint32_t aad[7] =   {0xD609B1F0,0x56637A0D,0x46DF998D,0x88E52E00,0xB2C28465,0x12153524,0xC0895E81}; //should be large enough to store input data, or can be just a pointer
uint32_t iv[3] = {0x12153524,0xC0895E81,0xB2C28465}; //fix with 3 elements = 32*3 = 96 bits
uint32_t tag[4] ={0,0,0,0}; //fix with 4 elements = 32*4 = 128 bits //this can be used for both ENC and DEC, because in DEC, we dont need to read tag
uint32_t output[12]; //should be large enough to store output data, or can be just a pointer -- SAME SIZE WITH INPUT


//for decryption test
uint32_t tag2[4] = {0x5ca597cd, 0xbb3edb8d, 0x1a1151ea, 0x0af7b436};
uint32_t input2[12] = {0xe2006eb4,0x2f527702,0x2d9b1992,0x5bc419d7,0xa592666c,0x925fe2ef,0x718eb4e3,0x08efeaa7,0xc5273b39,0x4118860a,0x5be2a97f,0x56ab7836};


int main(){
    int ret, fd;
    //char stringToSend[BUFFER_LENGTH];
    printf("Starting aes-gcm test code example...\n");
    fd = open("/dev/aes-gcm", O_RDWR); //Open the device with read/write access
    if(fd < 0){
        printf("Error(%d): ", fd);
        perror("Failed to open the module...");
        return errno;
    }

    //do encryption
    ret = aes_gcm_encrypt(fd, output, tag, input, input_len, key, key_len, iv, aad, aad_len);
    if(ret<0){
        perror("Failed to do encryption to module");
        return errno;
    }
    printf("Encryption result:\n");
    int i;
    for (i = 0; i < input_len; i=i+1) { //TODO: need to improve
        printf("output - 0x%08x%08x%08x%08x\n", output[i], output[i+1], output[i+2], output[i+3]);
        i = i + 3;
    }
    printf("otag - 0x%08x%08x%08x%08x\n", tag[0], tag[1],tag[2],tag[3]);


    //do decryption
    ret = aes_gcm_decrypt(fd, output, input2, input_len, key, key_len, iv, aad, aad_len, tag2);
    if(ret<0){
        perror("Failed to do encryption to module");
        return errno;
    }
    printf("Decryption result:\n");
    for (i = 0; i < input_len; i=i+1) { //TODO: need to improve
        printf("output - 0x%08x%08x%08x%08x\n", output[i], output[i+1], output[i+2], output[i+3]);
        i = i + 3;
    }
    //printf("otag - 0x%08x%08x%08x%08x\n", tag[0], tag[1],tag[2],tag[3]);

    printf("End of the program\n");
    return 0;
}