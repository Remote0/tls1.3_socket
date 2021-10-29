#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "chacha_poly_regs.h"
#include "chacha_poly_func.h"

// #define BUFFER_LENGTH 4
// static char receive[BUFFER_LENGTH]; //32b-reg


//for encryption test
uint32_t key[8] = {0x80818283,0x84858687,0x88898a8b,0x8c8d8e8f,0x90919293,0x94959697,0x98999a9b,0x9c9d9e9f}; //fix with 8 elements = 32*8 = 256 bits
const uint32_t input_len = 114;
uint32_t input[32] = {0x4c616469,0x65732061,0x6e642047,0x656e746c,
                    0x656d656e,0x206f6620,0x74686520,0x636c6173,
                    0x73206f66,0x20273939,0x3a204966,0x20492063,
                    0x6f756c64,0x206f6666,0x65722079,0x6f75206f,
                    0x6e6c7920,0x6f6e6520,0x74697020,0x666f7220,
                    0x74686520,0x66757475,0x72652c20,0x73756e73,
                    0x63726565,0x6e20776f,0x756c6420,0x62652069,
                    0x742e};
uint32_t aad[4] =   {0x50515253,0xc0c1c2c3,0xc4c5c6c7,0x00000000}; //fix with 4 elements = 32*4 = 128 bits
uint32_t nonce[3] = {0x07000000,0x40414243,0x44454647}; //fix with 3 elements = 32*3 = 96 bits
uint32_t mac[4] ={0,0,0,0}; //fix with 4 elements = 32*4 = 128 bits //this can be used for both ENC and DEC, because in DEC, we dont need to read tag
uint32_t output[32]; //should be large enough to store output data, or can be just a pointer -- SAME SIZE WITH INPUT

//for decryption test
uint32_t mac2[4] = {0x1ae10b59, 0x4f09e26a, 0x7e902ecb, 0xd0600691};
uint32_t input2[32] = {0xd31a8d34, 0x648e60db, 0x7b86afbc, 0x53ef7ec2,
                    0xa4aded51, 0x296e08fe, 0xa9e2b5a7, 0x36ee62d6,
                    0x3dbea45e, 0x8ca96712, 0x82fafb69, 0xda92728b,
                    0x1a71de0a, 0x9e060b29, 0x05d6a5b6, 0x7ecd3b36,
                    0x92ddbd7f, 0x2d778b8c, 0x9803aee3, 0x28091b58,
                    0xfab324e4, 0xfad67594, 0x5585808b, 0x4831d7bc,
                    0x3ff4def0, 0x8e4b7a9d, 0xe576d265, 0x86cec64b,
                    0x6116};


int main(){
    int ret, fd;
    //char stringToSend[BUFFER_LENGTH];
    printf("Starting chacha-poly test code example...\n");
    fd = open("/dev/chacha-poly", O_RDWR); //Open the device with read/write access
    if(fd < 0){
        printf("Error(%d): ", fd);
        perror("Failed to open the module...");
        return errno;
    }

    //do encryption
    ret = chacha_poly_encrypt(fd, output, mac, input, input_len, key, nonce, aad);
    if(ret<0){
        perror("Failed to do encryption to module");
        return errno;
    }
    printf("Encryption result:\n");
    int i;
    for (i = 0; i < 32; i=i+1) { //TODO: need to improve
        printf("output - 0x%08x%08x%08x%08x\n", output[i], output[i+1], output[i+2], output[i+3]);
        i = i + 3;
    }
    printf("mac - 0x%08x%08x%08x%08x\n", mac[0], mac[1],mac[2],mac[3]);




    //do decryption
    ret = chacha_poly_decrypt(fd, output, input2, input_len, key, nonce, aad, mac2);
    if(ret<0){
        perror("Failed to do decryption to module");
        return errno;
    }
    printf("Decryption result:\n");
    for (i = 0; i < 32; i=i+1) { //TODO: need to improve
        printf("output - 0x%08x%08x%08x%08x\n", output[i], output[i+1], output[i+2], output[i+3]);
        i = i + 3;
    }

    printf("End of the program\n");
    return 0;
}