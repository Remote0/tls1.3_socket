#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "aes_gcm_regs.h"

#define BUFFER_LENGTH 4
static char receive[BUFFER_LENGTH]; //32b-reg

int main(){
    int ret, fd;
    char stringToSend[BUFFER_LENGTH];
    printf("Starting aes-gcm test code example...\n");
    fd = open("/dev/aes-gcm", O_RDWR); //Open the device with read/write access
    if(fd < 0){
        printf("Error(%d): ", fd);
        perror("Failed to open the module...");
        return errno;
    }

    // printf("Type in a short string to send to the kernel module\n");
    // scanf("%[^\n]%*c", stringToSend); //Read in a string (with spaces)
    // printf("Writing message to the device [%s]. \n", stringToSend);
    // ret = write(fd, stringToSend, strlen(stringToSend)); //Send the string to the LKM
    // if(ret<0){
    //     perror("Failed to write the message to the device.");
    //     return errno;
    // }

    // printf("Press ENTER to read back from the device...\n");
    // getchar();
    // unsigned int offset;
    // offset = AES_GCM_OREADY;
    // printf("Offset to be read [0x%08x]. \n", offset);
    // ret = write(fd, offset, sizeof(unsigned int));
    printf("Reading from aes-gcm module...\n");


    ret = write(fd, stringToSend, strlen(stringToSend));



    ret = read(fd, receive, BUFFER_LENGTH); //Read the response from the LKM



    if(ret<0){
        perror("Failed to read from module");
        return errno;
    }
    printf("The received message is: [%s]\n", receive);

    printf("End of the program\n");
    return 0;
}