#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/list.h>

#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>

#include "aes_gcm_regs.h"

//#define DEBUG

#define DEVICE_NAME "aes-gcm"      //The dev will appear at /dev/aes-gcm using this value, and also in /proc/devices /proc/iomem
#define CLASS_NAME  "crypto"          //The device class -- this is a character device driver

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiet Dang");         //The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple aes-gcm platform device"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

// custom struct to hold device data
struct aes_gcm_data {
    //Use for create character device
    struct resource *rmem;
    dev_t devt; //hold major and minor number
    struct class* aes_gcm_class; // The device-driver class struct pointer        //appear in /sys/class/CLASS_NAME
    struct device* aes_gcm_device; // The device-driver device struct pointer
    struct cdev c_dev; //Global variable for the character device structure

    struct list_head device_entry;
    void __iomem *base_addr; /* virt. address of control registers */

    int numberOpens;
};

static LIST_HEAD(device_list);

// The prototype functions for the character driver -- must come before the struct definition
static int dev_open(struct inode*, struct file*);
static int dev_release(struct inode*, struct file*);
static ssize_t dev_read(struct file*, char*, size_t, loff_t*);
static ssize_t dev_write(struct file*, const char*, size_t, loff_t*);

//buffer
static uint32_t ker_buff[300];   
static short ker_buff_len;
static uint32_t sel_buffer = 0;

//for encryption test
static uint32_t* key; //fix with 8 elements = 32*8 = 256 bits
static uint32_t key_len;
static uint32_t* input; //should be large enough to store input data, or can be just a pointer
static uint32_t input_len;
static uint32_t aad_len;
static uint32_t* aad; //should be large enough to store input data, or can be just a pointer
static uint32_t* iv; //fix with 3 elements = 32*3 = 96 bits
static uint32_t* tag; //fix with 4 elements = 32*4 = 128 bits //this can be used for both ENC and DEC, because in DEC, we dont need to read tag
static uint32_t* output; //should be large enough to store output data, or can be just a pointer -- SAME SIZE WITH INPUT


//Function to control aes-gcm module

void hw_aes_gcm_reset (struct aes_gcm_data* aes_gcm){
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IRESETN);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_ICTRL);
    iowrite32(1, aes_gcm->base_addr + AES_GCM_IRESETN);
}

void hw_aes_gcm_set_key (struct aes_gcm_data* aes_gcm, uint32_t* key, uint32_t keylen){
    iowrite32(key[0], aes_gcm->base_addr + AES_GCM_IKEY_0);
    iowrite32(key[1], aes_gcm->base_addr + AES_GCM_IKEY_1);
    iowrite32(key[2], aes_gcm->base_addr + AES_GCM_IKEY_2);
    iowrite32(key[3], aes_gcm->base_addr + AES_GCM_IKEY_3);
    iowrite32(key[4], aes_gcm->base_addr + AES_GCM_IKEY_4);
    iowrite32(key[5], aes_gcm->base_addr + AES_GCM_IKEY_5);
    iowrite32(key[6], aes_gcm->base_addr + AES_GCM_IKEY_6);
    iowrite32(key[7], aes_gcm->base_addr + AES_GCM_IKEY_7);
    iowrite32(keylen, aes_gcm->base_addr + AES_GCM_IKEYLEN);
    iowrite32(1, aes_gcm->base_addr + AES_GCM_IKEY_VALID);
}

void hw_aes_gcm_clear_key (struct aes_gcm_data* aes_gcm){
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_0);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_1);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_2);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_3);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_4);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_5);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_6);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_7);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEYLEN);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IKEY_VALID);
}

void hw_aes_gcm_set_aad (struct aes_gcm_data* aes_gcm, uint32_t* aad, uint32_t mod4){

    switch(mod4) {
        case 3:
            iowrite32(aad[0], aes_gcm->base_addr + AES_GCM_IAAD_0);
            iowrite32(aad[1], aes_gcm->base_addr + AES_GCM_IAAD_1);
            iowrite32(aad[2], aes_gcm->base_addr + AES_GCM_IAAD_2);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IAAD_3);
            break;
        case 2:
            iowrite32(aad[0], aes_gcm->base_addr + AES_GCM_IAAD_0);
            iowrite32(aad[1], aes_gcm->base_addr + AES_GCM_IAAD_1);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IAAD_2);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IAAD_3);
            break;
        case 1:
            iowrite32(aad[0], aes_gcm->base_addr + AES_GCM_IAAD_0);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IAAD_1);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IAAD_2);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IAAD_3);
            break;
        case 0:
            iowrite32(aad[0], aes_gcm->base_addr + AES_GCM_IAAD_0);
            iowrite32(aad[1], aes_gcm->base_addr + AES_GCM_IAAD_1);
            iowrite32(aad[2], aes_gcm->base_addr + AES_GCM_IAAD_2);
            iowrite32(aad[3], aes_gcm->base_addr + AES_GCM_IAAD_3);
            break;
        default:
            iowrite32(aad[0], aes_gcm->base_addr + AES_GCM_IAAD_0);
            iowrite32(aad[1], aes_gcm->base_addr + AES_GCM_IAAD_1);
            iowrite32(aad[2], aes_gcm->base_addr + AES_GCM_IAAD_2);
            iowrite32(aad[3], aes_gcm->base_addr + AES_GCM_IAAD_3);
    }

    iowrite32(1, aes_gcm->base_addr + AES_GCM_IAAD_VALID);
}

void hw_aes_gcm_clear_aad (struct aes_gcm_data* aes_gcm){
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IAAD_0);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IAAD_1);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IAAD_2);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IAAD_3);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IAAD_VALID);
}

void hw_aes_gcm_set_iiv (struct aes_gcm_data* aes_gcm, uint32_t* iv){
    iowrite32(iv[0], aes_gcm->base_addr + AES_GCM_IIV_0);
    iowrite32(iv[1], aes_gcm->base_addr + AES_GCM_IIV_1);
    iowrite32(iv[2], aes_gcm->base_addr + AES_GCM_IIV_2);
    iowrite32(1, aes_gcm->base_addr + AES_GCM_IIV_VALID);
}

void hw_aes_gcm_clear_iiv (struct aes_gcm_data* aes_gcm){
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IIV_0);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IIV_1);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IIV_2);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IIV_VALID);
}

void hw_aes_gcm_set_block (struct aes_gcm_data* aes_gcm, uint32_t* block, uint32_t mod4){

    switch(mod4) {
        case 3:
            iowrite32(block[0], aes_gcm->base_addr + AES_GCM_IBLOCK_0);
            iowrite32(block[1], aes_gcm->base_addr + AES_GCM_IBLOCK_1);
            iowrite32(block[2], aes_gcm->base_addr + AES_GCM_IBLOCK_2);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IBLOCK_3);
            break;
        case 2:
            iowrite32(block[0], aes_gcm->base_addr + AES_GCM_IBLOCK_0);
            iowrite32(block[1], aes_gcm->base_addr + AES_GCM_IBLOCK_1);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IBLOCK_2);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IBLOCK_3);
            break;
        case 1:
            iowrite32(block[0], aes_gcm->base_addr + AES_GCM_IBLOCK_0);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IBLOCK_1);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IBLOCK_2);
            iowrite32(0x00000000, aes_gcm->base_addr + AES_GCM_IBLOCK_3);
            break;
        case 0:
            iowrite32(block[0], aes_gcm->base_addr + AES_GCM_IBLOCK_0);
            iowrite32(block[1], aes_gcm->base_addr + AES_GCM_IBLOCK_1);
            iowrite32(block[2], aes_gcm->base_addr + AES_GCM_IBLOCK_2);
            iowrite32(block[3], aes_gcm->base_addr + AES_GCM_IBLOCK_3);
            break;
        default:
            iowrite32(block[0], aes_gcm->base_addr + AES_GCM_IBLOCK_0);
            iowrite32(block[1], aes_gcm->base_addr + AES_GCM_IBLOCK_1);
            iowrite32(block[2], aes_gcm->base_addr + AES_GCM_IBLOCK_2);
            iowrite32(block[3], aes_gcm->base_addr + AES_GCM_IBLOCK_3);
    }

    iowrite32(1, aes_gcm->base_addr + AES_GCM_IBLOCK_VALID);
}

void hw_aes_gcm_clear_block (struct aes_gcm_data* aes_gcm){
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IBLOCK_0);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IBLOCK_1);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IBLOCK_2);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IBLOCK_3);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IBLOCK_VALID);
}

void hw_aes_gcm_set_tag (struct aes_gcm_data* aes_gcm, uint32_t* tag){
    iowrite32(tag[0], aes_gcm->base_addr + AES_GCM_ITAG_0);
    iowrite32(tag[1], aes_gcm->base_addr + AES_GCM_ITAG_1);
    iowrite32(tag[2], aes_gcm->base_addr + AES_GCM_ITAG_2);
    iowrite32(tag[3], aes_gcm->base_addr + AES_GCM_ITAG_3);
    iowrite32(1, aes_gcm->base_addr + AES_GCM_ITAG_VALID);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_ITAG_VALID);
}

void hw_aes_gcm_clear_tag (struct aes_gcm_data* aes_gcm){
    iowrite32(0, aes_gcm->base_addr + AES_GCM_ITAG_0);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_ITAG_1);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_ITAG_2);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_ITAG_3);
    iowrite32(0, aes_gcm->base_addr + AES_GCM_IAAD_VALID);
}

void hw_aes_gcm_ctrl (struct aes_gcm_data* aes_gcm, uint32_t init, uint32_t next, uint32_t encdec, uint32_t aad_only){
    uint32_t write_val = (init<<3) | (next<<2) | (encdec<<1) | (aad_only);
    iowrite32(write_val, aes_gcm->base_addr + AES_GCM_ICTRL);
}

uint32_t hw_aes_gcm_read_tag(struct aes_gcm_data* aes_gcm, uint32_t* tag){
    uint32_t wd = 0;
    while(1){
        if (ioread32(aes_gcm->base_addr + AES_GCM_OTAG_VALID) & 0x1){
            tag[0] = ioread32(aes_gcm->base_addr + AES_GCM_OTAG_0);
            tag[1] = ioread32(aes_gcm->base_addr + AES_GCM_OTAG_1);
            tag[2] = ioread32(aes_gcm->base_addr + AES_GCM_OTAG_2);
            tag[3] = ioread32(aes_gcm->base_addr + AES_GCM_OTAG_3);
            return 0;
        }else{
            wd++;
            if(wd > WD){
                printk(KERN_ALERT "aes-gcm: Error read tag - Out of wait time\n");
                return -1;
            } 
        }
    }
}

int hw_aes_gcm_read_result(struct aes_gcm_data* aes_gcm, uint32_t* result){
    uint32_t wd = 0;
    while(1){
        if (ioread32(aes_gcm->base_addr + AES_GCM_ORESULT_VALID) & 0x1){
            result[0] = ioread32(aes_gcm->base_addr + AES_GCM_ORESULT_0);
            result[1] = ioread32(aes_gcm->base_addr + AES_GCM_ORESULT_1);
            result[2] = ioread32(aes_gcm->base_addr + AES_GCM_ORESULT_2);
            result[3] = ioread32(aes_gcm->base_addr + AES_GCM_ORESULT_3);
            return 0;
        }else{
            wd++;
            if(wd > WD) {
                printk(KERN_ALERT "aes-gcm: Error read result - Out of wait time\n");
                return -1;
            }
        }
    }
}

int hw_aes_gcm_authentic (struct aes_gcm_data* aes_gcm){
    if(ioread32(aes_gcm->base_addr + AES_GCM_OAUTHENTIC) & 0x1)
        return 1;
    else
        return 0;
}

int hw_aes_gcm_ready (struct aes_gcm_data* aes_gcm){
    if(ioread32(aes_gcm->base_addr + AES_GCM_OREADY) & 0x1)
        return 1;
    else
        return 0;
}

int hw_aes_gcm_wait_ready (struct aes_gcm_data* aes_gcm){
    uint32_t wd = 0;
    while(1){
        if (ioread32(aes_gcm->base_addr + AES_GCM_OREADY) & 0x1){
            return 0;
        }else{
            wd++;
            if(wd > WD){
                printk(KERN_ALERT "aes-gcm: Error wait ready - Out of wait time\n");
                return -1;
            }
        }
    }
}

int hw_aes_gcm_tag_valid(struct aes_gcm_data* aes_gcm){
    if(ioread32(aes_gcm->base_addr + AES_GCM_OTAG_VALID) & 0x1)
        return 1;
    else
        return 0;
}

int hw_aes_gcm_encrypt(struct aes_gcm_data* aes_gcm, const uint32_t mode, uint32_t* output, uint32_t* input, uint32_t input_length, uint32_t* key, const uint32_t key_len, uint32_t* iv, uint32_t* aad, const size_t aad_len, uint32_t* tag){
    int i = 0;
    // 1 for enc, 0 for dec
    hw_aes_gcm_reset(aes_gcm);
    hw_aes_gcm_clear_block(aes_gcm);
    hw_aes_gcm_clear_aad(aes_gcm);
    hw_aes_gcm_clear_iiv(aes_gcm);
    hw_aes_gcm_clear_tag(aes_gcm);
    hw_aes_gcm_clear_key(aes_gcm);
    
    //if in DEC mode, tag is used for AUTHENTICATION
    if(mode == 0) {
        printk(KERN_INFO "aes-gcm: [6] Run aes-gcm module in DECRYPTION mode\n");
        hw_aes_gcm_set_tag(aes_gcm, tag);
    }else{
        printk(KERN_INFO "aes-gcm: [5] Run aes-gcm module in ENCRYPTION mode\n");
    }

    
    //Generate HashKey
    if(key_len == AES_256_BIT_KEY){
        hw_aes_gcm_set_key(aes_gcm, key, AES_256_BIT_KEY);
        printk(KERN_INFO "aes-gcm: Set key length: AES_256_BIT_KEY\n");
    }else if(key_len == AES_128_BIT_KEY){
        hw_aes_gcm_set_key(aes_gcm, key, AES_128_BIT_KEY);
        printk(KERN_INFO "aes-gcm: Set key length: AES_128_BIT_KEY\n");
    }else{
        printk(KERN_INFO "aes-gcm: Error set key\n");
        return -1;
    }
    hw_aes_gcm_set_iiv(aes_gcm, iv);
    printk(KERN_INFO "aes-gcm: Generating HahsKey...\n");
    //control register -- next signal rising edge makes the module process next step
    //init:1 - next:0 - encdec:1 - aad_only:0
    hw_aes_gcm_ctrl(aes_gcm,1,0,mode,0); //start enc 0
    hw_aes_gcm_ctrl(aes_gcm,1,1,mode,0); //rising next
    if(hw_aes_gcm_wait_ready(aes_gcm) == -1) { //wait for creating Hashkey
        printk(KERN_INFO "aes-gcm: Error generating HashKey\n");
        return -1;
    }
    hw_aes_gcm_ctrl(aes_gcm,1,0,mode,0); //prepare for next step


    printk(KERN_INFO "aes-gcm: HashKey Done - Compute AAD...\n");
    uint32_t mod4 = aad_len % 4; //auto set 0 for missing aad
    uint32_t div4;
    if(mod4 != 0)
        div4 = (aad_len/4) + 1; //floor and then create ceiling for the loop
    else
        div4 = aad_len/4;
    for (i = 0; i < div4 ; i++){
        if((i+1) == div4)
            hw_aes_gcm_set_aad(aes_gcm, aad+(i*4), mod4); //last block
        else
            hw_aes_gcm_set_aad(aes_gcm, aad+(i*4), 0);

        hw_aes_gcm_ctrl(aes_gcm,1,1,mode,0); //rising next
        //hw_aes_gcm_wait_ready(aes_gcm); //TODO: check whether need this in testbench
        hw_aes_gcm_ctrl(aes_gcm,1,0,mode,0); //prepare for next step
    }
    hw_aes_gcm_clear_aad(aes_gcm); //no more aad, go to next step


    printk(KERN_INFO "aes-gcm: AAD Done - Compute Ciphertext...\n");
    mod4 = input_length % 4;
    if(mod4 != 0)
        div4 = (input_length/4) + 1; //floor and then create ceiling for the loop
    else
        div4 = input_length/4;
    for (i=0; i < div4; i++){
        if((i+1) == div4)
            hw_aes_gcm_set_block(aes_gcm, input+(i*4), mod4); //last block
        else
            hw_aes_gcm_set_block(aes_gcm, input+(i*4), 0);
        hw_aes_gcm_ctrl(aes_gcm,1,1,mode,0); //rising next
        hw_aes_gcm_read_result(aes_gcm,output+(i*4));// get cypher text
        hw_aes_gcm_wait_ready(aes_gcm);
        hw_aes_gcm_ctrl(aes_gcm,1,0,mode,0); //prepare for next step
    }
    hw_aes_gcm_clear_block(aes_gcm);

    printk(KERN_INFO "aes-gcm: Ciphertext Done - Compute Tag...\n");
    uint32_t out_tag[4];
    uint32_t len[4]= {0x00000000,32*(aad_len),0x00000000,32*input_length}; //TODO: need improve, if the length is no large, it's ok for now 
    hw_aes_gcm_set_aad(aes_gcm,len,0);
    hw_aes_gcm_ctrl(aes_gcm,1,1,mode,0); //rising next
    if(mode == 0){
        hw_aes_gcm_read_tag(aes_gcm, out_tag); //get tag
        #ifdef DEBUG
        printk("aes-gcm: out_tag - 0x%08x%08x%08x%08x\n", out_tag[0], out_tag[1], out_tag[2], out_tag[3]);
        #endif //DEBUG
        if(hw_aes_gcm_authentic(aes_gcm))
            printk(KERN_INFO "aes-gcm: Authentic decryption\n");
        else
            printk(KERN_INFO "aes-gcm: Authenticate FAILED - cannot trust decryption\n");
    }else{
        hw_aes_gcm_read_tag(aes_gcm,tag); //get tag
    }


    hw_aes_gcm_ctrl(aes_gcm,0,0,0,0); //FINISHED
    printk(KERN_INFO "aes-gcm: Tag Done\n");

    return 0;
}


// void hwaesgcm_selftest(struct aes_gcm_data* aes_gcm){

//     static uint32_t key2[8] = {0xE3C08A8F,0x06C6E3AD,0x95A70557,0xB23F7548,0x3CE33021,0xA9C72B70,0x25666204,0xC69C0B72}; //fix with 8 elements = 32*8 = 256 bits
//     static uint32_t plaintext[12] = {0x08000F10,0x11121314,0x15161718,0x191A1B1C,0x1D1E1F20,0x21222324,0x25262728,0x292A2B2C,0x2D2E2F30,0x31323334,0x35363738,0x393A0002}; //should be large enough to store input data, or can be just a pointer
//     static uint32_t aad2[7] =   {0xD609B1F0,0x56637A0D,0x46DF998D,0x88E52E00,0xB2C28465,0x12153524,0xC0895E81}; //should be large enough to store input data, or can be just a pointer
//     static uint32_t iv2[3] = {0x12153524,0xC0895E81,0xB2C28465}; //fix with 3 elements = 32*3 = 96 bits
//     static uint32_t tag2[4] ={0,0,0,0}; //fix with 4 elements = 32*4 = 128 bits //this can be used for both ENC and DEC, because in DEC, we dont need to read tag
//     static uint32_t ciphertext2[12]; //should be large enough to store output data, or can be just a pointer -- SAME SIZE WITH INPUT

//     //reset
//     printk(KERN_INFO "aes-gcm: Reset before encrypt\n");
//     hw_aes_gcm_reset(aes_gcm);
//     printk(KERN_INFO "aes-gcm: Reset done\n");

//     printk(KERN_INFO "aes-gcm: Start Encrypt...\n");
//     hw_aes_gcm_encrypt(/*aes_gcm_data*/aes_gcm, /*mode*/1, /*output*/ciphertext2, /*input*/plaintext, /*input_length*/12, /*key*/key2, /*key_length*/AES_256_BIT_KEY, /*iv*/iv2, /*aad*/aad2, /*aad_len*/7, /*tag*/tag2);
//     printk(KERN_INFO "aes-gcm: Encrypt Done\n");

//     int i;
//     for (i = 0; i < 12; i++)
//     {
//         printk(KERN_INFO "aes-gcm: ciphertext - 0x%08x%08x%08x%08x\n", ciphertext2[i], ciphertext2[i+1], ciphertext2[i+2], ciphertext2[i+3]);
//         i = i + 3;
//     }

//     printk(KERN_INFO "aes-gcm: otag - 0x%08x%08x%08x%08x\n", tag2[0], tag2[1],tag2[2],tag2[3]);
// }



/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
* /linux/fs.h lists the callback functions that you wish to associated with your file opreations
* using a C99 syntax structure. char devices usually implement open, read, write and release calls
*/
static struct file_operations fops =
{
    /* data */
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
};

/* ============================================================================================ */
/* ============================================================================================ */

static int aes_gcm_probe( struct platform_device *pdev){

    struct aes_gcm_data *lp = NULL;
    int ret = 0;

    printk(KERN_INFO "aes-gcm: Device Tree Probing...\n");

    //Assign aes_gcm_data to platform device data:
    lp = (struct aes_gcm_data*)kmalloc(sizeof(struct aes_gcm_data), GFP_KERNEL);
    if(!lp) {
        printk(KERN_ALERT "aes-gcm: Could not allocate mychar device\n");
    }
    platform_set_drvdata(pdev, lp);

    //Get the memory range from the device tree by calling
    lp->rmem = platform_get_resource(pdev, IORESOURCE_MEM, 0);

    //Remap physical addr to virtual addr
    lp->base_addr = devm_ioremap_resource(&pdev->dev, lp->rmem);
    if (IS_ERR(lp->base_addr)) {
		ret = PTR_ERR(lp->base_addr);
	}
    dev_info(&pdev->dev, "Registered\n");
    printk(KERN_INFO "aes-gcm: devm platform ioremap - vir. baseaddr: 0x%lx\n", (long unsigned int)(lp->base_addr));
    
    lp->numberOpens = 0;
    //Perform module reset
    printk(KERN_INFO "aes-gcm: Perform module RESET...");
    iowrite32(0, lp->base_addr + AES_GCM_IRESETN);
    iowrite32(0, lp->base_addr + AES_GCM_ICTRL);
    iowrite32(1, lp->base_addr + AES_GCM_IRESETN);
    printk(KERN_INFO "aes-gcm: Module RESET done\n");

    // ************************ NORMAL Device driver *************************** //
    /** The main reason to do this is to create a device /dev/aes-gcm 
     *  It is a character device node exposing our userspace API
     *  It also simplies memory management.
     */

    INIT_LIST_HEAD(&lp->device_entry);

    printk(KERN_INFO "aes-gcm: Initializing aes-gcm char-driver\n");
    //Register a range of char device number
    /**Format: alloc_chrdev_region(dev_t* dev, uint firstminor, uint count, char* name)
    *dev_t* dev: store the major and minor number (use marcros MAJOR(dev_t), MINOR(dev_t) to get the coresponding number)
    *char* name: is the name of the device that should be associated with this number range (will appear in /proc/devices)
    */
    if(alloc_chrdev_region(&lp->devt, 0, 1, DEVICE_NAME) < 0){
        printk(KERN_ALERT "aes-gcm failed to register a major number\n");
        return -1;
    }
    printk(KERN_INFO "aes-gcm: asssigned correctly with major number %d and minor number %d\n", MAJOR(lp->devt), MINOR(lp->devt));

    //Register the device class
    lp->aes_gcm_class = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(lp->aes_gcm_class)) {     //Check for error and clean up if there is
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(lp->aes_gcm_class);  // Correct way to return an error on a pointer
    }
    //Register the device driver
    lp->aes_gcm_device = device_create(lp->aes_gcm_class, NULL, lp->devt, NULL, DEVICE_NAME);
    if(IS_ERR(lp->aes_gcm_device)) {         //Clean up if there is an error
        class_unregister(lp->aes_gcm_class);
        class_destroy(lp->aes_gcm_class);    //Repeated code but the alternative is goto statements
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(lp->aes_gcm_device);
    }
    printk(KERN_INFO "aes-gcm: Device class registered & created correctly\n");

    cdev_init(&lp->c_dev, &fops);
    if(cdev_add(&lp->c_dev, lp->devt, 1) == -1){
        device_destroy(lp->aes_gcm_class, lp->devt);
        class_unregister(lp->aes_gcm_class);
        class_destroy(lp->aes_gcm_class);
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Create character device failed\n");
    }
    printk(KERN_INFO "aes-gcm: Initialize cdev correctly\n");
    
    list_add(&lp->device_entry, &device_list);
    
    // ************************ NORMAL Device driver *************************** //


    return 0;
}

static int aes_gcm_remove(struct platform_device *pdev) {
    struct aes_gcm_data *lp = platform_get_drvdata(pdev);

    //delete character driver
    cdev_del(&lp->c_dev);
    device_destroy(lp->aes_gcm_class, lp->devt);
    class_unregister(lp->aes_gcm_class); //MUST UNREGSITER BEFORE DESTROY
    class_destroy(lp->aes_gcm_class); //Something happen in class destroy or unregister
    unregister_chrdev_region(lp->devt, 1);
    
    //remove from linked list
    list_del(&lp->device_entry);
    kfree(lp);
    dev_info(&pdev->dev, "Unregistered\n");
    return 0;
}


/** @brief Add an entry to device table. The kernel will look for a suitable entry in the device table
*   and call probe() to init the device
*/
static const struct of_device_id aes_gcm_of_match[]= {
    { .compatible = "uec,aes_gcm-0", },
    { /* end of list */ },
};
MODULE_DEVICE_TABLE(of, aes_gcm_of_match);

static struct platform_driver aes_gcm_driver = {
    .driver                 = {
            .name           = DEVICE_NAME,
            .owner          = THIS_MODULE,
            .of_match_table = aes_gcm_of_match,
    },
    .probe                  = aes_gcm_probe,
    .remove                 = aes_gcm_remove,
};
//module_platform_driver(aes_gcm_driver); //this use another dummy init and exit function



/* ============================================================================================ */
/* ============================================================================================ */

/** @brief Initialization function
*   The static keyword restricts the visibility of the function to within this C file.
*   The __init marcro means that for a built-in driver, the fucntion is only used at initialization
*   time and that it can be discarded and its memory freed up after that point.
*   @return returns 0 if successful
*/
static int __init aes_gcm_init(void){
    printk(KERN_INFO "aes-gcm: Hello module world.\n");
    return platform_driver_register(&aes_gcm_driver);
}

/** @brief Cleanup function
*   Similar to initialization, it is static.
*   The __exit macro notifies that if this code is used for a built-in driver
*   that this function is not required.
*/
static void __exit aes_gcm_exit(void){
    platform_driver_unregister(&aes_gcm_driver);
    printk(KERN_INFO "aes-gcm: Goodbye from the LKM!\n");
}

/** @brief Open function
 *  The open function is called each time the device is opened
 *  This will search for platform data in the linked list and give it to device file
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode* inodep, struct file* filep){
    //This is the way to pass platform data to device file
    struct aes_gcm_data *lp;
    list_for_each_entry(lp, &device_list, device_entry) {
        if(lp->devt == inodep->i_rdev) {
            break;
        }
    }
    filep->private_data = lp;
    stream_open(inodep, filep);

    lp->numberOpens++;
    printk(KERN_INFO "aes-gcm: Device has been open %d time(s)\n", lp->numberOpens);
    return 0;
}

/** @brief Release function
 * The device release function that is called whenever the device is closed/released by the userspace program
 * @param inodep A pointer to an inode object (defined in linux/fs.h)
 * @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode* inodep, struct file* filep){
    struct aes_gcm_data *lp;
    lp = filep->private_data;
    filep->private_data = NULL;
    printk(KERN_INFO "aes-gcm: Device successfully closed\n");
    return 0;
}

/** @brief Read function
 * This function is called whenever device is being read from user space i.e. data is being
 * sent from the device to the user. In this case is uses the copy_to_user() function to send 
 * the buffer string to the user and captures any errors.
 * @param filep A pointer to a file opject (defined in linux/fs.h)
 * @param buffer The pointer to the buffer to which this function writes the data
 * @param len The length of the buffer
 * @param offset the offset if required
 */
static ssize_t dev_read(struct file* filep, char* buffer, size_t len, loff_t* offset){
    struct aes_gcm_data *lp;
    lp = filep->private_data;
    
    //hwaesgcm_selftest(lp);

    int error_count;
    int send_byte;
    if(sel_buffer == 7) {
        send_byte = input_len*4;
        error_count = copy_to_user(buffer, output, send_byte);
        #ifdef DEBUG
        int i;
        for (i = 0; i < 12; i++) { //TODO: need to improve
            printk(KERN_INFO "aes-gcm: output - 0x%08x%08x%08x%08x\n", output[i], output[i+1], output[i+2], output[i+3]);
            i = i + 3;
        }
        #endif //DEBUG
        printk(KERN_INFO "aes-gcm: [7] read output\n");
        kfree(output);
    }

    if(sel_buffer == 8) {
        send_byte = 4*4;
        error_count = copy_to_user(buffer, tag, send_byte);
        #ifdef DEBUG
        printk(KERN_INFO "aes-gcm: otag - 0x%08x%08x%08x%08x\n", tag[0], tag[1],tag[2],tag[3]);
        #endif //DEBUG
        printk(KERN_INFO "aes-gcm: [8] read tag\n");
        kfree(tag);
    }

    if(sel_buffer == 9) {
        send_byte = 4;
        uint32_t status = hw_aes_gcm_authentic(lp);
        error_count = copy_to_user(buffer, &status, 4);
        printk(KERN_INFO "aes-gcm: [9] read authenic\n");
    }

    if(sel_buffer == 10){
        send_byte = 4;
        uint32_t status = hw_aes_gcm_tag_valid(lp);
        error_count = copy_to_user(buffer, &status, 4);
        printk(KERN_INFO "aes-gcm: [10] read tag valid\n");
    }

    if(error_count == 0){
        #ifdef DEBUG
        printk(KERN_INFO "aes-gcm: Sent %d bytes to the user\n", error_count);
        #endif //DEBUG
        return(error_count=0); // clear the position to the start and return 0
    }else{
        printk(KERN_INFO "aes-gcm: Failed to send %d bytes to the user\n", error_count);
        return -EFAULT; //Failed -- return a bad address message (i.e. -14)
    }

    return 0;
}

/** @brief Write function
 * This function is called when ever the device is being written to from user space i.e.
 * data is sent to the device from the user. The data is copied to the message[] array in this LKM using
 * the sprintf() function along with the length of the string.
 * @param filep A pointer to a file object
 * @param buffer The buffer to that contains the string to write to the device
 * @param len The length of the array of data that is being passed in the const char buffer (in bytes)
 * @param offset The offset if required
 */
static ssize_t dev_write(struct file* filep, const char* buffer, size_t len, loff_t* offset){
    struct aes_gcm_data *lp;
    lp = filep->private_data;
    int i = 0;

    //Get data from user to kernel spaces
    if(copy_from_user(ker_buff, buffer, len))
        return -EFAULT;
    ker_buff_len = len/4; //store number of uint32

    if(ker_buff_len < 2) { //select buffer, len <= 2 bytes
        sel_buffer = ker_buff[0];
        #ifdef DEBUG
        printk("aes-gcm: Select op: %d\n", sel_buffer);
        #endif //DEBUG
        if(sel_buffer == 5) {
            //call encryption mode
            output = (uint32_t*)kmalloc(sizeof(uint32_t) * input_len, GFP_KERNEL);
            tag = (uint32_t*)kmalloc(sizeof(uint32_t) * 4, GFP_KERNEL);
            hw_aes_gcm_encrypt(lp, 1, output, input, input_len, key, key_len, iv, aad, aad_len, tag);
        }
        if(sel_buffer == 6) {
            //call decryption mode
            output = (uint32_t*)kmalloc(sizeof(uint32_t) * input_len, GFP_KERNEL);
            hw_aes_gcm_encrypt(lp, 0, output, input, input_len, key, key_len, iv, aad, aad_len, tag);
        }
    }
    else {
        switch(sel_buffer) {
            case 0:
                key = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                for(i=0; i<ker_buff_len; i=i+1)
                    key[i] = ker_buff[i];
                if(ker_buff_len == 8)
                    key_len = AES_256_BIT_KEY;
                if(ker_buff_len == 4)
                    key_len = AES_128_BIT_KEY;
                #ifdef DEBUG
                printk(KERN_INFO "aes-gcm: Set key - 0x%08x%08x%08x%08x\n", *(key), *(key+1), *(key+2), *(key+3));
                printk(KERN_INFO "aes-gcm: Set key - 0x%08x%08x%08x%08x\n", *(key+4), *(key+5), *(key+6), *(key+7));
                #endif //DEBUG
                printk(KERN_INFO "aes-gcm: [0] key in driver with length - %d\n", ker_buff_len);
                break;
            case 1:
                //Get data from user to kernel spaces
                iv = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                for(i=0; i<ker_buff_len; i=i+1)
                    iv[i] = ker_buff[i];
                printk(KERN_INFO "aes-gcm: [1] iv in driver");
                break;
            case 2:
                //Get data from user to kernel spaces
                input = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                for(i=0; i<ker_buff_len; i=i+1)
                    input[i] = ker_buff[i];
                input_len = ker_buff_len; //len in bytes
                #ifdef DEBUG
                for (i = 0; i < input_len; i++)
                {
                    printk("aes-gcm: input - 0x%08x%08x%08x%08x\n", input[i], input[i+1], input[i+2], input[i+3]);
                    i = i + 3;
                }
                #endif //DEBUG
                printk(KERN_INFO "aes-gcm: [2] input in driver with length %d", input_len);
                break;
            case 3:
                //Get data from user to kernel spaces
                aad = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                for(i=0; i<ker_buff_len; i=i+1)
                    aad[i] = ker_buff[i];
                aad_len = ker_buff_len; //len in bytes
                #ifdef DEBUG
                printk(KERN_INFO "aes-gcm: Set aad - 0x%08x%08x%08x%08x\n", *(aad), *(aad+1), *(aad+2), *(aad+3));
                printk(KERN_INFO "aes-gcm: Set aad - 0x%08x%08x%08x%08x\n", *(aad+4), *(aad+5), *(aad+6), 0x0);
                #endif //DEBUG
                printk(KERN_INFO "aes-gcm: [3] aad in driver with length %d", aad_len);
                break;
            case 4:
                //Get data from user to kernel spaces
                tag = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                for(i=0; i<ker_buff_len; i=i+1)
                    tag[i] = ker_buff[i];
                printk(KERN_INFO "aes-gcm: [4] tag in driver");
                break;
            default:
                printk(KERN_INFO "aes-gcm: [error] Cannot decide what to do - Select again");
        }
    }
    return len;
}

/** @brief A module must use the module_init() and module_exit() macros from linux/init.h, which 
 * identify the initialization function at insertion time and the cleanup function (as listed above)
 */
module_init(aes_gcm_init);
module_exit(aes_gcm_exit);