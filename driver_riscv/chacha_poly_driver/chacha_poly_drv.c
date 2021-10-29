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

#include "chacha_poly_regs.h"

//#define DEBUG

#define DEVICE_NAME "chacha-poly"      //The dev will appear at /dev/chacha-poly using this value, and also in /proc/devices /proc/iomem
#define CLASS_NAME  "chacha-poly"          //The device class -- this is a character device driver //dont use the same name

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiet Dang");         //The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple chacha-poly platform device"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

// custom struct to hold device data
struct chacha_poly_data {
    //Use for create character device
    struct resource *rmem;
    dev_t devt; //hold major and minor number
    struct class* chacha_poly_class; // The device-driver class struct pointer        //appear in /sys/class/CLASS_NAME
    struct device* chacha_poly_device; // The device-driver device struct pointer
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
static uint32_t ker_buff[50];   
static short ker_buff_len;
static uint32_t sel_buffer = 0;

static uint32_t key[8];
static uint32_t nonce[3];
static uint32_t aad[4];
static uint32_t* input;
static uint32_t input_len;
static uint32_t* output;
static uint32_t mac[4];
static int authentic = 0;

//Function to control chacha_poly  module

void hw_CP_reset(struct chacha_poly_data* cp){
    int i;
    #ifdef DEBUG
    printk(KERN_INFO "chacha-poly: RESET module\n");
    #endif //DEBUG
    //Upload key - key always 256 bits
    for(i = 0; i < 8; i=i+1) {
        iowrite32(0, cp->base_addr + CHACHAPOLY_REG_KEY_0+i*4);
    }
    //Upload nonce - always 96 bits
    for(i = 0; i < 3; i=i+1) {
        iowrite32(0, cp->base_addr + CHACHAPOLY_REG_NONCE_0+i*4);
    }
    for(i=0; i<16; i=i+1){
        iowrite32(0, cp->base_addr + CHACHAPOLY_REG_IN_0+i*4);
    }
    iowrite32(0, cp->base_addr + CHACHAPOLY_REG_BLOCK_LEN);
    iowrite32(0, cp->base_addr + CHACHAPOLY_REG_INIT);
    iowrite32(0, cp->base_addr + CHACHAPOLY_REG_RST_CORE);
    iowrite32(1, cp->base_addr + CHACHAPOLY_REG_RST_CORE);
    #ifdef DEBUG
    printk(KERN_INFO "chacha-poly: RESET done\n");
    #endif //DEBUG
}

void hw_CP_init(struct chacha_poly_data* cp){
    iowrite32(0, cp->base_addr + CHACHAPOLY_REG_RST_CORE);
    iowrite32(1, cp->base_addr + CHACHAPOLY_REG_RST_CORE);
    iowrite32(1, cp->base_addr + CHACHAPOLY_REG_INIT);
    while(1){
        if(ioread32(cp->base_addr + CHACHAPOLY_REG_READY) & 0x1){
            break;
        }
    }
}

void hw_CP_next(struct chacha_poly_data* cp){
    iowrite32(1, cp->base_addr + CHACHAPOLY_REG_NEXT);
    while(1){
        if(ioread32(cp->base_addr + CHACHAPOLY_REG_READY) & 0x1){
            break;
        }
    }
}

void hw_CP_finish_AAD(struct chacha_poly_data* cp){
    iowrite32(1, cp->base_addr + CHACHAPOLY_REG_FINISH);
    while(1){
        if(ioread32(cp->base_addr + CHACHAPOLY_REG_READY) & 0x1){
            break;
        }
    }
}

void hwchacha_polyinit(struct chacha_poly_data* cp, uint32_t* key, uint32_t nonce[3], uint32_t encrytp){
    int i;
    //Upload key - key always 256 bits
    for(i = 0; i < 8; i=i+1) {
        iowrite32(key[i], cp->base_addr + CHACHAPOLY_REG_KEY_0+i*4);
    } 
    //Upload nonce - always 96 bits
    for(i = 0; i < 3; i=i+1) {
        iowrite32(nonce[i], cp->base_addr + CHACHAPOLY_REG_NONCE_0+i*4);
    }
    //Select encryption/decryption
    if(encrytp == 1){
        iowrite32(1, cp->base_addr + CHACHAPOLY_REG_ENCRIPT_AEAD);  
    }else{
        iowrite32(0, cp->base_addr + CHACHAPOLY_REG_ENCRIPT_AEAD);  
    }
    hw_CP_init(cp);  
}

void hwchacha_polyAAD(struct chacha_poly_data* cp, uint32_t* AAD, int len_AAD){
    //Upload AAD - maximum is 128bits
    int i;
    for(i=0; i<4; i=i+1){
        iowrite32(AAD[i], cp->base_addr + CHACHAPOLY_REG_AAD_0+i*4);
    }
    //Update the len of AAD
    iowrite32(len_AAD, cp->base_addr + CHACHAPOLY_REG_BLOCK_LEN);
    hw_CP_next(cp);
}

void hwchacha_polyText_add_finish(struct chacha_poly_data* cp, uint32_t plain_text[16], int len_plain_text ){
    //Upload PlainText - process 16x32 = 512 bits at a time
    int i;
    for(i=0; i<16; i=i+1){
        iowrite32(plain_text[i], cp->base_addr + CHACHAPOLY_REG_IN_0+i*4);
    }

    //Update the len of the plaintext
    iowrite32(len_plain_text, cp->base_addr + CHACHAPOLY_REG_BLOCK_LEN);
    hw_CP_finish_AAD(cp);
}

void hwchacha_polyText(struct chacha_poly_data* cp, uint32_t plain_text[16], int len_plain_text ){
    //Upload PlainText - process 16x32 = 512 bits at a time
    int i;
    for(i=0; i<16; i=i+1){
        iowrite32(plain_text[i], cp->base_addr + CHACHAPOLY_REG_IN_0+i*4);
    }

    //Update the len of the plaintext
    iowrite32(len_plain_text, cp->base_addr + CHACHAPOLY_REG_BLOCK_LEN);
    hw_CP_next(cp);
}

void hwCP_read_results(struct chacha_poly_data* cp, uint32_t* result){
    // *output = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_0);
    // *(output+1) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_1);
    // *(output+2) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_2);
    // *(output+3) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_3);
    // *(output+4) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_4);
    // *(output+5) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_5);
    // *(output+6) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_6);
    // *(output+7) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_7);
    // *(output+8) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_8);
    // *(output+9) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_9);
    // *(output+10) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_10);
    // *(output+11) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_11);
    // *(output+12) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_12);
    // *(output+13) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_13);
    // *(output+14) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_14);
    // *(output+15) = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_15);
    result[0] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_0);
    result[1] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_1);
    result[2] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_2);
    result[3] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_3);
    result[4] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_4);
    result[5] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_5);
    result[6] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_6);
    result[7] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_7);
    result[8] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_8);
    result[9] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_9);
    result[10] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_10);
    result[11] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_11);
    result[12] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_12);
    result[13] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_13);
    result[14] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_14);
    result[15] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_15);
}

uint32_t hwCP_read_ready(struct chacha_poly_data* cp){
    if(ioread32(cp->base_addr + CHACHAPOLY_REG_READY) & 0x1){
        return 1;
    }else{
        return 0;
    }
}

void hwCP_results(struct chacha_poly_data* cp){
    output[0] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_0);
    output[1] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_1);
    output[2] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_2);
    output[3] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_3);
    output[4] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_4);
    output[5] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_5);
    output[6] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_6);
    output[7] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_7);
    output[8] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_8);
    output[9] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_9);
    output[10] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_10);
    output[11] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_11);
    output[12] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_12);
    output[13] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_13);
    output[14] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_14);
    output[15] = ioread32(cp->base_addr + CHACHAPOLY_REG_OUT_15);
}

void hwCP_read_mac(struct chacha_poly_data* cp, uint32_t* out_mac){
    out_mac[0] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_0);
    out_mac[1] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_1);
    out_mac[2] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_2);
    out_mac[3] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_3);
}

void hwCP_results_mac(struct chacha_poly_data* cp){
    mac[0] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_0);
    mac[1] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_1);
    mac[2] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_2);
    mac[3] = ioread32(cp->base_addr + CHACHAPOLY_REG_MAC_3);
}

int hwchacha_poly_start(struct chacha_poly_data* cp, uint32_t mode, uint32_t* output, uint32_t* mac, uint32_t* input, uint32_t input_len, uint32_t* key, uint32_t* nonce, uint32_t* aad){
    uint32_t out_mac[4];
    int i = 0;
    uint32_t process_len = input_len;
    uint32_t* pos = input;
    

    if(mode == 1)
        {printk(KERN_INFO "chacha-poly: Start chacha-poly in encryption mode\n");}
    else
         {printk(KERN_INFO "chacha-poly: Start chacha-poly in decryption mode\n");}

    //Poly Key Auto-Gen
    hwchacha_polyinit(cp, key, nonce, mode);
    printk(KERN_INFO "chacha-poly: Initalize chacha-poly\n");
    //AAD
    hwchacha_polyAAD(cp, aad, 12);    
    printk(KERN_INFO "chacha-poly: AAD Done - compute input...\n");
    //Finish AAD

    //process input block - 64bytes = 16uint32_t at a time
    while(process_len > 64) {
        hwchacha_polyText_add_finish(cp,pos + i,64);
        hwCP_read_results(cp, output + i); //read result
        #ifdef DEBUG
        printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i],output[i+1],output[i+2],output[i+3]);
        printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i+4],output[i+5],output[i+6],output[i+7]);
        printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i+8],output[i+9],output[i+10],output[i+11]);
        printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i+12],output[i+13],output[i+14],output[i+15]);
        printk(KERN_INFO "chacha-poly: process_len - %d\n", 64);
        #endif //DEBUG
        process_len = process_len-64;
        i = i + 16;
    }

    //last block
    #ifdef DEBUG
    printk(KERN_INFO "chacha-poly: Block Done\n");
    printk(KERN_INFO "chacha-poly: last process_len - %d\n", process_len);
    #endif //DEBUG

    hwchacha_polyText(cp,pos + i, process_len);
    hwCP_read_results(cp, output + i); //read last result
    #ifdef DEBUG
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i],output[i+1],output[i+2],output[i+3]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i+4],output[i+5],output[i+6],output[i+7]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i+8],output[i+9],output[i+10],output[i+11]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", output[i+12],output[i+13],output[i+14],output[i+15]);
    printk(KERN_INFO "chacha-poly: Last Block Done\n");
    #endif //DEBUG
   
    printk(KERN_INFO "chacha-poly: Output done - compute mac...\n");

    //Finish 
    hw_CP_finish_AAD(cp);
    printk(KERN_INFO "chacha-poly: mac done\n");


    if(mode == 1){
        hwCP_read_mac(cp, mac); //read mac
        #ifdef DEBUG
        printk(KERN_INFO "chacha-poly: mac - 0x%08x%08x%08x%08x\n", mac[0],mac[1],mac[2],mac[3]);
        #endif //DEBUG
    }else{
        hwCP_read_mac(cp, out_mac); //read mac
        for(i=0;i<4;i=i+1){
            if(out_mac[i] != mac[i]) {
                printk(KERN_INFO "chacha-poly: omac - 0x%08x%08x%08x%08x\n", out_mac[0],out_mac[1],out_mac[2],out_mac[3]);
                printk(KERN_INFO "chacha-poly: Authentication failed\n");
                return -1;
            }
        }
        printk(KERN_INFO "chacha-poly: Authentic decryption\n");
    }
    
    return 0;
}

#ifdef DEBUG
void hwchacha_poly_selftest(struct chacha_poly_data* cp){
    uint32_t key_test [8]   = {0x80818283,0x84858687,0x88898a8b,0x8c8d8e8f,0x90919293,0x94959697,0x98999a9b,0x9c9d9e9f};
    uint32_t nonce_test [3] = {0x07000000,0x40414243,0x44454647};
    uint32_t AAD_test [4] = {0x50515253,0xc0c1c2c3,0xc4c5c6c7,0x00000000};
    uint32_t plain_test [16]  ={0x4c616469,0x65732061,0x6e642047,0x656e746c,
                                0x656d656e,0x206f6620,0x74686520,0x636c6173,
                                0x73206f66,0x20273939,0x3a204966,0x20492063,
                                0x6f756c64,0x206f6666,0x65722079,0x6f75206f};     
    uint32_t plain_test_2 [16]={0x6e6c7920,0x6f6e6520,0x74697020,0x666f7220,
                                0x74686520,0x66757475,0x72652c20,0x73756e73,
                                0x63726565,0x6e20776f,0x756c6420,0x62652069,
                                0x742e0000,0x00000000,0x00000000,0x00000000};

    uint32_t cipher1[16] = {0xd31a8d34, 0x648e60db, 0x7b86afbc, 0x53ef7ec2,
                    0xa4aded51, 0x296e08fe, 0xa9e2b5a7, 0x36ee62d6,
                    0x3dbea45e, 0x8ca96712, 0x82fafb69, 0xda92728b,
                    0x1a71de0a, 0x9e060b29, 0x05d6a5b6, 0x7ecd3b36};

    uint32_t cipher2[16] = {0x92ddbd7f, 0x2d778b8c, 0x9803aee3, 0x28091b58,
                    0xfab324e4, 0xfad67594, 0x5585808b, 0x4831d7bc,
                    0x3ff4def0, 0x8e4b7a9d, 0xe576d265, 0x86cec64b,
                    0x61160000, 0x00000000, 0x00000000, 0x00000000};

    uint32_t result[16];
    uint32_t result2[16];
    uint32_t omac[4];
    //Poly Key Auto-Gen
    hwchacha_polyinit(cp, key_test, nonce_test, 1);

    //AAD
    hwchacha_polyAAD(cp,AAD_test,12);

    //Finish AAD
    hwchacha_polyText_add_finish(cp,plain_test,64);

    //Print Cipher_1
    hwCP_read_results(cp,result);
    printk(KERN_INFO "chacha-poly: cipher - first read\n");
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result[0],result[1],result[2],result[3]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result[4],result[5],result[6],result[7]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result[8],result[9],result[10],result[11]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result[12],result[13],result[14],result[15]);

    //PlainText_2
    hwchacha_polyText(cp,plain_test_2,50);
    //Print Cipher_2
    hwCP_read_results(cp,result2);
    printk(KERN_INFO "chacha-poly: cipher - second read\n");
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result2[0],result2[1],result2[2],result2[3]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result2[4],result2[5],result2[6],result2[7]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result2[8],result2[9],result2[10],result2[11]);
    printk(KERN_INFO "chacha-poly: cipher - 0x%08x%08x%08x%08x\n", result2[12],result2[13],result2[14],result2[15]);

    //Finish Block
    hw_CP_finish_AAD(cp);

    //Print Mac
    
    hwCP_read_mac(cp,omac);
    printk(KERN_INFO "chacha-poly: mac - 0x%08x%08x%08x%08x\n", omac[0],omac[1],omac[2],omac[3]);
    printk(KERN_INFO "chacha-poly: RESET MODULE\n"); 
    hw_CP_reset(cp);
    printk(KERN_INFO "chacha-poly: RESET DONE\n"); 

    //---------------------Decrypt------------------------
    
    //Poly Key Auto-Gen
    hwchacha_polyinit(cp, key_test, nonce_test, 0);

    //AAD
    hwchacha_polyAAD(cp,AAD_test,12);

    //Finish AAD
    hwchacha_polyText_add_finish(cp,cipher1,64);
    
    //Print Cipher_1
    hwCP_read_results(cp,result);
    printk(KERN_INFO "chacha-poly: result - first read\n");
    printk(KERN_INFO "chacha-poly: result - 0x%08x%08x%08x%08x\n", result[0],result[1],result[2],result[3]);
    printk(KERN_INFO "chacha-poly: result - 0x%08x%08x%08x%08x\n", result[4],result[5],result[6],result[7]);
    printk(KERN_INFO "chacha-poly: result - 0x%08x%08x%08x%08x\n", result[8],result[9],result[10],result[11]);
    printk(KERN_INFO "chacha-poly: result - 0x%08x%08x%08x%08x\n", result[12],result[13],result[14],result[15]);

    //PlainText_2
    hwchacha_polyText(cp,cipher2,50);
    //Print Cipher_2
    hwCP_read_results(cp,result2);
    printk(KERN_INFO "chacha-poly: result2 - second read\n");
    printk(KERN_INFO "chacha-poly: result2 - 0x%08x%08x%08x%08x\n", result2[0],result2[1],result2[2],result2[3]);
    printk(KERN_INFO "chacha-poly: result2 - 0x%08x%08x%08x%08x\n", result2[4],result2[5],result2[6],result2[7]);
    printk(KERN_INFO "chacha-poly: result2 - 0x%08x%08x%08x%08x\n", result2[8],result2[9],result2[10],result2[11]);
    printk(KERN_INFO "chacha-poly: result2 - 0x%08x%08x%08x%08x\n", result2[12],result2[13],result2[14],result2[15]);

    //Finish Block
    hw_CP_finish_AAD(cp);

    //Print Mac
    hwCP_read_mac(cp,omac);
    printk(KERN_INFO "chacha-poly: mac - 0x%08x%08x%08x%08x\n", omac[0],omac[1],omac[2],omac[3]);
}
#endif //DEBUG
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

static int chacha_poly_probe( struct platform_device *pdev){

    struct chacha_poly_data *lp = NULL;
    int ret = 0;

    printk(KERN_INFO "chacha-poly: Device Tree Probing...\n");

    //Assign chacha_poly_data to platform device data:
    lp = (struct chacha_poly_data*)kmalloc(sizeof(struct chacha_poly_data), GFP_KERNEL);
    if(!lp) {
        printk(KERN_ALERT "chacha-poly: Could not allocate mychar device\n");
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
    printk(KERN_INFO "chacha-poly: devm platform ioremap - vir. baseaddr: 0x%lx\n", (long unsigned int)(lp->base_addr));
    
    lp->numberOpens = 0;

    // TODO: Perform module reset
    

    // ************************ NORMAL Device driver *************************** //
    /** The main reason to do this is to create a device /dev/chacha-poly 
     *  It is a character device node exposing our userspace API
     *  It also simplies memory management.
     */

    INIT_LIST_HEAD(&lp->device_entry);

    printk(KERN_INFO "chacha-poly: Initializing chacha-poly char-driver\n");
    //Register a range of char device number
    /**Format: alloc_chrdev_region(dev_t* dev, uint firstminor, uint count, char* name)
    *dev_t* dev: store the major and minor number (use marcros MAJOR(dev_t), MINOR(dev_t) to get the coresponding number)
    *char* name: is the name of the device that should be associated with this number range (will appear in /proc/devices)
    */
    if(alloc_chrdev_region(&lp->devt, 0, 1, DEVICE_NAME) < 0){
        printk(KERN_ALERT "chacha-poly failed to register a major number\n");
        return -1;
    }
    printk(KERN_INFO "chacha-poly: asssigned correctly with major number %d and minor number %d\n", MAJOR(lp->devt), MINOR(lp->devt));

    //Register the device class
    lp->chacha_poly_class = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(lp->chacha_poly_class)) {     //Check for error and clean up if there is
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(lp->chacha_poly_class);  // Correct way to return an error on a pointer
    }
    //Register the device driver
    lp->chacha_poly_device = device_create(lp->chacha_poly_class, NULL, lp->devt, NULL, DEVICE_NAME);
    if(IS_ERR(lp->chacha_poly_device)) {         //Clean up if there is an error
        class_unregister(lp->chacha_poly_class);
        class_destroy(lp->chacha_poly_class);    //Repeated code but the alternative is goto statements
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(lp->chacha_poly_device);
    }
    printk(KERN_INFO "chacha-poly: Device class registered & created correctly\n");

    cdev_init(&lp->c_dev, &fops);
    if(cdev_add(&lp->c_dev, lp->devt, 1) == -1){
        device_destroy(lp->chacha_poly_class, lp->devt);
        class_unregister(lp->chacha_poly_class);
        class_destroy(lp->chacha_poly_class);
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Create character device failed\n");
    }
    printk(KERN_INFO "chacha-poly: Initialize cdev correctly\n");
    
    list_add(&lp->device_entry, &device_list);
    
    // ************************ NORMAL Device driver *************************** //


    return 0;
}

static int chacha_poly_remove(struct platform_device *pdev) {
    struct chacha_poly_data *lp = platform_get_drvdata(pdev);

    //delete character driver
    cdev_del(&lp->c_dev);
    device_destroy(lp->chacha_poly_class, lp->devt);
    class_unregister(lp->chacha_poly_class); //MUST UNREGSITER BEFORE DESTROY
    class_destroy(lp->chacha_poly_class); //Something happen in class destroy or unregister
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
static const struct of_device_id chacha_poly_of_match[]= {
    { .compatible = "uec,chacha_poly-0", },
    { /* end of list */ },
};
MODULE_DEVICE_TABLE(of, chacha_poly_of_match);

static struct platform_driver chacha_poly_driver = {
    .driver                 = {
            .name           = DEVICE_NAME,
            .owner          = THIS_MODULE,
            .of_match_table = chacha_poly_of_match,
    },
    .probe                  = chacha_poly_probe,
    .remove                 = chacha_poly_remove,
};

/* ============================================================================================ */
/* ============================================================================================ */

/** @brief Initialization function
*   The static keyword restricts the visibility of the function to within this C file.
*   The __init marcro means that for a built-in driver, the fucntion is only used at initialization
*   time and that it can be discarded and its memory freed up after that point.
*   @return returns 0 if successful
*/
static int __init chacha_poly_init(void){
    printk(KERN_INFO "chacha-poly: Hello module world.\n");
    return platform_driver_register(&chacha_poly_driver);
}

/** @brief Cleanup function
*   Similar to initialization, it is static.
*   The __exit macro notifies that if this code is used for a built-in driver
*   that this function is not required.
*/
static void __exit chacha_poly_exit(void){
    platform_driver_unregister(&chacha_poly_driver);
    printk(KERN_INFO "chacha-poly: Goodbye from the LKM!\n");
}

/** @brief Open function
 *  The open function is called each time the device is opened
 *  This will search for platform data in the linked list and give it to device file
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode* inodep, struct file* filep){
    //This is the way to pass platform data to device file
    struct chacha_poly_data *lp;
    list_for_each_entry(lp, &device_list, device_entry) {
        if(lp->devt == inodep->i_rdev) {
            break;
        }
    }
    filep->private_data = lp;
    stream_open(inodep, filep);

    lp->numberOpens++;
    printk(KERN_INFO "chacha-poly: Device has been open %d time(s)\n", lp->numberOpens);
    return 0;
}

/** @brief Release function
 * The device release function that is called whenever the device is closed/released by the userspace program
 * @param inodep A pointer to an inode object (defined in linux/fs.h)
 * @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode* inodep, struct file* filep){
    struct chacha_poly_data *lp;
    lp = filep->private_data;
    filep->private_data = NULL;
    printk(KERN_INFO "chacha-poly: Device successfully closed\n");
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
    struct chacha_poly_data *lp;
    uint32_t status = 0;
    int error_count = 0;
    int send_byte;

    lp = filep->private_data;
    //hwchacha_poly_selftest(lp);

    switch(sel_buffer){
        case 7: //read output
            send_byte = input_len;
            output[input_len/4] = output[input_len/4] >> ((input_len%4)*8);
            error_count = copy_to_user(buffer, output, send_byte);
            printk(KERN_INFO "chacha-poly: [7] read output\n");
            kfree(output);
            kfree(input);
            hw_CP_reset(lp); //reset after run
            break;
        case 8: //read mac
            send_byte = 4*4;
            error_count = copy_to_user(buffer, mac, send_byte);
            printk(KERN_INFO "chacha-poly: [8] read mac\n");
            break;
        case 9: //read authentic
            send_byte = 4;
            error_count = copy_to_user(buffer, &authentic, 4);
            authentic = 0;
            printk(KERN_INFO "chacha-poly: [9] read authenic\n");
            break;
        case 10:
            send_byte = 4;
            status = hwCP_read_ready(lp);
            error_count = copy_to_user(buffer, &status, 4);
            printk(KERN_INFO "chacha-poly: [10] read ready\n");
            break;
    }

    if(error_count == 0){
        #ifdef DEBUG
        printk(KERN_INFO "chacha-poly: Sent %d bytes to the user\n", error_count);
        #endif //DEBUG
        return(error_count=0); // clear the position to the start and return 0
    }else{
        printk(KERN_INFO "chacha-poly: Failed to send %d bytes to the user\n", error_count);
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
    struct chacha_poly_data *lp;
    int i = 0;

    lp = filep->private_data;

    //Get data from user to kernel spaces
    if(copy_from_user(ker_buff, buffer, len))
        return -EFAULT;
    ker_buff_len = len/4; //store number of uint32
    
    if(ker_buff_len < 2) { //select buffer, len <= 2 bytes
        sel_buffer = ker_buff[0];
        #ifdef DEBUG
        printk("chacha-poly: Select op: %d\n", sel_buffer);
        #endif //DEBUG
        switch(sel_buffer){
            case 5:
                hwchacha_poly_start(lp, 1,output, mac,input, input_len, key,nonce, aad);
                break;
            case 6:
                authentic = hwchacha_poly_start(lp, 0,output, mac,input, input_len, key,nonce, aad);
                break;
        }
    }
    else {
        switch(sel_buffer) {
            case 0:
                for(i=0; i<8; i=i+1)
                    key[i] = ker_buff[i];
                #ifdef DEBUG
                printk(KERN_INFO "chacha-poly: Set key - 0x%08x%08x%08x%08x\n", *(key), *(key+1), *(key+2), *(key+3));
                printk(KERN_INFO "chacha-poly: Set key - 0x%08x%08x%08x%08x\n", *(key+4), *(key+5), *(key+6), *(key+7));
                #endif //DEBUG
                printk(KERN_INFO "chacha-poly: [0] key in driver \n");
                break;
            case 1:
                for(i=0; i<3; i=i+1)
                    nonce[i] = ker_buff[i];
                printk(KERN_INFO "chacha-poly: [1] nonce in driver");
                break;
            case 2:
                if((len%4) == 0){
                    input = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                    output = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                }else{
                    ker_buff_len = ker_buff_len + 1;
                    input = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                    output = (uint32_t*)kmalloc(sizeof(uint32_t) * ker_buff_len, GFP_KERNEL);
                }
                for(i=0; i<ker_buff_len; i=i+1) 
                    {input[i] = 0; output[i] = 0;}
                #ifdef DEBUG
                printk("chacha-poly: Create & reset in/out buffer\n");
                #endif //DEBUG
                for(i=0; i<ker_buff_len; i=i+1) {
                    if(i == (ker_buff_len-1)) {
                        input[i] = ker_buff[i] << ((len%4)*8); //last block process it len%4 != 0
                    }
                    else
                        input[i] = ker_buff[i];
                    ker_buff[i] = 0;
                }
                input_len = len; //number in bytes
                #ifdef DEBUG
                for (i = 0; i < ker_buff_len; i++)
                {
                    printk("chacha-poly: input - 0x%08x%08x%08x%08x\n", input[i], input[i+1], input[i+2], input[i+3]);
                    i = i + 3;
                }
                #endif //DEBUG
                printk(KERN_INFO "chacha-poly: [2] input in driver with length %d(bytes)", input_len);
                break;
            case 3:
                for(i=0; i<4; i=i+1)
                    aad[i] = ker_buff[i];
                #ifdef DEBUG
                printk(KERN_INFO "chacha-poly: Set aad - 0x%08x%08x%08x%08x\n", *(aad), *(aad+1), *(aad+2), *(aad+3));
                #endif //DEBUG
                printk(KERN_INFO "chacha-poly: [3] aad in driver\n");
                break;
            case 4:
                for(i=0; i<4; i=i+1)
                    mac[i] = ker_buff[i];
                #ifdef DEBUG
                printk(KERN_INFO "chacha-poly: Set mac - 0x%08x%08x%08x%08x\n", *(mac), *(mac+1), *(mac+2), *(mac+3));
                #endif //DEBUG
                printk(KERN_INFO "chacha-poly: [4] mac in driver");
                break;
            default:
                printk(KERN_INFO "chacha-poly: [error] Cannot decide what to do - Select again");
        }
    }
    return len;
    return 0;
}

/** @brief A module must use the module_init() and module_exit() macros from linux/init.h, which 
 * identify the initialization function at insertion time and the cleanup function (as listed above)
 */
module_init(chacha_poly_init);
module_exit(chacha_poly_exit);