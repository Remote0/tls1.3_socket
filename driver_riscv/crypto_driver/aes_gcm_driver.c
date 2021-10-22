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

#define DEVICE_NAME "aes-gcm"      //The dev will appear at /dev/aes-gcm using this value, and also in /proc/devices /proc/iomem
#define CLASS_NAME  "crypto"          //The device class -- this is a character device driver

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiet Dang");         //The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple aes-gcm platform device"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

//GUIDE: search google hook platform device to character driver -> xilinx video part 2

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
static unsigned int* kernel_buff;
static int kernel_buff_len;
static unsigned int* ker_buff;   
static short ker_buff_len;

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

void hw_aes_gcm_set_aad (struct aes_gcm_data* aes_gcm, uint32_t* aad){
    iowrite32(aad[0], aes_gcm->base_addr + AES_GCM_IAAD_0);
    iowrite32(aad[1], aes_gcm->base_addr + AES_GCM_IAAD_1);
    iowrite32(aad[2], aes_gcm->base_addr + AES_GCM_IAAD_2);
    iowrite32(aad[3], aes_gcm->base_addr + AES_GCM_IAAD_3);
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

void hw_aes_gcm_set_block (struct aes_gcm_data* aes_gcm, uint32_t* block ){
    iowrite32(block[0], aes_gcm->base_addr + AES_GCM_IBLOCK_0);
    iowrite32(block[1], aes_gcm->base_addr + AES_GCM_IBLOCK_1);
    iowrite32(block[2], aes_gcm->base_addr + AES_GCM_IBLOCK_2);
    iowrite32(block[3], aes_gcm->base_addr + AES_GCM_IBLOCK_3);
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
    iowrite32(1, aes_gcm->base_addr + AES_GCM_IAAD_VALID);
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

void hw_aes_gcm_encrypt(struct aes_gcm_data* aes_gcm, uint32_t * output, uint32_t * input, int input_length, uint32_t* key, const size_t key_len, uint32_t * iv, const size_t iv_len, uint32_t * aad, const size_t aad_len,uint32_t * tag, int tag_len){
    hw_aes_gcm_clear_block(aes_gcm);
    hw_aes_gcm_clear_aad(aes_gcm);
    hw_aes_gcm_clear_iiv(aes_gcm);
    hw_aes_gcm_clear_tag(aes_gcm);
    hw_aes_gcm_clear_key(aes_gcm);

    printk(KERN_INFO "aes-gcm: Set Key an IV\n");
    //Generate HashKey
    if(key_len==8){
        hw_aes_gcm_set_key(aes_gcm,key, AES_256_BIT_KEY);
    } 
    if(iv_len == 3){
        hw_aes_gcm_set_iiv(aes_gcm,iv);
    }
    printk(KERN_INFO "aes-gcm: Generate HahsKey\n");

    hw_aes_gcm_ctrl(aes_gcm,1,0,1,0); //start aes-gcm -- init:1 - next:0 - encdec:1 - aad_only:0
    hw_aes_gcm_ctrl(aes_gcm,1,1,1,0); //rising next   -- init:1 - next:1 - encdec:1 - aad_only:0
    hw_aes_gcm_wait_ready(aes_gcm);   //wait for creating Hashkey
    hw_aes_gcm_ctrl(aes_gcm,1,0,1,0); //lower next for next step

    printk(KERN_INFO "aes-gcm: HashKey Done - Compute AAD\n");
    int i = 0;
    for (i=0; i< ((aad_len+3)/4);i++){ //round up, TODO: need improve 
        hw_aes_gcm_set_aad(aes_gcm, aad+(i*4));
        hw_aes_gcm_ctrl(aes_gcm,1,1,1,0); //rising next to start aad compute
        //hw_aes_gcm_wait_ready(aes_gcm);
        hw_aes_gcm_ctrl(aes_gcm,1,0,1,0); //lower next for next step
    }

    hw_aes_gcm_clear_aad(aes_gcm); //no more aad, go to next step
    printk(KERN_INFO "aes-gcm: AAD Done - Compute Ciphertext\n");

    for (i=0; i< input_length/4;i++){
        hw_aes_gcm_set_block(aes_gcm,input+(i*4));
        hw_aes_gcm_ctrl(aes_gcm,1,1,1,0); //rising next to compute cyphertext
        hw_aes_gcm_read_result(aes_gcm,output+(i*4));// get cypher
        hw_aes_gcm_wait_ready(aes_gcm);
        hw_aes_gcm_ctrl(aes_gcm,1,0,1,0); 
    }

    hw_aes_gcm_clear_block(aes_gcm);
    printk(KERN_INFO "aes-gcm: Ciphertext Done - Compute Tag\n");

    uint32_t len [4]= {0x00000000,32*(aad_len),0x00000000,32*input_length}; //TODO: need improve 
    hw_aes_gcm_set_aad(aes_gcm,len);
    hw_aes_gcm_ctrl(aes_gcm,1,1,1,0); //start enc
    hw_aes_gcm_read_tag(aes_gcm,tag); //get tag
    hw_aes_gcm_wait_ready(aes_gcm);
    hw_aes_gcm_ctrl(aes_gcm,1,0,1,0);
    printk(KERN_INFO "aes-gcm: Tag Done\n");

}

void hwaesgcm_selftest(struct aes_gcm_data* aes_gcm){

    uint32_t key[8] = {0xE3C08A8F,0x06C6E3AD,0x95A70557,0xB23F7548,0x3CE33021,0xA9C72B70,0x25666204,0xC69C0B72};
    uint32_t plaintext[12] = {0x08000F10,0x11121314,0x15161718,0x191A1B1C,0x1D1E1F20,0x21222324,0x25262728,0x292A2B2C,0x2D2E2F30,0x31323334,0x35363738,0x393A0002};
    uint32_t aad[8] =   {0xD609B1F0,0x56637A0D,0x46DF998D,0x88E52E00,0xB2C28465,0x12153524,0xC0895E81,0x00000000};
    uint32_t iv[3] = {0x12153524,0xC0895E81,0xB2C28465};
    uint32_t tag [4] ={0,0,0,0};
    uint32_t ciphertext[12];


    //reset
    printk(KERN_INFO "aes-gcm: Reset before encrypt\n");
    hw_aes_gcm_reset (aes_gcm);
    printk(KERN_INFO "aes-gcm: Reset done\n");

    printk(KERN_INFO "aes-gcm: Start Encrypt...\n");
    hw_aes_gcm_encrypt(aes_gcm, ciphertext, plaintext, 12, key, 8, iv, 3, aad, 7, tag, 4);
    printk(KERN_INFO "aes-gcm: Encrypt Done\n");

    int i;
    for (i = 0; i < 12; i++)
    {
        printk(KERN_INFO "aes-gcm: ciphertext - 0x%08x%08x%08x%08x\n", ciphertext[i], ciphertext[i+1], ciphertext[i+2], ciphertext[i+3]);
        i = i + 3;
    }

    printk(KERN_INFO "aes-gcm: otag - 0x%08x%08x%08x%08x\n", tag[0], tag[1],tag[2],tag[3]);
}

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

    //perform test
    printk(KERN_INFO "aes-gcm: Perform Hardware Test...\n");
    hwaesgcm_selftest(lp);
    printk(KERN_INFO "aes-gcm: Hardware Test Done\n");

    //---------
    // //Copy from kernel space to user space
    // //format copy_to_user ( *to, *from, size) and returns 0 on success
    // error_count = copy_to_user(buffer, kernel_buff, kernel_buff_len);
    // if(error_count == 0){
    //     printk(KERN_INFO "aes-gcm: Sent %d characters to the user\n", kernel_buff_len);
    //     return(kernel_buff_len=0); // clear the position to the start and return 0;
    // }else{
    //     printk(KERN_INFO "aes-gcm: Failed to send %d characters to the user\n", error_count);
    //     return -EFAULT; //Failed -- return a bad address message (i.e. -14)
    // }
    return 0;
}

/** @brief Write function
 * This function is called when ever the device is being written to from user space i.e.
 * data is sent to the device from the user. The data is copied to the message[] array in this LKM using
 * the sprintf() function along with the length of the string.
 * @param filep A pointer to a file object
 * @param buffer The buffer to that contains the string to write to the device
 * @param len The length of the array of data that is being passed in the const char buffer
 * @param offset The offset if required
 */
static ssize_t dev_write(struct file* filep, const char* buffer, size_t len, loff_t* offset){
    //Get data from user to kernel space
    if(copy_from_user(ker_buff, buffer, len))
        return -EFAULT;
    //ker_buff_len = strlen(ker_buff);  //store the length of the stored message
    ker_buff_len = sizeof(unsigned int);
    printk(KERN_INFO "aes-gcm: Received %zu characters from the user\n", len);
    printk(KERN_INFO "aes-gcm: Received %d offset\n", *((unsigned int*)ker_buff));
    return len;
}



/** @brief A module must use the module_init() and module_exit() macros from linux/init.h, which 
 * identify the initialization function at insertion time and the cleanup function (as listed above)
 */
module_init(aes_gcm_init);
module_exit(aes_gcm_exit);