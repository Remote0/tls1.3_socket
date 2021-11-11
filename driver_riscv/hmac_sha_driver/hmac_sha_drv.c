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

#include "hmac_sha_regs.h"

//#define DEBUG

#define DEVICE_NAME "hmac-sha"      //The dev will appear at /dev/hmac-sha using this value, and also in /proc/devices /proc/iomem
#define CLASS_NAME  "hmac-sha"          //The device class -- this is a character device driver //dont use the same name

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiet Dang");         //The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple hmac-sha platform device"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

// custom struct to hold device data
struct hmac_sha_data {
    //Use for create character device
    struct resource *rmem;
    dev_t devt; //hold major and minor number
    struct class* hmac_sha_class; // The device-driver class struct pointer        //appear in /sys/class/CLASS_NAME
    struct device* hmac_sha_device; // The device-driver device struct pointer
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
static uint64_t ker_buff[300];   
static short ker_buff_len;
static uint32_t sel_buffer = 0;

static uint64_t key[8]; //512-bit before padding
static uint64_t* input;
static uint64_t msg[16];
static uint32_t input_len;
uint64_t msj_len[2] = {0, 176}; //fix value

static int mode = 0; //sha-1, hmac-2
static int sha_mode = 0;

static uint32_t* mac;
static uint32_t mac_len = 0;

//Function to control hmac-sha module
/*3’b100: 512-bits mode
 3’b010: 384-bits mode
 3’b001: 256-bits mode*/

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

void hmacsha_reset(struct hmac_sha_data* hs) {
    iowrite32(0, hs->base_addr + HMAC_SHA_REG_RESETN);
    //printk(KERN_INFO "hmac-sha: reset 1\n");
    iowrite32(0, hs->base_addr + HMAC_SHA_REG_ENABLE);
    //printk(KERN_INFO "hmac-sha: reset 2\n");
    iowrite32(0, hs->base_addr + HMAC_SHA_REG_END_PACKET);
    //printk(KERN_INFO "hmac-sha: reset 3\n");
    iowrite32(0, hs->base_addr + HMAC_SHA_REG_CONF_WE);
    //printk(KERN_INFO "hmac-sha: reset 4\n");
    iowrite32(1, hs->base_addr + HMAC_SHA_REG_RESETN);
    //printk(KERN_INFO "hmac-sha: reset 5\n");
}

void hmacsha_write_conf(struct hmac_sha_data* hs, uint32_t addr, uint64_t data)
{
    uint32_t temp;
    iowrite32(addr, hs->base_addr + HMAC_SHA_REG_CONF_ADDRESS);
    temp = (uint32_t)((data >> 32) & 0xFFFFFFFF);
    iowrite32(temp, hs->base_addr + HMAC_SHA_REG_CONF_DATA_0);
    temp = (uint32_t)(data & 0xFFFFFFFF);
    iowrite32(temp, hs->base_addr + HMAC_SHA_REG_CONF_DATA_1);
    iowrite32(1, hs->base_addr + HMAC_SHA_REG_CONF_WE);
    iowrite32(0, hs->base_addr + HMAC_SHA_REG_CONF_WE);
}

void hmacsha_end_packet(struct hmac_sha_data* hs)
{
    iowrite32(1, hs->base_addr + HMAC_SHA_REG_END_PACKET);
    iowrite32(0, hs->base_addr + HMAC_SHA_REG_END_PACKET);
}

void hmacsha_set_key(struct hmac_sha_data* hs, uint64_t *key)
{
    int i;
    /*always assume key of 512 bits/64 bytes, need to verify by software*/
    for (i = 0; i < 8; i++)
    {
        hmacsha_write_conf(hs, ADDR_KEY0 + i, key[i]);
    }
}

void hmacsha_set_len(struct hmac_sha_data* hs, uint64_t *msj_len)
{
    
    hmacsha_write_conf(hs, ADDR_MSGLENH, msj_len[0]);
    hmacsha_write_conf(hs, ADDR_MSGLENL, msj_len[1]);
}

void hmacsha_write_status(struct hmac_sha_data* hs, int mode, int submode)
{
    uint64_t config = (mode<<3 | submode ) & 0x0000001F;
    hmacsha_write_conf(hs, ADDR_STATUS, config);
}

uint32_t hmacsha_read_ready(struct hmac_sha_data* hs)
{
    if(ioread32(hs->base_addr+HMAC_SHA_REG_READY) == 1){
        return 1;
    }else{
        return 0;
    }
}

uint32_t hmacsha_read_input_ready(struct hmac_sha_data* hs)
{
    if(ioread32(hs->base_addr+HMAC_SHA_REG_INPUT_READY) == 1){
        return 1;
    }else{
        return 0;
    }
}

void hmacsha_enable(struct hmac_sha_data* hs)
{
    iowrite32(1, hs->base_addr + HMAC_SHA_REG_ENABLE);
}

void hmacsha_msj(struct hmac_sha_data* hs, uint64_t *msg)
{
    int i;
    for(i=0; i<16;i++){
        hmacsha_write_conf(hs, i, msg[i]);
    }
}

void hmacsha_read_mac(struct hmac_sha_data* hs, int mode, uint32_t *mac)
{
    int i;
    if(mode == SHA256) {
        iowrite32(0, hs->base_addr + HMAC_SHA_REG_CONF_WE);
        for (i = 0; i < 8; i++)
        {
            iowrite32(ADDR_DIGEST0 + i, hs->base_addr + HMAC_SHA_REG_CONF_ADDRESS);
            mac[7-i] = ioread32(hs->base_addr+HMAC_SHA_REG_DOUT_1);
        }
    }else{
        iowrite32(0, hs->base_addr + HMAC_SHA_REG_CONF_WE);
        for (i = 0; i < 8; i++)
        {
            iowrite32(ADDR_DIGEST0 + i, hs->base_addr + HMAC_SHA_REG_CONF_ADDRESS);
            mac[15-i*2-1] = ioread32(hs->base_addr+HMAC_SHA_REG_DOUT_0);
            mac[15-i*2] = ioread32(hs->base_addr+HMAC_SHA_REG_DOUT_1);
        }
    }
}

void hwhmacsha_start(struct hmac_sha_data* hs){
    int i = 0;
    int j;
    hmacsha_reset(hs);
    printk(KERN_INFO "hmac-sha: reset done\n");
    hmacsha_set_len(hs, msj_len);
    printk(KERN_INFO "hmac-sha: set length done\n");
    hmacsha_write_status(hs, mode, sha_mode);
    printk(KERN_INFO "hmac-sha: write status done\n");
    hmacsha_set_key(hs, key);
    printk(KERN_INFO "hmac-sha: set key done\n");
    hmacsha_enable(hs);
    printk(KERN_INFO "hmac-sha: enable \n");
    while(hmacsha_read_input_ready(hs)== 0){}

    while(i < input_len){
        for(j = i;(j<i+16)&(j<input_len);j++){
            msg[j] = input[j];
        }
        hmacsha_msj(hs, msg); //do this multiple times
        i = i + 16;
    }
    

    printk(KERN_INFO "hmac-sha: msg done \n");
    hmacsha_end_packet(hs);
    printk(KERN_INFO "hmac-sha: end packet \n");
    while(hmacsha_read_ready(hs)== 0){}
    printk(KERN_INFO "hmac-sha: wait ready done \n");
    hmacsha_read_mac(hs, sha_mode, mac);
    printk(KERN_INFO "hmac-sha: read mac done \n");
    for (i = 0; i < 16; i=i+2)
    {
        printk(KERN_INFO "mac result hmac-sha512: (%d)- 0x%08x%08x\n", i, mac[i], mac[i+1]);
    }
}

void hwhmacsha_selftest(struct hmac_sha_data* hs)
{
    int i;
    uint64_t msg[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; // multiple of msg - process 1024bit each time
    uint64_t key[8] = {1, 2, 3, 4, 5, 6, 7, 8}; //512bit - before padding
    
    uint64_t msg384[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint64_t key384[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    uint64_t msg256[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint64_t key256[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    printk(KERN_INFO "hmac-sha: Test hmac-sha512\n");
    hmacsha_reset(hs);
    printk(KERN_INFO "hmac-sha: reset done\n");
    hmacsha_set_len(hs, msj_len);
    printk(KERN_INFO "hmac-sha: set length done\n");
    hmacsha_write_status(hs, HMAC, SHA512);
    printk(KERN_INFO "hmac-sha: write status done\n");
    hmacsha_set_key(hs, key);
    printk(KERN_INFO "hmac-sha: set key done\n");
    hmacsha_enable(hs);
    printk(KERN_INFO "hmac-sha: enable \n");
    while(hmacsha_read_input_ready(hs)== 0){}
    printk(KERN_INFO "hmac-sha: wait input ready done \n");
    hmacsha_msj(hs, msg);
    printk(KERN_INFO "hmac-sha: msj done \n");
    hmacsha_end_packet(hs);
    printk(KERN_INFO "hmac-sha: end packet \n");
    while(hmacsha_read_ready(hs)== 0){}
    printk(KERN_INFO "hmac-sha: wait ready done \n");
    hmacsha_read_mac(hs, SHA512, mac);
    printk(KERN_INFO "hmac-sha: read mac done \n");
    for (i = 0; i < 16; i=i+2)
    {
        printk(KERN_INFO "mac result hmac-sha512: (%d)- 0x%08x%08x\n", i, mac[i], mac[i+1]);
    }

//---------------------------------------------------------------------//
    printk(KERN_INFO "hmac-sha: Hardware 384\n");
    hmacsha_reset(hs);
    hmacsha_set_len(hs, msj_len);
    hmacsha_write_status(hs, HMAC, SHA384);
    hmacsha_set_key(hs, key384);
    hmacsha_enable(hs);
    while(hmacsha_read_input_ready(hs)== 0){}
        hmacsha_msj(hs, msg384);
    hmacsha_end_packet(hs);
    while(hmacsha_read_ready(hs)== 0){}
    hmacsha_read_mac(hs, SHA384, mac);
    //Print
    for (i = 0; i < 16; i=i+2)
    {
        printk(KERN_INFO "mac result hmac-sha384: (%d)- 0x%08x%08x\n", i, mac[i], mac[i+1]);
    }

//---------------------------------------------------------------------//

    printk(KERN_INFO "hmac-sha: Hardware 256\n");
    hmacsha_reset(hs);
    hmacsha_set_len(hs, msj_len);
    hmacsha_write_status(hs, HMAC, SHA256);
    hmacsha_set_key(hs, key256);
    hmacsha_enable(hs);
    while(hmacsha_read_input_ready(hs)== 0){}
    hmacsha_msj(hs, msg256);
    hmacsha_end_packet(hs);
    while(hmacsha_read_ready(hs)== 0){}
    hmacsha_read_mac(hs, SHA256, mac);
    for (i = 0; i < 16; i=i+2)
    {
        printk(KERN_INFO "mac result hmac-sha256: (%d)- 0x%08x%08x\n", i, mac[i], mac[i+1]);
    }
    
}



/* ============================================================================================ */
/* ============================================================================================ */

static int hmac_sha_probe( struct platform_device *pdev){

    struct hmac_sha_data *lp = NULL;
    int ret = 0;

    printk(KERN_INFO "hmac-sha: Device Tree Probing...\n");

    //Assign hmac_sha_data to platform device data:
    lp = (struct hmac_sha_data*)kmalloc(sizeof(struct hmac_sha_data), GFP_KERNEL);
    if(!lp) {
        printk(KERN_ALERT "hmac-sha: Could not allocate mychar device\n");
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
    printk(KERN_INFO "hmac-sha: devm platform ioremap - vir. baseaddr: 0x%lx\n", (long unsigned int)(lp->base_addr));
    
    lp->numberOpens = 0;

    // TODO: Perform module reset
    

    // ************************ NORMAL Device driver *************************** //
    /** The main reason to do this is to create a device /dev/hmac-sha 
     *  It is a character device node exposing our userspace API
     *  It also simplies memory management.
     */

    INIT_LIST_HEAD(&lp->device_entry);

    printk(KERN_INFO "hmac-sha: Initializing hmac-sha char-driver\n");
    //Register a range of char device number
    /**Format: alloc_chrdev_region(dev_t* dev, uint firstminor, uint count, char* name)
    *dev_t* dev: store the major and minor number (use marcros MAJOR(dev_t), MINOR(dev_t) to get the coresponding number)
    *char* name: is the name of the device that should be associated with this number range (will appear in /proc/devices)
    */
    if(alloc_chrdev_region(&lp->devt, 0, 1, DEVICE_NAME) < 0){
        printk(KERN_ALERT "hmac-sha failed to register a major number\n");
        return -1;
    }
    printk(KERN_INFO "hmac-sha: asssigned correctly with major number %d and minor number %d\n", MAJOR(lp->devt), MINOR(lp->devt));

    //Register the device class
    lp->hmac_sha_class = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(lp->hmac_sha_class)) {     //Check for error and clean up if there is
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(lp->hmac_sha_class);  // Correct way to return an error on a pointer
    }
    //Register the device driver
    lp->hmac_sha_device = device_create(lp->hmac_sha_class, NULL, lp->devt, NULL, DEVICE_NAME);
    if(IS_ERR(lp->hmac_sha_device)) {         //Clean up if there is an error
        class_unregister(lp->hmac_sha_class);
        class_destroy(lp->hmac_sha_class);    //Repeated code but the alternative is goto statements
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(lp->hmac_sha_device);
    }
    printk(KERN_INFO "hmac-sha: Device class registered & created correctly\n");

    cdev_init(&lp->c_dev, &fops);
    if(cdev_add(&lp->c_dev, lp->devt, 1) == -1){
        device_destroy(lp->hmac_sha_class, lp->devt);
        class_unregister(lp->hmac_sha_class);
        class_destroy(lp->hmac_sha_class);
        unregister_chrdev_region(lp->devt, 1);
        printk(KERN_ALERT "Create character device failed\n");
    }
    printk(KERN_INFO "hmac-sha: Initialize cdev correctly\n");
    
    list_add(&lp->device_entry, &device_list);
    
    // ************************ NORMAL Device driver *************************** //


    return 0;
}

static int hmac_sha_remove(struct platform_device *pdev) {
    struct hmac_sha_data *lp = platform_get_drvdata(pdev);

    //delete character driver
    cdev_del(&lp->c_dev);
    device_destroy(lp->hmac_sha_class, lp->devt);
    class_unregister(lp->hmac_sha_class); //MUST UNREGSITER BEFORE DESTROY
    class_destroy(lp->hmac_sha_class); //Something happen in class destroy or unregister
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
static const struct of_device_id hmac_sha_of_match[]= {
    { .compatible = "uec,hmac_sha-0", },
    { /* end of list */ },
};
MODULE_DEVICE_TABLE(of, hmac_sha_of_match);

static struct platform_driver hmac_sha_driver = {
    .driver                 = {
            .name           = DEVICE_NAME,
            .owner          = THIS_MODULE,
            .of_match_table = hmac_sha_of_match,
    },
    .probe                  = hmac_sha_probe,
    .remove                 = hmac_sha_remove,
};

/* ============================================================================================ */
/* ============================================================================================ */

/** @brief Initialization function
*   The static keyword restricts the visibility of the function to within this C file.
*   The __init marcro means that for a built-in driver, the fucntion is only used at initialization
*   time and that it can be discarded and its memory freed up after that point.
*   @return returns 0 if successful
*/
static int __init hmac_sha_init(void){
    printk(KERN_INFO "hmac-sha: Hello module world.\n");
    return platform_driver_register(&hmac_sha_driver);
}

/** @brief Cleanup function
*   Similar to initialization, it is static.
*   The __exit macro notifies that if this code is used for a built-in driver
*   that this function is not required.
*/
static void __exit hmac_sha_exit(void){
    platform_driver_unregister(&hmac_sha_driver);
    printk(KERN_INFO "hmac-sha: Goodbye from the LKM!\n");
}

/** @brief Open function
 *  The open function is called each time the device is opened
 *  This will search for platform data in the linked list and give it to device file
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode* inodep, struct file* filep){
    //This is the way to pass platform data to device file
    struct hmac_sha_data *lp;
    list_for_each_entry(lp, &device_list, device_entry) {
        if(lp->devt == inodep->i_rdev) {
            break;
        }
    }
    filep->private_data = lp;
    stream_open(inodep, filep);

    lp->numberOpens++;
    printk(KERN_INFO "hmac-sha: Device has been open %d time(s)\n", lp->numberOpens);
    return 0;
}

/** @brief Release function
 * The device release function that is called whenever the device is closed/released by the userspace program
 * @param inodep A pointer to an inode object (defined in linux/fs.h)
 * @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode* inodep, struct file* filep){
    struct hmac_sha_data *lp;
    lp = filep->private_data;
    filep->private_data = NULL;
    printk(KERN_INFO "hmac-sha: Device successfully closed\n");
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
    struct hmac_sha_data *hs;
    uint32_t status = 0;
    int error_count = 0;
    int send_byte;

    hs = filep->private_data;
    //hwhmacsha_selftest(lp);

    switch(sel_buffer){
        case 8: //read mac
            send_byte = mac_len;
            error_count = copy_to_user(buffer, mac, mac_len);
            kfree(mac);
            printk(KERN_INFO "hmac-sha: [8] read mac\n");
            break;
        case 9: //ready ready
            send_byte = 4;
            status = hmacsha_read_ready(hs);
            error_count = copy_to_user(buffer, &status, 4);
            printk(KERN_INFO "chacha-poly: [9] read ready\n");
            break;
    }

    if(error_count == 0){
        #ifdef DEBUG
        printk(KERN_INFO "hmac-sha: Sent %d bytes to the user\n", send_byte);
        #endif //DEBUG
        return(error_count=0); // clear the position to the start and return 0
    }else{
        printk(KERN_INFO "hmac-sha: Failed to send %d bytes to the user\n", error_count);
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
    struct hmac_sha_data *lp;
    int i = 0;

    lp = filep->private_data;

    //Get data from user to kernel spaces
    if(copy_from_user(ker_buff, buffer, len))
        return -EFAULT;
    ker_buff_len = len/8; //store number of uint64
    
    if(ker_buff_len < 2) { //select buffer, len <= 2 bytes
        sel_buffer = ker_buff[0];
        #ifdef DEBUG
        printk("hmac-sha: Select op: %d\n", sel_buffer);
        #endif //DEBUG
        switch(sel_buffer){
            case 2:
                mode = SHA;
                printk(KERN_INFO "hmac-sha: [2] SHA mode \n");
                break;
            case 3:
                mode = HMAC;
                printk(KERN_INFO "hmac-sha: [3] HMAC mode \n");
                break;
            case 4:
                sha_mode = SHA512;
                mac = (uint32_t*)kmalloc(sizeof(uint32_t)*16, GFP_KERNEL);
                mac_len = 64; //bytes
                printk(KERN_INFO "hmac-sha: [4] selected SHA512 \n");
                break;
            case 5:
                sha_mode = SHA384;
                mac = (uint32_t*)kmalloc(sizeof(uint32_t)*12, GFP_KERNEL);
                mac_len = 48; //bytes
                printk(KERN_INFO "hmac-sha: [5] selected SHA384 \n");
                break;
            case 6:
                sha_mode = SHA256;
                mac = (uint32_t*)kmalloc(sizeof(uint32_t)*8, GFP_KERNEL);
                mac_len = 32; //bytes
                printk(KERN_INFO "hmac-sha: [6] selected SHA256 \n");
                break;
            case 7:
                hwhmacsha_start(lp);
                printk(KERN_INFO "hmac-sha: [7] hmac-module start \n");
                break;
        }
    }
    else {
        switch(sel_buffer) {
            case 0:
                for(i=0; i<(len/8); i=i+1)
                    key[i] = ker_buff[i];
                #ifdef DEBUG
                printk(KERN_INFO "hmac-sha: Set key - 0x%llx%llx\n", *(key), *(key+1));
                printk(KERN_INFO "hmac-sha: Set key - 0x%llx%llx\n", *(key+2), *(key+3));
                printk(KERN_INFO "hmac-sha: Set key - 0x%llx%llx\n", *(key+4), *(key+5));
                printk(KERN_INFO "hmac-sha: Set key - 0x%llx%llx\n", *(key+6), *(key+7));
                #endif //DEBUG
                printk(KERN_INFO "hmac-sha: [0] key in driver \n");
                break;
            case 1:
                if((len%8) == 0){
                    input = (uint64_t*)kmalloc(sizeof(uint64_t)*ker_buff_len, GFP_KERNEL);
                }else{
                    ker_buff_len = ker_buff_len + 1;
                    input = (uint64_t*)kmalloc(sizeof(uint64_t)*ker_buff_len, GFP_KERNEL);
                }
                for(i=0; i<ker_buff_len; i=i+1) 
                    {input[i] = 0;}
                for(i=0; i<ker_buff_len; i=i+1)
                    input[i] = ker_buff[i];
                input_len = ker_buff_len; //in bytes
            
                #ifdef DEBUG
                for(i=0; i<ker_buff_len; i=i+2){
                    printk(KERN_INFO "hmac-sha: Set input - 0x%llx%llx\n", input[i], input[i+1]);
                }
                #endif //DEBUG
                printk(KERN_INFO "hmac-sha: [1] input in driver \n");
                break;
            default:
                printk(KERN_INFO "hmac-sha: [error] Cannot decide what to do - Select again");
        }
    }
    return 0;
}

/** @brief A module must use the module_init() and module_exit() macros from linux/init.h, which 
 * identify the initialization function at insertion time and the cleanup function (as listed above)
 */
module_init(hmac_sha_init);
module_exit(hmac_sha_exit);