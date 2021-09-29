#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/ioport.h>

#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>

#include "aes_gcm_regs.h"

#define DEVICE_NAME "mychar"      //The dev will appear at /dev/mychar using this value
#define CLASS_NAME  "crypto"          //The device class -- this is a character device driver

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiet Dang");         //The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux char driver"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

// struct to hold the physical address of our device
struct mychar_local {
    int irq;
    unsigned long mem_start;
    unsigned long mem_end;
    void __iomem *base_addr;
};
static int majorNumber;     //Store device number -- determined automatically
static char ker_buff[256];     
static short ker_buff_len;
static int numberOpens = 0;
static struct class* kietcharClass = NULL; // The device-driver class struct pointer
static struct device* kietcharDevice = NULL; // The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int dev_open(struct inode*, struct file*);
static int dev_release(struct inode*, struct file*);
static ssize_t dev_read(struct file*, char*, size_t, loff_t*);
static ssize_t dev_write(struct file*, const char*, size_t, loff_t*);

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

static irqreturn_t mychar_irq(int irq, void* lp){
    printk(KERN_INFO "mychar interrupt\n");
    return IRQ_HANDLED;
}

static int mychar_probe( struct platform_device *pdev){
    struct resource *r_irq;
    struct resource *r_mem;
    struct device *dev = &pdev->dev;
    struct mychar_local *lp = NULL;

    int rc = 0;
    printk(KERN_INFO "My-char: Device Tree Probing\n");

    /* Get IO space for the device */
    // Todo: Base address of the device and the range
    r_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    if(!r_mem) {
        dev_err(dev, "My-char: Invalid address\n");
        return -ENODEV;
    }

    lp = (struct mychar_local*)kmalloc(sizeof(struct mychar_local), GFP_KERNEL);
    if(!lp) {
        printk(KERN_ALERT "My-char: Could not allocate mychar device\n");
    }

    dev_set_drvdata(dev, lp);
    
    lp->mem_start = r_mem->start;
    lp->mem_end = r_mem->end;

    /* MOST IMPORTANT CALL */
    /* IO memory regions must be allocated prior to use linux/ioport.h 
    *  Format: request_mem_region(unsigned long start, unsigned long len, char* name)
    *  This functions allocates a memory region of len bytes, starting at start.
    *  Return a non-NULL pointer on success.
    *  Note: All I/O memory allocation are listed in /proc/iomem
    */
    if(!request_mem_region(lp->mem_start, lp->mem_end - lp->mem_start + 1, DEVICE_NAME)) {
        dev_err(dev, "My-char: Couldn't lock memory region at %p\n", (void*)lp->mem_start);
        rc = -EBUSY;
        goto error1;
    }

    /* Ensure the allocated IO memory is accessible to the kernel 
    * (on many systems, dereferencing a pointer to IO memory is not available)
    *  Format: ioremap(unsigned long phys_addr, unsigned long size)
    * This functions assign virtual address to IO memory regions
    */
    lp->base_addr = ioremap(lp->mem_start, lp->mem_end - lp->mem_start + 1);
    if(!lp->base_addr){
        dev_err(dev, "My-char: Could not alllocate iomem\n");
        rc = -EIO;
        goto error2;
    }
    // ************************ NORMAL Device driver *************************** //
    printk(KERN_INFO "My-char: Initializing MyChar\n");
    //Dynamically allocate a major number for the device
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if(majorNumber < 0) {
        printk(KERN_ALERT "My-char:  failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "My-char: register correctly with a major number %d\n", majorNumber);

    //Register the device class
    kietcharClass = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(kietcharClass)) {     //Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(kietcharClass);  // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "My-char: device class register correctly\n");

    //Register the device driver
    kietcharDevice = device_create(kietcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if(IS_ERR(kietcharDevice)) {         //Clean up if there is an error
        class_destroy(kietcharClass);    //Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "My-char: Failed to create the device\n");
        return PTR_ERR(kietcharDevice);
    }
    printk(KERN_INFO "My-char: device class created correctly\n");

    /* Get IO space for the device */
    r_irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
    if (!r_irq) {
        printk("My-char: no IRQ found\n");
        printk("My-char: mychar at 0x%08x mapped to 0x%08x\n",
            (unsigned int __force) lp->mem_start,
            (unsigned int __force) lp->base_addr);

            /* Do something with pointer to registers */

        return 0;
    }
    lp->irq = r_irq->start;

    rc = request_irq(lp->irq, &mychar_irq, 0, DEVICE_NAME, lp);
    if(rc) {
        dev_err(dev, "My-char: Could not allocate interrupt %d/\n", lp->irq);
        goto error3;
    }

    /* IMPORTANT */
    /* Print success result:
    *  mychar at physical address (lp->mem_start) is mapped to virtual address (lp->base_addr)
    *  From now on, use the virtual address
    */
    printk("My-char: no IRQ found\n");
    printk("My-char:  at 0x%08x mapped to 0x%08x, irq=%d\n",
        (unsigned int __force) lp->mem_start,
        (unsigned int __force) lp->base_addr,
        lp->irq);
    return 0;        

error3:
    free_irq(lp->irq, lp);
error2:
    release_mem_region(lp->mem_start, lp->mem_end - lp->mem_start + 1);
error1:
    kfree(lp);
    dev_set_drvdata(dev, NULL);
    return rc;
}

static int mychar_remove(struct platform_device *pdev) {
    struct device *dev = &pdev->dev;
    struct mychar_local *lp = dev_get_drvdata(dev);
    free_irq(lp->irq, lp);
    iounmap(lp->base_addr);
    release_mem_region(lp->mem_start, lp->mem_end - lp->mem_start + 1);
    kfree(lp);
    dev_set_drvdata(dev, NULL);
    return 0;
}

/** @brief Add an entry to device table. The kernel will look for a suitable entry in the device table
*   and call probe() to init the device
*/
static struct of_device_id mychar_of_match[]= {
    { .compatible = "vendor,mychar", },
    { /* end of list */ },
};
MODULE_DEVICE_TABLE(of, mychar_of_match);

static struct platform_driver mychar_driver = {
    .driver                 = {
            .name           = DEVICE_NAME,
            .owner          = THIS_MODULE,
            .of_match_table = mychar_of_match,
    },
    .probe                  = mychar_probe,
    .remove                 = mychar_remove,
};

/* ============================================================================================ */
/* ============================================================================================ */

/** @brief Initialization function
*   The static keyword restricts the visibility of the function to within this C file.
*   The __init marcro means that for a built-in driver, the fucntion is only used at initialization
*   time and that it can be discarded and its memory freed up after that point.
*   @return returns 0 if successful
*/
static int __init mychar_init(void){
    // printk(KERN_INFO "My-char: Initializing MyChar\n");
    // //Dynamically allocate a major number for the device
    // majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    // if(majorNumber < 0) {
    //     printk(KERN_ALERT "MyChar failed to register a major number\n");
    //     return majorNumber;
    // }
    // printk(KERN_INFO "My-char: register correctly with a major number %d\n", majorNumber);

    // //Register the device class
    // kietcharClass = class_create(THIS_MODULE, CLASS_NAME);
    // if(IS_ERR(kietcharClass)) {     //Check for error and clean up if there is
    //     unregister_chrdev(majorNumber, DEVICE_NAME);
    //     printk(KERN_ALERT "Failed to register device class\n");
    //     return PTR_ERR(kietcharClass);  // Correct way to return an error on a pointer
    // }
    // printk(KERN_INFO "My-char: device class register correctly\n");

    // //Register the device driver
    // kietcharDevice = device_create(kietcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    // if(IS_ERR(kietcharDevice)) {         //Clean up if there is an error
    //     class_destroy(kietcharClass);    //Repeated code but the alternative is goto statements
    //     unregister_chrdev(majorNumber, DEVICE_NAME);
    //     printk(KERN_ALERT "Failed to create the device\n");
    //     return PTR_ERR(kietcharDevice);
    // }
    // printk(KERN_INFO "My-char: device class created correctly\n");
    // return 0;

    printk(KERN_INFO "My-char: Hello module world.\n");
    return platform_driver_register(&mychar_driver);

}

/** @brief Cleanup function
*   Similar to initialization, it is static.
*   The __exit macro notifies that if this code is used for a built-in driver
*   that this function is not required.
*/
static void __exit mychar_exit(void){
    // device_destroy(kietcharClass, MKDEV(majorNumber, 0));
    // class_unregister(kietcharClass);
    // class_destroy(kietcharClass);
    // unregister_chrdev(majorNumber, DEVICE_NAME);

    platform_driver_unregister(&mychar_driver);
    printk(KERN_INFO "My-char: Goodbye from the LKM!\n");
}

/** @brief Open function
 *  The open function is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode* inodep, struct file* filep){
    numberOpens++;
    printk(KERN_INFO "My-char: Device has been open %d time(s)\n", numberOpens);
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
    int error_count = 0;
    //Copy from kernel space to user space
    //format copy_to_user ( *to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, ker_buff, ker_buff_len);

    if(error_count == 0){
        printk(KERN_INFO "My-char: Sent %d characters to the user\n", ker_buff_len);
        return(ker_buff_len=0); // clear the position to the start and return 0;
    }else{
        printk(KERN_INFO "My-char: Failed to send %d characters to the user\n", error_count);
        return -EFAULT; //Failed -- return a bad address message (i.e. -14)
    }
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
    ker_buff_len = strlen(ker_buff);  //store the length of the stored message
    
    printk(KERN_INFO "My-char: Received %zu characters from the user\n", len);
    return len;
}

/** @brief Release function
 * The device release function that is called whenever the device is closed/released by the userspace program
 * @param inodep A pointer to an inode object (defined in linux/fs.h)
 * @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode* inodep, struct file* filep){
    printk(KERN_INFO "My-char: Device successfully closed\n");
    return 0;
}

/** @brief A module must use the module_init() and module_exit() macros from linux/init.h, which 
 * identify the initialization function at insertion time and the cleanup function (as listed above)
 */
module_init(mychar_init);
module_exit(mychar_exit);