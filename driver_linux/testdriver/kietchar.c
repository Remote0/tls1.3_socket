#include <linux/init.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>

#define DEVICE_NAME "kietchar"      //The dev will appear at /dev/kietchar using this value
#define CLASS_NAME  "CLASS_KIET"          //The device class -- this is a character device driver

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiet Dang");         //The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux char driver"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

static int majorNumber;     //Store device number -- determined automatically
static char message[256];     
static short message_len;
static int numberOpens = 0;
static struct class* kietcharClass = NULL; // The device-driver class struct pointer
static struct device* kietcharDevice = NULL; // The device-driver device struct pointer
static dev_t first;
static struct cdev c_dev; //Global variable for the character device structure
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

/** @brief Initialization function
*   The static keyword restricts the visibility of the function to within this C file.
*   The __init marcro means that for a built-in driver, the fucntion is only used at initialization
*   time and that it can be discarded and its memory freed up after that point.
*   @return returns 0 if successful
*/

static int __init kietchar_init(void){
    printk(KERN_INFO "Kiet-char: Initializing KietChar\n");
    //Register a range of char device number
    //The major number will be chosen dynamically and return (along with the first minor number) in dev_t
    if(alloc_chrdev_region(&first, 0, 1, "Leonardo") < 0){
        printk(KERN_ALERT "KietChar failed to register a major number\n");
        return -1;
    }
    printk(KERN_INFO "Kiet-char: register a range of char device number correctly\n");

    //Register the device class
    kietcharClass = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(kietcharClass)) {     //Check for error and clean up if there is
        unregister_chrdev_region(first, 1);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(kietcharClass);  // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "Kiet-char: device class register correctly\n");

    //Register the device driver
    kietcharDevice = device_create(kietcharClass, NULL, first, NULL, DEVICE_NAME);
    if(IS_ERR(kietcharDevice)) {         //Clean up if there is an error
        class_unregister(kietcharClass);
        class_destroy(kietcharClass);    //Repeated code but the alternative is goto statements
        unregister_chrdev_region(first, 1);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(kietcharDevice);
    }
    printk(KERN_INFO "Kiet-char: device class created correctly\n");

    cdev_init(&c_dev, &fops);
    if(cdev_add(&c_dev, first, 1) == -1){
        device_destroy(kietcharClass, first);
        class_unregister(kietcharClass);
        class_destroy(kietcharClass);
        unregister_chrdev_region(first, 1);
        printk(KERN_ALERT "Create character device failed\n");
    }
    printk(KERN_INFO "Kiet-char: initialize cdev correctly\n");

    return 0;
}

/** @brief Cleanup function
*   Similar to initialization, it is static.
*   The __exit macro notifies that if this code is used for a built-in driver
*   that this function is not required.
*/

static void __exit kietchar_exit(void){
    cdev_del(&c_dev);
    device_destroy(kietcharClass, first);
    class_unregister(kietcharClass); //MUST UNREGSITER BEFORE DESTROY
    class_destroy(kietcharClass);
    unregister_chrdev_region(first, 1);
    printk(KERN_INFO "Kiet-char: Goodbye from the LKM!\n");
}

/** @brief Open function
 *  The open function is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */

static int dev_open(struct inode* inodep, struct file* filep){
    numberOpens++;
    printk(KERN_INFO "Kiet-char: Device has been open %d time(s)\n", numberOpens);
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
    //format copy_to_user ( *to, *from, size) and returns 0 on success
    error_count = copy_to_user(buffer, message, message_len);

    if(error_count ==0){
        printk(KERN_INFO "Kiet-char: Sent %d characters to the user\n", message_len);
        return(message_len=0); // clear the position to the start and return 0;
    }else{
        printk(KERN_INFO "Kiet-char: Failed to send %d characters to the user\n", error_count);
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
    printk(KERN_INFO "Kiet-char: About to appending %ld characters from buffer to message\n", len);
    //sprintf(message, "%s", buffer); //appending received string with its length
    if(copy_from_user(message, buffer, len))
        return -EFAULT;
    printk(KERN_INFO "Kiet-char: Appending done\n");
    message_len = strlen(message);                      //store the length of the stored message
    //printk(KERN_INFO "Kiet-char: assign message length %d done\n", message_len);
    printk(KERN_INFO "Kiet-char: Received %zu characters from the user\n", len);
    return len;
}

/** @brief Release function
 * The device release function that is called whenever the device is closed/released by the userspace program
 * @param inodep A pointer to an inode object (defined in linux/fs.h)
 * @param filep A pointer to a file object (defined in linux/fs.h)
 */

static int dev_release(struct inode* inodep, struct file* filep){
    printk(KERN_INFO "Kiet-char: Device successfully closed\n");
    return 0;
}

/** @brief A module must use the module_init() and module_exit() macros from linux/init.h, which 
 * identify the initialization function at insertion time and the cleanup function (as listed above)
 */

module_init(kietchar_init);
module_exit(kietchar_exit);