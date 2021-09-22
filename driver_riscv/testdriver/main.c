#include <linux/fs.h> 	    /* file stuff */
#include <linux/kernel.h>   /* printk() */
#include <linux/errno.h>    /* error codes */
#include <linux/module.h>   /* THIS_MODULE */
#include <linux/cdev.h>     /* char device stuff */
#include <linux/uaccess.h>  /* copy_to_user() */
#include <linux/init.h>       /* module_init, module_exit */
#include <linux/module.h>     /* version info, MODULE_LICENSE, MODULE_AUTHOR, printk() */
#include <linux/compiler.h> /* __must_check */


#define DEVICE_NAME "kietchar"      //The dev will appear at /dev/kietchar using this value
#define CLASS_NAME  "kiet"          //The device class -- this is a character device driver

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kiet Dang");         //The author -- visible when you use modinfo
MODULE_DESCRIPTION("A simple Linux char driver"); // The description -- see modinfo
MODULE_VERSION("0.1");              // A version number to inform users

static int majorNumber;     //Store device number -- determined automatically
static char message[256] = {0};     
static int message_len;
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

/** @brief Initialization function
*   The static keyword restricts the visibility of the function to within this C file.
*   The __init marcro means that for a built-in driver, the fucntion is only used at initialization
*   time and that it can be discarded and its memory freed up after that point.
*   @return returns 0 if successful
*/

static int __init kietchar_init(void){
    printk(KERN_INFO "Kiet-char: Initializing KietChar\n");
    //Dynamically allocate a major number for the device
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if(majorNumber < 0) {
        printk(KERN_ALERT "KietChar failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "Kiet-char: register correctly with a major number %d\n", majorNumber);

    //Register the device class
    kietcharClass = class_create(THIS_MODULE, CLASS_NAME);
    if(IS_ERR(kietcharClass)) {     //Check for error and clean up if there is
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(kietcharClass);  // Correct way to return an error on a pointer
    }
    printk(KERN_INFO "Kiet-char: device class register correctly\n");

    //Register the device driver
    kietcharDevice = device_create(kietcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if(IS_ERR(kietcharDevice)) {         //Clean up if there is an error
        class_destroy(kietcharClass);    //Repeated code but the alternative is goto statements
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(kietcharDevice);
    }
    printk(KERN_INFO "Kiet-char: device class created correctly\n");
    return 0;
}

/** @brief Cleanup function
*   Similar to initialization, it is static.
*   The __exit macro notifies that if this code is used for a built-in driver
*   that this function is not required.
*/

static void __exit kietchar_exit(void){
    device_destroy(kietcharClass, MKDEV(majorNumber, 0));
    class_unregister(kietcharClass);
    class_destroy(kietcharClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
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
    //sprintf(message, "%s(%zu letters)", buffer, len); //appending received string with its length
    if(copy_from_user(message, buffer, len))
        return -EFAULT;
    message_len = strlen(message);                      //store the length of the stored message
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


// __must_check int register_device(void); /* 0 if Ok*/
// void unregister_device(void);

// static const char g_s_Hello_World_string[] = "Hello world from kernel mode!\n\0";
// static const ssize_t g_s_Hello_World_size = sizeof(g_s_Hello_World_string);

// /*===============================================================================================*/
// static ssize_t device_file_read(
//     struct file *file_ptr
//     , char __user *user_buffer
//     , size_t count
//     , loff_t *possition)
// {
//     printk( KERN_NOTICE "Simple-driver: Device file is read at offset = %i, read bytes count = %u\n"
//         , (int)*possition
//         , (unsigned int)count );

//     if( *possition >= g_s_Hello_World_size )
//         return 0;

//     if( *possition + count > g_s_Hello_World_size )
//         count = g_s_Hello_World_size - *possition;

//     if( copy_to_user(user_buffer, g_s_Hello_World_string + *possition, count) != 0 )
//         return -EFAULT;

//     *possition += count;
//     return count;
// }

// /*===============================================================================================*/
// static struct file_operations mychardriver_fops = 
// {
//     .owner = THIS_MODULE,
//     .read = device_file_read,
// };

// static int device_file_major_number = 0;
// static const char device_name[] = "Simple-driver";

// /*===============================================================================================*/
// int register_device(void)
// {
//     int result = 0;

//     printk( KERN_NOTICE "Simple-driver: register_device() is called.\n" );

//     result = register_chrdev( 0, device_name, &mychardriver_fops );
//     if( result < 0 )
//     {
//         printk( KERN_WARNING "Simple-driver:  can\'t register character device with errorcode = %i\n", result );
//         return result;
//     }

//     device_file_major_number = result;
//     printk( KERN_NOTICE "Simple-driver: registered character device with major number = %i and minor numbers 0...255\n"
//         , device_file_major_number );

//     return 0;
// }

// /*===============================================================================================*/
// void unregister_device(void)
// {
//     printk( KERN_NOTICE "Simple-driver: unregister_device() is called\n" );
//     if(device_file_major_number != 0)
//     {
//         unregister_chrdev(device_file_major_number, device_name);
//     }
// }

// MODULE_DESCRIPTION("Simple Linux driver");
// MODULE_LICENSE("GPL");
// MODULE_AUTHOR("Apriorit, Inc");

// /*===============================================================================================*/
// static int mychardriver_init(void)
// {
//     int result = 0;
//     printk( KERN_NOTICE "Simple-driver: Initialization started\n" );

//     result = register_device();
//     return result;
// }

// /*===============================================================================================*/
// static void mychardriver_exit(void)
// {
//     printk( KERN_NOTICE "Simple-driver: Exiting\n" );
//     unregister_device();
// }
 
// module_init(mychardriver_init);
// module_exit(mychardriver_exit);
