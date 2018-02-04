#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init init_hello_module(void)
{
	printk(KERN_INFO "Hello Module!\n");
	return 0;
}

static void __exit cleanup_hello_module(void)
{
	printk(KERN_INFO "Goodbye Module!\n");
}

module_init(init_hello_module);
module_exit(cleanup_hello_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Timothy Chow <timothyc@ucla.edu>");
MODULE_DESCRIPTION("Hello Module");
