/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#include <linux/xattr.h>

/** This is the main init function for MACL. */
static __init int macl_init(void)
{
	printk(KERN_INFO "MACL: Initializing\n");
	return 0;
}

__initcall(macl_init)

