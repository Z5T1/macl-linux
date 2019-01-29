/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#include <linux/xattr.h>

#include "lists.h"

/** This is the main init function for MACL. */
static __init int macl_init(void)
{
	struct macl_rule* rule;
	char* rule_str;

	printk(KERN_INFO "MACL: Initializing\n");

	// Testing code for macl_rule functions
	rule = macl_create_rule(
		MACL_ACTION_BLOCK, 
		MACL_EVENT_FILE_EXECUTE,
		MACL_FLAG_LOG, 
		"/etc/shadow");
	rule_str = macl_rule_to_string(rule);
	printk(KERN_INFO "MACL: %s\n", rule_str);
	kfree(rule_str);
	macl_destroy_rule(rule);
	rule = NULL;

	return 0;
}

__initcall(macl_init)

