/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#include <linux/xattr.h>

#include "rule.h"
#include "list.h"
#include "list_manager.h"

// A list of all the MACL lists
static struct macl_list_manager_node* list_manager;

/** This is the main init function for MACL. */
static __init int macl_init(void)
{
	printk(KERN_INFO "MACL: Initializing\n");

	list_manager = macl_create_list_manager_node();

	return 0;
}

static void print_list_manager_node(struct macl_list_manager_node* node)
{
	if (node == NULL)
		return;

	print_list_manager_node(node->lesser);
	printk(KERN_INFO "MACL: list %s\n", node->list->name);
	print_list_manager_node(node->greater);

}

