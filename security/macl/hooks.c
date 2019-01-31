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
static struct macl_lists_list_node* macl_lists;

static void macl_test(void);

/** This is the main init function for MACL. */
static __init int macl_init(void)
{
	printk(KERN_INFO "MACL: Initializing\n");

	//macl_lists = kmalloc(sizeof(struct macl_lists_list_node), GFP_KERNEL);

	macl_test();

	return 0;
}

static void macl_test(void)
{
	struct macl_rule* rule;
	struct macl_list* list;
	struct macl_list_node* node;
	char* rule_str;

	// Testing code for macl_rule functions
	rule = macl_create_rule(
		MACL_ACTION_BLOCK, 
		MACL_EVENT_FILE_EXECUTE,
		MACL_FLAG_LOG, 
		"/etc/shadow");
	rule_str = macl_rule_to_string(rule);
	printk(KERN_INFO "MACL: %s\n", rule_str);
	kfree(rule_str);

	// Testing code for macl_list functions
	list = macl_create_list("test_list");
	macl_append_rule_to_list(list, rule);
	rule = macl_create_rule(
		MACL_ACTION_BLOCK, 
		MACL_EVENT_FILE_EXECUTE,
		MACL_FLAG_LOG, 
		"/etc/passwd");
	macl_append_rule_to_list(list, rule);

	// Print out the testing list
	node = list->head;
	while (node != NULL)
	{
		rule_str = macl_rule_to_string(node->rule);
		printk(KERN_INFO "MACL: %s: %s\n", list->name, rule_str);
		kfree(rule_str);
		node = node->next;
	}

	macl_destroy_list(list);

}

__initcall(macl_init)

