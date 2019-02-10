/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#include <linux/xattr.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/limits.h>

#include "rule.h"
#include "list.h"
#include "list_manager.h"

/** A list of all the MACL lists. */
static struct macl_list_manager_node* list_manager;

/** MACL handler for the file_open LSM hook. */
static int macl_file_open(struct file* f) {
	char buffer[PATH_MAX];
	char* path;

	path = d_path(&f->f_path, buffer, PATH_MAX);

	if (f->f_mode & FMODE_READ)
		printk(KERN_INFO "MACL: Read file %s\n", path);
	if (f->f_mode & FMODE_WRITE)
		printk(KERN_INFO "MACL: Write file %s\n", path);
	if (current->in_execve)
		printk(KERN_INFO "MACL: Execute file %s\n", path);

	return 0;
}

static struct security_hook_list macl_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(file_open, macl_file_open),
};

/** This is the main init function for MACL. */
static __init int macl_init(void)
{
	printk(KERN_INFO "MACL: Initializing\n");

	list_manager = macl_create_list_manager_node();

	security_add_hooks(macl_hooks, ARRAY_SIZE(macl_hooks), "macl");

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

__initcall(macl_init)

