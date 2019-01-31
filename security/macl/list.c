/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#include <linux/slab.h>
#include <linux/string.h>

#include "list.h"

/** Creates a new macl_list containint no rules. The resulting structure must
  * be freed with macl_destroy_list.
  *
  * @param name		The name for this list
  *
  * @return A pointer to the macl_list, which must be freed by the caller using
  * macl_destroy_list.
  */
struct macl_list* macl_create_list(char* name)
{
	struct macl_list* list;
	size_t name_len;

	name_len = strlen(name) + 1;
	list = kmalloc(sizeof(struct macl_list), GFP_KERNEL);
	list->name = kmalloc(name_len, GFP_KERNEL);
	strlcpy(list->name, name, name_len);
	list->head = NULL;

	return list;
}

/** Destroys a macl_list, freeing its memory. Also recursively calls
  * macl_destroy_rule on all of the rules in the list.
  *
  * @param list		A pointer to the macl_list to destroy.
  */
void macl_destroy_list(struct macl_list* list)
{
	struct macl_list_node* node;

	if (list == NULL)
		return;

	node = list->head;

	while (node != NULL)
	{
		struct macl_list_node* next_node = node->next;
		macl_destroy_rule(node->rule);
		kfree(node);
		node = next_node;
	} 

	kfree(list->name);
	kfree(list);
}


/** Appends a macl_rule to the end of a macl_list.
  *
  * @param list		The list to append the rule to.
  * @param rule		The rule to append to the list.
  */
void macl_append_rule_to_list(struct macl_list* list, struct macl_rule* rule)
{
	struct macl_list_node** node_ptr;

	node_ptr = &(list->head);

	// Walk the list
	while (*node_ptr != NULL)
		node_ptr = &((*node_ptr)->next);

	// Add the node at the end
	*node_ptr = kmalloc(sizeof(struct macl_list_node), GFP_KERNEL);
	(*node_ptr)->rule = rule;
	(*node_ptr)->next = NULL;
}

