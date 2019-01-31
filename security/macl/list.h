/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#ifndef _MACL_LIST_H_
#define _MACL_LIST_H_

#include "rule.h"

struct macl_list_node
{
	struct macl_rule* rule;
	struct macl_list_node* next;
};

struct macl_list
{
	char* name;
	struct macl_list_node* head;
};

/** Creates a new macl_list containint no rules. The resulting structure must
  * be freed with macl_destroy_list.
  *
  * @param name		The name for this list
  *
  * @return A pointer to the macl_list, which must be freed by the caller using
  * macl_destroy_list.
  */
struct macl_list* macl_create_list(char* name);

/** Destroys a macl_list, freeing its memory. Also recursively calls
  * macl_destroy_rule on all of the rules in the list.
  *
  * @param list		A pointer to the macl_list to destroy.
  */
void macl_destroy_list(struct macl_list* list);

/** Appends a macl_rule to the end of a macl_list.
  *
  * @param list		The list to append the rule to.
  * @param rule		The rule to append to the list.
  */
void macl_append_rule_to_list(struct macl_list* list, struct macl_rule* rule);

#endif

