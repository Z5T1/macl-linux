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

#include "lists.h"

/** Creates a new macl_rule. The resulting structure must be freed with
  * macl_destroy_rule.
  *
  * @param action	The action to take when the criteria for this rule are
  * 			met.
  * @param event	The event for this rule to match.
  * @param flags	Any macl_flags for this rule. Multiple flags can be
  * 			OR'ed together.
  * @param path		The path for this rule to match.
  *
  * @return A pointer to the new macl_rule, which must be freed with
  * macl_destory_rule.
  */
struct macl_rule* macl_create_rule(
	enum macl_action action,
	enum macl_event event,
	macl_flags flags,
	char* path)
{
	struct macl_rule* rule;
	size_t path_len;

	rule = kmalloc(sizeof(struct macl_rule), GFP_KERNEL);
	rule->action = action;
	rule->event = event;
	rule->flags = flags;
	path_len = strlen(path)+1;
	rule->path = kmalloc(path_len, GFP_KERNEL);
	strlcpy(rule->path, path, path_len);

	return rule;
}

/** Destroys a macl_rule, freeing its memory.
  *
  * @param rule		A pointer to the rule to destroy.
  */
void macl_destroy_rule(struct macl_rule* rule)
{
	kfree(rule->path);
	kfree(rule);
}

