/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#include <linux/slab.h>

#include "rule.h"

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

/** Prints a macl_rule to a string.
  *
  * @param str		A pointer to the string to store the output in.
  * @param size		The size of the buffer, including trailing NULL space.
  * @param rule		A pointer to the  macl_rule to print.
  */
void macl_snprint_rule(char* str, size_t size, struct macl_rule* rule)
{
	char* action_str;
	char* event_str;
	char* flag_str;

	switch (rule->action)
	{
		case MACL_ACTION_BLOCK:
			action_str = "block";
			break;
		case MACL_ACTION_PASS:
			action_str = "pass";
			break;
		default:
			action_str = "";
	}

	switch (rule->event)
	{
		case MACL_EVENT_FILE_READ:
			event_str = "read";
			break;
		case MACL_EVENT_FILE_WRITE:
			event_str = "write";
			break;
		case MACL_EVENT_FILE_EXECUTE:
			event_str = "execute";
			break;
		default:
			event_str = "";
	}

	// Note: the log string must have a space at the end.
	if (rule->flags & MACL_FLAG_LOG)
		flag_str = "log ";
	else
		flag_str = "";

	snprintf(str, size, "%s %s %son %s",
		action_str, event_str, flag_str, rule->path);
}

/** Converts a macl_rule to a string. The resulting string must be freed by the
  * caller using kfree.
  *
  * @param rule		A pointer to the macl_rule structure to convert.
  * 
  * @return A pointer to the rule string, which must be freed by the caller
  * using kfree.
  */
char* macl_rule_to_string(struct macl_rule* rule)
{
	char* str;
	size_t len;

	/* action (6) + space + event (7) + space + max flag size (4) +
 	 * on (2) + space + path (variable) + NULL = 23 + strlen(path) */
	len = 23 + strlen(rule->path);
	str = kmalloc(len, GFP_KERNEL);
	macl_snprint_rule(str, len, rule);

	return str;
}

