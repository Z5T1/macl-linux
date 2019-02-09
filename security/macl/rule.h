/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#include <linux/slab.h>

#ifndef _MACL_RULE_H_
#define _MACL_RULE_H_

#define MACL_FLAG_NONE	0x00000000
#define MACL_FLAG_LOG	0x00000001

typedef uint32_t macl_flags;

enum macl_action
{
	MACL_ACTION_BLOCK = 0,
	MACL_ACTION_PASS = 1,
};

enum macl_event
{
	MACL_EVENT_TYPE_FILE_READ,
	MACL_EVENT_TYPE_FILE_WRITE,
	MACL_EVENT_TYPE_FILE_EXECUTE,
};

struct macl_rule
{
	enum macl_action action;
	enum macl_event event;
	macl_flags flags;
	char* path;
};

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
	char* path);

/** Destroys a macl_rule, freeing its memory.
  *
  * @param rule		A pointer to the macl_rule to destroy.
  */
void macl_destroy_rule(struct macl_rule* rule);

/** Prints a macl_rule to a string.
  *
  * @param str		A pointer to the string to store the output in.
  * @param size		The size of the buffer, including trailing NULL space.
  * @param rule		A pointer to the  macl_rule to print.
  */
void macl_snprint_rule(char* str, size_t size, struct macl_rule* rule);

/** Converts a macl_rule to a string. The resulting string must be freed by the
  * caller using kfree.
  *
  * @param rule		A pointer to the macl_rule structure to convert.
  * 
  * @return A pointer to the rule string, which must be freed by the caller
  * using kfree.
  */
char* macl_rule_to_string(struct macl_rule* rule);

#endif

