/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#define MACL_FLAG_LOG 0x00000001

typedef uint32_t macl_flags;

enum macl_action
{
	MACL_ACTION_BLOCK = 0,
	MACL_ACTION_PASS = 1,
};

enum macl_event
{
	MACL_FILE_READ,
	MACL_FILE_WRITE,
	MACL_FILE_EXECUTE,
};

struct macl_rule
{
	enum macl_action action;
	enum macl_event event;
	macl_flags flags;
	char* path;
};

struct macl_list_node
{
	struct macl_list_rule* rule;
	struct macl_list_node* next;
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
  * @param rule		A pointer to the rule to destroy.
  */
void macl_destroy_rule(struct macl_rule* rule);

