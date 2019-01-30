/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

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
	MACL_EVENT_FILE_READ,
	MACL_EVENT_FILE_WRITE,
	MACL_EVENT_FILE_EXECUTE,
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
	struct macl_rule* rule;
	struct macl_list_node* next;
};

struct macl_list
{
	char* name;
	struct macl_list_node* head;
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

