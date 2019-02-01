/* 
 *  Mandatory Access Control Lists (MACL) security module
 *
 *  Author:  Scott Court, <scott@cucumberlinux.com>
 *
 *  Copyright 2019 Scott Court <scott@cucumberlinux.com>
 *
 */

#ifndef _MACL_LIST_MANAGER_H_
#define _MACL_LIST_MANAGER_H_

#include "list.h"

struct macl_list_manager_node
{
	struct macl_list* list;
	struct macl_list_manager_node* lesser;
	struct macl_list_manager_node* greater;
};

/** Creates a new macl_list_manager_node that must be freed by the caller using
  * macl_destroy_list_manager_node.
  *
  * @return A pointer to a new macl_list_manager_node, which must be freed
  * using macl_destroy_list_manager_node.
  */
struct macl_list_manager_node* macl_create_list_manager_node(void);

/** Recursively destroys a macl_list_manager_node, freeing its memory, any
  * child nodes and the list.
  *
  * @param node		The node to free.
  */
void macl_destroy_list_manager_node(struct macl_list_manager_node* node);

/** Inserts a macl_list under a macl_list_manager_node.
  *
  * @param node		The node to insert the list under.
  * @param list		The list to insert.
  */
void macl_list_manager_insert_list(
	struct macl_list_manager_node* node,
	struct macl_list* list);

/** Retrives the pointer to the list with the given name.
  *
  * @param node		The node to the list manager to retrive the list from.
  * @param name		The name of the list to retrive.
  *
  * @return The pointer to the list, or NULL if the list is not found.
  */
struct macl_list* macl_list_manager_get_list(
	struct macl_list_manager_node* node,
	char* name);

#endif

