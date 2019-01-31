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

struct macl_list_manager_node {
	struct macl_list* list;
	struct macl_lists_list_node* next;
};

#endif

