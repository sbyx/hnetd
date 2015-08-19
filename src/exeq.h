/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 * This file provides a process execution fifo.
 * It uses execv and will not execute the next task before
 * the previous one has finished.
 */

#ifndef EXEQ_H_
#define EXEQ_H_

#include <libubox/uloop.h>
#include <libubox/list.h>

/* A single execution queue structure */
struct exeq {
	struct uloop_process process;
	struct list_head tasks;
};

/* Initializes a queue structure */
void exeq_init(struct exeq *);

/* Add a task to the queue.
 * The arguments are copied and can therefore be freed after the call.
 * Returns 0 on success. -errorcode on error. */
int exeq_add(struct exeq *, char **args);

/* Cancels the execution queue.
 * (Does not interrupt the current process if currently running) */
void exeq_term(struct exeq *e);

#endif /* EXEQ_H_ */
