/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 */

#include "exeq.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "hnetd.h"

/* One eweq task in the queue */
struct exeq_task {
	struct list_head le;
	char *args[];
	/* Additional data first contains the array of pointers
	 * provided to execv: {arg1_p, arg2_p, arg3_p, NULL}
	 * Then, it contains all the strings that are used in the
	 * previous array: arg1:arg2:arg3
	 */
};

static void exeq_start_maybe(struct exeq *e)
{
	if(e->process.pending || list_empty(&e->tasks))
		return;

	struct exeq_task *t = list_first_entry(&e->tasks, struct exeq_task, le);
	pid_t pid = fork();
	if (pid == 0) {
		execv(t->args[0], t->args);
		L_ERR("execv error: %s\n", strerror(errno));
		_exit(128);
	}
	L_DEBUG("exeq_run %s", t->args[0]);
	for (int i = 1 ; t->args[i] ; i++)
		L_DEBUG(" %s", t->args[i]);

	e->process.pid = pid;
	if(uloop_process_add(&e->process))
		L_ERR("Could not add process %d to uloop", pid);
	list_del(&t->le);
	free(t);
}

static  void _process_handler(struct uloop_process *c, int ret)
{
	struct exeq *e = container_of(c, struct exeq, process);
	if(ret)
		L_WARN("Child process %d exited with status %d", c->pid, ret);
	else
		L_DEBUG("Child process %d terminated normally.", c->pid, ret);
	exeq_start_maybe(e);
}

/* Add a task to the queue.
 * The arguments are copied and can therefore be freed after the call. */
int exeq_add(struct exeq *e, char **args)
{
	size_t datalen = 0;
	struct exeq_task *task;
	size_t arg_cnt;
	char *str;
	for(arg_cnt = 0; args[arg_cnt] ; arg_cnt++)
		datalen += strlen(args[arg_cnt]) + 1;

	if(!(task = malloc(sizeof(*task) + (arg_cnt + 1) * sizeof(char *) + datalen))) {
		L_ERR("exeq_add: malloc failed");
		return -1;
	}

	str = (char *)&task->args[arg_cnt + 1];
	for(arg_cnt = 0; args[arg_cnt]; arg_cnt++) {
		strcpy(str, args[arg_cnt]);
		task->args[arg_cnt] = str;
		str += strlen(args[arg_cnt]) + 1;
	}
	task->args[arg_cnt] = NULL;

	list_add_tail(&task->le, &e->tasks);
	exeq_start_maybe(e);
	return 0;
}

void exeq_init(struct exeq *e)
{
	memset(&e->process, 0, sizeof(*e));
	e->process.cb = _process_handler;
	INIT_LIST_HEAD(&e->tasks);
}

void exeq_term(struct exeq *e)
{
	struct exeq_task *t, *ts;
	list_for_each_entry_safe(t, ts, &e->tasks, le)
		free(t);

	uloop_process_delete(&e->process);
}

