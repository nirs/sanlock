/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __CMD_H__
#define __CMD_H__

struct cmd_args {
	struct list_head list; /* thread_pool data */
	int ci_in;
	int ci_target;
	int cl_fd;
	int cl_pid;
	struct sm_header header;
};

/* cmds processed by thread pool */
void call_cmd_thread(struct task *task, struct cmd_args *ca);

/* cmds processed by main loop */
void call_cmd_daemon(int ci, struct sm_header *h_recv, int client_maxi);

#endif
