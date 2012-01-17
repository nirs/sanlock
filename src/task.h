/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#ifndef __TASK_H__
#define __TASK_H__

void setup_task_timeouts(struct task *task, int io_timeout_arg);
void setup_task_aio(struct task *task, int use_aio, int cb_size);
void close_task_aio(struct task *task);

#endif
