/*
 * Copyright (C) 2010-2011 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 */

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#include "sanlock_internal.h"
#include "sanlock_direct.h"
#include "direct.h"
#include "task.h"

void log_level(int space_id GNUC_UNUSED, int token_id GNUC_UNUSED,
	       int level GNUC_UNUSED, const char *fmt GNUC_UNUSED, ...);

void log_level(int space_id GNUC_UNUSED, int token_id GNUC_UNUSED,
	       int level GNUC_UNUSED, const char *fmt GNUC_UNUSED, ...)
{
}

int host_id_disk_info(char *name GNUC_UNUSED, struct sync_disk *disk GNUC_UNUSED);

int host_id_disk_info(char *name GNUC_UNUSED, struct sync_disk *disk GNUC_UNUSED)
{
	return -1;
}

static void setup_task_lib(struct task *task, int use_aio, int io_timeout_sec)
{
	memset(task, 0, sizeof(struct task));
	if (!io_timeout_sec)
		io_timeout_sec = DEFAULT_IO_TIMEOUT;
	setup_task_timeouts(task, io_timeout_sec);
	setup_task_aio(task, use_aio, LIB_AIO_CB_SIZE);
	sprintf(task->name, "%s", "lib");
}


int sanlock_direct_read_id(struct sanlk_lockspace *ls,
			   uint64_t *timestamp,
			   uint64_t *owner_id,
			   uint64_t *owner_generation,
			   int use_aio,
			   int io_timeout_sec)
{
	struct task task;
	int rv;

	setup_task_lib(&task, use_aio, io_timeout_sec);

	rv = direct_read_id(&task, ls, timestamp, owner_id, owner_generation);

	close_task_aio(&task);

	return rv;
}

int sanlock_direct_live_id(struct sanlk_lockspace *ls,
			   uint64_t *timestamp,
			   uint64_t *owner_id,
			   uint64_t *owner_generation,
			   int *live,
			   int use_aio,
			   int io_timeout_sec)
{
	struct task task;
	int rv;

	setup_task_lib(&task, use_aio, io_timeout_sec);

	rv = direct_live_id(&task, ls, timestamp, owner_id, owner_generation, live);

	close_task_aio(&task);

	return rv;
}

int sanlock_direct_init(struct sanlk_lockspace *ls,
			struct sanlk_resource *res,
			int max_hosts, int num_hosts, int use_aio)
{
	struct task task;
	int rv;

	setup_task_lib(&task, use_aio, DEFAULT_IO_TIMEOUT);

	if (!max_hosts)
		max_hosts = DEFAULT_MAX_HOSTS;

	rv = direct_init(&task, ls, res, max_hosts, num_hosts);

	close_task_aio(&task);

	return rv;
}

