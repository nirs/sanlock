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

static void setup_task_lib(struct task *task, int use_aio)
{
	int rv;

	memset(task, 0, sizeof(struct task));

	sprintf(task->name, "%s", "lib");

	task->io_timeout_seconds = DEFAULT_IO_TIMEOUT_SECONDS;
	task->host_id_timeout_seconds = DEFAULT_HOST_ID_TIMEOUT_SECONDS;
	task->host_id_renewal_seconds = DEFAULT_HOST_ID_RENEWAL_SECONDS;
	task->host_id_renewal_fail_seconds = DEFAULT_HOST_ID_RENEWAL_FAIL_SECONDS;
	task->host_id_renewal_warn_seconds = DEFAULT_HOST_ID_RENEWAL_WARN_SECONDS;

	task->use_aio = use_aio;

	if (task->use_aio) {
		rv = io_setup(LIB_AIO_CB_SIZE, &task->aio_ctx);
		if (rv < 0)
			goto fail;

		task->cb_size = LIB_AIO_CB_SIZE;
		task->callbacks = malloc(LIB_AIO_CB_SIZE * sizeof(struct aicb));
		if (!task->callbacks) {
			rv = -ENOMEM;
			goto fail_setup;
		}
		memset(task->callbacks, 0, LIB_AIO_CB_SIZE * sizeof(struct aicb));
	}
	return;

 fail_setup:
	io_destroy(task->aio_ctx);
 fail:
	task->use_aio = 0;
}

static void close_task_lib(struct task *task)
{
	if (task->use_aio)
		io_destroy(task->aio_ctx);

	if (task->callbacks)
		free(task->callbacks);
	task->callbacks = NULL;
}

int sanlock_direct_read_id(struct sanlk_lockspace *ls,
			   uint64_t *timestamp,
			   uint64_t *owner_id,
			   uint64_t *owner_generation,
			   int use_aio)
{
	struct task task;
	int rv;

	setup_task_lib(&task, use_aio);

	rv = direct_read_id(&task, ls, timestamp, owner_id, owner_generation);

	close_task_lib(&task);

	return rv;
}

int sanlock_direct_live_id(struct sanlk_lockspace *ls,
			   uint64_t *timestamp,
			   uint64_t *owner_id,
			   uint64_t *owner_generation,
			   int *live,
			   int use_aio)
{
	struct task task;
	int rv;

	setup_task_lib(&task, use_aio);

	rv = direct_live_id(&task, ls, timestamp, owner_id, owner_generation, live);

	close_task_lib(&task);

	return rv;
}

int sanlock_direct_init(struct sanlk_lockspace *ls,
			struct sanlk_resource *res,
			int max_hosts, int num_hosts, int use_aio)
{
	struct task task;
	int rv;

	setup_task_lib(&task, use_aio);

	if (!max_hosts)
		max_hosts = DEFAULT_MAX_HOSTS;

	rv = direct_init(&task, ls, res, max_hosts, num_hosts);

	close_task_lib(&task);

	return rv;
}

