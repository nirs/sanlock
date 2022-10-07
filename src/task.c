/*
 * Copyright 2010-2011 Red Hat, Inc.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v2 or (at your option) any later version.
 */

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sanlock_internal.h"
#include "log.h"
#include "task.h"

void setup_task_aio(struct task *task, int use_aio, int cb_size)
{
	int rv;

	task->use_aio = use_aio;

	memset(&task->aio_ctx, 0, sizeof(task->aio_ctx));

	/* main task doesn't actually do disk io so it passes in,
	 * cb_size 0, but it still wants use_aio set for other
	 * tasks to copy */

	if (!use_aio)
		return;

	if (!cb_size)
		return;

	rv = io_setup(cb_size, &task->aio_ctx);
	if (rv < 0)
		goto fail;

	task->cb_size = cb_size;
	task->callbacks = malloc(cb_size * sizeof(struct aicb));
	if (!task->callbacks) {
		rv = -ENOMEM;
		goto fail_setup;
	}
	memset(task->callbacks, 0, cb_size * sizeof(struct aicb));
	return;

 fail_setup:
	io_destroy(task->aio_ctx);
 fail:
	task->use_aio = 0;
}

void close_task_aio(struct task *task)
{
	struct timespec ts;
	struct io_event event;
	uint64_t last_warn;
	uint64_t begin;
	uint64_t now;
	int rv, i, used, lvl;

	if (!task->use_aio)
		goto skip_aio;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = com.io_timeout;

	last_warn = time(NULL);
	begin = last_warn;

	/* wait for all outstanding aio to complete before
	   destroying aio context, freeing iocb and buffers */

	while (1) {
		now = time(NULL);

		if (now - last_warn >= (com.io_timeout * 6)) {
			last_warn = now;
			lvl = LOG_ERR;
		} else {
			lvl = LOG_DEBUG;
		}

		used = 0;

		for (i = 0; i < task->cb_size; i++) {
			if (!task->callbacks[i].used)
				continue;
			used++;

			log_level(0, 0, task->name, lvl, "close_task_aio %d %p busy",
				  i, &task->callbacks[i]);
		}

		if (!used)
			break;

		if (now - begin >= 120)
			break;

		memset(&event, 0, sizeof(event));

		rv = io_getevents(task->aio_ctx, 1, 1, &event, &ts);
		if (rv == -EINTR)
			continue;
		if (rv < 0)
			break;
		if (rv == 1) {
			struct iocb *ev_iocb = event.obj;
			struct aicb *ev_aicb = container_of(ev_iocb, struct aicb, iocb);

			if (ev_aicb->buf == task->iobuf)
				task->iobuf = NULL;

			log_taske(task, "aio collect %p:%p:%p result %ld:%ld close free",
				  ev_aicb, ev_iocb, ev_aicb->buf, event.res, event.res2);

			ev_aicb->used = 0;
			free(ev_aicb->buf);
			ev_aicb->buf = NULL;
		}
	}

	if (used)
		log_taskd(task, "close_task_aio destroy %d incomplete ops", used);

	io_destroy(task->aio_ctx);

	if (used)
		log_taske(task, "close_task_aio destroyed %d incomplete ops", used);

	if (task->iobuf)
		free(task->iobuf);

 skip_aio:
	if (task->callbacks)
		free(task->callbacks);
	task->callbacks = NULL;
}

