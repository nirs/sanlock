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

void setup_task_timeouts(struct task *task, int io_timeout_arg)
{
	int io_timeout_seconds = io_timeout_arg;
	int id_renewal_seconds = 2 * io_timeout_seconds;
	int id_renewal_fail_seconds = 8 * io_timeout_seconds;
	int id_renewal_warn_seconds = 6 * io_timeout_seconds;

	/* those above are chosen by us, the rest are based on them */

	int host_dead_seconds      = id_renewal_fail_seconds + WATCHDOG_FIRE_TIMEOUT;
	int delta_large_delay      = id_renewal_seconds + (6 * io_timeout_seconds);
	int delta_short_delay      = 2 * io_timeout_seconds;

	int max = host_dead_seconds;
	if (delta_large_delay > max)
		max = delta_large_delay;

	int delta_acquire_held_max = max + delta_short_delay + (4 * io_timeout_seconds);
	int delta_acquire_held_min = max;
	int delta_acquire_free_max = delta_short_delay + (3 * io_timeout_seconds);
	int delta_acquire_free_min = delta_short_delay;
	int delta_renew_max        = 2 * io_timeout_seconds;
	int delta_renew_min        = 0;
	int paxos_acquire_held_max = host_dead_seconds + (7 * io_timeout_seconds);
	int paxos_acquire_held_min = host_dead_seconds;
	int paxos_acquire_free_max = 6 * io_timeout_seconds;
	int paxos_acquire_free_min = 0;
	int request_finish_seconds = 3 * id_renewal_seconds; /* random */

	task->io_timeout_seconds = io_timeout_seconds;
	task->id_renewal_seconds = id_renewal_seconds;
	task->id_renewal_fail_seconds = id_renewal_fail_seconds;
	task->id_renewal_warn_seconds = id_renewal_warn_seconds;
	task->host_dead_seconds = host_dead_seconds;
	task->request_finish_seconds = request_finish_seconds;

	/* interval between each kill count is approx 1 sec, so we
	   spend about 10 seconds sending 10 SIGTERMs to a pid,
	   then send SIGKILLs to it. after 60 attempts the watchdog
	   should have fired if the kills are due to failed renewal;
	   otherwise we just give up at that point */

	task->kill_count_term = 10;
	task->kill_count_max = 60;

	/* the rest are calculated as needed in place */

	/* hack to make just main thread log this info */
	if (strcmp(task->name, "main"))
		return;

	log_debug("io_timeout_seconds %d", io_timeout_seconds);
	log_debug("id_renewal_seconds %d", id_renewal_seconds);
	log_debug("id_renewal_fail_seconds %d", id_renewal_fail_seconds);
	log_debug("id_renewal_warn_seconds %d", id_renewal_warn_seconds);

	log_debug("host_dead_seconds %d", host_dead_seconds);
	log_debug("delta_large_delay %d", delta_large_delay);
	log_debug("delta_short_delay %d", delta_short_delay);
	log_debug("delta_acquire_held_max %d", delta_acquire_held_max);
	log_debug("delta_acquire_held_min %d", delta_acquire_held_min);
	log_debug("delta_acquire_free_max %d", delta_acquire_free_max);
	log_debug("delta_acquire_free_min %d", delta_acquire_free_min);
	log_debug("delta_renew_max %d", delta_renew_max);
	log_debug("delta_renew_min %d", delta_renew_min);
	log_debug("paxos_acquire_held_max %d", paxos_acquire_held_max);
	log_debug("paxos_acquire_held_min %d", paxos_acquire_held_min);
	log_debug("paxos_acquire_free_max %d", paxos_acquire_free_max);
	log_debug("paxos_acquire_free_min %d", paxos_acquire_free_min);
	log_debug("request_finish_seconds %d", request_finish_seconds);
}

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
	int rv, i, used, warn;

	if (!task->use_aio)
		goto skip_aio;

	memset(&ts, 0, sizeof(struct timespec));
	ts.tv_sec = task->io_timeout_seconds;

	last_warn = time(NULL);

	/* wait for all outstanding aio to complete before
	   destroying aio context, freeing iocb and buffers */

	while (1) {
		warn = 0;

		if (time(NULL) - last_warn >= task->io_timeout_seconds) {
			last_warn = time(NULL);
			warn = 1;
		}

		used = 0;

		for (i = 0; i < task->cb_size; i++) {
			if (!task->callbacks[i].used)
				continue;
			used++;

			if (!warn)
				continue;
			log_taske(task, "close_task_aio %d %p busy",
				  i, &task->callbacks[i]);
		}

		if (!used)
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
	io_destroy(task->aio_ctx);

	if (task->iobuf)
		free(task->iobuf);

 skip_aio:
	if (task->callbacks)
		free(task->callbacks);
	task->callbacks = NULL;
}

