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

	task->io_timeout_seconds = io_timeout_seconds;
	task->id_renewal_seconds = id_renewal_seconds;
	task->id_renewal_fail_seconds = id_renewal_fail_seconds;
	task->id_renewal_warn_seconds = id_renewal_warn_seconds;
	task->host_dead_seconds = host_dead_seconds;
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

/* TODO: do we need/want to go through all task->callbacks that are still used
   and wait to reap events for them before doing io_destroy? */

void close_task_aio(struct task *task)
{
	if (task->use_aio)
		io_destroy(task->aio_ctx);

	if (task->callbacks)
		free(task->callbacks);
	task->callbacks = NULL;
}

