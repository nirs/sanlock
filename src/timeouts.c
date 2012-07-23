/*
 * Copyright 2012 Red Hat, Inc.
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
#include "timeouts.h"

int calc_host_dead_seconds(int io_timeout)
{
	/* id_renewal_fail_seconds + WATCHDOG_FIRE_TIMEOUT */
	return (8 * io_timeout) + WATCHDOG_FIRE_TIMEOUT;
}

int calc_id_renewal_seconds(int io_timeout)
{
	return 2 * io_timeout;
}

int calc_id_renewal_fail_seconds(int io_timeout)
{
	return 8 * io_timeout;
}

int calc_id_renewal_warn_seconds(int io_timeout)
{
	return 6 * io_timeout;
}

int calc_request_finish_seconds(int io_timeout)
{
	/* 3 * id_renewal_seconds, somewhat random choice */
	return 6 * io_timeout;
}

void log_timeouts(int io_timeout_arg)
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
