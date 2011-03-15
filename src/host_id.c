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
#include "diskio.h"
#include "log.h"
#include "delta_lease.h"
#include "host_id.h"
#include "watchdog.h"
#include "client_msg.h"

struct list_head spaces;
struct list_head spaces_remove;
pthread_mutex_t spaces_mutex = PTHREAD_MUTEX_INITIALIZER;

int print_space_state(struct space *sp, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "space_id=%u "
		 "host_generation=%llu "
		 "killing_pids=%d "
		 "acquire_last_result=%d "
		 "renewal_last_result=%d "
		 "release_last_result=%d "
		 "acquire_last_time=%llu "
		 "acquire_good_time=%llu "
		 "renewal_last_time=%llu "
		 "renewal_good_time=%llu "
		 "release_last_time=%llu "
		 "release_good_time=%llu "
		 "max_renewal_time=%llu "
		 "max_renewal_interval=%d",
		 sp->space_id,
		 (unsigned long long)sp->host_generation,
		 sp->killing_pids,
		 sp->lease_status.acquire_last_result,
		 sp->lease_status.renewal_last_result,
		 sp->lease_status.release_last_result,
		 (unsigned long long)sp->lease_status.acquire_last_time,
		 (unsigned long long)sp->lease_status.acquire_good_time,
		 (unsigned long long)sp->lease_status.renewal_last_time,
		 (unsigned long long)sp->lease_status.renewal_good_time,
		 (unsigned long long)sp->lease_status.release_last_time,
		 (unsigned long long)sp->lease_status.release_good_time,
		 (unsigned long long)sp->lease_status.max_renewal_time,
		 sp->lease_status.max_renewal_interval);

	return strlen(str);
}

static struct space *_search_space(char *space_name, struct list_head *head)
{
	struct space *sp;

	list_for_each_entry(sp, head, list) {
		if (strncmp(sp->space_name, space_name, NAME_ID_SIZE))
			continue;
		return sp;
	}
	return NULL;
}

int get_space_info(char *space_name, struct space *sp_out)
{
	struct space *sp;

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry(sp, &spaces, list) {
		if (strncmp(sp->space_name, space_name, NAME_ID_SIZE))
			continue;
		memcpy(sp_out, sp, sizeof(struct space));
		pthread_mutex_unlock(&spaces_mutex);
		return 0;
	}
	pthread_mutex_unlock(&spaces_mutex);
	return -1;
}

uint64_t get_our_host_id(char *space_name)
{
	struct space *sp;
	uint64_t id = 0;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(space_name, &spaces);
	if (sp)
		id = sp->host_id;
	pthread_mutex_unlock(&spaces_mutex);
	return id;
}

int host_id_leader_read(char *space_name, uint64_t host_id,
			struct leader_record *leader_ret)
{
	struct space space;
	int rv;

	rv = get_space_info(space_name, &space);
	if (rv < 0)
		return rv;

	rv = delta_lease_leader_read(&space.host_id_disk, space_name,
				     host_id, leader_ret);
	if (rv < 0)
		return rv;

	return 0;
}

/*
 * check if our_host_id_thread has renewed within timeout
 */

int host_id_renewed(struct space *sp)
{
	uint64_t good_time;
	int good_diff;

	pthread_mutex_lock(&sp->mutex);
	good_time = sp->lease_status.renewal_good_time;
	pthread_mutex_unlock(&sp->mutex);

	good_diff = time(NULL) - good_time;

	if (good_diff >= to.host_id_renewal_fail_seconds) {
		log_erros(sp, "host_id_renewed failed %d", good_diff);
		return 0;
	}

	if (good_diff >= to.host_id_renewal_warn_seconds) {
		log_erros(sp, "host_id_renewed warning %d last good %llu",
			  good_diff,
			  (unsigned long long)good_time);
	}

	return 1;
}

static void *host_id_thread(void *arg_in)
{
	struct leader_record leader;
	struct timespec renew_time;
	struct space *sp = (struct space *)arg_in;
	uint64_t our_host_id;
	uint64_t t;
	uint64_t good_time;
	int good_diff;
	int rv, stop, result, dl_result;

	our_host_id = sp->host_id;

	result = delta_lease_acquire(sp, &sp->host_id_disk, sp->space_name,
				     our_host_id, sp->host_id, &leader);
	dl_result = result;
	t = leader.timestamp;

	/* we need to start the watchdog after we acquire the host_id but
	   before we allow any pid's to begin running */

	if (result == DP_OK) {
		rv = create_watchdog_file(sp, t);
		if (rv < 0) {
			log_erros(sp, "create_watchdog failed %d", rv);
			result = DP_ERROR;
		}
	}

	pthread_mutex_lock(&sp->mutex);
	sp->lease_status.acquire_last_result = result;
	sp->lease_status.acquire_last_time = t;
	if (result == DP_OK)
		sp->lease_status.acquire_good_time = t;
	sp->lease_status.renewal_last_result = result;
	sp->lease_status.renewal_last_time = t;
	if (result == DP_OK)
		sp->lease_status.renewal_good_time = t;
	pthread_cond_broadcast(&sp->cond);
	pthread_mutex_unlock(&sp->mutex);

	if (result < 0) {
		log_erros(sp, "host_id %llu acquire failed %d",
			  (unsigned long long)sp->host_id, result);
		goto out;
	}

	log_erros(sp, "host_id %llu generation %llu acquire %llu",
		  (unsigned long long)sp->host_id,
		  (unsigned long long)leader.owner_generation,
		  (unsigned long long)t);

	sp->host_generation = leader.owner_generation;

	good_time = t;
	good_diff = 0;
	renew_time.tv_sec = t;

	while (1) {
		pthread_mutex_lock(&sp->mutex);
		renew_time.tv_sec += to.host_id_renewal_seconds;
		rv = 0;
		while (!sp->thread_stop && rv == 0) {
			rv = pthread_cond_timedwait(&sp->cond,
						    &sp->mutex,
						    &renew_time);
		}
		stop = sp->thread_stop;
		pthread_mutex_unlock(&sp->mutex);
		if (stop)
			break;

		clock_gettime(CLOCK_REALTIME, &renew_time);

		result = delta_lease_renew(sp, &sp->host_id_disk, sp->space_name,
					   our_host_id, sp->host_id, &leader);
		dl_result = result;
		t = leader.timestamp;

		pthread_mutex_lock(&sp->mutex);
		sp->lease_status.renewal_last_result = result;
		sp->lease_status.renewal_last_time = t;

		if (result == DP_OK) {
			sp->lease_status.renewal_good_time = t;

			good_diff = t - good_time;
			good_time = t;

			if (good_diff > sp->lease_status.max_renewal_interval) {
				sp->lease_status.max_renewal_interval = good_diff;
				sp->lease_status.max_renewal_time = t;
			}

			log_space(sp, "host_id %llu renewal %llu interval %d",
				  (unsigned long long)sp->host_id,
				  (unsigned long long)t, good_diff);

			if (!sp->thread_stop)
				update_watchdog_file(sp, t);
		} else {
			log_erros(sp, "host_id %llu renewal error %d last good %llu",
				  (unsigned long long)sp->host_id, result,
				  (unsigned long long)sp->lease_status.renewal_good_time);
		}
		pthread_mutex_unlock(&sp->mutex);
	}

	/* unlink called below to get it done ASAP */
	close_watchdog_file(sp);
 out:
	if (dl_result == DP_OK)
		delta_lease_release(sp, &sp->host_id_disk, sp->space_name,
				    sp->host_id, &leader, &leader);

	return NULL;
}

/*
 * When this function returns, it needs to be safe to being processing lease
 * requests and allowing pid's to run, so we need to own our host_id, and the
 * watchdog needs to be active watching our host_id renewals.
 */

int add_space(struct space *sp)
{
	int rv, result;

	if (space_exists(sp->space_name)) {
		log_erros(sp, "add_space exists");
		goto fail;
	}

	rv = open_disks(&sp->host_id_disk, 1);
	if (rv != 1) {
		log_erros(sp, "add_space open_disk failed %d %s",
			  rv, sp->host_id_disk.path);
		rv = -1;
		goto fail;
	}

	log_space(sp, "add_space host_id %llu path %s offset %llu",
		  (unsigned long long)sp->host_id,
		  sp->host_id_disk.path,
		  (unsigned long long)sp->host_id_disk.offset);

	rv = pthread_create(&sp->thread, NULL, host_id_thread, sp);
	if (rv < 0) {
		log_erros(sp, "add_space create thread failed");
		goto fail_close;
	}

	pthread_mutex_lock(&sp->mutex);
	while (!sp->lease_status.acquire_last_result) {
		pthread_cond_wait(&sp->cond, &sp->mutex);
	}
	result = sp->lease_status.acquire_last_result;
	pthread_mutex_unlock(&sp->mutex);

	if (result != DP_OK) {
		/* the thread exits right away if acquire fails */
		pthread_join(sp->thread, NULL);
		rv = result;
		goto fail_close;
	}

	pthread_mutex_lock(&spaces_mutex);
	/* TODO: repeating check here unnecessary if we serialize adds and removes */
	if (_search_space(sp->space_name, &spaces) ||
	    _search_space(sp->space_name, &spaces_remove)) {
		pthread_mutex_unlock(&spaces_mutex);
		log_erros(sp, "add_space duplicate name");
		goto fail_stop;
	} else {
		list_add(&sp->list, &spaces);
	}
	pthread_mutex_unlock(&spaces_mutex);
	return 0;

 fail_stop:
	sp->thread_stop = 1;
	pthread_join(sp->thread, NULL);
 fail_close:
	close_disks(&sp->host_id_disk, 1);
 fail:
	return rv;
}

int rem_space(char *space_name)
{
	struct space *sp;
	int rv = -ENOENT;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(space_name, &spaces);
	if (sp) {
		sp->external_remove = 1;
		rv = 0;
	}
	pthread_mutex_unlock(&spaces_mutex);
	return rv;
}

/* 
 * we call stop_host_id() when all pids are gone and we're in a safe state, so
 * it's safe to unlink the watchdog right away here.  We want to sp the unlink
 * as soon as it's safe, so we can reduce the chance we get killed by the
 * watchdog (we could actually call this in main_loop just before the break).
 * Getting this unlink done quickly is more important than doing at the more
 * "logical" point commented above in host_id_thread.
 */

static int finish_space(struct space *sp, int wait)
{
	int stop, rv;

	pthread_mutex_lock(&sp->mutex);
	stop = sp->thread_stop;
	pthread_mutex_unlock(&sp->mutex);

	if (!stop) {
		log_erros(sp, "finish_space zero thread_stop");
		return -EINVAL;
	}

	log_space(sp, "finish_space");

	if (wait)
		rv = pthread_join(sp->thread, NULL);
	else
		rv = pthread_tryjoin_np(sp->thread, NULL);

	if (rv)
		return rv;

	log_space(sp, "close_disks");

	close_disks(&sp->host_id_disk, 1);
	return 0;
}

void clear_spaces(int wait)
{
	struct space *sp, *safe;
	int rv;

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry_safe(sp, safe, &spaces_remove, list) {
		rv = finish_space(sp, wait);
		if (!rv) {
			list_del(&sp->list);
			free(sp);
		}
	}
	pthread_mutex_unlock(&spaces_mutex);
}

int space_exists(char *space_name)
{
	struct space *sp;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(space_name, &spaces);
	if (!sp)
		sp = _search_space(space_name, &spaces_remove);
	pthread_mutex_unlock(&spaces_mutex);
	if (sp)
		return 1;
	return 0;
}

void setup_spaces(void)
{
	INIT_LIST_HEAD(&spaces);
	INIT_LIST_HEAD(&spaces_remove);
}

