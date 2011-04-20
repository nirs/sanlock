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
		 "acquire_last_attempt=%llu "
		 "acquire_last_success=%llu "
		 "renewal_last_attempt=%llu "
		 "renewal_last_success=%llu",
		 sp->space_id,
		 (unsigned long long)sp->host_generation,
		 sp->killing_pids,
		 sp->lease_status.acquire_last_result,
		 sp->lease_status.renewal_last_result,
		 (unsigned long long)sp->lease_status.acquire_last_attempt,
		 (unsigned long long)sp->lease_status.acquire_last_success,
		 (unsigned long long)sp->lease_status.renewal_last_attempt,
		 (unsigned long long)sp->lease_status.renewal_last_success);

	return strlen(str);
}

static struct space *_search_space(char *name, struct sync_disk *disk,
				   uint64_t host_id, struct list_head *head)
{
	struct space *sp;

	list_for_each_entry(sp, head, list) {
		if (strncmp(sp->space_name, name, NAME_ID_SIZE))
			continue;
		if (disk && strncmp(sp->host_id_disk.path, disk->path, SANLK_PATH_LEN))
			continue;
		if (host_id && sp->host_id != host_id)
			continue;
		return sp;
	}
	return NULL;
}

int _get_space_info(char *space_name, struct space *sp_out)
{
	struct space *sp;

	list_for_each_entry(sp, &spaces, list) {
		if (strncmp(sp->space_name, space_name, NAME_ID_SIZE))
			continue;
		memcpy(sp_out, sp, sizeof(struct space));
		return 0;
	}
	return -1;
}

int get_space_info(char *space_name, struct space *sp_out)
{
	int rv;

	pthread_mutex_lock(&spaces_mutex);
	rv = _get_space_info(space_name, sp_out);
	pthread_mutex_unlock(&spaces_mutex);

	return rv;
}

int host_id_disk_info(char *name, struct sync_disk *disk)
{
	struct space space;
	int rv;

	pthread_mutex_lock(&spaces_mutex);
	rv = _get_space_info(name, &space);
	if (!rv) {
		memcpy(disk, &space.host_id_disk, sizeof(struct sync_disk));
		disk->fd = -1;
	}
	pthread_mutex_unlock(&spaces_mutex);

	return rv;
}

/*
 * check if our_host_id_thread has renewed within timeout
 */

int host_id_check(struct space *sp)
{
	uint64_t last_success;
	int gap;

	pthread_mutex_lock(&sp->mutex);
	last_success = sp->lease_status.renewal_last_success;
	pthread_mutex_unlock(&sp->mutex);

	gap = time(NULL) - last_success;

	if (gap >= to.host_id_renewal_fail_seconds) {
		log_erros(sp, "host_id_check failed %d", gap);
		return 0;
	}

	if (gap >= to.host_id_renewal_warn_seconds) {
		log_erros(sp, "host_id_check warning %d last_success %llu",
			  gap, (unsigned long long)last_success);
	}

	if (com.debug_renew > 1) {
		log_space(sp, "host_id_check good %d %llu",
		  	  gap, (unsigned long long)last_success);
	}

	return 1;
}

static void *host_id_thread(void *arg_in)
{
	struct space *sp;
	char space_name[NAME_ID_SIZE];
	struct sync_disk host_id_disk;
	struct leader_record leader;
	uint64_t host_id;
	time_t last_attempt, last_success;
	int rv, stop = 0, result, delta_result, delta_length, gap;

	sp = (struct space *)arg_in;
	host_id = sp->host_id;
	memcpy(&space_name, sp->space_name, NAME_ID_SIZE);
	memcpy(&host_id_disk, &sp->host_id_disk, sizeof(host_id_disk));

	last_attempt = time(NULL);

	result = delta_lease_acquire(&to, sp, &host_id_disk, space_name,
				     host_id, host_id, &leader);
	delta_result = result;
	delta_length = time(NULL) - last_attempt;

	if (result == SANLK_OK)
		last_success = leader.timestamp;

	/* we need to start the watchdog after we acquire the host_id but
	   before we allow any pid's to begin running */

	if (result == SANLK_OK) {
		rv = create_watchdog_file(sp, last_success);
		if (rv < 0) {
			log_erros(sp, "create_watchdog failed %d", rv);
			result = SANLK_ERROR;
		}
	}

	pthread_mutex_lock(&sp->mutex);
	sp->lease_status.acquire_last_result = result;
	sp->lease_status.acquire_last_attempt = last_attempt;
	if (result == SANLK_OK)
		sp->lease_status.acquire_last_success = last_success;
	sp->lease_status.renewal_last_result = result;
	sp->lease_status.renewal_last_attempt = last_attempt;
	if (result == SANLK_OK)
		sp->lease_status.renewal_last_success = last_success;
	pthread_mutex_unlock(&sp->mutex);

	if (result < 0) {
		log_erros(sp, "host_id %llu acquire failed %d",
			  (unsigned long long)host_id, result);
		goto out;
	}

	log_erros(sp, "host_id %llu generation %llu acquire %llu",
		  (unsigned long long)host_id,
		  (unsigned long long)leader.owner_generation,
		  (unsigned long long)leader.timestamp);

	sp->host_generation = leader.owner_generation;

	while (1) {
		if (stop)
			break;

		sleep(1);

		pthread_mutex_lock(&sp->mutex);
		stop = sp->thread_stop;
		pthread_mutex_unlock(&sp->mutex);

		if (stop)
			break;

		if (time(NULL) - last_success < to.host_id_renewal_seconds)
			continue;

		last_attempt = time(NULL);

		result = delta_lease_renew(&to, sp, &host_id_disk, space_name,
					   host_id, host_id, &leader);
		delta_result = result;
		delta_length = time(NULL) - last_attempt;

		if (result == SANLK_OK)
			last_success = leader.timestamp;

		pthread_mutex_lock(&sp->mutex);
		sp->lease_status.renewal_last_result = result;
		sp->lease_status.renewal_last_attempt = last_attempt;

		if (result == SANLK_OK) {
			gap = last_success - sp->lease_status.renewal_last_success;
			sp->lease_status.renewal_last_success = last_success;

			if (com.debug_renew) {
				log_space(sp, "host_id %llu renewed %llu len %d interval %d",
					  (unsigned long long)host_id,
					  (unsigned long long)last_success,
					  delta_length, gap);
			}

			if (!sp->thread_stop)
				update_watchdog_file(sp, last_success);
		} else {
			log_erros(sp, "host_id %llu renewal error %d len %d last_success %llu",
				  (unsigned long long)host_id, result, delta_length,
				  (unsigned long long)sp->lease_status.renewal_last_success);
		}
		stop = sp->thread_stop;
		pthread_mutex_unlock(&sp->mutex);
	}

	/* unlink called below to get it done ASAP */
	close_watchdog_file(sp);
 out:
	if (delta_result == SANLK_OK)
		delta_lease_release(&to, sp, &host_id_disk, space_name,
				    host_id, &leader, &leader);

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

	if (!sp->space_name[0]) {
		log_erros(sp, "add_space no name");
		rv = -EINVAL;
		goto fail;
	}

	if (!sp->host_id) {
		log_erros(sp, "add_space zero host_id");
		rv = -EINVAL;
		goto fail;
	}

	if (space_exists(sp->space_name, &sp->host_id_disk, sp->host_id)) {
		log_erros(sp, "add_space exists");
		rv = -EEXIST;
		goto fail;
	}

	if (space_exists(sp->space_name, NULL, 0)) {
		log_erros(sp, "add_space name exists with other host info");
		rv = -EINVAL;
		goto fail;
	}

	rv = open_disks(&sp->host_id_disk, 1);
	if (rv != 1) {
		log_erros(sp, "add_space open_disk failed %d %s",
			  rv, sp->host_id_disk.path);
		rv = -ENODEV;
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

	while (1) {
		pthread_mutex_lock(&sp->mutex);
		result = sp->lease_status.acquire_last_result;
		pthread_mutex_unlock(&sp->mutex);
		if (result)
			break;
		sleep(1);
	}

	if (result != SANLK_OK) {
		/* the thread exits right away if acquire fails */
		pthread_join(sp->thread, NULL);
		rv = result;
		goto fail_close;
	}

	pthread_mutex_lock(&spaces_mutex);
	/* TODO: repeating check here unnecessary if we serialize adds and removes */
	if (_search_space(sp->space_name, NULL, 0, &spaces) ||
	    _search_space(sp->space_name, NULL, 0, &spaces_remove)) {
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

int rem_space(char *name, struct sync_disk *disk, uint64_t host_id)
{
	struct space *sp;
	int rv = -ENOENT;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(name, disk, host_id, &spaces);
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

int space_exists(char *name, struct sync_disk *disk, uint64_t host_id)
{
	struct space *sp;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(name, disk, host_id, &spaces);
	if (!sp)
		sp = _search_space(name, disk, host_id, &spaces_remove);
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

