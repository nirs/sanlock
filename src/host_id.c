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
#include <sys/utsname.h>
#include <sys/un.h>
#include <uuid/uuid.h>

#include "sanlock_internal.h"
#include "sanlock_sock.h"
#include "diskio.h"
#include "log.h"
#include "delta_lease.h"
#include "host_id.h"
#include "watchdog.h"
#include "task.h"

static unsigned int space_id_counter = 1;

static struct random_data rand_data;
static char rand_state[32];
static pthread_mutex_t rand_mutex = PTHREAD_MUTEX_INITIALIZER;

struct list_head spaces;
struct list_head spaces_add;
struct list_head spaces_rem;
pthread_mutex_t spaces_mutex = PTHREAD_MUTEX_INITIALIZER;

int print_space_state(struct space *sp, char *str)
{
	memset(str, 0, SANLK_STATE_MAXSTR);

	snprintf(str, SANLK_STATE_MAXSTR-1,
		 "space_id=%u "
		 "host_generation=%llu "
		 "space_dead=%d "
		 "killing_pids=%d "
		 "corrupt_result=%d "
		 "acquire_last_result=%d "
		 "renewal_last_result=%d "
		 "acquire_last_attempt=%llu "
		 "acquire_last_success=%llu "
		 "renewal_last_attempt=%llu "
		 "renewal_last_success=%llu",
		 sp->space_id,
		 (unsigned long long)sp->host_generation,
		 sp->space_dead,
		 sp->killing_pids,
		 sp->lease_status.corrupt_result,
		 sp->lease_status.acquire_last_result,
		 sp->lease_status.renewal_last_result,
		 (unsigned long long)sp->lease_status.acquire_last_attempt,
		 (unsigned long long)sp->lease_status.acquire_last_success,
		 (unsigned long long)sp->lease_status.renewal_last_attempt,
		 (unsigned long long)sp->lease_status.renewal_last_success);

	return strlen(str) + 1;
}

static struct space *_search_space(char *name,
				   struct sync_disk *disk,
				   uint64_t host_id,
				   struct list_head *head1,
				   struct list_head *head2,
				   struct list_head *head3)
{
	struct space *sp;

	if (head1) {
		list_for_each_entry(sp, head1, list) {
			if (name && strncmp(sp->space_name, name, NAME_ID_SIZE))
				continue;
			if (disk && strncmp(sp->host_id_disk.path, disk->path, SANLK_PATH_LEN))
				continue;
			if (disk && sp->host_id_disk.offset != disk->offset)
				continue;
			if (host_id && sp->host_id != host_id)
				continue;
			return sp;
		}
	}
	if (head2) {
		list_for_each_entry(sp, head2, list) {
			if (name && strncmp(sp->space_name, name, NAME_ID_SIZE))
				continue;
			if (disk && strncmp(sp->host_id_disk.path, disk->path, SANLK_PATH_LEN))
				continue;
			if (disk && sp->host_id_disk.offset != disk->offset)
				continue;
			if (host_id && sp->host_id != host_id)
				continue;
			return sp;
		}
	}
	if (head3) {
		list_for_each_entry(sp, head3, list) {
			if (name && strncmp(sp->space_name, name, NAME_ID_SIZE))
				continue;
			if (disk && strncmp(sp->host_id_disk.path, disk->path, SANLK_PATH_LEN))
				continue;
			if (disk && sp->host_id_disk.offset != disk->offset)
				continue;
			if (host_id && sp->host_id != host_id)
				continue;
			return sp;
		}
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

int host_id_check(struct task *task, struct space *sp)
{
	uint64_t last_success;
	int corrupt_result;
	int gap;

	pthread_mutex_lock(&sp->mutex);
	last_success = sp->lease_status.renewal_last_success;
	corrupt_result = sp->lease_status.corrupt_result;
	pthread_mutex_unlock(&sp->mutex);

	if (corrupt_result) {
		log_erros(sp, "host_id_check corrupt %d", corrupt_result);
		return 0;
	}

	gap = monotime() - last_success;

	if (gap >= task->id_renewal_fail_seconds) {
		log_erros(sp, "host_id_check failed %d", gap);
		return 0;
	}

	if (gap >= task->id_renewal_warn_seconds) {
		log_erros(sp, "host_id_check warning %d last_success %llu",
			  gap, (unsigned long long)last_success);
	}

	if (com.debug_renew > 1) {
		log_space(sp, "host_id_check good %d %llu",
		  	  gap, (unsigned long long)last_success);
	}

	return 1;
}

/* If a renewal result is one of the listed errors, it means our
   delta lease has been corrupted/overwritten/reinitialized out from
   under us, and we should stop using it immediately.  There's no
   point in retrying the renewal. */

static int corrupt_result(int result)
{
	switch (result) {
	case SANLK_RENEW_OWNER:
	case SANLK_RENEW_DIFF:
	case SANLK_LEADER_MAGIC:
	case SANLK_LEADER_VERSION:
	case SANLK_LEADER_SECTORSIZE:
	case SANLK_LEADER_LOCKSPACE:
	case SANLK_LEADER_CHECKSUM:
		return result;
	default:
		return 0;
	}
}

static void *lockspace_thread(void *arg_in)
{
	struct task task;
	struct space *sp;
	struct leader_record leader;
	time_t last_attempt, last_success;
	int rv, result, delta_length, gap;
	int delta_result = 0;
	int opened = 0;
	int stop = 0;

	sp = (struct space *)arg_in;

	setup_task_timeouts(&task, main_task.io_timeout_seconds);
	setup_task_aio(&task, main_task.use_aio, HOSTID_AIO_CB_SIZE);
	memcpy(task.name, sp->space_name, NAME_ID_SIZE);

	last_attempt = monotime();

	rv = open_disk(&sp->host_id_disk);
	if (rv < 0) {
		log_erros(sp, "open_disk %s error %d", sp->host_id_disk.path, rv);
		result = -ENODEV;
		goto set_status;
	}
	opened = 1;

	result = delta_lease_acquire(&task, sp, &sp->host_id_disk,
				     sp->space_name, our_host_name_global,
				     sp->host_id, &leader);
	delta_result = result;
	delta_length = monotime() - last_attempt;

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

 set_status:
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

	if (result < 0)
		goto out;

	sp->host_generation = leader.owner_generation;

	while (1) {
		if (stop)
			break;

		pthread_mutex_lock(&sp->mutex);
		stop = sp->thread_stop;
		pthread_mutex_unlock(&sp->mutex);

		if (stop)
			break;

		if (monotime() - last_success < task.id_renewal_seconds) {
			sleep(1);
			continue;
		} else {
			/* don't spin too quickly if renew is failing
			   immediately and repeatedly */
			usleep(500000);
		}

		last_attempt = monotime();

		result = delta_lease_renew(&task, sp, &sp->host_id_disk,
					   sp->space_name, delta_result,
					   &leader, &leader);
		delta_result = result;
		delta_length = monotime() - last_attempt;

		if (result == SANLK_OK)
			last_success = leader.timestamp;

		pthread_mutex_lock(&sp->mutex);
		sp->lease_status.renewal_last_result = result;
		sp->lease_status.renewal_last_attempt = last_attempt;

		if (result == SANLK_OK) {
			gap = last_success - sp->lease_status.renewal_last_success;
			sp->lease_status.renewal_last_success = last_success;

			if (delta_length > task.id_renewal_seconds) {
				log_erros(sp, "renewed %llu delta_length %d too long",
					  (unsigned long long)last_success,
					  delta_length);
			} else if (com.debug_renew) {
				log_space(sp, "renewed %llu delta_length %d interval %d",
					  (unsigned long long)last_success,
					  delta_length, gap);
			}

			if (!sp->thread_stop)
				update_watchdog_file(sp, last_success);
		} else {
			log_erros(sp, "renewal error %d delta_length %d last_success %llu",
				  result, delta_length,
				  (unsigned long long)sp->lease_status.renewal_last_success);

			if (!sp->lease_status.corrupt_result) {
				sp->lease_status.corrupt_result = corrupt_result(result);
				log_erros(sp, "renewal error %d is corruption",
					  sp->lease_status.corrupt_result);
			}
		}
		stop = sp->thread_stop;
		pthread_mutex_unlock(&sp->mutex);
	}

	/* unlink called below to get it done ASAP */
	close_watchdog_file(sp);
 out:
	if (delta_result == SANLK_OK)
		delta_lease_release(&task, sp, &sp->host_id_disk,
				    sp->space_name, &leader, &leader);

	if (opened)
		close(sp->host_id_disk.fd);

	close_task_aio(&task);
	return NULL;
}

/*
 * When this function returns, it needs to be safe to being processing lease
 * requests and allowing pid's to run, so we need to own our host_id, and the
 * watchdog needs to be active watching our host_id renewals.
 */

int add_lockspace(struct sanlk_lockspace *ls)
{
	struct space *sp, *sp2;
	int rv, result;

	if (!ls->name[0] || !ls->host_id || !ls->host_id_disk.path[0]) {
		log_error("add_lockspace bad args id %llu name %zu path %zu",
			  (unsigned long long)ls->host_id,
			  strlen(ls->name), strlen(ls->host_id_disk.path));
		return -EINVAL;
	}

	sp = malloc(sizeof(struct space));
	if (!sp)
		return -ENOMEM;
	memset(sp, 0, sizeof(struct space));

	memcpy(sp->space_name, ls->name, NAME_ID_SIZE);
	memcpy(&sp->host_id_disk, &ls->host_id_disk, sizeof(struct sanlk_disk));
	sp->host_id_disk.sector_size = 0;
	sp->host_id_disk.fd = -1;
	sp->host_id = ls->host_id;
	pthread_mutex_init(&sp->mutex, NULL);

	pthread_mutex_lock(&spaces_mutex);

	/* search all lists for an identical lockspace */

	sp2 = _search_space(sp->space_name, &sp->host_id_disk, sp->host_id,
			    &spaces, NULL, NULL);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EEXIST;
		goto fail_free;
	}

	sp2 = _search_space(sp->space_name, &sp->host_id_disk, sp->host_id,
			    &spaces_add, NULL, NULL);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINPROGRESS;
		goto fail_free;
	}

	sp2 = _search_space(sp->space_name, &sp->host_id_disk, sp->host_id,
			    &spaces_rem, NULL, NULL);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EAGAIN;
		goto fail_free;
	}

	/* search all lists for a lockspace with the same name */

	sp2 = _search_space(sp->space_name, NULL, 0,
			    &spaces, &spaces_add, &spaces_rem);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINVAL;
		goto fail_free;
	}

	/* search all lists for a lockspace with the same host_id_disk */

	sp2 = _search_space(NULL, &sp->host_id_disk, 0,
			    &spaces, &spaces_add, &spaces_rem);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINVAL;
		goto fail_free;
	}

	sp->space_id = space_id_counter++;
	list_add(&sp->list, &spaces_add);
	pthread_mutex_unlock(&spaces_mutex);

	rv = pthread_create(&sp->thread, NULL, lockspace_thread, sp);
	if (rv < 0) {
		log_erros(sp, "add_lockspace create thread failed");
		goto fail_del;
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
		goto fail_del;
	}

	/* once we move sp to spaces list, tokens can begin using it,
	   and the main loop will begin monitoring its renewals */

	pthread_mutex_lock(&spaces_mutex);
	if (sp->external_remove || external_shutdown) {
		rv = -1;
		pthread_mutex_unlock(&spaces_mutex);
		goto fail_del;
	}
	list_move(&sp->list, &spaces);
	pthread_mutex_unlock(&spaces_mutex);
	return 0;

 fail_del:
	pthread_mutex_lock(&spaces_mutex);
	list_del(&sp->list);
	pthread_mutex_unlock(&spaces_mutex);
 fail_free:
	free(sp);
	return rv;
}

int rem_lockspace(struct sanlk_lockspace *ls)
{
	struct space *sp, *sp2;
	unsigned int id;
	int rv, done;

	pthread_mutex_lock(&spaces_mutex);

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces_rem, NULL, NULL);
	if (sp) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINPROGRESS;
		goto out;
	}

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces_add, NULL, NULL);
	if (sp) {
		sp->external_remove = 1;
		pthread_mutex_unlock(&spaces_mutex);
		rv = 0;
		goto out;
	}

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces, NULL, NULL);
	if (!sp) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -ENOENT;
		goto out;
	}

	sp->external_remove = 1;
	id = sp->space_id;
	pthread_mutex_unlock(&spaces_mutex);

	while (1) {
		pthread_mutex_lock(&spaces_mutex);
		sp2 = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   	    &spaces, &spaces_rem, NULL);
		if (sp2 && sp2->space_id == id)
			done = 0;
		else
			done = 1;
		pthread_mutex_unlock(&spaces_mutex);

		if (done)
			break;
		sleep(1);
	}
	rv = 0;
 out:
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

static int stop_lockspace_thread(struct space *sp, int wait)
{
	int stop, rv;

	pthread_mutex_lock(&sp->mutex);
	stop = sp->thread_stop;
	sp->thread_stop = 1;
	pthread_mutex_unlock(&sp->mutex);

	if (!stop) {
		/* should never happen */
		log_erros(sp, "stop_lockspace_thread zero thread_stop");
		return -EINVAL;
	}

	if (wait)
		rv = pthread_join(sp->thread, NULL);
	else
		rv = pthread_tryjoin_np(sp->thread, NULL);

	return rv;
}

void free_lockspaces(int wait)
{
	struct space *sp, *safe;
	int rv;

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry_safe(sp, safe, &spaces_rem, list) {
		rv = stop_lockspace_thread(sp, wait);
		if (!rv) {
			log_space(sp, "free lockspace");
			list_del(&sp->list);
			free(sp);
		}
	}
	pthread_mutex_unlock(&spaces_mutex);
}

/* return a random int between a and b inclusive */

int get_rand(int a, int b)
{
	int32_t val;
	int rv;

	pthread_mutex_lock(&rand_mutex);
	rv = random_r(&rand_data, &val);
	pthread_mutex_unlock(&rand_mutex);
	if (rv < 0)
		return rv;

	return a + (int) (((float)(b - a + 1)) * val / (RAND_MAX+1.0));
}

void setup_spaces(void)
{
	struct utsname name;
	char uuid[37];
	uuid_t uu;

	INIT_LIST_HEAD(&spaces);
	INIT_LIST_HEAD(&spaces_add);
	INIT_LIST_HEAD(&spaces_rem);

	memset(rand_state, 0, sizeof(rand_state));
	memset(&rand_data, 0, sizeof(rand_data));

	initstate_r(time(NULL), rand_state, sizeof(rand_state), &rand_data);

	/* use host name from command line */

	if (com.our_host_name[0]) {
		memcpy(our_host_name_global, com.our_host_name, SANLK_NAME_LEN);
		return;
	}

	/* make up something that's likely to be different among hosts */

	memset(&our_host_name_global, 0, sizeof(our_host_name_global));
	memset(&name, 0, sizeof(name));
	memset(&uuid, 0, sizeof(uuid));

	uname(&name);
	uuid_generate(uu);
	uuid_unparse_lower(uu, uuid);

	snprintf(our_host_name_global, NAME_ID_SIZE, "%s.%s",
		 uuid, name.nodename);
}

