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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#include "sanlock_internal.h"
#include "sanlock_admin.h"
#include "sanlock_sock.h"
#include "diskio.h"
#include "ondisk.h"
#include "log.h"
#include "delta_lease.h"
#include "lockspace.h"
#include "resource.h"
#include "watchdog.h"
#include "task.h"
#include "timeouts.h"
#include "direct.h"

static uint32_t space_id_counter = 1;

static struct space *_search_space(const char *name,
				   struct sync_disk *disk,
				   uint64_t host_id,
				   struct list_head *head1,
				   struct list_head *head2,
				   struct list_head *head3,
				   int *listnum)
{
	int i;
	struct space *sp;
	struct list_head *heads[] = {head1, head2, head3};

	for (i = 0; i < 3; i++) {
		if (!heads[i]) {
			continue;
		}

		list_for_each_entry(sp, heads[i], list) {
			if (name && strncmp(sp->space_name, name, NAME_ID_SIZE))
				continue;
			if (disk && strncmp(sp->host_id_disk.path, disk->path, SANLK_PATH_LEN))
				continue;
			if (disk && sp->host_id_disk.offset != disk->offset)
				continue;
			if (host_id && sp->host_id != host_id)
				continue;

			if (listnum)
				*listnum = i+1;
			return sp;
		}
	}
	return NULL;
}

struct space *find_lockspace(const char *name)
{
	return _search_space(name, NULL, 0, &spaces, &spaces_rem, &spaces_add, NULL);
}

static struct space *find_lockspace_id(uint32_t space_id)
{
	struct space *sp;

	list_for_each_entry(sp, &spaces, list) {
		if (sp->space_id == space_id)
			return sp;
	}
	return NULL;
}

int _lockspace_info(const char *space_name, struct space_info *spi)
{
	struct space *sp;

	list_for_each_entry(sp, &spaces, list) {
		if (strncmp(sp->space_name, space_name, NAME_ID_SIZE))
			continue;

		/* keep this in sync with any new fields added to
		   struct space_info */

		spi->space_id = sp->space_id;
		spi->io_timeout = sp->io_timeout;
		spi->sector_size = sp->sector_size;
		spi->align_size = sp->align_size;
		spi->host_id = sp->host_id;
		spi->host_generation = sp->host_generation;
		spi->killing_pids = sp->killing_pids;

		return 0;
	}
	return -1;
}

int lockspace_info(const char *space_name, struct space_info *spi)
{
	int rv;

	pthread_mutex_lock(&spaces_mutex);
	rv = _lockspace_info(space_name, spi);
	pthread_mutex_unlock(&spaces_mutex);

	return rv;
}

int lockspace_disk(char *space_name, struct sync_disk *disk, int *sector_size)
{
	struct space *sp;
	int rv = -1;

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry(sp, &spaces, list) {
		if (strncmp(sp->space_name, space_name, NAME_ID_SIZE))
			continue;

		memcpy(disk, &sp->host_id_disk, sizeof(struct sync_disk));
		*sector_size = sp->sector_size;
		disk->fd = -1;
		rv = 0;
	}
	pthread_mutex_unlock(&spaces_mutex);

	return rv;
}

#if 0
static void clear_bit(int host_id, char *bitmap)
{
	char *byte = bitmap + ((host_id - 1) / 8);
	unsigned int bit = host_id % 8;

	*byte &= ~bit;
}
#endif

void set_id_bit(int host_id, char *bitmap, char *c)
{
	char *byte = bitmap + ((host_id - 1) / 8);
	unsigned int bit = (host_id - 1) % 8;
	char mask;

	mask = 1 << bit;

	*byte |= mask;

	if (c)
		*c = *byte;
}

/* FIXME: another copy in direct_lib.c */

int test_id_bit(int host_id, char *bitmap)
{
	char *byte = bitmap + ((host_id - 1) / 8);
	unsigned int bit = (host_id - 1) % 8;
	char mask;

	mask = 1 << bit;

	return (*byte & mask);
}

int host_status_set_bit(char *space_name, uint64_t host_id)
{
	struct space *sp;
	int found = 0;

	if (!host_id || host_id > DEFAULT_MAX_HOSTS)
		return -EINVAL;

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry(sp, &spaces, list) {
		if (strncmp(sp->space_name, space_name, NAME_ID_SIZE))
			continue;
		found = 1;
		break;
	}
	pthread_mutex_unlock(&spaces_mutex);

	if (!found)
		return -ENOSPC;

	pthread_mutex_lock(&sp->mutex);
	sp->host_status[host_id-1].set_bit_time = monotime();
	pthread_mutex_unlock(&sp->mutex);
	return 0;
}

int host_info(char *space_name, uint64_t host_id, struct host_status *hs_out)
{
	struct space *sp;
	int found = 0;

	if (!host_id || host_id > DEFAULT_MAX_HOSTS)
		return -EINVAL;

	pthread_mutex_lock(&spaces_mutex);
	list_for_each_entry(sp, &spaces, list) {
		if (strncmp(sp->space_name, space_name, NAME_ID_SIZE))
			continue;
		memcpy(hs_out, &sp->host_status[host_id-1], sizeof(struct host_status));
		found = 1;

		if (!hs_out->io_timeout) {
			log_erros(sp, "host_info %llu use own io_timeout %d",
				  (unsigned long long)host_id, sp->io_timeout);
			hs_out->io_timeout = sp->io_timeout;
		}
		break;
	}
	pthread_mutex_unlock(&spaces_mutex);

	if (!found)
		return -ENOSPC;
	return 0;
}

static void create_bitmap_and_extra(struct space *sp, char *bitmap, struct delta_extra *extra)
{
	uint64_t now;
	int i;
	char c;

	now = monotime();

	pthread_mutex_lock(&sp->mutex);
	for (i = 0; i < DEFAULT_MAX_HOSTS; i++) {
		if (i+1 == sp->host_id)
			continue;

		if (!sp->host_status[i].set_bit_time)
			continue;

		if (now - sp->host_status[i].set_bit_time > sp->set_bitmap_seconds) {
			/* log_space(sp, "bitmap clear host_id %d", i+1); */
			sp->host_status[i].set_bit_time = 0;
		} else {
			set_id_bit(i+1, bitmap, &c);
			/* log_space(sp, "bitmap set host_id %d byte %x", i+1, c); */
		}
	}

	extra->field1 = sp->host_event.generation;
	extra->field2 = sp->host_event.event;
	extra->field3 = sp->host_event.data;
	pthread_mutex_unlock(&sp->mutex);
}

/* 
 * Called from main thread to look through the lease data collected in
 * the last renewal.  Records liveness history about other hosts in the
 * lockspace, checks if another host is notifying us (through their bitmap)
 * to look at resource requests or an event they've written.
 *
 * NB. the way that this gets the copy of all leases to look at is
 * unfortunately very subtle and convoluted.
 *
 * The lockspace thread makes a copy of task iobuf, which holds all
 * delta leases that were read in the last renewal, into
 * sp->lease_status.renewal_read_buf.  Then check_our_lease() called
 * by the main loop makes a copy of sp->lease_status.renewal_read_buf
 * to pass to this function.
 */

void check_other_leases(struct space *sp, char *buf)
{
	struct leader_record leader_in;
	struct leader_record *leader_end;
	struct leader_record *leader;
	struct host_status *hs;
	struct sanlk_host_event he;
	char *bitmap;
	uint64_t now;
	int i, new;

	now = monotime();
	new = 0;

	for (i = 0; i < DEFAULT_MAX_HOSTS; i++) {
		hs = &sp->host_status[i];
		hs->last_check = now;

		if (!hs->first_check)
			hs->first_check = now;

		leader_end = (struct leader_record *)(buf + (i * sp->sector_size));

		leader_record_in(leader_end, &leader_in);
		leader = &leader_in;

		/*
		 * If this lease has invalid fields, log an error.  Limit the logging
		 * frequency to avoid blowing up logs if some lease is left in a bad
		 * state for a long time.  Should we check other fields in addition
		 * to magic and space_name?
		 */
		if ((leader->magic != DELTA_DISK_MAGIC) || (strncmp(leader->space_name, sp->space_name, NAME_ID_SIZE))) {
			if (!hs->lease_bad || !(hs->lease_bad % 100)) {
				log_erros(sp, "check_other_lease invalid for host %llu %llu ts %llu name %.48s in %.48s",
					  (unsigned long long)hs->owner_id,
					  (unsigned long long)hs->owner_generation,
					  (unsigned long long)hs->timestamp,
					  hs->owner_name,
					  sp->space_name);
				log_erros(sp, "check_other_lease leader %x owner %llu %llu ts %llu sn %.48s rn %.48s",
					  leader->magic,
					  (unsigned long long)leader->owner_id,
					  (unsigned long long)leader->owner_generation,
					  (unsigned long long)leader->timestamp,
					  leader->space_name,
					  leader->resource_name);
			}
			hs->lease_bad++;
			if (!hs->lease_bad)
				hs->lease_bad++;
		} else {
			if (hs->lease_bad) {
				log_erros(sp, "check_other_lease corrected for host %llu %llu ts %llu name %.48s in %.48s",
					  (unsigned long long)hs->owner_id,
					  (unsigned long long)hs->owner_generation,
					  (unsigned long long)hs->timestamp,
					  hs->owner_name,
					  sp->space_name);
			}
			hs->lease_bad = 0;
		}

		/*
		 * Save a record of each new host instance to help with debugging.
		 */
		if (!hs->lease_bad &&
		    (strncmp(hs->owner_name, leader->resource_name, NAME_ID_SIZE) ||
		     (hs->owner_generation != leader->owner_generation))) {
			log_level(sp->space_id, 0, NULL, LOG_WARNING,
				  "host %llu %llu %llu %.48s",
				  (unsigned long long)leader->owner_id,
				  (unsigned long long)leader->owner_generation,
				  (unsigned long long)leader->timestamp,
				  leader->resource_name);
			strncpy(hs->owner_name, leader->resource_name, NAME_ID_SIZE);
		}

		if (hs->owner_id == leader->owner_id &&
		    hs->owner_generation == leader->owner_generation &&
		    hs->timestamp == leader->timestamp) {
			continue;
		}

		/*
		 * Replacing good values with potentially bad values
		 * would have no purpose, and would confuse things, so
		 * don't replace these fields if the lease is bad.
		 * But, continue to update the timestamp because we don't
		 * want to consider the host to be dead if the lease
		 * is being renewed, even if the lease has bad fields.
		 */
		if (!hs->lease_bad) {
			hs->owner_id = leader->owner_id;
			hs->owner_generation = leader->owner_generation;
			strncpy(hs->owner_name, leader->resource_name, NAME_ID_SIZE);
			hs->io_timeout = leader->io_timeout;
		}

		hs->timestamp = leader->timestamp;
		hs->last_live = now;

		if (i+1 == sp->host_id)
			continue;

		bitmap = (char *)leader_end + HOSTID_BITMAP_OFFSET;

		if (!test_id_bit(sp->host_id, bitmap))
			continue;

		/*
		 * Our bit is set in the bitmap, so this host is
		 * notifying us of a host_event or resource request.
		 */

		memset(&he, 0, sizeof(he));
		he.host_id = sp->host_id;
		he.generation = leader->write_id;
		he.event = leader->write_generation;
		he.data = leader->write_timestamp;

		/*
		 * Pass an event to the resource_thread which is a
		 * convenient place to do callbacks (we don't want
		 * the main thread to be delayed with that.)
		 */
		if (he.event) {
			/*
			 * lock order: spaces_mutex (main_loop), then
			 * resource_mutex (add_host_event).
			 */
			log_space(sp, "host event from host_id %d", i+1);
			add_host_event(sp->space_id, &he,
				       hs->owner_id, hs->owner_generation);
		}

		/* this host has made a resource request for us, we won't take a new
		   request from this host for another set_bitmap_seconds */

		if (now - hs->last_req < sp->set_bitmap_seconds)
			continue;

		log_space(sp, "request from host_id %d", i+1);
		hs->last_req = now;
		new = 1;
	}

	/*
	 * Have the resource_thread check the request records of resources
	 * in this lockspace.
	 */
	if (new)
		set_resource_examine(sp->space_name, NULL);
}

/*
 * check if our_host_id_thread has renewed within timeout
 */

int check_our_lease(struct space *sp, int *check_all, char *check_buf)
{
	int id_renewal_fail_seconds, id_renewal_warn_seconds;
	uint64_t last_success;
	int corrupt_result;
	int gap;

	pthread_mutex_lock(&sp->mutex);
	last_success = sp->lease_status.renewal_last_success;
	corrupt_result = sp->lease_status.corrupt_result;

	if (sp->lease_status.renewal_read_count > sp->lease_status.renewal_read_check) {
		/*
		 * NB. it's unfortunate how subtle this is.
		 * main loop will pass this buf to check_other_leases next
		 */
		sp->lease_status.renewal_read_check = sp->lease_status.renewal_read_count;
		*check_all = 1;
		if (check_buf)
			memcpy(check_buf, sp->lease_status.renewal_read_buf, sp->align_size);
	}
	pthread_mutex_unlock(&sp->mutex);

	if (corrupt_result) {
		log_erros(sp, "check_our_lease corrupt %d", corrupt_result);
		return -1;
	}

	gap = monotime() - last_success;

	id_renewal_fail_seconds = calc_id_renewal_fail_seconds(sp->io_timeout);
	id_renewal_warn_seconds = calc_id_renewal_warn_seconds(sp->io_timeout);

	if (gap >= id_renewal_fail_seconds) {
		log_erros(sp, "check_our_lease failed %d", gap);
		return -1;
	}

	if (gap >= id_renewal_warn_seconds) {
		log_erros(sp, "check_our_lease warning %d last_success %llu",
			  gap, (unsigned long long)last_success);
	}

	if (com.debug_renew > 1) {
		log_space(sp, "check_our_lease good %d %llu",
		  	  gap, (unsigned long long)last_success);
	}

	return 0;
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

static void close_event_fds(struct space *sp)
{
	int i;

	pthread_mutex_lock(&sp->mutex);
	for (i = 0; i < MAX_EVENT_FDS; i++) {
		if (sp->event_fds[i] == -1)
			continue;

		close(sp->event_fds[i]);
		sp->event_fds[i] = -1;
	}
	pthread_mutex_unlock(&sp->mutex);
}

/*
 * if delta_result is success:
 * new record saving last_success (timestamp in renewal), rd_ms, wr_ms
 * if delta_result is timeout:
 * increment next_timeouts in prev record
 * if delta_result is failure:
 * increment next_errors in prev record
 */

static void save_renewal_history(struct space *sp, int delta_result,
				 uint64_t last_success, int rd_ms, int wr_ms)
{
	struct renewal_history *hi;

	if (!sp->renewal_history_size || !sp->renewal_history)
		return;

	if (delta_result == SANLK_OK) {
		hi = &sp->renewal_history[sp->renewal_history_next];

		hi->timestamp = last_success;
		hi->read_ms = rd_ms;
		hi->write_ms = wr_ms;

		sp->renewal_history_prev = sp->renewal_history_next;
		sp->renewal_history_next++;
		if (sp->renewal_history_next >= sp->renewal_history_size)
			sp->renewal_history_next = 0;
	} else {
		hi = &sp->renewal_history[sp->renewal_history_prev];

		if (delta_result == SANLK_AIO_TIMEOUT)
			hi->next_timeouts++;
		else
			hi->next_errors++;
	}
}

/*
 * This thread must not be stopped unless all pids that may be using any
 * resources in it are dead/gone.  (The USED flag in the lockspace represents
 * pids using resources in the lockspace, when those pids are not using actual
 * sanlock resources.  So the USED flag must also prevent this thread from
 * stopping.)
 */

static void *lockspace_thread(void *arg_in)
{
	char bitmap[HOSTID_BITMAP_SIZE];
	struct delta_extra extra;
	struct task task;
	struct space *sp;
	struct leader_record leader;
	uint64_t delta_begin, last_success = 0;
	int log_renewal_level = -1;
	int rv, delta_length, renewal_interval = 0;
	int id_renewal_seconds, id_renewal_fail_seconds;
	int acquire_result, delta_result, read_result;
	int rd_ms, wr_ms;
	int opened = 0;
	int stop = 0;
	int wd_con;

	if (com.debug_renew)
		log_renewal_level = LOG_DEBUG;

	sp = (struct space *)arg_in;

	memset(&task, 0, sizeof(struct task));
	setup_task_aio(&task, main_task.use_aio, HOSTID_AIO_CB_SIZE);
	memcpy(task.name, sp->space_name, NAME_ID_SIZE);

	id_renewal_seconds = calc_id_renewal_seconds(sp->io_timeout);
	id_renewal_fail_seconds = calc_id_renewal_fail_seconds(sp->io_timeout);

	delta_begin = monotime();

	rv = open_disk(&sp->host_id_disk);
	if (rv < 0) {
		log_erros(sp, "open_disk %s error %d", sp->host_id_disk.path, rv);
		acquire_result = -ENODEV;
		delta_result = -1;
		goto set_status;
	}
	opened = 1;

	if (!sp->sector_size) {
		int ss = 0;

		rv = delta_read_lockspace_sector_size(&task, &sp->host_id_disk, sp->io_timeout, &ss);
		if (rv < 0) {
			log_erros(sp, "failed to read device to find sector size error %d %s", rv, sp->host_id_disk.path);
			acquire_result = rv;
			delta_result = -1;
			goto set_status;
		}

		if ((ss != 512) && (ss != 4096)) {
			log_erros(sp, "failed to get valid sector size %d %s", ss, sp->host_id_disk.path);
			acquire_result = SANLK_LEADER_SECTORSIZE;
			delta_result = -1;
			goto set_status;
		}

		sp->sector_size = ss;
		sp->align_size = sector_size_to_align_size(ss);
	}

	sp->lease_status.renewal_read_buf = malloc(sp->align_size);
	if (!sp->lease_status.renewal_read_buf) {
		acquire_result = -ENOMEM;
		delta_result = -1;
		goto set_status;
	}

	/* Connect first so we can fail quickly if wdmd is not running. */
	wd_con = connect_watchdog(sp);
	if (wd_con < 0) {
		log_erros(sp, "connect_watchdog failed %d", wd_con);
		acquire_result = SANLK_WD_ERROR;
		delta_result = -1;
		goto set_status;
	}

	/*
	 * acquire the delta lease
	 */

	delta_begin = monotime();

	delta_result = delta_lease_acquire(&task, sp, &sp->host_id_disk,
					   sp->space_name, our_host_name_global,
					   sp->host_id, &leader);
	delta_length = monotime() - delta_begin;

	if (delta_result == SANLK_OK)
		last_success = leader.timestamp;

	acquire_result = delta_result;

	/* we need to start the watchdog after we acquire the host_id but
	   before we allow any pid's to begin running */

	if (delta_result == SANLK_OK) {
		rv = activate_watchdog(sp, last_success, id_renewal_fail_seconds, wd_con);
		if (rv < 0) {
			log_erros(sp, "activate_watchdog failed %d", rv);
			acquire_result = SANLK_WD_ERROR;
		}
	} else {
		if (com.use_watchdog)
			close(wd_con);
	}

 set_status:
	pthread_mutex_lock(&sp->mutex);
	sp->lease_status.acquire_last_result = acquire_result;
	sp->lease_status.acquire_last_attempt = delta_begin;
	if (delta_result == SANLK_OK)
		sp->lease_status.acquire_last_success = last_success;
	sp->lease_status.renewal_last_result = acquire_result;
	sp->lease_status.renewal_last_attempt = delta_begin;
	if (delta_result == SANLK_OK)
		sp->lease_status.renewal_last_success = last_success;
	/* First renewal entry shows the acquire time with 0 latencies. */
	save_renewal_history(sp, delta_result, last_success, 0, 0);
	pthread_mutex_unlock(&sp->mutex);

	if (acquire_result < 0)
		goto out;

	sp->host_generation = leader.owner_generation;

	while (1) {
		pthread_mutex_lock(&sp->mutex);
		stop = sp->thread_stop;
		pthread_mutex_unlock(&sp->mutex);
		if (stop)
			break;

		/*
		 * wait between each renewal
		 */

		if (monotime() - last_success < id_renewal_seconds) {
			sleep(1);
			continue;
		} else {
			/* don't spin too quickly if renew is failing
			   immediately and repeatedly */
			usleep(500000);
		}


		/*
		 * do a renewal, measuring length of time spent in renewal,
		 * and the length of time between successful renewals
		 */

		memset(bitmap, 0, sizeof(bitmap));
		memset(&extra, 0, sizeof(extra));
		create_bitmap_and_extra(sp, bitmap, &extra);

		delta_begin = monotime();

		delta_result = delta_lease_renew(&task, sp, &sp->host_id_disk,
						 sp->space_name, bitmap, &extra,
						 delta_result, &read_result,
						 log_renewal_level,
						 &leader, &leader,
						 &rd_ms, &wr_ms);
		delta_length = monotime() - delta_begin;

		if (delta_result == SANLK_OK) {
			renewal_interval = leader.timestamp - last_success;
			last_success = leader.timestamp;
		}


		/*
		 * publish the results
		 */

		pthread_mutex_lock(&sp->mutex);
		sp->lease_status.renewal_last_result = delta_result;
		sp->lease_status.renewal_last_attempt = delta_begin;

		if (delta_result == SANLK_OK)
			sp->lease_status.renewal_last_success = last_success;

		if (delta_result != SANLK_OK && !sp->lease_status.corrupt_result)
			sp->lease_status.corrupt_result = corrupt_result(delta_result);

		if (read_result == SANLK_OK && task.iobuf) {
			/* NB. be careful with how this iobuf escapes */
			memcpy(sp->lease_status.renewal_read_buf, task.iobuf, sp->align_size);
			sp->lease_status.renewal_read_count++;
		}

		/*
		 * pet the watchdog
		 * (don't update on thread_stop because it's probably unlinked)
		 */

		if (delta_result == SANLK_OK && !sp->thread_stop)
			update_watchdog(sp, last_success, id_renewal_fail_seconds);

		save_renewal_history(sp, delta_result, last_success, rd_ms, wr_ms);
		pthread_mutex_unlock(&sp->mutex);


		/*
		 * log the results
		 */

		if (delta_result != SANLK_OK) {
			log_erros(sp, "renewal error %d delta_length %d last_success %llu",
				  delta_result, delta_length, (unsigned long long)last_success);
		} else if (delta_length > id_renewal_seconds) {
			log_erros(sp, "renewed %llu delta_length %d too long",
				  (unsigned long long)last_success, delta_length);
		} else {
			if (com.debug_renew) {
				log_space(sp, "renewed %llu delta_length %d interval %d",
					  (unsigned long long)last_success, delta_length, renewal_interval);
			}
		}
	}

	/* watchdog unlink was done in main_loop when thread_stop was set, to
	   get it done as quickly as possible in case the wd is about to fire. */

	close_watchdog(sp);
 out:
	if (delta_result == SANLK_OK)
		delta_lease_release(&task, sp, &sp->host_id_disk,
				    sp->space_name, &leader, &leader);

	if (opened)
		close(sp->host_id_disk.fd);

	/*
	 * TODO: are there cases where struct resources for this lockspace
	 * still exist on resource_held/resource_add/resource_rem?  Is that ok?
	 * Should we purge all of them here?  When a lockspace is removed and
	 * pids are killed, their resources go through release_token_async,
	 * which will see token->space_dead, and those resources are freed
	 * directly.  resources that may have already been on resources_rem and
	 * the resource_thread may be in the middle of releasing one of them.
	 * For any further async releases, resource_thread will see that the
	 * lockspace is going away and will just free the resource.
	 */

	purge_resource_orphans(sp->space_name);

	close_event_fds(sp);

	close_task_aio(&task);
	return NULL;
}

static void free_sp(struct space *sp)
{
	if (sp->lease_status.renewal_read_buf)
		free(sp->lease_status.renewal_read_buf);
	free(sp);
}

int add_lockspace_start(struct sanlk_lockspace *ls, uint32_t io_timeout, struct space **sp_out)
{
	struct space *sp, *sp2;
	int listnum = 0;
	int rv;
	int i;

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
	sp->io_timeout = io_timeout;
	sp->set_bitmap_seconds = calc_set_bitmap_seconds(io_timeout);
	pthread_mutex_init(&sp->mutex, NULL);

	if (com.renewal_read_extend_sec_set)
		sp->renewal_read_extend_sec = com.renewal_read_extend_sec;
	else
		sp->renewal_read_extend_sec = io_timeout;

	for (i = 0; i < MAX_EVENT_FDS; i++)
		sp->event_fds[i] = -1;

	if (com.renewal_history_size) {
		sp->renewal_history = malloc(sizeof(struct renewal_history) * com.renewal_history_size);
		if (sp->renewal_history) {
			sp->renewal_history_size = com.renewal_history_size;
			memset(sp->renewal_history, 0, sizeof(struct renewal_history) * com.renewal_history_size);
		}
	}

	pthread_mutex_lock(&spaces_mutex);

	/* search all lists for an identical lockspace */

	sp2 = _search_space(sp->space_name, &sp->host_id_disk, sp->host_id,
			    &spaces, NULL, NULL, NULL);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EEXIST;
		goto fail_free;
	}

	sp2 = _search_space(sp->space_name, &sp->host_id_disk, sp->host_id,
			    &spaces_add, NULL, NULL, NULL);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINPROGRESS;
		goto fail_free;
	}

	sp2 = _search_space(sp->space_name, &sp->host_id_disk, sp->host_id,
			    &spaces_rem, NULL, NULL, NULL);
	if (sp2) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EAGAIN;
		goto fail_free;
	}

	/* search all lists for a lockspace with the same name */

	sp2 = _search_space(sp->space_name, NULL, 0,
			    &spaces, &spaces_add, &spaces_rem, &listnum);
	if (sp2) {
		log_error("add_lockspace %.48s:%llu:%.256s:%llu conflicts with name of list%d s%d %.48s:%llu:%.256s:%llu",
			  sp->space_name,
			  (unsigned long long)sp->host_id,
			  sp->host_id_disk.path,
			  (unsigned long long)sp->host_id_disk.offset,
			  listnum,
			  sp2->space_id,
			  sp2->space_name,
			  (unsigned long long)sp2->host_id,
			  sp2->host_id_disk.path,
			  (unsigned long long)sp2->host_id_disk.offset);
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINVAL;
		goto fail_free;
	}

	/* search all lists for a lockspace with the same host_id_disk */

	sp2 = _search_space(NULL, &sp->host_id_disk, 0,
			    &spaces, &spaces_add, &spaces_rem, &listnum);
	if (sp2) {
		log_error("add_lockspace %.48s:%llu:%.256s:%llu conflicts with path of list%d s%d %.48s:%llu:%.256s:%llu",
			  sp->space_name,
			  (unsigned long long)sp->host_id,
			  sp->host_id_disk.path,
			  (unsigned long long)sp->host_id_disk.offset,
			  listnum,
			  sp2->space_id,
			  sp2->space_name,
			  (unsigned long long)sp2->host_id,
			  sp2->host_id_disk.path,
			  (unsigned long long)sp2->host_id_disk.offset);
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINVAL;
		goto fail_free;
	}

	sp->space_id = space_id_counter++;
	list_add(&sp->list, &spaces_add);
	pthread_mutex_unlock(&spaces_mutex);

	/* save a record of what this space_id is for later debugging */
	log_level(sp->space_id, 0, NULL, LOG_WARNING,
		  "lockspace %.48s:%llu:%.256s:%llu",
		  sp->space_name,
		  (unsigned long long)sp->host_id,
		  sp->host_id_disk.path,
		  (unsigned long long)sp->host_id_disk.offset);

	rv = pthread_create(&sp->thread, NULL, lockspace_thread, sp);
	if (rv < 0) {
		log_erros(sp, "add_lockspace create thread failed");
		goto fail_del;
	}

	*sp_out = sp;
	return 0;

 fail_del:
	pthread_mutex_lock(&spaces_mutex);
	list_del(&sp->list);
	pthread_mutex_unlock(&spaces_mutex);
 fail_free:
	free_sp(sp);
	return rv;
}

int add_lockspace_wait(struct space *sp)
{
	int rv, result;

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
		log_erros(sp, "add_lockspace fail result %d", result);
		goto fail_del;
	}

	/* Once we move sp to spaces list, tokens can begin using it,
	   the main loop will begin monitoring its renewals, and will
	   handle removing it. */

	pthread_mutex_lock(&spaces_mutex);
	if (sp->external_remove || external_shutdown) {
		pthread_mutex_unlock(&spaces_mutex);
		log_space(sp, "add_lockspace undo remove %d shutdown %d",
			  sp->external_remove, external_shutdown);

		/* We've caught a remove/shutdown just before completing
		   the add process.  Don't complete it, but reverse the
		   add, leaving the sp on spaces_add while reversing.
		   Do the same thing that main_loop would do, except we
		   don't have to go through killing_pids and checking for
		   all_pids_dead since this lockspace has never been on
		   the spaces list, so it could not have been used yet. */

		pthread_mutex_lock(&sp->mutex);
		sp->thread_stop = 1;
		deactivate_watchdog(sp);
		pthread_mutex_unlock(&sp->mutex);
		pthread_join(sp->thread, NULL);
		rv = -1;
		log_space(sp, "add_lockspace undo complete");
		goto fail_del;
	} else {
		list_move(&sp->list, &spaces);
		log_space(sp, "add_lockspace done");
		pthread_mutex_unlock(&spaces_mutex);
		return 0;
	}

 fail_del:
	pthread_mutex_lock(&spaces_mutex);
	list_del(&sp->list);
	pthread_mutex_unlock(&spaces_mutex);
	free_sp(sp);
	return rv;
}

int inq_lockspace(struct sanlk_lockspace *ls)
{
	int rv;
	struct space *sp;

	pthread_mutex_lock(&spaces_mutex);

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces, NULL, NULL, NULL);

	if (sp) {
		rv = 0;
		goto out;
	} else {
		rv = -ENOENT;
	}

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces_add, &spaces_rem, NULL, NULL);

	if (sp)
		rv = -EINPROGRESS;

 out:
	pthread_mutex_unlock(&spaces_mutex);
	return rv;
}

int rem_lockspace_start(struct sanlk_lockspace *ls, unsigned int *space_id)
{
	struct space *sp;
	unsigned int id;
	int rv;

	pthread_mutex_lock(&spaces_mutex);

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces_rem, NULL, NULL, NULL);
	if (sp) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -EINPROGRESS;
		goto out;
	}

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces_add, NULL, NULL, NULL);
	if (sp) {
		/* add_lockspace will be aborted and undone and the sp will
		   not be moved to the spaces list */
		sp->external_remove = 1;
		id = sp->space_id;
		pthread_mutex_unlock(&spaces_mutex);
		*space_id = id;
		rv = 0;
		goto out;
	}

	sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   &spaces, NULL, NULL, NULL);
	if (!sp) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -ENOENT;
		goto out;
	}

	/*
	 * Removal happens in a round about way:
	 * - we set external_remove
	 * - main_loop sees external_remove and sets space_dead, killing_pids
	 * - main_loop sees killing_pids and all pids dead, sets thread_stop,
	 *   and moves sp from spaces to spaces_rem
	 * - main_loop calls free_lockspaces(0), which joins any
	 *   lockspace_thread that is done, and then frees sp
	 *
	 * Once we release spaces_mutex, the sp could be freed any time,
	 * so we can't touch it.  Use its space_id to check for completion.
	 */

	sp->external_remove = 1;
	id = sp->space_id;
	pthread_mutex_unlock(&spaces_mutex);
	*space_id = id;
	rv = 0;
 out:
	return rv;
}

/* check for matching space_id in case the lockspace is added again */

int rem_lockspace_wait(struct sanlk_lockspace *ls, unsigned int space_id)
{
	struct space *sp;
	int done;

	while (1) {
		pthread_mutex_lock(&spaces_mutex);
		sp = _search_space(ls->name, (struct sync_disk *)&ls->host_id_disk, ls->host_id,
			   	   &spaces, &spaces_rem, &spaces_add, NULL);
		if (sp && (sp->space_id == space_id))
			done = 0;
		else
			done = 1;
		pthread_mutex_unlock(&spaces_mutex);

		if (done)
			break;
		sleep(1);
	}
	return 0;
}

int get_lockspaces(char *buf, int *len, int *count, int maxlen)
{
	struct sanlk_lockspace *ls;
	struct space *sp;
	struct list_head *heads[] = {&spaces, &spaces_rem, &spaces_add};
	int i, rv, sp_count = 0;

	rv = 0;
	*len = 0;
	*count = 0;
	ls = (struct sanlk_lockspace *)buf;

	pthread_mutex_lock(&spaces_mutex);
	for (i = 0; i < 3; i++) {
		list_for_each_entry(sp, heads[i], list) {
			sp_count++;

			if (*len + sizeof(struct sanlk_lockspace) > maxlen) {
				rv = -ENOSPC;
				continue;
			}

			memcpy(ls->name, sp->space_name, NAME_ID_SIZE);
			memcpy(&ls->host_id_disk, &sp->host_id_disk, sizeof(struct sync_disk));
			ls->host_id_disk.pad1 = 0;
			ls->host_id_disk.pad2 = 0;
			ls->host_id = sp->host_id;
			ls->flags = 0;

			if (i == 1)
				ls->flags |= SANLK_LSF_REM;
			else if (i == 2)
				ls->flags |= SANLK_LSF_ADD;

			*len += sizeof(struct sanlk_lockspace);

			ls++;
		}
	}
	pthread_mutex_unlock(&spaces_mutex);

	*count = sp_count;

	return rv;
}

/*
 * After the lockspace starts, there is a limited amount of
 * time that we've been watching the other hosts.  This means
 * we can't make an accurate assessment of their state, because
 * the state is based on monitoring the hosts for host_fail_seconds
 * and host_dead_seconds, or seeing a renewal.  When none of
 * those are true (not enough time monitoring and not seeing a
 * renewal), we return UNKNOWN.
 *
 * (Example number of seconds below are based on hosts using the
 * default 10 second io timeout.)
 *
 * * For hosts that are alive when we start, we return:
 *   UNKNOWN then LIVE
 *
 *   UNKNOWN would typically last for 10-20 seconds, but it's possible that
 *   UNKNOWN could persist for up to 80 seconds before LIVE is returned.
 *   LIVE is returned after we see the timestamp change once.
 * 
 * * For hosts that are dead when we start, we'd return:
 *   UNKNOWN then FAIL then DEAD
 *
 *   UNKNOWN would last for 80 seconds before we return FAIL.
 *   FAIL would last for 60 more seconds before we return DEAD.
 *
 * * Hosts that are failing and don't recover would be the same as prev.
 *
 * * For hosts thet are failing but recover, we'd return:
 *   UNKNOWN then FAIL then LIVE
 *
 *
 * For another host that is alive when we start,
 * the sequence of values is:
 *
 *  0: we have not yet called check_other_leases()
 *     first_check = 0,  last_check = 0,  last_live = 0
 *
 *     other host renews its lease
 *
 * 10: we call check_other_leases() for the first time,
 *     first_check = 10, last_check = 10, last_live = 10
 *
 *     other host renews its lease
 *
 * 20: we call check_other_leases() for the second time,
 *     first_check = 10, last_check = 20, last_live = 20
 *
 * At 10, we have not yet seen a renewal from the other host, i.e. we have
 * not seen its timestamp change (we only have one sample).  The host could
 * be dead or alive, so we set the state to UNKNOWN.  The way we know
 * that we have not yet observed the timestamp change is that
 * first_check == last_live, (10 == 10).
 *
 * At 20, we have seen a renewal, i.e. the timestamp changed between checks,
 * so we return LIVE.
 *
 * In the other case, if the host was actually dead, not alive, it would not
 * have renewed between 10 and 20.  So at 20 we would continue to see
 * first_check == last_live, and would return UNKNOWN.  If the host remains
 * dead, we'd continue to report UNKNOWN for the first 80 seconds.
 * After 80 seconds, we'd return FAIL.  After 140 seconds we'd return DEAD.
 */

/* Also see host_live() */

static uint32_t get_host_flag(struct space *sp, struct host_status *hs)
{
	uint64_t now, last;
	uint32_t flags;
	uint32_t other_io_timeout;
	int other_host_fail_seconds, other_host_dead_seconds;

	now = monotime();
	other_io_timeout = hs->io_timeout;
	other_host_fail_seconds = calc_id_renewal_fail_seconds(other_io_timeout);
	other_host_dead_seconds = calc_host_dead_seconds(other_io_timeout);

	flags = 0;

	if (!hs->timestamp) {
		flags = SANLK_HOST_FREE;
		goto out;
	}

	if (!hs->last_live)
		last = hs->first_check;
	else
		last = hs->last_live;

	if (sp->host_id == hs->owner_id) {
		/* we are alive */
		flags = SANLK_HOST_LIVE;

	} else if ((now - last <= other_host_fail_seconds) &&
		   (hs->first_check == hs->last_live)) {
		/* we haven't seen the timestamp change yet */
		flags = SANLK_HOST_UNKNOWN;

	} else if (now - last <= other_host_fail_seconds) {
		flags = SANLK_HOST_LIVE;

	} else if (now - last > other_host_dead_seconds) {
		flags = SANLK_HOST_DEAD;

	} else if (now - last > other_host_fail_seconds) {
		flags = SANLK_HOST_FAIL;
	}
out:
	return flags;
}

int get_hosts(struct sanlk_lockspace *ls, char *buf, int *len, int *count, int maxlen)
{
	struct space *sp;
	struct host_status *hs;
	struct sanlk_host *host;
	int host_count = 0;
	int i, rv;

	rv = 0;
	*len = 0;
	*count = 0;
	host = (struct sanlk_host *)buf;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(ls->name, NULL, 0, &spaces, NULL, NULL, NULL);
	if (!sp) {
		rv = -ENOENT;
		goto out;
	}

	/*
	 * Between add_lockspace completing and the first
	 * time we call check_other_leases, we don't have
	 * any data on other hosts, so return this error
	 * to indicate this to the caller.
	 */
	if (!sp->host_status[0].last_check) {
		rv = -EAGAIN;
		goto out;
	}

	for (i = 0; i < DEFAULT_MAX_HOSTS; i++) {
		hs = &sp->host_status[i];

		if (ls->host_id && (ls->host_id != (i + 1)))
			continue;

		if (!ls->host_id && !hs->timestamp)
			continue;

		host_count++;

		if (*len + sizeof(struct sanlk_host) > maxlen) {
			rv = -ENOSPC;
			continue;
		}

		host->host_id = i + 1;
		host->generation = hs->owner_generation;
		host->timestamp = hs->timestamp;
		host->io_timeout = hs->io_timeout;
		host->flags = get_host_flag(sp, hs);

		*len += sizeof(struct sanlk_host);

		host++;
	}
 out:
	pthread_mutex_unlock(&spaces_mutex);

	*count = host_count;

	return rv;
}

int lockspace_set_config(struct sanlk_lockspace *ls, GNUC_UNUSED uint32_t flags, uint32_t cmd)
{
	struct space *sp;
	int rv;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(ls->name, NULL, 0, &spaces, NULL, NULL, NULL);
	if (!sp) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -ENOENT;
		goto out;
	}
	pthread_mutex_unlock(&spaces_mutex);

	pthread_mutex_lock(&sp->mutex);

	switch (cmd) {
	case SANLK_CONFIG_USED:
		if (sp->space_dead) {
			rv = -ENOSPC;
		} else {
			sp->flags |= SP_EXTERNAL_USED;
			rv = 0;
		}
		break;

	case SANLK_CONFIG_UNUSED:
		sp->flags &= ~SP_EXTERNAL_USED;
		rv = 0;
		break;

	case SANLK_CONFIG_USED_BY_ORPHANS:
		if (sp->space_dead) {
			rv = -ENOSPC;
		} else {
			sp->flags |= SP_USED_BY_ORPHANS;
			rv = 0;
		}
		break;

	case SANLK_CONFIG_UNUSED_BY_ORPHANS:
		sp->flags &= ~SP_USED_BY_ORPHANS;
		rv = 0;
		break;
	default:
		rv = -EINVAL;
	}
	pthread_mutex_unlock(&sp->mutex);
 out:
	return rv;
}

static int _clean_event_fds(struct space *sp)
{
	uint32_t end;
	int count = 0;
	int old_fd;
	int i, rv;

	pthread_mutex_lock(&sp->mutex);
	for (i = 0; i < MAX_EVENT_FDS; i++) {
		if (sp->event_fds[i] == -1)
			continue;

		old_fd = sp->event_fds[i];

		rv = recv(old_fd, &end, sizeof(end), MSG_DONTWAIT);
		if (rv == -1 && errno == EAGAIN)
			continue;

		if ((rv == sizeof(end)) && (end != 1)) {
			log_erros(sp, "clean_event_fds ignore end value %u on event fd %d", end, old_fd);
			continue;
		}

		if ((rv == sizeof(end)) || !rv || (rv < 0))
			log_space(sp, "clean_event_fds unregister event fd %d recv %d", old_fd, rv);
		else
			log_erros(sp, "clean_event_fds close event fd %d recv %d", old_fd, rv);

		close(old_fd);
		sp->event_fds[i] = -1;
		count++;
	}
	pthread_mutex_unlock(&sp->mutex);

	return count;
}

/*
 * end_event/reg_event don't need to worry about sp being freed
 * beause the main daemon thread processes end_event/reg_event,
 * and the main thread is also the only thread that will free
 * sp structs.
 */

int lockspace_end_event(struct sanlk_lockspace *ls)
{
	struct space *sp;

	if (!ls->name[0])
		return -EINVAL;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(ls->name, NULL, 0, &spaces, NULL, NULL, NULL);
	pthread_mutex_unlock(&spaces_mutex);
	if (!sp)
		return -ENOENT;

	_clean_event_fds(sp);
	return 0;
}

int lockspace_reg_event(struct sanlk_lockspace *ls, int fd, GNUC_UNUSED uint32_t flags)
{
	struct space *sp;
	int retried = 0;
	int cleaned = 0;
	int new_fd = -1;
	int i;

	if (!ls->name[0])
		return -EINVAL;

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(ls->name, NULL, 0, &spaces, NULL, NULL, NULL);
	if (!sp) {
		pthread_mutex_unlock(&spaces_mutex);
		log_error("lockspace_reg_event %s not found", ls->name);
		return -ENOENT;
	}
	pthread_mutex_unlock(&spaces_mutex);
retry:
	pthread_mutex_lock(&sp->mutex);
	for (i = 0; i < MAX_EVENT_FDS; i++) {
		if (sp->event_fds[i] != -1)
			continue;
		/* _client_free closes the fd when the reg_event call is done,
		   so we dup it here instead of adding a special case in
		   _client free to keep it open. */
		new_fd = dup(fd);
		sp->event_fds[i] = new_fd;
		break;
	}
	pthread_mutex_unlock(&sp->mutex);
	log_space(sp, "lockspace_reg_event new_fd %d from client fd %d", new_fd, fd);

	if (new_fd < 0) {
		if (retried)
			return -ENOCSI;
		cleaned = _clean_event_fds(sp);
		if (!cleaned)
			return -ENOCSI;
		retried = 1;
		goto retry;
	}
	return 0;
}

int lockspace_set_event(struct sanlk_lockspace *ls, struct sanlk_host_event *he, uint32_t flags)
{
	struct space *sp;
	struct host_status *hs;
	uint64_t now;
	int i, rv = 0;

	if (!ls->name[0] || !he->host_id || he->host_id > DEFAULT_MAX_HOSTS) {
		log_error("set_event invalid args host_id %llu name %s",
			  (unsigned long long)he->host_id, ls->name);
		return -EINVAL;
	}

	pthread_mutex_lock(&spaces_mutex);
	sp = _search_space(ls->name, NULL, 0, &spaces, NULL, NULL, NULL);
	if (!sp) {
		pthread_mutex_unlock(&spaces_mutex);
		return -ENOENT;
	}
	pthread_mutex_unlock(&spaces_mutex);

	if (!he->generation && (flags & SANLK_SETEV_CUR_GENERATION)) {
		hs = &(sp->host_status[he->host_id-1]);
		he->generation = hs->owner_generation;
	}

	now = monotime();

	pthread_mutex_lock(&sp->mutex);

	if (flags & SANLK_SETEV_CLEAR_EVENT) {
		memset(&sp->host_event, 0, sizeof(struct sanlk_host_event));
		sp->set_event_time = now;
		goto out;
	}

	if (flags & SANLK_SETEV_CLEAR_HOSTID) {
		sp->host_status[he->host_id-1].set_bit_time = 0;
		goto out;
	}

	if (flags & SANLK_SETEV_REPLACE_EVENT)
		goto set;

	/* log a warning if one non-zero event clobbers another non-zero event */

	if ((now - sp->set_event_time < sp->set_bitmap_seconds) &&
	    sp->host_event.event && he->event &&
	    (sp->host_event.event != he->event)) {
		log_level(sp->space_id, 0, NULL, LOG_WARNING,
			  "event %llu %llu %llu %llu replaced by %llu %llu %llu %llu t %llu",
			  (unsigned long long)sp->host_event.host_id,
			  (unsigned long long)sp->host_event.generation,
			  (unsigned long long)sp->host_event.event,
			  (unsigned long long)sp->host_event.data,
			  (unsigned long long)he->host_id,
			  (unsigned long long)he->generation,
			  (unsigned long long)he->event,
			  (unsigned long long)he->data,
			  (unsigned long long)sp->set_event_time);
		rv = -EBUSY;
		goto out;
	}
set:
	sp->set_event_time = now;
	sp->host_status[he->host_id-1].set_bit_time = now;
	memcpy(&sp->host_event, he, sizeof(struct sanlk_host_event));

	if (flags & SANLK_SETEV_ALL_HOSTS) {
		for (i = 0; i < DEFAULT_MAX_HOSTS; i++)
			sp->host_status[i].set_bit_time = now;
	}
out:
	pthread_mutex_unlock(&sp->mutex);
	return rv;
}

int send_event_callbacks(uint32_t space_id,
			 uint64_t from_host_id,
			 uint64_t from_generation,
			 struct sanlk_host_event *he)
{
	struct space *sp;
	struct event_cb cb;
	int fd, i;
	int rv = 0;

	memset(&cb, 0, sizeof(cb));
	cb.h.magic = SM_MAGIC;
	cb.h.version = SM_CB_PROTO;
	cb.h.cmd = SM_CB_GET_EVENT;
	cb.h.length = sizeof(cb);

	memcpy(&cb.he, he, sizeof(struct sanlk_host_event));

	cb.from_host_id = from_host_id;
	cb.from_generation = from_generation;

	pthread_mutex_lock(&spaces_mutex);
	sp = find_lockspace_id(space_id);
	if (!sp) {
		pthread_mutex_unlock(&spaces_mutex);
		rv = -ENOSPC;
		goto ret;
	}
	pthread_mutex_unlock(&spaces_mutex);

	pthread_mutex_lock(&sp->mutex);

	for (i = 0; i < MAX_EVENT_FDS; i++) {
		if (sp->event_fds[i] == -1)
			continue;

		fd = sp->event_fds[i];

		rv = send(fd, &cb, sizeof(cb), MSG_NOSIGNAL | MSG_DONTWAIT);
		if (rv < 0) {
			log_erros(sp, "send_event_callbacks error %d %d close fd %d", rv, errno, fd);
			close(fd);
			sp->event_fds[i] = -1;
		}
		log_space(sp, "sent event to fd %d", fd);
	}
	pthread_mutex_unlock(&sp->mutex);
ret:
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
			free_sp(sp);
		}
	}
	pthread_mutex_unlock(&spaces_mutex);
}

