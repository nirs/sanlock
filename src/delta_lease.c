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
#include "diskio.h"
#include "direct.h"
#include "log.h"
#include "paxos_lease.h"
#include "delta_lease.h"

/* Based on "Light-Weight Leases for Storage-Centric Coordination"
   by Gregory Chockler and Dahlia Malkhi */

/* delta_leases are a series max_hosts leader_records, one leader per sector,
   host N's delta_lease is the leader_record in sectors N-1 */

/*
 * variable names:
 * rv: success is 0, failure is < 0
 * error: success is 1 (SANLK_OK), failure is < 0
 */

static void log_leader_error(int result,
			     char *space_name,
			     uint64_t host_id,
			     struct sync_disk *disk,
			     struct leader_record *lr,
			     const char *caller)
{
	log_error("leader1 %s error %d lockspace %.48s host_id %llu",
		  caller ? caller : "unknown",
		  result,
		  space_name,
		  (unsigned long long)host_id);

	log_error("leader2 path %s offset %llu",
		  disk->path,
		  (unsigned long long)disk->offset);

	log_error("leader3 m %x v %x ss %u nh %llu mh %llu oi %llu og %llu lv %llu",
		  lr->magic,
		  lr->version,
		  lr->sector_size,
		  (unsigned long long)lr->num_hosts,
		  (unsigned long long)lr->max_hosts,
		  (unsigned long long)lr->owner_id,
		  (unsigned long long)lr->owner_generation,
		  (unsigned long long)lr->lver);

	log_error("leader4 sn %.48s rn %.48s ts %llu cs %x",
		  lr->space_name,
		  lr->resource_name,
		  (unsigned long long)lr->timestamp,
		  lr->checksum);
}

static int verify_leader(struct sync_disk *disk,
			 char *space_name,
			 uint64_t host_id,
			 struct leader_record *lr,
			 const char *caller)
{
	uint32_t sum;
	int result;

	if (lr->magic != DELTA_DISK_MAGIC) {
		log_error("verify_leader %llu wrong magic %x %s",
			  (unsigned long long)host_id,
			  lr->magic, disk->path);
		result = SANLK_LEADER_MAGIC;
		goto fail;
	}

	if ((lr->version & 0xFFFF0000) != DELTA_DISK_VERSION_MAJOR) {
		log_error("verify_leader %llu wrong version %x %s",
			  (unsigned long long)host_id,
			  lr->version, disk->path);
		result = SANLK_LEADER_VERSION;
		goto fail;
	}

	if (lr->sector_size != disk->sector_size) {
		log_error("verify_leader %llu wrong sector size %d %d %s",
			  (unsigned long long)host_id,
			  lr->sector_size, disk->sector_size, disk->path);
		result = SANLK_LEADER_SECTORSIZE;
		goto fail;
	}

	if (strncmp(lr->space_name, space_name, NAME_ID_SIZE)) {
		log_error("verify_leader %llu wrong space name %.48s %.48s %s",
			  (unsigned long long)host_id,
			  lr->space_name, space_name, disk->path);
		result = SANLK_LEADER_LOCKSPACE;
		goto fail;
	}

	sum = leader_checksum(lr);

	if (lr->checksum != sum) {
		log_error("verify_leader %llu wrong checksum %x %x %s",
			  (unsigned long long)host_id,
			  lr->checksum, sum, disk->path);
		result = SANLK_LEADER_CHECKSUM;
		goto fail;
	}

	return SANLK_OK;

 fail:
	log_leader_error(result, space_name, host_id, disk, lr, caller);

	/*
	struct leader_record leader_rr;
	int rv;

	memset(&leader_rr, 0, sizeof(leader_rr));

	rv = read_sectors(disk, host_id - 1, 1, (char *)&leader_rr,
			  sizeof(struct leader_record),
			  NULL, "delta_verify");

	log_leader_error(rv, space_name, host_id, disk, &leader_rr, "delta_verify");
	*/

	return result;
}

int delta_lease_leader_read(struct task *task,
			    struct sync_disk *disk,
			    char *space_name,
			    uint64_t host_id,
			    struct leader_record *leader_ret,
			    const char *caller)
{
	struct leader_record leader;
	int rv, error;

	/* host_id N is block offset N-1 */

	memset(&leader, 0, sizeof(struct leader_record));
	memset(leader_ret, 0, sizeof(struct leader_record));

	rv = read_sectors(disk, host_id - 1, 1, (char *)&leader, sizeof(struct leader_record),
			  task, "delta_leader");
	if (rv < 0)
		return rv;

	error = verify_leader(disk, space_name, host_id, &leader, caller);

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return error;
}

/*
 * delta_lease_acquire:
 * set the owner of host_id to our_host_name.
 *
 * paxos_lease_acquire:
 * set the owner of resource_name to host_id.
 *
 * our_host_name is a unique host identifier used to detect when two different
 * hosts are trying to acquire the same host_id (since both will be using the
 * same host_id, that host_id won't work to distinguish between them.) We copy
 * our_host_name into leader.resource_name, so in a sense the owner_id and
 * resource_name fields of the leader_record switch functions: the common
 * resource is the ower_id, and the distinguishing id is the resource_name.
 */

int delta_lease_acquire(struct task *task,
			struct space *sp,
			struct sync_disk *disk,
			char *space_name,
			char *our_host_name,
			uint64_t host_id,
			struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct leader_record leader1;
	uint64_t new_ts;
	int i, error, rv, delay, delta_large_delay;

	log_space(sp, "delta_acquire %llu begin", (unsigned long long)host_id);

	error = delta_lease_leader_read(task, disk, space_name, host_id, &leader,
					"delta_acquire_begin");
	if (error < 0)
		return error;

	if (leader.timestamp == LEASE_FREE)
		goto write_new;

	if (!strncmp(leader.resource_name, our_host_name, NAME_ID_SIZE)) {
		log_space(sp, "delta_acquire %llu fast reacquire",
			  (unsigned long long)host_id);
		goto write_new;
	}

	/* we need to ensure that a host_id cannot be acquired and released
	 * sooner than host_dead_seconds because the change in host_id
	 * ownership affects the host_id "liveness" determination used by paxos
	 * leases, and the ownership of paxos leases cannot change until after
	 * host_dead_seconds to ensure that the watchdog has fired.  So, I
	 * think we want the delay here to be the max of host_dead_seconds and
	 * the D+6d delay.
	 *
	 * Per the algorithm in the paper, a delta lease can change ownership
	 * in the while loop below after the delta_delay of D+6d.  However,
	 * because we use the change of delta lease ownership to directly
	 * determine the change in paxos lease ownership, we need the delta
	 * delay to also meet the delay requirements of the paxos leases.  The
	 * paxos leases cannot change ownership until a min of
	 * host_dead_seconds to ensure the watchdog has fired.  So, the timeout
	 * we use here must be the max of the delta delay (D+6d) and
	 * host_dead_seconds */

	delay = task->host_dead_seconds;
	delta_large_delay = task->id_renewal_seconds + (6 * task->io_timeout_seconds);
	if (delta_large_delay > delay)
		delay = delta_large_delay;

	while (1) {
		memcpy(&leader1, &leader, sizeof(struct leader_record));

		log_space(sp, "delta_acquire %llu delta_large_delay %d delay %d",
			  (unsigned long long)host_id, delta_large_delay, delay);

		/* TODO: we could reread every several seconds to see if
		   it has changed, so we can abort more quickly if so */

		for (i = 0; i < delay; i++) {
			if (sp->external_remove || external_shutdown)
				return SANLK_ERROR;
			sleep(1);
		}

		error = delta_lease_leader_read(task, disk, space_name, host_id,
						&leader, "delta_acquire_wait");
		if (error < 0)
			return error;

		if (!memcmp(&leader1, &leader, sizeof(struct leader_record)))
			break;

		if (leader.timestamp == LEASE_FREE)
			break;

		log_erros(sp, "delta_acquire %llu busy %llu %llu %llu %.48s",
			  (unsigned long long)host_id,
			  (unsigned long long)leader.owner_id,
			  (unsigned long long)leader.owner_generation,
			  (unsigned long long)leader.timestamp,
			  leader.resource_name);
		return SANLK_HOSTID_BUSY;
	}

 write_new:
	new_ts = monotime();
	leader.timestamp = new_ts;
	leader.owner_id = host_id;
	leader.owner_generation++;
	snprintf(leader.resource_name, NAME_ID_SIZE, "%s", our_host_name);
	leader.checksum = leader_checksum(&leader);

	log_space(sp, "delta_acquire %llu write %llu %llu %llu %.48s",
		  (unsigned long long)host_id,
		  (unsigned long long)leader.owner_id,
		  (unsigned long long)leader.owner_generation,
		  (unsigned long long)leader.timestamp,
		  leader.resource_name);

	rv = write_sector(disk, host_id - 1, (char *)&leader, sizeof(struct leader_record),
			  task, "delta_leader");
	if (rv < 0)
		return rv;

	memcpy(&leader1, &leader, sizeof(struct leader_record));

	delay = 2 * task->io_timeout_seconds;
	log_space(sp, "delta_acquire %llu delta_short_delay %d",
		  (unsigned long long)host_id, delay);

	for (i = 0; i < delay; i++) {
		if (sp->external_remove || external_shutdown)
			return SANLK_ERROR;
		sleep(1);
	}

	error = delta_lease_leader_read(task, disk, space_name, host_id, &leader,
					"delta_acquire_check");
	if (error < 0)
		return error;

	if (memcmp(&leader1, &leader, sizeof(struct leader_record))) {
		log_erros(sp, "delta_acquire %llu busy %llu %llu %llu %.48s",
			  (unsigned long long)host_id,
			  (unsigned long long)leader.owner_id,
			  (unsigned long long)leader.owner_generation,
			  (unsigned long long)leader.timestamp,
			  leader.resource_name);
		return SANLK_HOSTID_BUSY;
	}

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;
}

int delta_lease_renew(struct task *task,
		      struct space *sp,
		      struct sync_disk *disk,
		      char *space_name,
		      char *bitmap,
		      int prev_result,
		      int *read_result,
		      struct leader_record *leader_last,
		      struct leader_record *leader_ret)
{
	struct leader_record leader;
	char **p_iobuf;
	char **p_wbuf;
	char *wbuf;
	uint64_t host_id, id_offset, new_ts;
	int rv, iobuf_len, sector_size, io_timeout_save;

	if (!leader_last)
		return -EINVAL;

	*read_result = SANLK_ERROR;

	host_id = leader_last->owner_id;

	iobuf_len = sp->align_size;

	sector_size = disk->sector_size;

	/* offset of our leader_record */
	id_offset = (host_id - 1) * sector_size;
	if (id_offset > iobuf_len)
		return -EINVAL;


	/* if the previous renew timed out in this initial read, and that read
	   is now complete, we can use that result here instead of discarding
	   it and doing another. */

	if (prev_result == SANLK_AIO_TIMEOUT) {
		if (!task->read_iobuf_timeout_aicb) {
			/* shouldn't happen, when do_linux_aio returned AIO_TIMEOUT
			   it should have set read_iobuf_timeout_aicb */
			log_erros(sp, "delta_renew reap no aicb");
			goto skip_reap;
		}

		if (!task->iobuf) {
			/* shouldn't happen */
			log_erros(sp, "delta_renew reap no iobuf");
			goto skip_reap;
		}

		rv = read_iobuf_reap(disk->fd, disk->offset,
				     task->iobuf, iobuf_len, task);

		log_space(sp, "delta_renew reap %d", rv);

		if (!rv) {
			task->read_iobuf_timeout_aicb = NULL;
			goto read_done;
		}
 skip_reap:
		/* abandon the previous timed out read and try a new
		   one from scratch.  the current task->iobuf mem will
		   freed when timeout_aicb completes sometime */

		task->read_iobuf_timeout_aicb = NULL;
		task->iobuf = NULL;
	}

	if (task->read_iobuf_timeout_aicb) {
		/* this could happen get here if there was another read between
		   renewal reads, which timed out and caused
		   read_iobuf_timeout_aicb to be set; I don't think there are
		   any cases where that would happen, though.  we could avoid
		   this confusion by passing back the timed out aicb along with
		   SANLK_AIO_TIMEOUT, and only save the timed out aicb when we
		   want to try to reap it later. */

		log_space(sp, "delta_renew timeout_aicb is unexpectedly %p iobuf %p",
			  task->read_iobuf_timeout_aicb, task->iobuf);
		task->read_iobuf_timeout_aicb = NULL;
		task->iobuf = NULL;
	}

	if (!task->iobuf) {
		/* this will happen the first time renew is called, and after
		   a timed out renewal read fails to be reaped (see
		   task->iobuf = NULL above) */

		p_iobuf = &task->iobuf;

		rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
		if (rv) {
			log_erros(sp, "dela_renew memalign rv %d", rv);
			rv = -ENOMEM;
		}
	}

	rv = read_iobuf(disk->fd, disk->offset, task->iobuf, iobuf_len, task);
	if (rv) {
		/* the next time delta_lease_renew() is called, prev_result
		   will be this rv.  If this rv is SANLK_AIO_TIMEOUT, we'll
		   try to reap the event */

		log_erros(sp, "delta_renew read rv %d offset %llu %s",
			  rv, (unsigned long long)disk->offset, disk->path);
		return rv;
	}

 read_done:
	*read_result = SANLK_OK;
	memcpy(&leader, task->iobuf+id_offset, sizeof(struct leader_record));

	rv = verify_leader(disk, space_name, host_id, &leader, "delta_renew");
	if (rv < 0)
		return rv;

	/* We can't always memcmp(&leader, leader_last) because previous writes
	   may have timed out and we don't know if they were actually written
	   or not.  We can definately verify that we're still the owner,
	   though, which is the main thing we need to know. */

	if (leader.owner_id != leader_last->owner_id ||
	    leader.owner_generation != leader_last->owner_generation ||
	    memcmp(leader.resource_name, leader_last->resource_name, NAME_ID_SIZE)) {
		log_erros(sp, "delta_renew not owner");
		log_leader_error(0, space_name, host_id, disk, leader_last, "delta_renew_last");
		log_leader_error(0, space_name, host_id, disk, &leader, "delta_renew_read");
		return SANLK_RENEW_OWNER;
	}

	if (prev_result == SANLK_OK &&
	    memcmp(&leader, leader_last, sizeof(struct leader_record))) {
		log_erros(sp, "delta_renew reread mismatch");
		log_leader_error(0, space_name, host_id, disk, leader_last, "delta_renew_last");
		log_leader_error(0, space_name, host_id, disk, &leader, "delta_renew_read");
		return SANLK_RENEW_DIFF;
	}

	new_ts = monotime();

	if (leader.timestamp >= new_ts) {
		log_erros(sp, "delta_renew timestamp too small");
	}

	leader.timestamp = new_ts;
	leader.checksum = leader_checksum(&leader);

	p_wbuf = &wbuf;
	rv = posix_memalign((void *)p_wbuf, getpagesize(), sector_size);
	if (rv) {
		log_erros(sp, "dela_renew write memalign rv %d", rv);
		return -ENOMEM;
	}
	memset(wbuf, 0, sector_size);
	memcpy(wbuf, &leader, sizeof(struct leader_record));
	memcpy(wbuf+LEADER_RECORD_MAX, bitmap, HOSTID_BITMAP_SIZE);

	/* extend io timeout for this one write; we need to give this write
	   every chance to succeed, and there's no point in letting it time
	   out.  there's nothing we would do but retry it, and timing out and
	   retrying unnecessarily would probably be counter productive. */

	io_timeout_save = task->io_timeout_seconds;
	task->io_timeout_seconds = task->host_dead_seconds;

	rv = write_iobuf(disk->fd, disk->offset+id_offset, wbuf, sector_size, task);

	if (rv != SANLK_AIO_TIMEOUT)
		free(wbuf);

	task->io_timeout_seconds = io_timeout_save;

	if (rv < 0)
		return rv;

	/* the paper shows doing a delay and another read here, but it seems
	   unnecessary since we do the same at the beginning of the next renewal */

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;
}

int delta_lease_release(struct task *task,
			struct space *sp,
			struct sync_disk *disk,
			char *space_name GNUC_UNUSED,
			struct leader_record *leader_last,
			struct leader_record *leader_ret)
{
	struct leader_record leader;
	uint64_t host_id;
	int rv;

	if (!leader_last)
		return -EINVAL;

	host_id = leader_last->owner_id;

	log_space(sp, "delta_release %llu begin", (unsigned long long)host_id);

	memcpy(&leader, leader_last, sizeof(struct leader_record));
	leader.timestamp = LEASE_FREE;
	leader.checksum = leader_checksum(&leader);

	rv = write_sector(disk, host_id - 1, (char *)&leader, sizeof(struct leader_record),
			  task, "delta_leader");
	if (rv < 0)
		return rv;

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;
}

/* the host_id lease area begins disk->offset bytes from the start of
   block device disk->path */

int delta_lease_init(struct task *task,
		     struct sync_disk *disk,
		     char *space_name,
		     int max_hosts)
{
	struct leader_record *leader;
	char *iobuf, **p_iobuf;
	int iobuf_len;
	int align_size;
	int i, rv;

	if (!max_hosts)
		max_hosts = DEFAULT_MAX_HOSTS;

	align_size = direct_align(disk);
	if (align_size < 0)
		return align_size;

	if (disk->sector_size * max_hosts > align_size)
		return -E2BIG;

	iobuf_len = align_size;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return rv;

	memset(iobuf, 0, iobuf_len);

	/* host_id N is block offset N-1 */

	for (i = 0; i < max_hosts; i++) {
		leader = (struct leader_record *)(iobuf + (i * disk->sector_size));
		leader->magic = DELTA_DISK_MAGIC;
		leader->version = DELTA_DISK_VERSION_MAJOR | DELTA_DISK_VERSION_MINOR;
		leader->sector_size = disk->sector_size;
		leader->max_hosts = 1;
		leader->timestamp = LEASE_FREE;
		strncpy(leader->space_name, space_name, NAME_ID_SIZE);
		leader->checksum = leader_checksum(leader);
	}

	rv = write_iobuf(disk->fd, disk->offset, iobuf, iobuf_len, task);

	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);

	if (rv < 0)
		return rv;

	return 0;
}

