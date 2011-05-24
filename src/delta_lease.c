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
#include "paxos_lease.h"
#include "delta_lease.h"

/* Based on "Light-Weight Leases for Storage-Centric Coordination"
   by Gregory Chockler and Dahlia Malkhi */

/* delta_leases are a series max_hosts leader_records, one leader per sector,
   host N's delta_lease is the leader_record in sectors N-1 */

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
	struct leader_record leader_rr;
	char resource_name[NAME_ID_SIZE];
	uint32_t sum;
	int result, rv;

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

	memset(resource_name, 0, NAME_ID_SIZE);
	snprintf(resource_name, NAME_ID_SIZE, "host_id_%llu",
		 (unsigned long long)host_id);

	if (strncmp(lr->resource_name, resource_name, NAME_ID_SIZE)) {
		log_error("verify_leader %llu wrong resource name %.48s %.48s %s",
			  (unsigned long long)host_id,
			  lr->resource_name, resource_name, disk->path);
		result = SANLK_LEADER_RESOURCE;
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

	memset(&leader_rr, 0, sizeof(leader_rr));

	rv = read_sectors(disk, host_id - 1, 1, (char *)&leader_rr,
			  sizeof(struct leader_record),
			  NULL, "delta_verify");

	log_leader_error(rv, space_name, host_id, disk, &leader_rr, "delta_verify");

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
		return SANLK_LEADER_READ;

	error = verify_leader(disk, space_name, host_id, &leader, caller);

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return error;
}

/* TODO: do we need to set the watchdog to expire in host_dead_seconds just
 * before we do the write here?  The algorithm depends on io timeouts to
 * protect against this write happening at a latest possible time, but since
 * our ios don't ever really timeout reliably, we need to timeout in
 * host_dead_seconds.
 * And can we touch the watchdog immediately after the write, or do we
 * need to wait for the read to complete also? */

int delta_lease_acquire(struct task *task,
			struct space *sp,
			struct sync_disk *disk,
			char *space_name,
			uint64_t our_host_id,
			uint64_t host_id,
			struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct leader_record leader1;
	uint64_t new_ts;
	int error, delay, delta_large_delay;

	log_space(sp, "delta_acquire %llu begin", (unsigned long long)host_id);

	error = delta_lease_leader_read(task, disk, space_name, host_id, &leader,
					"delta_acquire_begin");
	if (error < 0)
		return error;

 retry:
	if (leader.timestamp == LEASE_FREE)
		goto write_new;

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

		log_space(sp, "delta_acquire delta_large_delay %d", delay);
		sleep(delay);

		error = delta_lease_leader_read(task, disk, space_name, host_id,
						&leader, "delta_acquire_wait");
		if (error < 0)
			return error;

		if (!memcmp(&leader1, &leader, sizeof(struct leader_record)))
			break;

		if (leader.timestamp == LEASE_FREE)
			break;

		/* TODO: fail and return an error? */
	}

 write_new:
	new_ts = time(NULL);
	leader.timestamp = new_ts;
	leader.owner_id = our_host_id;
	leader.owner_generation++;
	leader.checksum = leader_checksum(&leader);

	log_space(sp, "delta_acquire write new %llu", (unsigned long long)new_ts);

	error = write_sector(disk, host_id - 1, (char *)&leader, sizeof(struct leader_record),
			     task, "delta_leader");
	if (error < 0)
		return error;

	delay = 2 * task->io_timeout_seconds;
	log_space(sp, "delta_acquire delta_short_delay %d", delay);
	sleep(delay);

	error = delta_lease_leader_read(task, disk, space_name, host_id, &leader,
					"delta_acquire_check");
	if (error < 0)
		return error;

	if ((leader.timestamp != new_ts) || (leader.owner_id != our_host_id))
		goto retry;

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;
}

/* our_host_id and host_id will always be the same, i.e. we
   only ever try to acquire/renew our own host_id */

int delta_lease_renew(struct task *task,
		      struct space *sp,
		      struct sync_disk *disk,
		      char *space_name,
		      uint64_t our_host_id,
		      uint64_t our_host_id_generation,
		      uint64_t host_id,
		      int prev_result,
		      struct leader_record *leader_last,
		      struct leader_record *leader_ret)
{
	struct leader_record leader;
	uint64_t new_ts;
	int io_timeout_save;
	int error;

	/* TODO: if the previous renew timed out in this initial read, and that
	 * read is now complete, we could just use the result from that read
	 * here instead of ignoring it and doing another. */

	error = delta_lease_leader_read(task, disk, space_name, host_id, &leader,
					"delta_renew_begin");
	if (error < 0)
		return error;

	if (!our_host_id_generation)
		our_host_id_generation = leader.owner_generation;

	if (leader.owner_id != our_host_id ||
	    leader.owner_generation != our_host_id_generation) {
		log_erros(sp, "delta_renew %llu not owner", (unsigned long long)host_id);
		log_leader_error(0, space_name, host_id, disk, leader_last, "delta_renew_last");
		log_leader_error(0, space_name, host_id, disk, &leader, "delta_renew_read");
		return SANLK_RENEW_OWNER;
	}

	if (prev_result == SANLK_OK &&
	    memcmp(&leader, leader_last, sizeof(struct leader_record))) {
		log_erros(sp, "delta_renew %llu reread mismatch", (unsigned long long)host_id);
		log_leader_error(0, space_name, host_id, disk, leader_last, "delta_renew_last");
		log_leader_error(0, space_name, host_id, disk, &leader, "delta_renew_read");
		return SANLK_RENEW_DIFF;
	}

	new_ts = time(NULL);

	if (leader.timestamp >= new_ts) {
		log_erros(sp, "delta_renew timestamp too small");
	}

	leader.timestamp = new_ts;
	leader.checksum = leader_checksum(&leader);

	/* extend io timeout for this one write; we need to give this write
	 * every chance to succeed, and there's no point in letting it time
	 * out.  there's nothing we would do but retry it, and timing out and
	 * retrying unnecessarily would probably be counter productive. */

	io_timeout_save = task->io_timeout_seconds;
	task->io_timeout_seconds = task->host_dead_seconds;

	error = write_sector(disk, host_id - 1, (char *)&leader, sizeof(struct leader_record),
			     task, "delta_leader");

	task->io_timeout_seconds = io_timeout_save;

	if (error < 0)
		return error;

#if 0
	/* the paper shows doing a delay and another read here, but it seems
	   unnecessary since we do the same at the beginning of the next renewal */

	delay = 2 * task->io_timeout_seconds;
	/* log_space(sp, "delta_renew sleep 2d %d", delay); */
	sleep(delay);

	error = delta_lease_leader_read(task, disk, space_name, host_id, &leader_read,
					"delta_renew_check");
	if (error < 0)
		return error;

	/*
	if ((leader.timestamp != new_ts) || (leader.owner_id != our_host_id))
		return SANLK_BAD_LEADER;
	*/

	if (memcmp(&leader, &leader_read, sizeof(struct leader_record))) {
		log_erros(sp, "delta_renew %llu reread mismatch",
			  (unsigned long long)host_id);
		log_leader_error(0, space_name, host_id, disk, &leader, "delta_renew_write");
		log_leader_error(0, space_name, host_id, disk, &leader_read, "delta_renew_reread");
		return SANLK_RENEW_DIFF;
	}
#endif

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;
}

int delta_lease_release(struct task *task,
			struct space *sp,
			struct sync_disk *disk,
			char *space_name GNUC_UNUSED,
			uint64_t host_id,
			struct leader_record *leader_last,
			struct leader_record *leader_ret)
{
	struct leader_record leader;
	int error;

	log_space(sp, "delta_release %llu begin", (unsigned long long)host_id);

	memcpy(&leader, leader_last, sizeof(struct leader_record));
	leader.timestamp = LEASE_FREE;
	leader.checksum = leader_checksum(&leader);

	error = write_sector(disk, host_id - 1, (char *)&leader, sizeof(struct leader_record),
			     task, "delta_leader");
	if (error < 0)
		return error;

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
	int i, rv;

	iobuf_len = disk->sector_size * max_hosts;

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
		snprintf(leader->resource_name, NAME_ID_SIZE, "host_id_%d", i+1);
		leader->checksum = leader_checksum(leader);
	}

	rv = write_iobuf(disk->fd, disk->offset, iobuf, iobuf_len, task);

	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);

	if (rv < 0)
		return rv;

	return 0;
}

