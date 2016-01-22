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
#include "ondisk.h"
#include "direct.h"
#include "log.h"
#include "paxos_lease.h"
#include "delta_lease.h"
#include "timeouts.h"

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
			 uint32_t checksum,
			 const char *caller)
{
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

	if (lr->checksum != checksum) {
		log_error("verify_leader %llu wrong checksum %x %x %s",
			  (unsigned long long)host_id,
			  lr->checksum, checksum, disk->path);
		result = SANLK_LEADER_CHECKSUM;
		goto fail;
	}

	return SANLK_OK;

 fail:
	log_leader_error(result, space_name, host_id, disk, lr, caller);

	/*
	struct leader_record leader_end;
	struct leader_record leader_rr;
	int rv;

	memset(&leader_end, 0, sizeof(leader_end));

	rv = read_sectors(disk, host_id - 1, 1, (char *)&leader_end,
			  sizeof(struct leader_record),
			  NULL, "delta_verify");
	
	leader_record_in(&leader_end, &leader_rr);

	log_leader_error(rv, space_name, host_id, disk, &leader_rr, "delta_verify");
	*/

	return result;
}


/* read the lockspace name and io_timeout given the disk location */

int delta_read_lockspace(struct task *task,
			 struct sync_disk *disk,
			 uint64_t host_id,
			 struct sanlk_lockspace *ls,
			 int io_timeout,
			 int *io_timeout_ret)
{
	struct leader_record leader_end;
	struct leader_record leader;
	uint32_t checksum;
	char *space_name;
	int rv, error;

	/* host_id N is block offset N-1 */

	memset(&leader_end, 0, sizeof(struct leader_record));

	rv = read_sectors(disk, host_id - 1, 1, (char *)&leader_end, sizeof(struct leader_record),
			  task, io_timeout, "read_lockspace");
	if (rv < 0)
		return rv;

	/* N.B. compute checksum before byte swapping */
	checksum = leader_checksum(&leader_end);

	leader_record_in(&leader_end, &leader);

	if (!ls->name[0])
		space_name = leader.space_name;
	else
		space_name = ls->name;

	error = verify_leader(disk, space_name, host_id, &leader, checksum, "read_lockspace");

	if (error == SANLK_OK) {
		memcpy(ls->name, leader.space_name, SANLK_NAME_LEN);
		ls->host_id = host_id;
		*io_timeout_ret = leader.io_timeout;
	}

	return error;
}

int delta_lease_leader_read(struct task *task, int io_timeout,
			    struct sync_disk *disk,
			    char *space_name,
			    uint64_t host_id,
			    struct leader_record *leader_ret,
			    const char *caller)
{
	struct leader_record leader_end;
	struct leader_record leader;
	uint32_t checksum;
	int rv, error;

	/* host_id N is block offset N-1 */

	memset(&leader_end, 0, sizeof(struct leader_record));
	memset(leader_ret, 0, sizeof(struct leader_record));

	rv = read_sectors(disk, host_id - 1, 1, (char *)&leader_end, sizeof(struct leader_record),
			  task, io_timeout, "delta_leader");
	if (rv < 0)
		return rv;

	/* N.B. compute checksum before byte swapping */
	checksum = leader_checksum(&leader_end);

	leader_record_in(&leader_end, &leader);

	error = verify_leader(disk, space_name, host_id, &leader, checksum, caller);

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return error;
}

/*
 * NB. this should not be used to write the leader record, it is meant only
 * for manually clobbering the disk to corrupt it for testing, or to manually
 * repair it after it's corrupted.
 */

int delta_lease_leader_clobber(struct task *task, int io_timeout,
			       struct sync_disk *disk,
			       uint64_t host_id,
			       struct leader_record *leader,
			       const char *caller)
{
	struct leader_record leader_end;
	int rv;

	leader_record_out(leader, &leader_end);

	rv = write_sector(disk, host_id - 1, (char *)&leader_end, sizeof(struct leader_record),
			  task, io_timeout, caller);
	if (rv < 0)
		return rv;
	return SANLK_OK;
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
	struct leader_record leader_end;
	uint64_t new_ts;
	uint32_t checksum;
	int other_io_timeout, other_host_dead_seconds, other_id_renewal_seconds;
	int i, error, rv, delay, delta_large_delay;

	log_space(sp, "delta_acquire begin %.48s:%llu",
		  sp->space_name, (unsigned long long)host_id);

	error = delta_lease_leader_read(task, sp->io_timeout, disk, space_name, host_id, &leader,
					"delta_acquire_begin");
	if (error < 0) {
		log_space(sp, "delta_acquire leader_read1 error %d", error);
		return error;
	}

	other_io_timeout = leader.io_timeout;

	if (!other_io_timeout) {
		log_erros(sp, "delta_acquire use own io_timeout %d", sp->io_timeout);
		other_io_timeout = sp->io_timeout;
	} else if (other_io_timeout != sp->io_timeout) {
		log_erros(sp, "delta_acquire other_io_timeout %u our %u",
			  leader.io_timeout, sp->io_timeout);
	}

	if (leader.timestamp == LEASE_FREE)
		goto write_new;

	if (!strncmp(leader.resource_name, our_host_name, NAME_ID_SIZE)) {
		log_space(sp, "delta_acquire fast reacquire");
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

	/*
	 * delay = task->host_dead_seconds;
	 * delta_large_delay = task->id_renewal_seconds + (6 * task->io_timeout_seconds);
	 * if (delta_large_delay > delay)
	 * 	delay = delta_large_delay;
	 */

	other_host_dead_seconds = calc_host_dead_seconds(other_io_timeout);
	other_id_renewal_seconds = calc_id_renewal_seconds(other_io_timeout);

	delay = other_host_dead_seconds;
	delta_large_delay = other_id_renewal_seconds + (6 * other_io_timeout);
	if (delta_large_delay > delay)
		delay = delta_large_delay;

	while (1) {
		memcpy(&leader1, &leader, sizeof(struct leader_record));

		log_space(sp, "delta_acquire delta_large_delay %d delay %d",
			  delta_large_delay, delay);

		/* TODO: we could reread every several seconds to see if
		   it has changed, so we can abort more quickly if so */

		for (i = 0; i < delay; i++) {
			if (sp->external_remove || external_shutdown) {
				log_space(sp, "delta_acquire abort1 remove %d shutdown %d",
					  sp->external_remove, external_shutdown);
				return SANLK_ERROR;
			}
			sleep(1);
		}

		error = delta_lease_leader_read(task, sp->io_timeout, disk, space_name, host_id,
						&leader, "delta_acquire_wait");
		if (error < 0) {
			log_space(sp, "delta_acquire leader_read2 error %d", error);
			return error;
		}

		if (!memcmp(&leader1, &leader, sizeof(struct leader_record)))
			break;

		if (leader.timestamp == LEASE_FREE)
			break;

		log_erros(sp, "delta_acquire host_id %llu busy1 %llu %llu %llu %.48s",
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
	leader.io_timeout = (sp->io_timeout & 0x00FF);
	leader.owner_id = host_id;
	leader.owner_generation++;
	snprintf(leader.resource_name, NAME_ID_SIZE, "%s", our_host_name);
	leader.checksum = 0; /* set below */

	log_space(sp, "delta_acquire write %llu %llu %llu %.48s",
		  (unsigned long long)leader.owner_id,
		  (unsigned long long)leader.owner_generation,
		  (unsigned long long)leader.timestamp,
		  leader.resource_name);

	leader_record_out(&leader, &leader_end);

	/*
	 * N.B. must compute checksum after the data has been byte swapped.
	 */
	checksum = leader_checksum(&leader_end);
	leader.checksum = checksum;
	leader_end.checksum = cpu_to_le32(checksum);

	rv = write_sector(disk, host_id - 1, (char *)&leader_end, sizeof(struct leader_record),
			  task, sp->io_timeout, "delta_leader");
	if (rv < 0) {
		log_space(sp, "delta_acquire write error %d", rv);
		return rv;
	}

	memcpy(&leader1, &leader, sizeof(struct leader_record));

	delay = 2 * other_io_timeout;
	log_space(sp, "delta_acquire delta_short_delay %d", delay);

	for (i = 0; i < delay; i++) {
		if (sp->external_remove || external_shutdown) {
			log_space(sp, "delta_acquire abort2 remove %d shutdown %d",
				  sp->external_remove, external_shutdown);
			return SANLK_ERROR;
		}
		sleep(1);
	}

	error = delta_lease_leader_read(task, sp->io_timeout, disk, space_name, host_id, &leader,
					"delta_acquire_check");
	if (error < 0) {
		log_space(sp, "delta_acquire leader_read3 error %d", error);
		return error;
	}

	if (memcmp(&leader1, &leader, sizeof(struct leader_record))) {
		log_erros(sp, "delta_acquire host_id %llu busy2 %llu %llu %llu %.48s",
			  (unsigned long long)host_id,
			  (unsigned long long)leader.owner_id,
			  (unsigned long long)leader.owner_generation,
			  (unsigned long long)leader.timestamp,
			  leader.resource_name);
		return SANLK_HOSTID_BUSY;
	}

	log_space(sp, "delta_acquire done %llu %llu %llu",
		  (unsigned long long)leader.owner_id,
		  (unsigned long long)leader.owner_generation,
		  (unsigned long long)leader.timestamp);

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;
}

int delta_lease_renew(struct task *task,
		      struct space *sp,
		      struct sync_disk *disk,
		      char *space_name,
		      char *bitmap,
		      struct delta_extra *extra,
		      int prev_result,
		      int *read_result,
		      int log_renewal_level,
		      struct leader_record *leader_last,
		      struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct leader_record leader_end;
	char **p_iobuf;
	char **p_wbuf;
	char *wbuf;
	uint32_t checksum;
	uint64_t host_id, id_offset, new_ts, now;
	int rv, iobuf_len, sector_size;

	if (!leader_last) {
		log_erros(sp, "delta_renew no leader_last");
		return -EINVAL;
	}

	*read_result = SANLK_ERROR;

	host_id = leader_last->owner_id;

	iobuf_len = sp->align_size;

	sector_size = disk->sector_size;

	/* offset of our leader_record */
	id_offset = (host_id - 1) * sector_size;
	if (id_offset > iobuf_len) {
		log_erros(sp, "delta_renew bad offset %llu iobuf_len %d",
			  (unsigned long long)id_offset, iobuf_len);
		return -EINVAL;
	}

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

		/* only wait .5 sec when trying to reap a prev io */
		rv = read_iobuf_reap(disk->fd, disk->offset,
				     task->iobuf, iobuf_len, task, 500000000);

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

	/*
	 * NB. this task->iobuf is also copied by the lockspace thread
	 * into renewal_read_buf, which is then copied in the main loop
	 * by check_our_lease and passed to check_other_leases.
	 */

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

	if (log_renewal_level != -1)
		log_level(sp->space_id, 0, NULL, log_renewal_level, "delta_renew begin read");

	rv = read_iobuf(disk->fd, disk->offset, task->iobuf, iobuf_len, task, sp->io_timeout);
	if (rv) {
		/* the next time delta_lease_renew() is called, prev_result
		   will be this rv.  If this rv is SANLK_AIO_TIMEOUT, we'll
		   try to reap the event */

		if (rv == SANLK_AIO_TIMEOUT)
			log_erros(sp, "delta_renew read timeout %u sec offset %llu %s",
				  sp->io_timeout, (unsigned long long)disk->offset, disk->path);
		else
			log_erros(sp, "delta_renew read rv %d offset %llu %s",
				  rv, (unsigned long long)disk->offset, disk->path);
		return rv;
	}

 read_done:
	*read_result = SANLK_OK;
	memcpy(&leader_end, task->iobuf+id_offset, sizeof(struct leader_record));

	/* N.B. compute checksum before byte swapping */
	checksum = leader_checksum(&leader_end);

	leader_record_in(&leader_end, &leader);

	rv = verify_leader(disk, space_name, host_id, &leader, checksum, "delta_renew");
	if (rv < 0) {
		log_erros(sp, "delta_renew verify_leader error %d", rv);
		return rv;
	}

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

	if (leader.io_timeout != sp->io_timeout) {
		log_erros(sp, "delta_renew io_timeout changed disk %d sp %d",
			  leader.io_timeout, sp->io_timeout);
		leader.io_timeout = (sp->io_timeout & 0x00FF);
	}

	new_ts = monotime();

	if (log_renewal_level != -1)
		log_level(sp->space_id, 0, NULL, log_renewal_level, "delta_renew begin write for new ts %llu", (unsigned long long)new_ts);

	if (leader.timestamp >= new_ts)
		log_erros(sp, "delta_renew timestamp too small");

	leader.timestamp = new_ts;
	leader.checksum = 0; /* set below */

	/* TODO: rename the leader fields */
	if (extra) {
		leader.write_id = extra->field1;
		leader.write_generation = extra->field2;
		leader.write_timestamp = extra->field3;
	}

	p_wbuf = &wbuf;
	rv = posix_memalign((void *)p_wbuf, getpagesize(), sector_size);
	if (rv) {
		log_erros(sp, "dela_renew write memalign rv %d", rv);
		return -ENOMEM;
	}
	memset(wbuf, 0, sector_size);

	leader_record_out(&leader, &leader_end);

	/*
	 * N.B. must compute checksum after the data has been byte swapped.
	 */
	checksum = leader_checksum(&leader_end);
	leader.checksum = checksum;
	leader_end.checksum = cpu_to_le32(checksum);

	memcpy(wbuf, &leader_end, sizeof(struct leader_record));
	memcpy(wbuf+LEADER_RECORD_MAX, bitmap, HOSTID_BITMAP_SIZE);

	/* extend io timeout for this one write; we need to give this write
	   every chance to succeed, and there's no point in letting it time
	   out.  there's nothing we would do but retry it, and timing out and
	   retrying unnecessarily would probably be counter productive. */

	rv = write_iobuf(disk->fd, disk->offset+id_offset, wbuf, sector_size, task,
			 calc_host_dead_seconds(sp->io_timeout));

	if (rv != SANLK_AIO_TIMEOUT)
		free(wbuf);

	now = monotime();

	if (rv < 0) {
		log_erros(sp, "delta_renew write time %llu error %d",
			  (unsigned long long)(now - new_ts), rv);
		return rv;
	}

	if (now - new_ts >= sp->io_timeout)
		log_erros(sp, "delta_renew long write time %llu sec",
			  (unsigned long long)(now - new_ts));

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
	struct leader_record leader_end;
	uint64_t host_id;
	uint32_t checksum;
	int rv;

	if (!leader_last)
		return -EINVAL;

	host_id = leader_last->owner_id;

	log_space(sp, "delta_release begin %.48s:%llu",
		  sp->space_name, (unsigned long long)host_id);

	memcpy(&leader, leader_last, sizeof(struct leader_record));
	leader.timestamp = LEASE_FREE;
	leader.checksum = 0; /* set below */

	leader_record_out(&leader, &leader_end);

	/*
	 * N.B. must compute checksum after the data has been byte swapped.
	 */
	checksum = leader_checksum(&leader_end);
	leader.checksum = checksum;
	leader_end.checksum = cpu_to_le32(checksum);

	rv = write_sector(disk, host_id - 1, (char *)&leader_end, sizeof(struct leader_record),
			  task, sp->io_timeout, "delta_leader");
	if (rv < 0) {
		log_space(sp, "delta_release write error %d", rv);
		return rv;
	}

	log_space(sp, "delta_release done %llu %llu %llu",
		  (unsigned long long)leader.owner_id,
		  (unsigned long long)leader.owner_generation,
		  (unsigned long long)leader.timestamp);

	memcpy(leader_ret, &leader, sizeof(struct leader_record));
	return SANLK_OK;
}

/* the host_id lease area begins disk->offset bytes from the start of
   block device disk->path */

int delta_lease_init(struct task *task,
		     int io_timeout,
		     struct sync_disk *disk,
		     char *space_name,
		     int max_hosts)
{
	struct leader_record leader_first;
	struct leader_record leader_end;
	struct leader_record leader;
	char *iobuf, **p_iobuf;
	int iobuf_len;
	int align_size;
	int i, rv;
	uint32_t checksum;

	if (!max_hosts)
		max_hosts = DEFAULT_MAX_HOSTS;

	if (max_hosts > DEFAULT_MAX_HOSTS)
		return -E2BIG;

	if (!io_timeout)
		io_timeout = DEFAULT_IO_TIMEOUT;

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
		memset(&leader, 0, sizeof(struct leader_record));
		leader.magic = DELTA_DISK_MAGIC;
		leader.version = DELTA_DISK_VERSION_MAJOR | DELTA_DISK_VERSION_MINOR;
		leader.sector_size = disk->sector_size;
		leader.max_hosts = 1;
		leader.timestamp = LEASE_FREE;
		leader.io_timeout = io_timeout;
		strncpy(leader.space_name, space_name, NAME_ID_SIZE);
		leader.checksum = 0; /* set below */

		/* make the first record invalid so we can do a single atomic
		   write below to commit the whole thing */
		if (!i) {
			leader.magic = 0;
			memcpy(&leader_first, &leader, sizeof(struct leader_record));
		}

		leader_record_out(&leader, &leader_end);

		/*
		 * N.B. must compute checksum after the data has been byte swapped.
		 */
		checksum = leader_checksum(&leader_end);
		leader.checksum = checksum;
		leader_end.checksum = cpu_to_le32(checksum);

		memcpy(iobuf + (i * disk->sector_size), &leader_end, sizeof(struct leader_record));
	}

	rv = write_iobuf(disk->fd, disk->offset, iobuf, iobuf_len, task, io_timeout);
	if (rv < 0)
		goto out;

	/* commit the whole lockspace by making the first record valid */

	leader_first.magic = DELTA_DISK_MAGIC;
	leader_first.checksum = 0; /* set below */

	leader_record_out(&leader_first, &leader_end);

	/*
	 * N.B. must compute checksum after the data has been byte swapped.
	 */
	checksum = leader_checksum(&leader_end);
	leader_first.checksum = checksum;
	leader_end.checksum = cpu_to_le32(checksum);

	memcpy(iobuf, &leader_end, sizeof(struct leader_record));

	rv = write_iobuf(disk->fd, disk->offset, iobuf, disk->sector_size, task, io_timeout);
 out:
	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);

	return rv;
}

