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
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sanlock_internal.h"
#include "diskio.h"
#include "ondisk.h"
#include "log.h"
#include "paxos_lease.h"
#include "lockspace.h"
#include "resource.h"
#include "task.h"
#include "timeouts.h"
#include "helper.h"

/* from cmd.c */
void send_state_resource(int fd, struct resource *r, const char *list_name, int pid, uint32_t token_id);

/* from main.c */
int get_rand(int a, int b);

static pthread_t resource_pt;
static int resource_thread_stop;
static int resource_thread_work;
static int resource_thread_work_examine;
static struct list_head resources_held;
static struct list_head resources_add;
static struct list_head resources_rem;
static struct list_head resources_orphan;
static pthread_mutex_t resource_mutex;
static pthread_cond_t resource_cond;
static struct list_head host_events;


static void free_resource(struct resource *r)
{
	if (r->lvb)
		free(r->lvb);
	free(r);
}

/* N.B. the reporting function looks for the
   strings "add" and "rem", so if changed, they
   should be changed in both places. */

void send_state_resources(int fd)
{
	struct resource *r;
	struct token *token;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry(r, &resources_held, list) {
		list_for_each_entry(token, &r->tokens, list)
			send_state_resource(fd, r, "held", token->pid, token->token_id);
	}

	list_for_each_entry(r, &resources_add, list) {
		list_for_each_entry(token, &r->tokens, list)
			send_state_resource(fd, r, "add", token->pid, token->token_id);
	}

	list_for_each_entry(r, &resources_rem, list)
		send_state_resource(fd, r, "rem", r->pid, r->release_token_id);

	list_for_each_entry(r, &resources_orphan, list)
		send_state_resource(fd, r, "orphan", r->pid, r->release_token_id);
	pthread_mutex_unlock(&resource_mutex);
}

int read_resource_owners(struct task *task, struct token *token,
			 struct sanlk_resource *res,
			 char **send_buf, int *send_len, int *count)
{
	struct leader_record leader;
	struct leader_record leader_end;
	struct mode_block mb;
	struct sync_disk *disk;
	struct sanlk_host *host;
	struct mode_block *mb_end;
	uint64_t host_id;
	char *lease_buf_dblock;
	char *lease_buf = NULL;
	char *hosts_buf = NULL;
	int host_count = 0;
	int i, rv;

	disk = &token->disks[0];

	/* we could in-line paxos_read_buf here like we do in read_mode_block */

	rv = paxos_read_buf(task, token, &lease_buf);
	if (rv < 0) {
		log_errot(token, "read_resource_owners read_buf rv %d", rv);

		if (lease_buf && (rv != SANLK_AIO_TIMEOUT))
			free(lease_buf);
		return rv;
	}

	memcpy(&leader_end, lease_buf, sizeof(struct leader_record));

	leader_record_in(&leader_end, &leader);

	rv = paxos_verify_leader(token, disk, &leader, "read_resource_owners");
	if (rv < 0)
		goto out;

	res->lver = leader.lver;

	if (leader.timestamp && leader.owner_id)
		host_count++;

	for (i = 0; i < leader.num_hosts; i++) {
		lease_buf_dblock = lease_buf + ((2 + i) * disk->sector_size);
		mb_end = (struct mode_block *)(lease_buf_dblock + MBLOCK_OFFSET);

		mode_block_in(mb_end, &mb);

		host_id = i + 1;

		if (!(mb.flags & MBLOCK_SHARED))
			continue;

		res->flags |= SANLK_RES_SHARED;

		/* the leader owner has already been counted above;
		   in the ex case it won't have a mode block set */

		if (leader.timestamp && leader.owner_id && (host_id == leader.owner_id))
			continue;

		host_count++;
	}

	*count = host_count;

	if (!host_count) {
		rv = 0;
		goto out;
	}

	hosts_buf = malloc(host_count * sizeof(struct sanlk_host));
	if (!hosts_buf) {
		host_count = 0;
		rv = -ENOMEM;
		goto out;
	}
	memset(hosts_buf, 0, host_count * sizeof(struct sanlk_host));
	host = (struct sanlk_host *)hosts_buf;

	/*
	 * Usually when leader owner is set, it's an exclusive lock and
	 * we could skip to the end, but if we read while a new shared
	 * owner is being added, we'll see the leader owner set, and
	 * then may see other shared owners in the mode blocks.
	 */

	if (leader.timestamp && leader.owner_id) {
		host->host_id = leader.owner_id;
		host->generation = leader.owner_generation;
		host->timestamp = leader.timestamp;
		host++;
	}

	for (i = 0; i < leader.num_hosts; i++) {
		lease_buf_dblock = lease_buf + ((2 + i) * disk->sector_size);
		mb_end = (struct mode_block *)(lease_buf_dblock + MBLOCK_OFFSET);

		mode_block_in(mb_end, &mb);

		host_id = i + 1;

		if (!(mb.flags & MBLOCK_SHARED))
			continue;

		if (leader.timestamp && leader.owner_id && (host_id == leader.owner_id))
			continue;

		host->host_id = host_id;
		host->generation = mb.generation;
		host++;
	}
	rv = 0;
 out:
	*send_len = host_count * sizeof(struct sanlk_host);
	*send_buf = hosts_buf;
	free(lease_buf);
	return rv;
}

/* return 1 (is alive) to force a failure if we don't have enough
   knowledge to know it's really not alive.  Later we could have this sit and
   wait (like paxos_lease_acquire) until we have waited long enough or have
   enough knowledge to say it's safely dead (unless of course we find it is
   alive while waiting) */

static int host_live(char *lockspace_name, uint64_t host_id, uint64_t gen)
{
	struct host_status hs;
	uint64_t now;
	int other_io_timeout, other_host_dead_seconds;
	int rv;

	rv = host_info(lockspace_name, host_id, &hs);
	if (rv) {
		log_debug("host_live %llu %llu yes host_info %d",
			  (unsigned long long)host_id, (unsigned long long)gen, rv);
		return 1;
	}

	if (!hs.last_check) {
		log_debug("host_live %llu %llu yes unchecked",
			  (unsigned long long)host_id, (unsigned long long)gen);
		return 1;
	}

	/* the host_id lease is free, not being used */
	if (!hs.timestamp) {
		log_debug("host_live %llu %llu no lease free",
			  (unsigned long long)host_id, (unsigned long long)gen);
		return 0;
	}

	if (hs.owner_generation > gen) {
		log_debug("host_live %llu %llu no old gen %llu",
			  (unsigned long long)host_id, (unsigned long long)gen,
			  (unsigned long long)hs.owner_generation);
		return 0;
	}

	now = monotime();

	other_io_timeout = hs.io_timeout;
	other_host_dead_seconds = calc_host_dead_seconds(other_io_timeout);

	if (!hs.last_live && (now - hs.first_check > other_host_dead_seconds)) {
		log_debug("host_live %llu %llu no first_check %llu",
			  (unsigned long long)host_id, (unsigned long long)gen,
			  (unsigned long long)hs.first_check);
		return 0;
	}

	if (hs.last_live && (now - hs.last_live > other_host_dead_seconds)) {
		log_debug("host_live %llu %llu no last_live %llu",
			  (unsigned long long)host_id, (unsigned long long)gen,
			  (unsigned long long)hs.last_live);
		return 0;
	}

	log_debug("host_live %llu %llu yes recent first_check %llu last_live %llu",
		  (unsigned long long)host_id, (unsigned long long)gen,
		  (unsigned long long)hs.first_check,
		  (unsigned long long)hs.last_live);

	return 1;
}

void check_mode_block(struct token *token, uint64_t next_lver, int q, char *dblock_buf)
{
	struct mode_block *mb_end;
	struct mode_block mb;

	mb_end = (struct mode_block *)(dblock_buf + MBLOCK_OFFSET);

	mode_block_in(mb_end, &mb);

	if (mb.flags & MBLOCK_SHARED) {
		set_id_bit(q + 1, token->shared_bitmap, NULL);
		token->shared_count++;
		log_token(token, "ballot %llu mode[%d] shared %d",
			  (unsigned long long)next_lver, q, token->shared_count);
	}
}

static int set_mode_block(struct task *task, struct token *token,
			  uint64_t host_id, uint64_t gen, uint32_t flags)
{
	struct sync_disk *disk;
	struct mode_block mb;
	struct mode_block mb_end;
	char *iobuf, **p_iobuf;
	uint64_t offset;
	int num_disks = token->r.num_disks;
	int iobuf_len, rv, d;

	disk = &token->disks[0];

	iobuf_len = disk->sector_size;
	if (!iobuf_len)
		return -EINVAL;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return -ENOMEM;

	for (d = 0; d < num_disks; d++) {
		disk = &token->disks[d];

		offset = disk->offset + ((2 + host_id - 1) * disk->sector_size);

		rv = read_iobuf(disk->fd, offset, iobuf, iobuf_len, task, token->io_timeout);
		if (rv < 0)
			break;

		memset(&mb, 0, sizeof(mb));
		mb.flags = flags;
		mb.generation = gen;

		mode_block_out(&mb, &mb_end);
		memcpy(iobuf + MBLOCK_OFFSET, &mb_end, sizeof(struct mode_block));

		rv = write_iobuf(disk->fd, offset, iobuf, iobuf_len, task, token->io_timeout);
		if (rv < 0)
			break;
	}

	if (rv < 0) {
		log_errot(token, "set_mode_block host_id %llu flags %x gen %llu d %d rv %d",
			  (unsigned long long)host_id, flags, (unsigned long long)gen, d, rv);
	} else {
		log_token(token, "set_mode_block host_id %llu flags %x gen %llu",
			  (unsigned long long)host_id, flags, (unsigned long long)gen);
	}

	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);
	return rv;
}

static int read_mode_block(struct task *task, struct token *token,
			   uint64_t host_id, uint64_t *max_gen)
{
	struct sync_disk *disk;
	struct mode_block *mb_end;
	struct mode_block mb;
	char *iobuf, **p_iobuf;
	uint64_t offset;
	uint64_t max = 0;
	int num_disks = token->r.num_disks;
	int iobuf_len, rv, d;

	disk = &token->disks[0];

	iobuf_len = disk->sector_size;
	if (!iobuf_len)
		return -EINVAL;

	p_iobuf = &iobuf;

	rv = posix_memalign((void *)p_iobuf, getpagesize(), iobuf_len);
	if (rv)
		return -ENOMEM;

	for (d = 0; d < num_disks; d++) {
		disk = &token->disks[d];

		offset = disk->offset + ((2 + host_id - 1) * disk->sector_size);

		rv = read_iobuf(disk->fd, offset, iobuf, iobuf_len, task, token->io_timeout);
		if (rv < 0)
			break;

		mb_end = (struct mode_block *)(iobuf + MBLOCK_OFFSET);

		mode_block_in(mb_end, &mb);

		if (!(mb.flags & MBLOCK_SHARED))
			continue;

		if (!max || mb.generation > max)
			max = mb.generation;
	}

	if (rv != SANLK_AIO_TIMEOUT)
		free(iobuf);

	*max_gen = max;
	return rv;
}

static int clear_dead_shared(struct task *task, struct token *token,
			     int num_hosts, int *live_count)
{
	uint64_t host_id, max_gen = 0;
	int i, rv = 0, live = 0;

	for (i = 0; i < num_hosts; i++) {
		host_id = i + 1;

		if (host_id == token->host_id)
			continue;

		if (!test_id_bit(host_id, token->shared_bitmap))
			continue;

		rv = read_mode_block(task, token, host_id, &max_gen);
		if (rv < 0) {
			log_errot(token, "clear_dead_shared read_mode_block %llu %d",
				  (unsigned long long)host_id, rv);
			return rv;
		}

		if (host_live(token->r.lockspace_name, host_id, max_gen)) {
			log_token(token, "clear_dead_shared host_id %llu gen %llu alive",
				  (unsigned long long)host_id, (unsigned long long)max_gen);
			live++;
			continue;
		}

		rv = set_mode_block(task, token, host_id, 0, 0);
		if (rv < 0) {
			log_errot(token, "clear_dead_shared host_id %llu set_mode_block %d",
				  (unsigned long long)host_id, rv);
			return rv;
		}

		log_token(token, "clear_dead_shared host_id %llu gen %llu dead and cleared",
			  (unsigned long long)host_id, (unsigned long long)max_gen);
	}

	*live_count = live;
	return rv;
}

/* the lvb is the sector after the dblock for host_id 2000, i.e. 2002 */

#define LVB_SECTOR 2002

static int read_lvb_block(struct task *task, struct token *token)
{
	struct sync_disk *disk;
	struct resource *r;
	char *iobuf;
	uint64_t offset;
	int iobuf_len, rv;

	r = token->resource;
	disk = &token->disks[0];
	iobuf_len = disk->sector_size;
	iobuf = r->lvb;
	offset = disk->offset + (LVB_SECTOR * disk->sector_size);

	if (!r->lvb)
		return 0;

	rv = read_iobuf(disk->fd, offset, iobuf, iobuf_len, task, token->io_timeout);

	return rv;
}

static int write_lvb_block(struct task *task, struct resource *r, struct token *token)
{
	struct sync_disk *disk;
	char *iobuf;
	uint64_t offset;
	int iobuf_len, rv;

	disk = &token->disks[0];
	iobuf_len = disk->sector_size;
	iobuf = r->lvb;
	offset = disk->offset + (LVB_SECTOR * disk->sector_size);

	if (!r->lvb)
		return 0;

	rv = write_iobuf(disk->fd, offset, iobuf, iobuf_len, task, token->io_timeout);

	return rv;
}

int res_set_lvb(struct sanlk_resource *res, char *lvb, int lvblen)
{
	struct resource *r;
	int rv = -ENOENT;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry(r, &resources_held, list) {
		if (strncmp(r->r.lockspace_name, res->lockspace_name, NAME_ID_SIZE))
			continue;
		if (strncmp(r->r.name, res->name, NAME_ID_SIZE))
			continue;

		if (!r->lvb) {
			rv = -EINVAL;
			break;
		}

		if (lvblen > r->leader.sector_size) {
			rv = -E2BIG;
			break;
		}

		memcpy(r->lvb, lvb, lvblen);
		r->flags |= R_LVB_WRITE_RELEASE;
		rv = 0;
		break;
	}
	pthread_mutex_unlock(&resource_mutex);

	return rv;
}

int res_get_lvb(struct sanlk_resource *res, char **lvb_out, int *lvblen)
{
	struct resource *r;
	char *lvb;
	int rv = -ENOENT;
	int len = *lvblen;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry(r, &resources_held, list) {
		if (strncmp(r->r.lockspace_name, res->lockspace_name, NAME_ID_SIZE))
			continue;
		if (strncmp(r->r.name, res->name, NAME_ID_SIZE))
			continue;

		if (!r->lvb) {
			rv = -EINVAL;
			break;
		}

		if (!len)
			len = r->leader.sector_size;

		lvb = malloc(len);
		if (!lvb) {
			rv = -ENOMEM;
			break;
		}

		memcpy(lvb, r->lvb, len);
		*lvb_out = lvb;
		*lvblen = len;
		rv = 0;
		break;
	}
	pthread_mutex_unlock(&resource_mutex);

	return rv;
}

/* return < 0 on error, 1 on success */

static int acquire_disk(struct task *task, struct token *token,
			uint64_t acquire_lver, int new_num_hosts,
			struct leader_record *leader)
{
	struct leader_record leader_tmp;
	int rv;
	uint32_t flags = 0;

	if (com.quiet_fail)
		flags |= PAXOS_ACQUIRE_QUIET_FAIL;

	if (token->acquire_flags & SANLK_RES_SHARED)
		flags |= PAXOS_ACQUIRE_SHARED;

	memset(&leader_tmp, 0, sizeof(leader_tmp));

	rv = paxos_lease_acquire(task, token, flags, &leader_tmp, acquire_lver,
				 new_num_hosts);

	log_token(token, "acquire_disk rv %d lver %llu at %llu", rv,
		  (unsigned long long)leader_tmp.lver,
		  (unsigned long long)leader_tmp.timestamp);

	memcpy(leader, &leader_tmp, sizeof(struct leader_record));

	return rv; /* SANLK_RV */
}

/* return < 0 on error, 1 on success */

static int release_disk(struct task *task, struct token *token,
			struct sanlk_resource *resrename,
			struct leader_record *leader)
{
	struct leader_record leader_tmp;
	int rv;

	rv = paxos_lease_release(task, token, resrename, leader, &leader_tmp);

	/* log_token(token, "release_disk rv %d", rv); */

	if (rv < 0)
		return rv;

	memcpy(leader, &leader_tmp, sizeof(struct leader_record));
	return rv; /* SANLK_OK */
}

/*
 * This function will:
 * 1. list_del token from the struct resource (caller frees struct token)
 * 2. perform on-disk operations to remove this host's ownership of the lease
 * 3. list_del and free the struct resource
 *
 * The on-disk operations in step 2 include five variations:
 * . skip all on-disk operations
 * . write zero mode block
 * . write zero leader record
 * . write zero mode block and write zero leader record
 * . write zero dblock and write zero leader record
 *
 * These on-disk variations are controlled by the following:
 *
 * - if the token indicates it's being released because the lockspace is
 *   failed/dead, then all on-disk operations are skipped.
 *
 * - if r->leader is zero, it implies that the on-disk lease was never
 *   acquired, so all on-disk operations are skipped.
 *
 * - if the caller has specified nodisk, then all on-disk operations are
 *   skipped.
 *
 * - if R_SHARED is set, then only the host's mode_block is zeroed.
 *
 * - if R_SHARED is not set, then the leader_record is released
 *   (involves reading it, verifying it's owned, then writing it)
 *
 * - if R_UNDO_SHARED is set, then the mode_block and leader_record
 *   are both cleared
 *
 * - if R_ERASE_ALL is set, then the dblock and leader_record
 *   are both cleared
 *
 * Error handling:
 *
 * If any on-disk i/o operation times out in step 2, then the struct resource
 * is moved to the resource_thread for retrying and step 3 is deferred.
 * The resource_thread will retry the on-disk operations until they succeed,
 * then free the resource.
 *
 * For ERASE_ALL we don't want another host running the ballot to select
 * our dblock values and commit them, making us the owner after we've aborted
 * the acquire.  So, we clear our dblock values first to prevent that from
 * happening from this point forward.  However, another host contending for the
 * lease at the same time we failed, could already have read our dblock values
 * from before we cleared them.  In the worst case, that host could commit our
 * dblock values as the new leader, and that new leader write could apppear on
 * disk up to host_dead_seconds later.  So it seems that technically we would
 * need to monitor the leader for up to host_dead_seconds after clearing our
 * dblock to check if we become the on-disk owner of the lease.  The chances
 * of all this happening seem so remote that we don't do this monitoring.
 * The best approach to dealing with the ERASE_ALL case is to run a full ballot
 * again, to ensure there's a known owner, and then release normally from that
 * state.  We don't attempt to queue up an another async ballot in the error
 * path either because it would get fairly complicated.  If the caller wants
 * to be extra sure that these obscure cases do not leave an orphaned lease
 * on disk, it can either:
 * - repeat the acquire call until it does not fail with a timeout, i.e.
 *   rerun the ballot until there's a known owner
 * - leave and rejoin the lockspace after an acquire times out, which will
 *   invalidate any on-disk lease state
 */

static int _release_token(struct task *task, struct token *token,
			  struct sanlk_resource *resrename,
			  int opened, int nodisk)
{
	struct leader_record leader;
	struct resource *r = token->resource;
	uint64_t lver;
	uint32_t r_flags = 0;
	int last_token = 0;
	int rv = 0;

	/* We keep r on the resources_rem list while doing the actual release 
	   on disk so another acquire for the same resource will see it on
	   the list and fail. we can't have one thread releasing and another
	   acquiring the same resource.  While on the rem list, the resource
	   can't be used by anyone. */

	pthread_mutex_lock(&resource_mutex);
	list_del(&token->list);
	if (list_empty(&r->tokens)) {
		list_move(&r->list, &resources_rem);
		last_token = 1;
	}
	lver = r->leader.lver;
	r_flags = r->flags;
	pthread_mutex_unlock(&resource_mutex);

	if ((r_flags & R_SHARED) && !last_token) {
		/* will release when final sh token is released */
		log_token(token, "release_token more shared");
		close_disks(token->disks, token->r.num_disks);
		return SANLK_OK;
	}

	if (!last_token) {
		/* should never happen */
		log_errot(token, "release_token exclusive not last");
		close_disks(token->disks, token->r.num_disks);
		return SANLK_ERROR;
	}

	if (token->space_dead) {
		/* don't bother trying disk op which will probably timeout */
		close_disks(token->disks, token->r.num_disks);
		rv = SANLK_OK;
		goto out;
	}

	if (nodisk) {
		rv = SANLK_OK;
		goto out;
	}

	if (!opened) {
		rv = open_disks_fd(token->disks, token->r.num_disks);
		if (rv < 0) {
			log_errot(token, "release_token open error %d", rv);
			goto out;
		}
	}

	if (r_flags & R_ERASE_ALL) {
		rv = paxos_erase_dblock(task, token, token->host_id);
		if (rv < 0) {
			log_errot(token, "release_token erase_dblock error %d r_flags %x",
				  rv, r_flags);
			goto out_close;
		}
		log_token(token, "release_token erase dblock done");

		/* Even when acquire did not get far enough to get a copy of the
		   leader (!lver), we still want to try to release the leader
		   in case we own it from another host committing our dblock. */

		if (!lver)
			rv = paxos_lease_release(task, token, NULL, NULL, &leader);
		else
			rv = paxos_lease_release(task, token, NULL, &r->leader, &leader);

		/* want to see this result in sanlock.log but not worry people with error */
		log_level(0, token->token_id, NULL, LOG_WARNING,
			  "release_token erase leader lver %llu rv %d",
			  (unsigned long long)lver, rv);

		goto out_close;
	}

	if ((r_flags & R_SHARED) || (r_flags & R_UNDO_SHARED)) {
		rv = set_mode_block(task, token, token->host_id, 0, 0);
		if (rv < 0) {
			log_errot(token, "release_token set_mode_block error %d r_flags %x",
				  rv, r_flags);
			goto out_close;
		}
	}

	if (!lver) {
		/* zero lver means acquire did not get to the point of writing a leader,
		   so we don't need to release the lease on disk. */
		close_disks(token->disks, token->r.num_disks);
		rv = SANLK_OK;
		goto out;
	}

	if (!(r_flags & R_SHARED) || (r_flags & R_UNDO_SHARED)) {
		if (r_flags & R_LVB_WRITE_RELEASE) {
			rv = write_lvb_block(task, r, token);
			if (!rv)
				r->flags &= ~R_LVB_WRITE_RELEASE;
			else
				log_errot(token, "release_token write_lvb error %d", rv);
			/* do we want to give more effort to writing lvb? */
		}

		rv = release_disk(task, token, resrename, &r->leader);
		if (rv < 0) {
			log_errot(token, "release_token disk error %d r_flags %x lver %llu",
				  rv, r_flags, (unsigned long long)lver);
			goto out_close;
		}
	}

	log_token(token, "release_token done %d r_flags %x t_flags %x", rv, r->flags, token->flags);

 out_close:
	close_disks(token->disks, token->r.num_disks);

 out:
	/*
	 * If a transient i/o error prevented the release on disk,
	 * then handle this like an async release; set R_THREAD_RELEASE,
	 * leave r on resources_rem, let resource_thread_release attempt
	 * to release it.  We don't want to leave the lease locked on
	 * disk, preventing others from acquiring it.
	 */

	pthread_mutex_lock(&resource_mutex);
	if (rv == SANLK_AIO_TIMEOUT) {
		r->flags |= R_THREAD_RELEASE;
		r->release_token_id = token->token_id;
	} else {
		list_del(&r->list);
	}
	pthread_mutex_unlock(&resource_mutex);

	if (rv != SANLK_AIO_TIMEOUT)
		free_resource(r);

	return rv;
}

static int release_token_nodisk(struct task *task, struct token *token)
{
	return _release_token(task, token, NULL, 0, 1);
}

static int release_token_opened(struct task *task, struct token *token)
{
	return _release_token(task, token, NULL, 1, 0);
}

int release_token(struct task *task, struct token *token,
		  struct sanlk_resource *resrename)
{
	return _release_token(task, token, resrename, 0, 0);
}

/* We're releasing a token from the main thread, in which we don't want to block,
   so we can't do a real release involving disk io.  So, pass the release off to
   the resource_thread. */

void release_token_async(struct token *token)
{
	struct resource *r = token->resource;

	pthread_mutex_lock(&resource_mutex);
	list_del(&token->list);
	if (list_empty(&r->tokens)) {
		if (token->space_dead || !r->leader.lver) {
			/* don't bother trying to release if the lockspace
			   is dead (release will probably fail), or the
			   lease was never acquired */
			list_del(&r->list);
			free_resource(r);
		} else if (token->acquire_flags & SANLK_RES_PERSISTENT) {
			r->release_token_id = token->token_id;
			list_move(&r->list, &resources_orphan);
		} else {
			r->flags |= R_THREAD_RELEASE;
			r->release_token_id = token->token_id;
			resource_thread_work = 1;
			list_move(&r->list, &resources_rem);
			pthread_cond_signal(&resource_cond);
		}
	}
	pthread_mutex_unlock(&resource_mutex);
}

static struct resource *find_resource(struct token *token,
				      struct list_head *head)
{
	struct resource *r;

	list_for_each_entry(r, head, list) {
		if (strncmp(r->r.lockspace_name, token->r.lockspace_name, NAME_ID_SIZE))
			continue;
		if (strncmp(r->r.name, token->r.name, NAME_ID_SIZE))
			continue;
		return r;
	}
	return NULL;
}

/*
 * Determines if lockspace is "used" for the purpose of
 * rem_lockspace(REM_UNUSED).
 */

int lockspace_is_used(struct sanlk_lockspace *ls)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry(r, &resources_held, list) {
		if (!strncmp(r->r.lockspace_name, ls->name, NAME_ID_SIZE))
			goto yes;
	}
	list_for_each_entry(r, &resources_add, list) {
		if (!strncmp(r->r.lockspace_name, ls->name, NAME_ID_SIZE))
			goto yes;
	}
	list_for_each_entry(r, &resources_rem, list) {
		if (!strncmp(r->r.lockspace_name, ls->name, NAME_ID_SIZE))
			goto yes;
	}
	list_for_each_entry(r, &resources_orphan, list) {
		if (!strncmp(r->r.lockspace_name, ls->name, NAME_ID_SIZE))
			goto yes;
	}
	pthread_mutex_unlock(&resource_mutex);
	return 0;
 yes:
	pthread_mutex_unlock(&resource_mutex);
	return 1;
}

int resource_orphan_count(char *space_name)
{
	struct resource *r;
	int count = 0;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry(r, &resources_orphan, list) {
		if (!strncmp(r->r.lockspace_name, space_name, NAME_ID_SIZE))
			count++;
	}
	pthread_mutex_unlock(&resource_mutex);
	return count;
}	

static void copy_disks(void *dst, void *src, int num_disks)
{
	struct sync_disk *d, *s;
	int i;

	d = (struct sync_disk *)dst;
	s = (struct sync_disk *)src;

	for (i = 0; i < num_disks; i++) {
		memcpy(d->path, s->path, SANLK_PATH_LEN);
		d->offset = s->offset;
		d->sector_size = s->sector_size;

		/* fd's are private */
		d->fd = -1;

		d++;
		s++;
	}
}

static struct resource *new_resource(struct token *token)
{
	struct resource *r;
	int disks_len, r_len;

	disks_len = token->r.num_disks * sizeof(struct sync_disk);
	r_len = sizeof(struct resource) + disks_len;

	r = malloc(r_len);
	if (!r)
		return NULL;

	memset(r, 0, r_len);
	memcpy(&r->r, &token->r, sizeof(struct sanlk_resource));

	r->io_timeout = token->io_timeout;

	/* disks copied after open_disks because open_disks sets sector_size
	   which we want copied */

	INIT_LIST_HEAD(&r->tokens);

	r->host_id = token->host_id;
	r->host_generation = token->host_generation;

	if (token->acquire_flags & SANLK_RES_SHARED) {
		r->flags |= R_SHARED;
	} else {
		r->pid = token->pid;
		if (token->flags & T_RESTRICT_SIGKILL)
			r->flags |= R_RESTRICT_SIGKILL;
		if (token->flags & T_RESTRICT_SIGTERM)
			r->flags |= R_RESTRICT_SIGTERM;
	}

	return r;
}

static int convert_sh2ex_token(struct task *task, struct resource *r, struct token *token)
{
	struct leader_record leader;
	int live_count = 0;
	int fail_count = 0;
	int undo_dblock = 0;
	int error;
	int rv;

	memset(&leader, 0, sizeof(leader));

	/* paxos_lease_acquire modifies these token values, and we check them after */
	token->shared_count = 0;
	memset(token->shared_bitmap, 0, HOSTID_BITMAP_SIZE);

	/* Using a token flag like this to manipulate the write_dblock to preserve
	   our mblock is ugly. The diskio/paxos/resource layer separations are not
	   quite right, but would take some major effort to change.  The flag is
	   needed to prevent the ballot from clobbering our SHARED mblock.  Rewriting
	   our mblock after acquire isn't safe because if the paxos acquire doesn't
	   succeed, then we don't hold any lease for a time. */

	token->flags |= T_WRITE_DBLOCK_MBLOCK_SH;

	rv = paxos_lease_acquire(task, token, 0, &leader, 0, 0);

	token->flags &= ~T_WRITE_DBLOCK_MBLOCK_SH;

	if (rv < 0) {
		log_errot(token, "convert_sh2ex acquire error %d t_flags %x", rv, token->flags);

		/* If we might own the lease, then we need to do on-disk release
		   of owner and dblock.  Keep token and SH mblock. */

		if (token->flags & T_RETRACT_PAXOS) {
			token->flags &= ~T_RETRACT_PAXOS;
			undo_dblock = 1;
			error = rv;
			goto fail;
		}

		return rv;
	}

	memcpy(&r->leader, &leader, sizeof(struct leader_record));
	token->r.lver = leader.lver;

	/* paxos_lease_acquire set token->shared_count to the number of
	   SHARED mode blocks it found */

	if (!token->shared_count) {
		/* no other SHARED mode blocks found */
		goto do_mb;
	}

	log_token(token, "convert_sh2ex shared_count %d", token->shared_count);

	rv = clear_dead_shared(task, token, leader.num_hosts, &live_count);
	if (rv < 0) {
		log_errot(token, "convert_sh2ex clear_dead error %d", rv);
		/* Do on-disk release of owner. Keep token and SH mblock. */
		error = rv;
		goto fail;
	}

	log_token(token, "convert_sh2ex live_count %d", live_count);

	if (live_count) {
		/*
		 * A live host with a sh lock exists.  The token is kept, the
		 * lease owner is released.
		 */

		rv = release_disk(task, token, NULL, &leader);
		if (rv < 0) {
			log_errot(token, "convert_sh2ex release_disk error %d", rv);
			/* Do on-disk release of owner. Keep token and SH mblock. */
			error = rv;
			goto fail;
		}

		/* standard exit when convert fails due to other shared locks */
		return -EAGAIN;
	}

 do_mb:
	rv = set_mode_block(task, token, token->host_id, token->host_generation, 0);
	if (rv < 0) {
		log_errot(token, "convert_sh2ex set_mode_block error %d %d", rv, fail_count);

		/* We have the ex lease, so return success.  We just need to clear
		   our SH mblock.  We retry a couple times, and then set ERASE_ALL
		   so that when the token is later released, both owner and mblock will
		   be cleared. */
		   
		if ((rv == SANLK_AIO_TIMEOUT) && (fail_count < 2)) {
			fail_count++;
			sleep(1);
			goto do_mb;
		}

		if (rv < 0 && (rv != SANLK_AIO_TIMEOUT)) {
			error = rv;
			goto fail;
		}

		r->flags |= R_ERASE_ALL;
	}

	/* TODO: clean up the duplication of stuff among: t, t->r, r, r->r */
	token->r.flags &= ~SANLK_RES_SHARED;
	token->acquire_flags &= ~SANLK_RES_SHARED;
	r->r.flags &= ~SANLK_RES_SHARED;
	r->flags &= ~R_SHARED;
	return SANLK_OK;

 fail:
 	/*
	 * We want to fail and return an error to the caller while keeping
	 * the existing shared lease, and not being the ex owner.
	 *
	 * There's no easy way to pass off the undo of dblock/owner while
	 * keeping the lease token which still represents our sh lease, so
	 * we'll just retry here.  We don't want to retry forever, so there's
	 * an arbitrary limit.  If we reach the limit, we may want to pass back
	 * a new error to indicate that the lease may be in a non-standard
	 * state, e.g. both owner and mblock sh are set.  The caller will see
	 * the error, know that it still holds a sh lease, but the owner may be
	 * in limbo.  To clear the lease state, it should release the lease
	 * or leave/rejoin the lockspace.  We set ERASE_ALL on the resource
	 * here so that if/when the caller releases its lease (explicitly or
	 * implicitly by exit), the release_token will clear owner/dblock/mblock.
	 *
	 * As elsewhere, non-timeout errors during disk operations should not
	 * happen, are considered uncorrectable, are not retried, and the
	 * lockspace/leases should be considered invalid.
	 */

	fail_count++;

	if (token->space_dead)
		return error;

	if (undo_dblock) {
		token->flags |= T_WRITE_DBLOCK_MBLOCK_SH;

		rv = paxos_erase_dblock(task, token, token->host_id);

		token->flags &= ~T_WRITE_DBLOCK_MBLOCK_SH;

		if ((rv == SANLK_AIO_TIMEOUT) && (fail_count < token->io_timeout)) {
			log_errot(token, "convert_sh2ex fail %d undo dblock timeout", fail_count);
			sleep(fail_count);
			goto fail;
		} else if (rv < 0) {
			log_errot(token, "convert_sh2ex fail %d undo dblock error %d", fail_count, rv);
			r->flags |= R_ERASE_ALL;
			return error;
		}

		undo_dblock = 0;
	}

	rv = paxos_lease_release(task, token, NULL, leader.lver ? &leader : NULL, &leader);
	if ((rv == SANLK_AIO_TIMEOUT) && (fail_count < token->io_timeout)) {
		log_errot(token, "convert_sh2ex fail %d undo owner timeout", fail_count);
		sleep(fail_count);
		goto fail;
	} else if (rv < 0) {
		log_errot(token, "convert_sh2ex fail %d undo owner error %d", fail_count, rv);
		r->flags |= R_ERASE_ALL;
		return error;
	}

	/* We've managed to release the owner, so the lease is in a standard state
	   with ourselves having a shared lease and not holding the owner ex. */

	return error;
}

static int convert_ex2sh_token(struct task *task, struct resource *r, struct token *token)
{
	struct leader_record leader;
	int fail_count = 0;
	int rv;

	memcpy(&leader, &r->leader, sizeof(leader));

	if (r->flags & R_LVB_WRITE_RELEASE)
		write_lvb_block(task, r, token);

	rv = set_mode_block(task, token, token->host_id, token->host_generation, MBLOCK_SHARED);
	if (rv < 0) {
		log_errot(token, "convert_ex2sh set_mode_block error %d", rv);
		return rv;
	}

 retry:
	/* the token is kept, the paxos lease is released but with shared now set */
	rv = release_disk(task, token, NULL, &leader);
	if ((rv == SANLK_AIO_TIMEOUT) && (fail_count < token->io_timeout)) {
		log_errot(token, "convert_ex2sh release_disk timeout %d", fail_count);
		fail_count++;
		if (token->space_dead)
			return rv;
		sleep(fail_count);
		goto retry;
	} else if (rv < 0) {
		log_errot(token, "convert_ex2sh release_disk error %d", rv);

		/* We have sh, and possibly ex.  Given this uncertain state on
		   disk, we want release_token to ensure owner/dblock/mblock are
		   all cleared when the lease is released by the client (either
		   explicitly or implicitly when it exits).  ERASE_ALL
		   will cause release_token to do this. */

		r->flags |= R_ERASE_ALL;
		return rv;
	}

	token->r.flags |= SANLK_RES_SHARED;
	token->acquire_flags |= SANLK_RES_SHARED;
	r->r.flags |= SANLK_RES_SHARED;
	r->flags |= R_SHARED;
	return SANLK_OK;
}

int convert_token(struct task *task, struct sanlk_resource *res, struct token *cl_token)
{
	struct resource *r;
	struct token *tk;
	struct token *token = NULL;
	int sh_count = 0;
	int rv;

	/* we could probably grab cl_token->r, but it's good to verify */

	pthread_mutex_lock(&resource_mutex);

	r = find_resource(cl_token, &resources_held);
	if (!r) {
		pthread_mutex_unlock(&resource_mutex);
		log_error("convert_token resource not found %.48s:%.48s",
			  cl_token->r.lockspace_name, cl_token->r.name);
		rv = -ENOENT;
		goto out;
	}

	/* find existing token */

	list_for_each_entry(tk, &r->tokens, list) {
		if (tk == cl_token)
			token = tk;

		if (tk->acquire_flags & SANLK_RES_SHARED)
			sh_count++;
	}
	pthread_mutex_unlock(&resource_mutex);

	if (!token) {
		log_errot(cl_token, "convert_token token not found pid %d %.48s:%.48s",
			  cl_token->pid, cl_token->r.lockspace_name, cl_token->r.name);
		rv = -ENOENT;
		goto out;
	}

	if (sh_count && !(r->flags & R_SHARED)) {
		/* should not be possible */
		log_errot(token, "convert_token invalid sh_count %d flags %x", sh_count, r->flags);
		rv = -EINVAL;
		goto out;
	}

	if (!sh_count && (r->flags & R_SHARED)) {
		/* should not be possible */
		log_errot(token, "convert_token invalid sh_count %d flags %x", sh_count, r->flags);
		rv = -EINVAL;
		goto out;
	}

	if (!(res->flags & SANLK_RES_SHARED) && !(r->flags & R_SHARED)) {
		rv = -EALREADY;
		goto out;
	}

	if ((res->flags & SANLK_RES_SHARED) && (r->flags & R_SHARED)) {
		rv = -EALREADY;
		goto out;
	}

	rv = open_disks_fd(token->disks, token->r.num_disks);
	if (rv < 0) {
		log_errot(token, "convert_token open error %d", rv);
		goto out;
	}

	if (!(res->flags & SANLK_RES_SHARED)) {
		rv = convert_sh2ex_token(task, r, token);
	} else if (res->flags & SANLK_RES_SHARED) {
		rv = convert_ex2sh_token(task, r, token);
	} else {
		/* not possible */
		rv = -EINVAL;
	}

	close_disks(token->disks, token->r.num_disks);
 out:
	return rv;
}

int acquire_token(struct task *task, struct token *token, uint32_t cmd_flags,
		  char *killpath, char *killargs)
{
	struct leader_record leader;
	struct resource *r;
	uint64_t acquire_lver = 0;
	uint32_t new_num_hosts = 0;
	int sh_retries = 0;
	int live_count = 0;
	int rv;

	if (token->acquire_flags & SANLK_RES_LVER)
		acquire_lver = token->acquire_lver;
	if (token->acquire_flags & SANLK_RES_NUM_HOSTS)
		new_num_hosts = token->acquire_data32;

	pthread_mutex_lock(&resource_mutex);

	/*
	 * Check if this resource already exists on any of the resource lists.
	 */

	r = find_resource(token, &resources_rem);
	if (r) {
		if (!com.quiet_fail)
			log_errot(token, "acquire_token resource being removed");
		pthread_mutex_unlock(&resource_mutex);
		return -EAGAIN;
	}

	r = find_resource(token, &resources_add);
	if (r) {
		if (!com.quiet_fail)
			log_errot(token, "acquire_token resource being added");
		pthread_mutex_unlock(&resource_mutex);
		return -EBUSY;
	}

	r = find_resource(token, &resources_held);
	if (r && (token->acquire_flags & SANLK_RES_SHARED) && (r->flags & R_SHARED)) {
		/* multiple shared holders allowed */
		log_token(token, "acquire_token add shared");
		copy_disks(&token->r.disks, &r->r.disks, token->r.num_disks);
		token->resource = r;
		list_add(&token->list, &r->tokens);
		pthread_mutex_unlock(&resource_mutex);
		return SANLK_OK;
	}

	if (r) {
		if (!com.quiet_fail)
			log_errot(token, "acquire_token resource exists");
		pthread_mutex_unlock(&resource_mutex);
		return -EEXIST;
	}

	/* caller did not ask for orphan, but an orphan exists */

	r = find_resource(token, &resources_orphan);
	if (r && !(cmd_flags & SANLK_ACQUIRE_ORPHAN)) {
		log_errot(token, "acquire_token found orphan");
		pthread_mutex_unlock(&resource_mutex);
		return -EUCLEAN;
	}

	/* caller asked for exclusive orphan, but a shared orphan exists */

	if (r && (cmd_flags & SANLK_ACQUIRE_ORPHAN) && 
	    (r->flags & R_SHARED) && !(token->acquire_flags & SANLK_RES_SHARED)) {
		log_errot(token, "acquire_token orphan is shared");
		pthread_mutex_unlock(&resource_mutex);
		return -EUCLEAN;
	}

	/* caller asked for a shared orphan, but an exclusive orphan exists */

	if (r && (cmd_flags & SANLK_ACQUIRE_ORPHAN) &&
	    !(r->flags & R_SHARED) && (token->acquire_flags & SANLK_RES_SHARED)) {
		log_errot(token, "acquire_token orphan is exclusive");
		pthread_mutex_unlock(&resource_mutex);
		return -EUCLEAN;
	}

	/* caller asked for shared orphan, and a shared orphan exists */

	if (r && (cmd_flags & SANLK_ACQUIRE_ORPHAN) && 
	    (r->flags & R_SHARED) && (token->acquire_flags & SANLK_RES_SHARED)) {
		log_token(token, "acquire_token adopt shared orphan");
		token->resource = r;
		list_add(&token->list, &r->tokens);
		list_move(&r->list, &resources_held);
		pthread_mutex_unlock(&resource_mutex);
		return SANLK_OK;
	}

	/* caller asked for exclusive orphan, and an exclusive orphan exists */

	if (r && (cmd_flags & SANLK_ACQUIRE_ORPHAN) &&
	    !(r->flags & R_SHARED) && !(token->acquire_flags & SANLK_RES_SHARED)) {
		log_token(token, "acquire_token adopt orphan");
		token->r.lver = r->leader.lver;
		r->pid = token->pid;
		token->resource = r;
		list_add(&token->list, &r->tokens);
		list_move(&r->list, &resources_held);
		pthread_mutex_unlock(&resource_mutex);

		/* do this to initialize some token fields */
		rv = open_disks(token->disks, token->r.num_disks);
		if (rv < 0) {
			/* TODO: what parts above need to be undone? */
			log_errot(token, "acquire_token orphan open error %d", rv);
			release_token_nodisk(task, token);
			return rv;
		}
		close_disks(token->disks, token->r.num_disks);
		return SANLK_OK;
	}

	/*
	 * The resource does not exist, so create it.
	 */

	r = new_resource(token);
	if (!r) {
		pthread_mutex_unlock(&resource_mutex);
		return -ENOMEM;
	}

	memcpy(r->killpath, killpath, SANLK_HELPER_PATH_LEN);
	memcpy(r->killargs, killargs, SANLK_HELPER_ARGS_LEN);
	list_add(&token->list, &r->tokens);
	list_add(&r->list, &resources_add);
	token->resource = r;
	pthread_mutex_unlock(&resource_mutex);

	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		log_errot(token, "acquire_token open error %d", rv);
		release_token_nodisk(task, token);
		return rv;
	}

	copy_disks(&r->r.disks, &token->r.disks, token->r.num_disks);

	if (cmd_flags & SANLK_ACQUIRE_LVB) {
		char *iobuf, **p_iobuf;
		p_iobuf = &iobuf;

		rv = posix_memalign((void *)p_iobuf, getpagesize(), token->disks[0].sector_size);
		if (rv)
			log_errot(token, "acquire_token lvb size %d memalign error %d",
				  token->disks[0].sector_size, rv);
		else
			r->lvb = iobuf;
	}

 retry:
	memset(&leader, 0, sizeof(struct leader_record));

	rv = acquire_disk(task, token, acquire_lver, new_num_hosts, &leader);

	if (rv == SANLK_ACQUIRE_IDLIVE || rv == SANLK_ACQUIRE_OWNED || rv == SANLK_ACQUIRE_OTHER) {
		/*
		 * Another host owns the lease.  They may be holding for
		 * only a short time while getting a shared lease.
		 * Multiple parallel sh requests can fail because
		 * the lease is briefly held in ex mode.  The ex
		 * holder sets SHORT_HOLD in the leader record to
		 * indicate that it's only held for a short time
		 * while acquiring a shared lease.  A retry will
		 * probably succeed.
		 */
		if ((token->acquire_flags & SANLK_RES_SHARED) && (leader.flags & LFL_SHORT_HOLD)) {
			if (sh_retries++ < com.sh_retries) {
				int us = get_rand(0, 1000000);
				log_token(token, "acquire_token sh_retry %d %d", rv, us);
				usleep(us);
				goto retry;
			}
			/* zero r->leader means not owned and release will just close */
			release_token_opened(task, token);
			return SANLK_ACQUIRE_SHRETRY;
		}
		if (com.quiet_fail)
			log_token(token, "acquire_token held error %d", rv);
		else
			log_errot(token, "acquire_token held error %d", rv);
		/* zero r->leader means not owned and release will just close */
		release_token_opened(task, token);
		return rv;
	}

	if (rv < 0 && !(token->flags & T_RETRACT_PAXOS)) {
		log_errot(token, "acquire_token disk error %d", rv);
		r->flags &= ~R_SHARED;
		/* zero r->leader means not owned and release will just close */
		release_token_opened(task, token);
		return rv;
	}

	if (rv < 0 && (token->flags & T_RETRACT_PAXOS)) {
		/*
		 * We might own the lease, we don't know, so we need to try to
		 * release on disk to avoid possibly having an orphan lease on disk.
		 */
		log_errot(token, "acquire_token disk error %d RETRACT_PAXOS", rv);
		r->flags &= ~R_SHARED;
		r->flags |= R_ERASE_ALL;
		memcpy(&r->leader, &leader, sizeof(struct leader_record));
		release_token_opened(task, token);
		return rv;
	}

	memcpy(&r->leader, &leader, sizeof(struct leader_record));

	/* copy lver into token because inquire looks there for it */
	if (!(token->acquire_flags & SANLK_RES_SHARED))
		token->r.lver = leader.lver;

	/*
	 * acquiring shared lease, so we set SHARED in our mode_block
	 * and release the leader owner.
	 */

	if (token->acquire_flags & SANLK_RES_SHARED) {
		rv = set_mode_block(task, token, token->host_id,
				    token->host_generation, MBLOCK_SHARED);
		if (rv < 0) {
			log_errot(token, "acquire_token sh set_mode_block error %d", rv);
			r->flags &= ~R_SHARED;
			r->flags |= R_UNDO_SHARED;
			release_token_opened(task, token);
			return rv;
		}

		/* the token is kept, the paxos lease is released but with shared set */

		rv = release_disk(task, token, NULL, &leader);
		if (rv < 0) {
			log_errot(token, "acquire_token sh release_disk error %d", rv);
			r->flags &= ~R_SHARED;
			r->flags |= R_UNDO_SHARED;
			release_token_opened(task, token);
			return rv;
		}

		/* normal exit case for successful acquire sh */
		goto out;
	}

	/*
	 * paxos_lease_acquire() calls check_mode_block() which increments
	 * token->shared_count when it finds a mode block with SHARED set.
	 * Zero shared_count means no one holds it shared, so we're done.
	 * Normal exit case for successful acquire ex.
	 */
	if (!token->shared_count) {
		goto out;
	}

	/*
	 * acquiring normal ex lease, other hosts have it shared.
	 * check if those other hosts are alive or dead (clear any that are dead).
	 */

	/*
	 * paxos_lease_acquire() counted some SHARED mode blocks.
	 * Here we check if they are held by live hosts.  If a host
	 * with SHARED mb is dead, we clear it, otherwise it's alive
	 * and we count it in live_count.
	 */
	rv = clear_dead_shared(task, token, leader.num_hosts, &live_count);
	if (rv < 0) {
		log_errot(token, "acquire_token clear_dead_shared error %d", rv);
		release_token_opened(task, token);
		return rv;
	}

	/*
	 * acquiring normal ex lease, other hosts have it shared and are alive.
	 * normal exit case for acquire ex that failed due to existing sh lock.
	 */

	if (live_count) {
		rv = release_token_opened(task, token);
		if (rv < 0) {
			log_errot(token, "acquire_token live_count release error %d", rv);
			return rv;
		}
		return -EAGAIN;
	}

 out:
	if (cmd_flags & SANLK_ACQUIRE_LVB) {
		rv = read_lvb_block(task, token);
		if (rv < 0) {
			/* TODO: we should probably notify the caller somehow about
			   lvb read/write independent of the lease results. */
			log_errot(token, "acquire_token read_lvb error %d", rv);
		}
	}

	close_disks(token->disks, token->r.num_disks);

	pthread_mutex_lock(&resource_mutex);
	list_move(&r->list, &resources_held);
	pthread_mutex_unlock(&resource_mutex);

	return SANLK_OK;
}

int request_token(struct task *task, struct token *token, uint32_t force_mode,
		  uint64_t *owner_id, int next_lver)
{
	struct leader_record leader;
	struct request_record req;
	int rv;

	memset(&req, 0, sizeof(req));

	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		log_errot(token, "request_token open error %d", rv);
		return rv;
	}

	if (!token->acquire_lver && !force_mode)
		goto req_read;

	rv = paxos_lease_leader_read(task, token, &leader, "request");
	if (rv < 0)
		goto out;

	if (leader.timestamp == LEASE_FREE) {
		*owner_id = 0;
		rv = SANLK_OK;
		goto out;
	}

	*owner_id = leader.owner_id;

	if (!token->acquire_lver && next_lver)
		token->acquire_lver = leader.lver + 1;

	if (leader.lver >= token->acquire_lver) {
		rv = SANLK_REQUEST_OLD;
		goto out;
	}

 req_read:
	rv = paxos_lease_request_read(task, token, &req);
	if (rv < 0)
		goto out;

	if (req.magic != REQ_DISK_MAGIC) {
		rv = SANLK_REQUEST_MAGIC;
		goto out;
	}

	if ((req.version & 0xFFFF0000) != REQ_DISK_VERSION_MAJOR) {
		rv = SANLK_REQUEST_VERSION;
		goto out;
	}

	if (!token->acquire_lver && !force_mode)
		goto req_write;

	/* > instead of >= so multiple hosts can request the same
	   version at once and all succeed */

	if (req.lver > token->acquire_lver) {
		rv = SANLK_REQUEST_LVER;
		goto out;
	}

 req_write:
	req.version = REQ_DISK_VERSION_MAJOR | REQ_DISK_VERSION_MINOR;
	req.lver = token->acquire_lver;
	req.force_mode = force_mode;

	rv = paxos_lease_request_write(task, token, &req);
 out:
	close_disks(token->disks, token->r.num_disks);

	log_debug("request_token rv %d owner %llu lver %llu mode %u",
		  rv, (unsigned long long)*owner_id,
		  (unsigned long long)req.lver, req.force_mode);

	return rv;
}

static int examine_token(struct task *task, struct token *token,
			 struct request_record *req_out)
{
	struct request_record req;
	int rv;

	memset(&req, 0, sizeof(req));

	rv = paxos_lease_request_read(task, token, &req);
	if (rv < 0)
		goto out;

	if (req.magic != REQ_DISK_MAGIC) {
		rv = SANLK_REQUEST_MAGIC;
		goto out;
	}

	if ((req.version & 0xFFFF0000) != REQ_DISK_VERSION_MAJOR) {
		rv = SANLK_REQUEST_VERSION;
		goto out;
	}

	memcpy(req_out, &req, sizeof(struct request_record));
 out:
	log_debug("examine_token rv %d lver %llu mode %u",
		  rv, (unsigned long long)req.lver, req.force_mode);

	return rv;
}

static void do_request(struct token *tt, int pid, uint32_t force_mode)
{
	char killpath[SANLK_HELPER_PATH_LEN];
	char killargs[SANLK_HELPER_ARGS_LEN];
	struct helper_msg hm;
	struct resource *r;
	uint32_t flags;
	int rv, found = 0;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(tt, &resources_held);
	if (r && r->pid == pid) {
		found = 1;
		flags = r->flags;
		memcpy(killpath, r->killpath, SANLK_HELPER_PATH_LEN);
		memcpy(killargs, r->killargs, SANLK_HELPER_ARGS_LEN);
	}
	pthread_mutex_unlock(&resource_mutex);

	if (!found) {
		log_error("do_request pid %d %.48s:%.48s not found",
			   pid, tt->r.lockspace_name, tt->r.name);
		return;
	}

	log_debug("do_request %d flags %x %.48s:%.48s",
		  pid, flags, tt->r.lockspace_name, tt->r.name);

	if (helper_kill_fd == -1) {
		log_error("do_request %d no helper fd", pid);
		return;
	}

	memset(&hm, 0, sizeof(hm));

	if (force_mode == SANLK_REQ_FORCE) {
		hm.type = HELPER_MSG_KILLPID;
		hm.pid = pid;
		hm.sig = (flags & R_RESTRICT_SIGKILL) ? SIGTERM : SIGKILL;
	} else if (force_mode == SANLK_REQ_GRACEFUL) {
		if (killpath[0]) {
			hm.type = HELPER_MSG_RUNPATH;
			memcpy(hm.path, killpath, SANLK_HELPER_PATH_LEN);
			memcpy(hm.args, killargs, SANLK_HELPER_ARGS_LEN);
		} else {
			hm.type = HELPER_MSG_KILLPID;
			hm.pid = pid;
			hm.sig = (flags & R_RESTRICT_SIGTERM) ? SIGKILL : SIGTERM;
		}
	} else {
		log_error("do_request %d unknown force_mode %d",
			  pid, force_mode);
		return;
	}

 retry:
	rv = write(helper_kill_fd, &hm, sizeof(hm));
	if (rv == -1 && errno == EINTR)
		goto retry;

	if (rv == -1)
		log_error("do_request %d helper write error %d",
			  pid, errno);
}

int set_resource_examine(char *space_name, char *res_name)
{
	struct resource *r;
	int count = 0;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry(r, &resources_held, list) {
		if (strncmp(r->r.lockspace_name, space_name, NAME_ID_SIZE))
			continue;
		if (res_name && strncmp(r->r.name, res_name, NAME_ID_SIZE))
			continue;
		r->flags |= R_THREAD_EXAMINE;
		resource_thread_work = 1;
		resource_thread_work_examine = 1;
		count++;
	}
	if (count)
		pthread_cond_signal(&resource_cond);
	pthread_mutex_unlock(&resource_mutex);

	return count;
}

/*
 * resource_thread
 * - on-disk lease release for pid's that exit without doing release
 * - on-disk lease release for which release_token had transient i/o error
 * - examines request blocks of resources
 */

static struct resource *find_resource_thread(struct list_head *head, uint32_t flag)
{
	struct resource *r;
	uint64_t now = monotime();

	list_for_each_entry(r, head, list) {
		if (!(r->flags & flag))
			continue;

		if (flag & R_THREAD_EXAMINE)
			return r;

		if (now >= r->thread_release_retry)
			return r;
	}
	return NULL;
}

/*
 * When release_token is called from a context where it cannot block by doing
 * disk io, the token itself is released, but the struct resource is passed to
 * the resource_thread to do the on-disk operations.
 *
 * Also, if release_token gets an io timeout during the disk operations, it
 * removes the token, but passes the struct resource to the resource_thread
 * to retry the on-disk release operations.  It doesn't want to leave a
 * potentially locked lease on disk simply due to a transient io error.
 *
 * This does this non-token related on-disk release operations.  It uses
 * a fake token emulating the original because the paxos layer wants that.
 *
 * As long as the on-disk release fails due to io timeouts, the struct resource
 * is kept and the on-disk release retried.  If another, non-timeout error occurs,
 * we give up and delete/free the struct resource.
 */

static void resource_thread_release(struct task *task, struct resource *r, struct token *token)
{
	struct leader_record leader;
	struct space_info spi;
	uint32_t r_flags;
	int rv = 0;

	rv = open_disks_fd(token->disks, token->r.num_disks);
	if (rv < 0) {
		log_errot(token, "release async open error %d", rv);
		goto out;
	}

	/* The lockspace may fail after the resource was transferred to the
	   resource_thread, so we need to check here if if that's the case. */

	rv = lockspace_info(token->r.lockspace_name, &spi);
	if (rv < 0 || spi.killing_pids) {
		rv = -1;
		goto out_close;
	}

	r_flags = r->flags;

	if (r_flags & R_ERASE_ALL) {
		rv = paxos_erase_dblock(task, token, token->host_id);
		if (rv < 0) {
			log_errot(token, "release async erase_dblock error %d r_flags %x",
				  rv, r_flags);
			goto out_close;
		}
		log_token(token, "release async erase dblock done");

		/* Even when acquire did not get far enough to get a copy of the
		   leader (!lver), we still want to try to release the leader
		   in case we own it from another host committing our dblock. */

		if (!r->leader.lver)
			rv = paxos_lease_release(task, token, NULL, NULL, &leader);
		else
			rv = paxos_lease_release(task, token, NULL, &r->leader, &leader);

		/* want to see this result in sanlock.log but not worry people with error */
		log_level(0, token->token_id, NULL, LOG_WARNING,
			  "release async erase leader lver %llu rv %d",
			  (unsigned long long)r->leader.lver, rv);

		goto out_close;
	}

	if ((r_flags & R_SHARED) || (r_flags & R_UNDO_SHARED)) {
		rv = set_mode_block(task, token, token->host_id, 0, 0);
		if (rv < 0) {
			log_errot(token, "release async set_mode_block error %d r_flags %x",
				  rv, r_flags);
			goto out_close;
		}
	}

	if (!(r_flags & R_SHARED) || (r_flags & R_UNDO_SHARED)) {
		if (r_flags & R_LVB_WRITE_RELEASE) {
			rv = write_lvb_block(task, r, token);
			if (!rv)
				r->flags &= ~R_LVB_WRITE_RELEASE;
			else
				log_errot(token, "release async write_lvb error %d", rv);
		}

		rv = release_disk(task, token, NULL, &r->leader);
		if (rv < 0) {
			log_errot(token, "release async disk error %d r_flags %x lver %llu",
				  rv, r_flags, (unsigned long long)r->leader.lver);
			goto out_close;
		}
	}

	log_token(token, "release async done %d r_flags %x", rv, r_flags);

 out_close:
	close_disks(token->disks, token->r.num_disks);

 out:
	pthread_mutex_lock(&resource_mutex);
	if (rv == SANLK_AIO_TIMEOUT) {
		r->flags |= R_THREAD_RELEASE;
	} else {
		list_del(&r->list);
	}
	pthread_mutex_unlock(&resource_mutex);

	if (rv != SANLK_AIO_TIMEOUT)
		free_resource(r);
}

static void resource_thread_examine(struct task *task, struct token *tt, int pid, uint64_t lver)
{
	struct request_record req;
	int rv;

	rv = open_disks_fd(tt->disks, tt->r.num_disks);
	if (rv < 0) {
		log_errot(tt, "examine open error %d", rv);
		return;
	}

	rv = examine_token(task, tt, &req);

	close_disks(tt->disks, tt->r.num_disks);

	if (rv != SANLK_OK)
		return;

	if (!req.force_mode || !req.lver)
		return;

	if (req.lver <= lver) {
		log_debug("examine req lver %llu our lver %llu",
			  (unsigned long long)req.lver, (unsigned long long)lver);
		return;
	}

	if (req.force_mode) {
		do_request(tt, pid, req.force_mode);
	} else {
		log_error("req force_mode %u unknown", req.force_mode);
	}
}

struct recv_he {
	struct list_head list;
	uint32_t space_id;
	uint64_t from_host_id;
	uint64_t from_generation;
	struct sanlk_host_event he;
};

void add_host_event(uint32_t space_id, struct sanlk_host_event *he,
		    uint64_t from_host_id, uint64_t from_generation)
{
	struct recv_he *rhe;

	rhe = malloc(sizeof(struct recv_he));
	if (!rhe) {
		log_error("add_host_event no mem");
		return;
	}

	memset(rhe, 0, sizeof(struct recv_he));
	memcpy(&rhe->he, he, sizeof(struct sanlk_host_event));
	rhe->space_id = space_id;
	rhe->from_host_id = from_host_id;
	rhe->from_generation = from_generation;

	pthread_mutex_lock(&resource_mutex);
	list_add_tail(&rhe->list, &host_events);
	resource_thread_work = 1;
	pthread_cond_signal(&resource_cond);
	pthread_mutex_unlock(&resource_mutex);
}

static struct recv_he *find_host_event(void)
{
	if (list_empty(&host_events))
		return NULL;
	return list_first_entry(&host_events, struct recv_he, list);
}

static void *resource_thread(void *arg GNUC_UNUSED)
{
	struct task task;
	struct resource *r;
	struct token *tt = NULL;
	struct recv_he *rhe;
	uint64_t lver;
	int pid, tt_len;

	memset(&task, 0, sizeof(struct task));
	setup_task_aio(&task, main_task.use_aio, RESOURCE_AIO_CB_SIZE);
	sprintf(task.name, "%s", "resource");

	/* a fake/tmp token struct we copy necessary res info into,
	   because other functions take a token struct arg */

	tt_len = sizeof(struct token) + (SANLK_MAX_DISKS * sizeof(struct sync_disk));
	tt = malloc(tt_len);
	if (!tt) {
		log_error("resource_thread tt malloc error");
		goto out;
	}

	while (1) {
		pthread_mutex_lock(&resource_mutex);
		while (!resource_thread_work) {
			if (resource_thread_stop) {
				pthread_mutex_unlock(&resource_mutex);
				goto out;
			}
			pthread_cond_wait(&resource_cond, &resource_mutex);
		}

		rhe = find_host_event();
		if (rhe) {
			list_del(&rhe->list);
			pthread_mutex_unlock(&resource_mutex);
			send_event_callbacks(rhe->space_id, rhe->from_host_id, rhe->from_generation, &rhe->he);
			free(rhe);
			continue;
		}

		/* FIXME: it's not nice how we copy a bunch of stuff
		 * from token to r so that we can later copy it back from
		 * r into a temp token.  The whole duplication of stuff
		 * between token and r would be nice to clean up. */

		memset(tt, 0, tt_len);
		tt->disks = (struct sync_disk *)&tt->r.disks[0];

		r = find_resource_thread(&resources_rem, R_THREAD_RELEASE);
		if (r) {
			memcpy(&tt->r, &r->r, sizeof(struct sanlk_resource));
			copy_disks(&tt->r.disks, &r->r.disks, r->r.num_disks);
			tt->host_id = r->host_id;
			tt->host_generation = r->host_generation;
			tt->token_id = r->release_token_id;
			tt->io_timeout = r->io_timeout;

			/*
			 * Set the time after which we should try to release this
			 * resource again if this current attempt times out.
			 */
			if (!r->thread_release_retry)
				r->thread_release_retry = monotime() + r->io_timeout;
			else
				r->thread_release_retry = monotime() + (r->io_timeout * 2);

			r->flags &= ~R_THREAD_RELEASE;
			pthread_mutex_unlock(&resource_mutex);

			resource_thread_release(&task, r, tt);
			continue;
		}

		/*
		 * We don't want to search all of resource_held each time
		 * we are woken unless we know there is something to examine.
		 */
		if (!resource_thread_work_examine)
			goto find_done;

		r = find_resource_thread(&resources_held, R_THREAD_EXAMINE);
		if (r) {
			/* make copies of things we need because we can't use r
			   once we unlock the mutex since it could be released */

			memcpy(&tt->r, &r->r, sizeof(struct sanlk_resource));
			copy_disks(&tt->r.disks, &r->r.disks, r->r.num_disks);
			tt->host_id = r->host_id;
			tt->host_generation = r->host_generation;
			tt->io_timeout = r->io_timeout;
			pid = r->pid;
			lver = r->leader.lver;

			r->flags &= ~R_THREAD_EXAMINE;
			pthread_mutex_unlock(&resource_mutex);

			resource_thread_examine(&task, tt, pid, lver);
			continue;
		}

 find_done:
		resource_thread_work = 0;
		resource_thread_work_examine = 0;
		pthread_mutex_unlock(&resource_mutex);
	}
 out:
	if (tt)
		free(tt);
	close_task_aio(&task);
	return NULL;
}

int release_orphan(struct sanlk_resource *res)
{
	struct resource *r, *safe;
	int count = 0;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry_safe(r, safe, &resources_orphan, list) {
		if (strncmp(r->r.lockspace_name, res->lockspace_name, NAME_ID_SIZE))
			continue;

		if (!res->name[0] || !strncmp(r->r.name, res->name, NAME_ID_SIZE)) {
			log_debug("release orphan %.48s:%.48s", r->r.lockspace_name, r->r.name);
			r->flags |= R_THREAD_RELEASE;
			list_move(&r->list, &resources_rem);
			count++;
		}
	}

	if (count) {
		resource_thread_work = 1;
		pthread_cond_signal(&resource_cond);
	}
	pthread_mutex_unlock(&resource_mutex);

	return count;
}

void purge_resource_orphans(char *space_name)
{
	struct resource *r, *safe;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry_safe(r, safe, &resources_orphan, list) {
		if (strncmp(r->r.lockspace_name, space_name, NAME_ID_SIZE))
			continue;
		log_debug("purge orphan %.48s:%.48s", r->r.lockspace_name, r->r.name);
		list_del(&r->list);
		free_resource(r);
	}
	pthread_mutex_unlock(&resource_mutex);
}

/*
 * This is called by the main_loop once a second during normal operation.
 * The resources_rem list should normally be empty, so this does nothing.
 * This is needed to wake up the resource_thread to retry release operations
 * that had timed out previously and need to be retried.
 */

void free_resources(void)
{
	pthread_mutex_lock(&resource_mutex);
	if (!list_empty(&resources_rem) && !resource_thread_work) {
		resource_thread_work = 1;
		pthread_cond_signal(&resource_cond);
	}
	pthread_mutex_unlock(&resource_mutex);
}

int setup_token_manager(void)
{
	int rv;

	pthread_mutex_init(&resource_mutex, NULL);
	pthread_cond_init(&resource_cond, NULL);
	INIT_LIST_HEAD(&resources_add);
	INIT_LIST_HEAD(&resources_rem);
	INIT_LIST_HEAD(&resources_held);
	INIT_LIST_HEAD(&resources_orphan);
	INIT_LIST_HEAD(&host_events);

	rv = pthread_create(&resource_pt, NULL, resource_thread, NULL);
	if (rv)
		return -1;
	return 0;
}

void close_token_manager(void)
{
	pthread_mutex_lock(&resource_mutex);
	resource_thread_stop = 1;
	pthread_cond_signal(&resource_cond);
	pthread_mutex_unlock(&resource_mutex);
	pthread_join(resource_pt, NULL);
}

