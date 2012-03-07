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
#include "log.h"
#include "paxos_lease.h"
#include "lockspace.h"
#include "resource.h"
#include "task.h"
#include "mode_block.h"

/* from cmd.c */
void send_state_resource(int fd, struct resource *r, const char *list_name, int pid, uint32_t token_id);

/* from main.c */
int get_rand(int a, int b);

static pthread_t resource_pt;
static int resource_thread_stop;
static int resource_thread_work;
static struct list_head resources_held;
static struct list_head resources_add;
static struct list_head resources_rem;
static pthread_mutex_t resource_mutex;
static pthread_cond_t resource_cond;


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
	pthread_mutex_unlock(&resource_mutex);
}

/* return 1 (is alive) to force a failure if we don't have enough
   knowledge to know it's really not alive.  Later we could have this sit and
   wait (like paxos_lease_acquire) until we have waited long enough or have
   enough knowledge to say it's safely dead (unless of course we find it is
   alive while waiting) */

static int host_live(struct task *task, char *lockspace_name, uint64_t host_id, uint64_t gen)
{
	struct host_status hs;
	uint64_t now;
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

	if (!hs.last_live && (now - hs.first_check > task->host_dead_seconds)) {
		log_debug("host_live %llu %llu no first_check %llu",
			  (unsigned long long)host_id, (unsigned long long)gen,
			  (unsigned long long)hs.first_check);
		return 0;
	}

	if (hs.last_live && (now - hs.last_live > task->host_dead_seconds)) {
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

void check_mode_block(struct token *token, int q, char *dblock)
{
	struct mode_block *mb;

	mb = (struct mode_block *)(dblock + MBLOCK_OFFSET);

	if (mb->flags & MBLOCK_SHARED) {
		set_id_bit(q + 1, token->shared_bitmap, NULL);
		token->shared_count++;
	}
}

static int set_mode_block(struct task *task, struct token *token,
			  uint64_t host_id, uint64_t gen, uint32_t flags)
{
	struct sync_disk *disk;
	struct mode_block *mb;
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

		rv = read_iobuf(disk->fd, offset, iobuf, iobuf_len, task);
		if (rv < 0)
			break;

		mb = (struct mode_block *)(iobuf + MBLOCK_OFFSET);
		mb->flags = flags;
		mb->generation = gen;

		rv = write_iobuf(disk->fd, offset, iobuf, iobuf_len, task);
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
	struct mode_block *mb;
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

		rv = read_iobuf(disk->fd, offset, iobuf, iobuf_len, task);
		if (rv < 0)
			break;

		mb = (struct mode_block *)(iobuf + MBLOCK_OFFSET);

		if (!(mb->flags & MBLOCK_SHARED))
			continue;

		if (!max || mb->generation > max)
			max = mb->generation;
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
	int i, rv, live = 0;

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

		if (host_live(task, token->r.lockspace_name, host_id, max_gen)) {
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
			 struct leader_record *leader)
{
	struct leader_record leader_tmp;
	int rv;

	rv = paxos_lease_release(task, token, leader, &leader_tmp);

	log_token(token, "release_disk rv %d", rv);

	if (rv < 0)
		return rv;

	memcpy(leader, &leader_tmp, sizeof(struct leader_record));
	return rv; /* SANLK_OK */
}

static int _release_token(struct task *task, struct token *token, int opened, int nodisk)
{
	struct resource *r = token->resource;
	uint64_t lver;
	int last_token = 0;
	int rv;

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
	pthread_mutex_unlock(&resource_mutex);

	if ((r->flags & R_SHARED) && !last_token) {
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

	if (!lver) {
		/* never acquired on disk so no need to release on disk */
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
			/* it's not terrible if we can't do the disk release */
			rv = SANLK_OK;
			goto out;
		}
	}

	if (r->flags & R_SHARED) {
		rv = set_mode_block(task, token, token->host_id, 0, 0);
	} else {
		rv = release_disk(task, token, &r->leader);
	}

	close_disks(token->disks, token->r.num_disks);

 out:
	if (rv < 0)
		log_errot(token, "release_token rv %d flags %x lver %llu o %d n %d",
			  rv, r->flags, (unsigned long long)lver, opened, nodisk);
	else
		log_token(token, "release_token flags %x", r->flags);

	pthread_mutex_lock(&resource_mutex);
	list_del(&r->list);
	pthread_mutex_unlock(&resource_mutex);
	free(r);

	return rv;
}

static int release_token_nodisk(struct task *task, struct token *token)
{
	return _release_token(task, token, 0, 1);
}

static int release_token_opened(struct task *task, struct token *token)
{
	return _release_token(task, token, 1, 0);
}

int release_token(struct task *task, struct token *token)
{
	return _release_token(task, token, 0, 0);
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
		if ((token->flags & T_LS_DEAD) || !r->leader.lver) {
			/* don't bother trying to release if the lockspace
			   is dead (release will probably fail), or the
			   lease wasn't never acquired */
			list_del(&r->list);
			free(r);
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
	}

	return r;
}

int acquire_token(struct task *task, struct token *token)
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

	r = new_resource(token);
	if (!r) {
		pthread_mutex_unlock(&resource_mutex);
		return -ENOMEM;
	}

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

 retry:
	memset(&leader, 0, sizeof(struct leader_record));

	rv = acquire_disk(task, token, acquire_lver, new_num_hosts, &leader);
	if (rv < 0) {
		if ((token->acquire_flags & SANLK_RES_SHARED) &&
		    (leader.flags & LFL_SHORT_HOLD)) {
			/*
			 * Multiple parallel sh requests can fail because
			 * the lease is briefly held in ex mode.  The ex
			 * holder sets SHORT_HOLD in the leader record to
			 * indicate that it's only held for a short time
			 * while acquiring a shared lease.  A retry will
			 * probably succeed.
			 */
			if (sh_retries++ < com.sh_retries) {
				int us = get_rand(0, 1000000);
				log_token(token, "acquire_token sh_retry %d %d", rv, us);
				usleep(us);
				goto retry;
			}
			rv = SANLK_ACQUIRE_SHRETRY;
		}
		release_token_opened(task, token);
		return rv;
	}

	memcpy(&r->leader, &leader, sizeof(struct leader_record));

	if (token->acquire_flags & SANLK_RES_SHARED) {
		rv = set_mode_block(task, token, token->host_id,
				    token->host_generation, MBLOCK_SHARED);
		if (rv < 0) {
			release_token_opened(task, token);
			return rv;
		} else {
			release_disk(task, token, &leader);
			/* the token is kept, the paxos lease is released but with shared set */
			goto out;
		}
	}

	if (!token->shared_count)
		goto out;

	rv = clear_dead_shared(task, token, leader.num_hosts, &live_count);
	if (rv < 0) {
		release_token_opened(task, token);
		return rv;
	}

	if (live_count) {
		/* a live host with a sh lock exists */
		release_token_opened(task, token);
		return -EAGAIN;
	}

 out:
	close_disks(token->disks, token->r.num_disks);

	pthread_mutex_lock(&resource_mutex);
	list_move(&r->list, &resources_held);
	pthread_mutex_unlock(&resource_mutex);

	return SANLK_OK;
}

int request_token(struct task *task, struct token *token, uint32_t force_mode,
		  uint64_t *owner_id)
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

static void do_req_kill_pid(struct token *tt, int pid)
{
	struct resource *r;
	uint32_t flags;
	int found = 0;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(tt, &resources_held);
	if (r && r->pid == pid) {
		found = 1;
		flags = r->flags;
	}
	pthread_mutex_unlock(&resource_mutex);

	if (!found) {
		log_error("req pid %d %.48s:%.48s not found",
			   pid, tt->r.lockspace_name, tt->r.name);
		return;
	}

	log_debug("do_req_kill_pid %d flags %x %.48s:%.48s",
		  pid, flags, tt->r.lockspace_name, tt->r.name);

	/* TODO: share code with kill_pids() to gradually
	 * escalate from killscript, SIGTERM, SIGKILL */

	kill(pid, SIGTERM);

	if (flags & R_RESTRICT_SIGKILL)
		return;

	sleep(1);
	kill(pid, SIGKILL);
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
		count++;
	}
	if (count)
		pthread_cond_signal(&resource_cond);
	pthread_mutex_unlock(&resource_mutex);

	return count;
}

/*
 * resource_thread
 * - releases tokens of pid's that die
 * - examines request blocks of resources
 */

static struct resource *find_resource_flag(struct list_head *head, uint32_t flag)
{
	struct resource *r;

	list_for_each_entry(r, head, list) {
		if (r->flags & flag)
			return r;
	}
	return NULL;
}

static void resource_thread_release(struct task *task, struct resource *r, struct token *tt)
{
	int rv;

	rv = open_disks_fd(tt->disks, tt->r.num_disks);
	if (rv < 0) {
		log_errot(tt, "resource_thread_release open error %d", rv);
		goto out;
	}

	if (r->flags & R_SHARED) {
		set_mode_block(task, tt, tt->host_id, 0, 0);
	} else {
		release_disk(task, tt, &r->leader);
	}

	close_disks(tt->disks, tt->r.num_disks);
 out:
	pthread_mutex_lock(&resource_mutex);
	list_del(&r->list);
	pthread_mutex_unlock(&resource_mutex);
	free(r);
}

static void resource_thread_examine(struct task *task, struct token *tt, int pid, uint64_t lver)
{
	struct request_record req;
	int rv;

	rv = open_disks_fd(tt->disks, tt->r.num_disks);
	if (rv < 0) {
		log_errot(tt, "resource_thread_examine open error %d", rv);
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

	if (req.force_mode == SANLK_REQ_KILL_PID) {
		do_req_kill_pid(tt, pid);
	} else {
		log_error("req force_mode %u unknown", req.force_mode);
	}
}

static void *resource_thread(void *arg GNUC_UNUSED)
{
	struct task task;
	struct resource *r;
	struct token *tt = NULL;
	uint64_t lver;
	int pid, tt_len;

	memset(&task, 0, sizeof(struct task));
	setup_task_timeouts(&task, main_task.io_timeout_seconds);
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

		/* FIXME: it's not nice how we copy a bunch of stuff
		 * from token to r so that we can later copy it back from
		 * r into a temp token.  The whole duplication of stuff
		 * between token and r would be nice to clean up. */

		memset(tt, 0, tt_len);
		tt->disks = (struct sync_disk *)&tt->r.disks[0];

		r = find_resource_flag(&resources_rem, R_THREAD_RELEASE);
		if (r) {
			memcpy(&tt->r, &r->r, sizeof(struct sanlk_resource));
			copy_disks(&tt->r.disks, &r->r.disks, r->r.num_disks);
			tt->host_id = r->host_id;
			tt->host_generation = r->host_generation;
			tt->token_id = r->release_token_id;

			r->flags &= ~R_THREAD_RELEASE;
			pthread_mutex_unlock(&resource_mutex);

			resource_thread_release(&task, r, tt);
			continue;
		}

		r = find_resource_flag(&resources_held, R_THREAD_EXAMINE);
		if (r) {
			/* make copies of things we need because we can't use r
			   once we unlock the mutex since it could be released */

			memcpy(&tt->r, &r->r, sizeof(struct sanlk_resource));
			copy_disks(&tt->r.disks, &r->r.disks, r->r.num_disks);
			tt->host_id = r->host_id;
			tt->host_generation = r->host_generation;
			pid = r->pid;
			lver = r->leader.lver;

			r->flags &= ~R_THREAD_EXAMINE;
			pthread_mutex_unlock(&resource_mutex);

			resource_thread_examine(&task, tt, pid, lver);
			continue;
		}

		resource_thread_work = 0;
		pthread_mutex_unlock(&resource_mutex);
	}
 out:
	if (tt)
		free(tt);
	close_task_aio(&task);
	return NULL;
}

int setup_token_manager(void)
{
	int rv;

	pthread_mutex_init(&resource_mutex, NULL);
	pthread_cond_init(&resource_cond, NULL);
	INIT_LIST_HEAD(&resources_add);
	INIT_LIST_HEAD(&resources_rem);
	INIT_LIST_HEAD(&resources_held);

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

