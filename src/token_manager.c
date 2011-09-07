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
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>

#include "sanlock_internal.h"
#include "diskio.h"
#include "log.h"
#include "paxos_lease.h"
#include "token_manager.h"
#include "task.h"
#include "host_id.h"

static struct list_head resources;
static struct list_head dispose_resources;
static pthread_mutex_t resource_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t resource_cond = PTHREAD_COND_INITIALIZER;
static pthread_t resource_pt;
static int resource_thread_stop;
static int resource_examine;

#define R_EXAMINE    0x00000001

struct resource {
	struct list_head list;
	struct token *token;
	int pid;
	uint32_t flags;
	uint64_t lver;
	struct sanlk_resource r;
};

int set_resource_examine(char *space_name, char *res_name)
{
	struct resource *r;
	int count = 0;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry(r, &resources, list) {
		if (strncmp(r->r.lockspace_name, space_name, NAME_ID_SIZE))
			continue;
		if (res_name && strncmp(r->r.name, res_name, NAME_ID_SIZE))
			continue;
		r->flags |= R_EXAMINE;
		resource_examine = 1;
		count++;
	}
	if (count)
		pthread_cond_signal(&resource_cond);
	pthread_mutex_unlock(&resource_mutex);

	return count;
}

static struct resource *find_resource_examine(void)
{
	struct resource *r;

	list_for_each_entry(r, &resources, list) {
		if (r->flags & R_EXAMINE)
			return r;
	}
	return NULL;
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

static void save_resource_lver(struct token *token, uint64_t lver)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(token, &resources);
	if (r)
		r->lver = lver;
	pthread_mutex_unlock(&resource_mutex);

	if (!r)
		log_errot(token, "save_resource_lver no r");

}

int add_resource(struct token *token, int pid)
{
	struct resource *r;
	int rv, disks_len, r_len;

	pthread_mutex_lock(&resource_mutex);

	r = find_resource(token, &resources);
	if (r) {
		if (!com.quiet_fail)
			log_errot(token, "add_resource name exists");
		rv = -EEXIST;
		goto out;
	}

	r = find_resource(token, &dispose_resources);
	if (r) {
		if (!com.quiet_fail)
			log_errot(token, "add_resource disposed");
		rv = -EAGAIN;
		goto out;
	}

	disks_len = token->r.num_disks * sizeof(struct sync_disk);
	r_len = sizeof(struct resource) + disks_len;

	r = malloc(r_len);
	if (!r) {
		rv = -ENOMEM;
		goto out;
	}
	memset(r, 0, r_len);
	memcpy(&r->r, &token->r, sizeof(struct sanlk_resource));
	memcpy(&r->r.disks, &token->r.disks, disks_len);
	r->token = token;
	r->pid = pid;
	list_add_tail(&r->list, &resources);
	rv = 0;
 out:
	pthread_mutex_unlock(&resource_mutex);
	return rv;
}

/* resource_mutex must be held */

static void _del_resource(struct resource *r)
{
	list_del(&r->list);
	free(r);
}

void del_resource(struct token *token)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(token, &resources);
	if (r)
		_del_resource(r);
	pthread_mutex_unlock(&resource_mutex);
}

/* return < 0 on error, 1 on success */

int acquire_token(struct task *task, struct token *token,
		  uint64_t acquire_lver, int new_num_hosts)
{
	struct leader_record leader_ret;
	int rv;
	uint32_t flags = 0;

	if (com.quiet_fail)
		flags |= PAXOS_ACQUIRE_QUIET_FAIL;

	rv = open_disks(token->disks, token->r.num_disks);
	if (!majority_disks(token, rv)) {
		log_errot(token, "acquire open_disk error %s", token->disks[0].path);
		return -ENODEV;
	}

	rv = paxos_lease_acquire(task, token, flags, &leader_ret, acquire_lver,
				 new_num_hosts);

	token->acquire_result = rv;

	/* we could leave this open so release does not have to reopen */
	close_disks(token->disks, token->r.num_disks);

	log_token(token, "acquire rv %d lver %llu at %llu", rv,
		  (unsigned long long)token->leader.lver,
		  (unsigned long long)token->leader.timestamp);

	if (rv < 0)
		return rv;

	save_resource_lver(token, token->leader.lver);

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	token->r.lver = token->leader.lver;
	return rv; /* SANLK_OK */
}

/* return < 0 on error, 1 on success */

int release_token(struct task *task, struct token *token)
{
	struct leader_record leader_ret;
	int rv;

	rv = open_disks_fd(token->disks, token->r.num_disks);
	if (!majority_disks(token, rv)) {
		log_errot(token, "release open_disk error %s", token->disks[0].path);
		return -ENODEV;
	}

	rv = paxos_lease_release(task, token, &token->leader, &leader_ret);

	token->release_result = rv;

	close_disks(token->disks, token->r.num_disks);

	log_token(token, "release rv %d", rv);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return rv; /* SANLK_OK */
}

int request_token(struct task *task, struct token *token, uint32_t force_mode,
		  uint64_t *owner_id)
{
	struct leader_record leader;
	struct request_record req;
	int rv;

	memset(&req, 0, sizeof(req));

	rv = open_disks(token->disks, token->r.num_disks);
	if (!majority_disks(token, rv)) {
		log_debug("request open_disk error %s", token->disks[0].path);
		return -ENODEV;
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

	log_debug("request rv %d owner %llu lver %llu mode %u",
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

	rv = open_disks(token->disks, token->r.num_disks);
	if (!majority_disks(token, rv)) {
		log_debug("request open_disk error %s", token->disks[0].path);
		return -ENODEV;
	}

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
	close_disks(token->disks, token->r.num_disks);

	log_debug("examine rv %d lver %llu mode %u",
		  rv, (unsigned long long)req.lver, req.force_mode);

	return rv;
}

/*
 * - releases tokens of pid's that die
 * - examines request blocks of resources
 */

static void *resource_thread(void *arg GNUC_UNUSED)
{
	struct task task;
	struct resource *r;
	struct token *token, *tt = NULL;
	struct request_record req;
	uint64_t lver;
	int rv, j, pid, tt_len;

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
	memset(tt, 0, tt_len);
	tt->disks = (struct sync_disk *)&tt->r.disks[0];

	while (1) {
		pthread_mutex_lock(&resource_mutex);
		while (list_empty(&dispose_resources) && !resource_examine) {
			if (resource_thread_stop) {
				pthread_mutex_unlock(&resource_mutex);
				goto out;
			}
			pthread_cond_wait(&resource_cond, &resource_mutex);
		}

		if (!list_empty(&dispose_resources)) {
			r = list_first_entry(&dispose_resources, struct resource, list);
			pthread_mutex_unlock(&resource_mutex);

			token = r->token;
			release_token(&task, token);

			/* we don't want to remove r from dispose_list until after the
		   	   lease is released because we don't want a new token for
		   	   the same resource to be added and attempt to acquire
		   	   the lease until after it's been released */

			pthread_mutex_lock(&resource_mutex);
			_del_resource(r);
			pthread_mutex_unlock(&resource_mutex);
			free(token);

		} else if (resource_examine) {
			r = find_resource_examine();
			if (!r) {
				resource_examine = 0;
				pthread_mutex_unlock(&resource_mutex);
				continue;
			}
			r->flags &= ~R_EXAMINE;

			/* we can't safely access r->token here, and
			   r may be freed after we release mutex, so copy
			   everything we need before unlocking mutex */

			pid = r->pid;
			lver = r->lver;
			memcpy(&tt->r, &r->r, sizeof(struct sanlk_resource));
			memcpy(&tt->r.disks, &r->r.disks, r->r.num_disks * sizeof(struct sync_disk));
			pthread_mutex_unlock(&resource_mutex);

			for (j = 0; j < tt->r.num_disks; j++) {
				tt->disks[j].sector_size = 0;
				tt->disks[j].fd = -1;
			}

			rv = examine_token(&task, tt, &req);

			if (rv != SANLK_OK)
				continue;

			if (!req.force_mode || !req.lver)
				continue;

			if (req.lver <= lver) {
				log_debug("examine req lver %llu our lver %llu",
					  (unsigned long long)req.lver,
					  (unsigned long long)lver);
				continue;
			}

			if (req.force_mode == SANLK_REQ_KILL_PID) {
				/* look up r again to check it still exists and
				   pid is same? */

				log_error("req_kill_pid %d %.48s:%.48s", pid,
					  tt->r.lockspace_name, tt->r.name);
				kill(pid, SIGKILL);
			} else {
				log_error("req force_mode unknown %u", req.force_mode);
			}
		}
	}
 out:
	if (tt)
		free(tt);
	close_task_aio(&task);
	return NULL;
}

void release_token_async(struct token *token)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(token, &resources);
	if (r) {
		/* assert r->token == token ? */

		if (token->space_dead || (token->acquire_result != SANLK_OK)) {
			_del_resource(r);
			free(token);
		} else {
			list_move(&r->list, &dispose_resources);
			pthread_cond_signal(&resource_cond);
		}
	}
	pthread_mutex_unlock(&resource_mutex);
}

int setup_token_manager(void)
{
	int rv;

	INIT_LIST_HEAD(&resources);
	INIT_LIST_HEAD(&dispose_resources);

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

