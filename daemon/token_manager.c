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
#include "token_manager.h"

static struct list_head resources;
static struct list_head dispose_resources;
static struct list_head saved_resources;
static pthread_mutex_t resource_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t resource_cond = PTHREAD_COND_INITIALIZER;
static pthread_t release_thread;
static int release_thread_stop;

struct resource {
	struct list_head list;
	char space_name[NAME_ID_SIZE+1];
	char resource_name[NAME_ID_SIZE+1];
	struct token *token;
	struct leader_record leader;
	int pid;
};

static struct resource *find_resource(struct token *token,
				      struct list_head *head)
{
	struct resource *r;

	list_for_each_entry(r, head, list) {
		if (strncmp(r->space_name, token->space_name, NAME_ID_SIZE))
			continue;
		if (strncmp(r->resource_name, token->resource_name, NAME_ID_SIZE))
			continue;
		return r;
	}
	return NULL;
}

void save_resource_leader(struct token *token)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(token, &resources);
	if (r)
		memcpy(&r->leader, &token->leader, sizeof(struct leader_record));
	pthread_mutex_unlock(&resource_mutex);
}

int add_resource(struct token *token, int pid)
{
	struct resource *r;
	int rv;

	pthread_mutex_lock(&resource_mutex);

	r = find_resource(token, &resources);
	if (r) {
		log_errot(token, "add_resource name exists");
		rv = -EEXIST;
		goto out;
	}

	r = find_resource(token, &dispose_resources);
	if (r) {
		log_errot(token, "add_resource disposed");
		rv = -EEXIST;
		goto out;
	}

	r = find_resource(token, &saved_resources);
	if (r) {
		if (r->pid == pid) {
			/* the same pid is allowed to reacquire a resource */
			list_del(&r->list);
			goto add;
		} else {
			/* a different pid may not acquire a resource that
			   was released by an existing (but paused) pid,
			   because the paused pid may resume and expect to
			   reacquire the lease unchanged */
			log_errot(token, "add_resource saved for %d", r->pid);
			rv = -EBUSY;
			goto out;
		}
	}

	r = malloc(sizeof(struct resource));
	if (!r) {
		rv = -ENOMEM;
		goto out;
	}

	memset(r, 0, sizeof(struct resource));
	strncpy(r->space_name, token->space_name, NAME_ID_SIZE);
	strncpy(r->resource_name, token->resource_name, NAME_ID_SIZE);
 add:
	/* leader.ver is the last lver we knew when we last held the lease.
	 * we're sticking it in token->prev_lver just to pass it back to
	 * cmd_acquire, so cmd_acquire can pass it into acquire_token().
	 * (it would probably be less confusing to pass leader.lver back to
	 * cmd_acquire through a function param rather than using a token
	 * field to pass it between functions) */
	token->prev_lver = r->leader.lver;

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

/* resources are kept on the saved list when the token is released for a pid
   that's still running (e.g. vm paused) in case the leases need to be
   reacquired later with the same version (e.g. vm resumed).  r->pid is the
   only pid that will be allowed to reacquire this resource off the
   saved_resources list */

void save_resource(struct token *token)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(token, &resources);
	if (r) {
		r->token = NULL;
		list_move(&r->list, &saved_resources);
	}
	pthread_mutex_unlock(&resource_mutex);
}

void purge_saved_resources(int pid)
{
	struct resource *r, *r2;

	pthread_mutex_lock(&resource_mutex);
	list_for_each_entry_safe(r, r2, &saved_resources, list) {
		if (r->pid == pid) {
			list_del(&r->list);
			free(r);
		}
	}
	pthread_mutex_unlock(&resource_mutex);
}

/* return < 0 on error, 1 on success */

int acquire_token(struct token *token, uint64_t reacquire_lver,
		  int new_num_hosts)
{
	struct leader_record leader_ret;
	int rv;

	rv = paxos_lease_acquire(token, 0, &leader_ret, reacquire_lver,
				 new_num_hosts);

	token->acquire_result = rv;

	log_token(token, "acquire rv %d lver %llu at %llu", rv,
		  (unsigned long long)token->leader.lver,
		  (unsigned long long)token->leader.timestamp);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

int setowner_token(struct token *token)
{
	struct leader_record leader_ret;
	int rv;

	rv = paxos_lease_leader_read(token, &leader_ret);
	if (rv < 0)
		return rv;

	if (memcmp(&token->leader, &leader_ret, sizeof(struct leader_record))) {
		log_errot(token, "setowner leader_read mismatch");
		return -1;
	}

	/* we want the dblocks to reflect a full, proper ownership, so we
	   do the full acquire rather than just writing a new leader_record */

	rv = paxos_lease_acquire(token, 0, &leader_ret, 0, 0);

	token->setowner_result = rv;

	log_token(token, "setowner rv %d lver %llu at %llu", rv,
		  (unsigned long long)token->leader.lver,
		  (unsigned long long)token->leader.timestamp);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

/* return < 0 on error, 1 on success */

int release_token(struct token *token)
{
	struct leader_record leader_ret;
	int rv;

	if (token->leader.owner_id != token->host_id) {
		/* this case occurs on the receiving side of migration, when
		   the local host hasn't become the lease owner (just next_owner),
		   and the pid fails, causing sm to clean up the pid's tokens */
		log_token(token, "release we are not owner");
		return 1;
	}

	rv = paxos_lease_release(token, &token->leader, &leader_ret);

	token->release_result = rv;

	log_token(token, "release rv %d", rv);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

/* migration source: writes leader_record.next_owner_id = target_host_id */

int migrate_token(struct token *token, uint64_t target_host_id)
{
	struct leader_record leader_ret;
	int rv;

	rv = paxos_lease_migrate(token, &token->leader, &leader_ret, target_host_id);

	token->migrate_result = rv;

	log_token(token, "migrate rv %d", rv);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

/* migration target: verifies that the source wrote us as the next_owner_id */

int receive_token(struct token *token, char *opt_str GNUC_UNUSED)
{
	struct leader_record leader_ret;
	int rv;

	rv = paxos_lease_leader_read(token, &leader_ret);
	if (rv < 0)
		return rv;

	/* TODO: opt_str will be an encoding of a bunch of lease state
	 * (full leader_record?) from the migration source. */
#if 0
	/* token->leader is a copy of the leader_record that the source wrote
	   in migrate_token(); it should not have changed between then and when
	   we read it here. */

	if (memcmp(&token->leader, &leader_ret, sizeof(struct leader_record))) {
		log_errot(token, "receive leader_read mismatch");
		return -1;
	}
#endif
	
	/* token->migrate_result is a copy of the paxos_lease_migrate() return
	   value on the source; if it was successful on the source (1), then
	   next_owner_id should equal our_host_id; if the source could not
	   write to the lease, then next_owner_id should be 0, and we'll write
	   next_owner_id = our_host_id for it. */

	if (token->migrate_result == 1) {
		if (leader_ret.next_owner_id != token->host_id) {
			log_errot(token, "receive wrong next_owner %llu",
				  (unsigned long long)leader_ret.next_owner_id);
			return -1;
		}
		goto out;
	}

	/* source failed to migrate this lease, so next_owner_id should still
	   be zero */

	if (leader_ret.next_owner_id != 0) {
		log_errot(token, "receive expect zero next_owner %llu",
			  (unsigned long long)leader_ret.next_owner_id);
		return -1;
	}

	/* TODO: not sure about this */
	/* since the source failed to write next_owner_id to be us, we do it
	   instead */

	return migrate_token(token, token->host_id);

 out:
	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

int create_token(int num_disks, struct token **token_out)
{
	struct token *token;
	struct sync_disk *disks;

	token = malloc(sizeof(struct token));
	if (!token)
		return -ENOMEM;
	memset(token, 0, sizeof(struct token));

	disks = malloc(num_disks * sizeof(struct sync_disk));
	if (!disks) {
		free(token);
		return -ENOMEM;
	}

	token->disks = disks;
	token->num_disks = num_disks;
	*token_out = token;
	return 0;
}

void free_token(struct token *token)
{
	if (token->disks)
		free(token->disks);
	free(token);
}

/* thread that releases tokens of pid's that die */

static void *async_release_thread(void *arg GNUC_UNUSED)
{
	struct resource *r;
	struct token *token;

	while (1) {
		pthread_mutex_lock(&resource_mutex);
		while (list_empty(&dispose_resources)) {
			if (release_thread_stop) {
				pthread_mutex_unlock(&resource_mutex);
				goto out;
			}
			pthread_cond_wait(&resource_cond, &resource_mutex);
		}

		r = list_first_entry(&dispose_resources, struct resource, list);
		pthread_mutex_unlock(&resource_mutex);

		token = r->token;

		if (token->acquire_result == 1)
			release_token(token);

		close_disks(token->disks, token->num_disks);

		/* we don't want to remove r from dispose_list until after the
		   lease is released because we don't want a new token for
		   the same resource to be added and attempt to acquire
		   the lease until after it's been released */

		pthread_mutex_lock(&resource_mutex);
		_del_resource(r);
		pthread_mutex_unlock(&resource_mutex);
		free_token(token);
	}
 out:
	return NULL;
}

void release_token_async(struct token *token)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(token, &resources);
	if (r) {
		/* assert r->token == token ? */
		list_move(&r->list, &dispose_resources);
		pthread_cond_signal(&resource_cond);
	}
	pthread_mutex_unlock(&resource_mutex);
}

int setup_token_manager(void)
{
	int rv;

	INIT_LIST_HEAD(&resources);
	INIT_LIST_HEAD(&dispose_resources);
	INIT_LIST_HEAD(&saved_resources);

	rv = pthread_create(&release_thread, NULL, async_release_thread, NULL);
	if (rv)
		return -1;
	return 0;
}

void close_token_manager(void)
{
	pthread_mutex_lock(&resource_mutex);
	release_thread_stop = 1;
	pthread_cond_signal(&resource_cond);
	pthread_mutex_unlock(&resource_mutex);
	pthread_join(release_thread, NULL);
}

