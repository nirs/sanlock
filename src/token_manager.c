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
	return rv; /* DP_OK */
}

/* return < 0 on error, 1 on success */

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

	rv = paxos_lease_acquire(token, 1, &leader_ret, 0, 0);

	token->setowner_result = rv;

	/* we set acquire_result here for at least one reason: because release
	   will not release the token if acquire_result is not 1 */

	token->acquire_result = rv;

	log_token(token, "setowner rv %d lver %llu at %llu", rv,
		  (unsigned long long)token->leader.lver,
		  (unsigned long long)token->leader.timestamp);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return rv; /* DP_OK */
}

/*
 * migration creates special cases for release.  if either the source or
 * the dest calls release_token and read leader shows next_owner_id is not
 * zero, it means migration is in progress, and they should not free the
 * lease.
 *
 * In other words, paxos release should only be done (lease freed) on a
 * "fully owned", clean lease, i.e. next_owner_id is zero, and current
 * leader matches our last leader.
 *
 * (A second mechanism is also needed to prevent release of migrating leases,
 * the token->migrating flag.  This is because we need to block releases
 * on the source effective immediately, before next_owner may be written.)
 *
 * setowner on the destination, in the case of migration success, moves a
 * disk lease from being in limbo (both owner and next_owner set), to having
 * just an owner (the dest).  After this the owner (dest) can release it.
 *
 * TODO: setowner on the source, in the case of migration failure, moves the
 * disk lease from being in limbo with both owner and next_owner, to having
 * just an owner (the source).  This setowner call will need to ignore the
 * fact that the leader block doesn't match its latest copy since it may
 * have been the dest that wrote next_owner at the start of migration.
 *
 * We don't have to worry that next_owner is ever running the vm; setowner
 * on dest is required to complete successfully (making dest the owner and
 * clearing next_owner) before vm is resumed on the dest.
 *
 * If migration fails, the source/owner does not free the paxos lease, but
 * the source/owner continues running and renewing its host_id, then no
 * other host will be able to take ownership of the lease, because they will
 * see that the owner is alive.  The source/owner will be able to acquire
 * the lease, though.  So, the source/owner needs to either
 * 1. call setowner to clear next_owner_id, then call release to free it (TODO above)
 * 2. call acquire to acquire the lease, then call release to free it
 *
 * If migration fails, the source/owner does not free the paxos lease, and
 * the source/owner does not continue running or renewing its host_id, then
 * another host will be able to take ownership of the lease, because they
 * will see that the owner is not alive (or comes back with a different
 * generation).
 *
 * For migration, the paxos lease is in limbo: both owner and next_owner
 * are set, and in this state neither the source nor the dest can free the
 * paxos lease.  The limbo state needs to be cleared (next_owner cleared)
 * before the lease can be freed.
 *
 * - if migration succeeds, the dest will call setowner to clear next_owner
 *   and bring the lease out of limbo
 *
 * - if migration fails because the dest host fails,
 *   setowner on the source will clear next_owner, and allow source to
 *   continue running and holding the lease, or release the lease.
 *   setowner on source would have to ignore the fact that the leader
 *   will have been changed since it last read or wrote it (by the dest
 *   writing itself as the next_owner_id)
 *
 * - if migration fails because the source host fails,
 *   the paxos lease will be left on disk with owner and next_owner set,
 *   and neither source nor dest owning the lease to free it.
 *   The lease can be acquired because someone will see that the owner's
 *   host_id is not renewed (or a different generation).  This acquire
 *   will clear next_owner.
 *
 * - if migration fails and both source and dest fail, the lease can be
 *   acquired because someone will see that the owner's host_id is not
 *   renewed (or a diff generation).  This acquire will clear next_owner.
 *
 * - if migration fails because the the dest qemu fails but dest host still ok
 *   setowner on the source will clear next_owner (same as if dest host fails)
 *
 * - if migration fails because the the source qemu fails but source host still ok
 *   sanlock will not free the lease in release_token because next_owner is set.
 *   no other host can acquire the lease because its owned by a live host_id.
 *   the source host can acquire the lease again, and then free it.  what causes
 *   the source host to try to acquire the lease again?  trying to start the vm
 *   on the source again...
 *
 * - if migration fails because the the source and dest qemu fails but hosts ok
 *    same as prev
 */

/* return < 0 on error, 1 on success */

int release_token(struct token *token)
{
	struct leader_record leader_ret;
	int rv;

	if (token->migrating) {
		log_errot(token, "release skip migrating");
		return DP_ERROR;
	}

	rv = paxos_lease_release(token, &token->leader, &leader_ret);

	token->release_result = rv;

	log_token(token, "release rv %d", rv);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return rv; /* DP_OK */
}

/* return < 0 on error, 1 on success */

int set_next_owner_other(struct token *token, uint64_t target_host_id)
{
	struct leader_record leader;
	int rv;

	rv = paxos_lease_leader_read(token, &leader);
	if (rv < 0)
		return rv;

	if (memcmp(&leader, &token->leader, sizeof(struct leader_record))) {
		log_errot(token, "set_next_owner_other leader changed before migrate");
		return DP_BAD_LEADER;
	}

	if (leader.num_hosts < target_host_id) {
		log_errot(token, "set_next_owner_other num_hosts %llu "
			  "target_host_id %llu",
			  (unsigned long long)leader.num_hosts,
			  (unsigned long long)target_host_id);
		return DP_BAD_NUMHOSTS;
	}

	leader.next_owner_id = target_host_id;

	rv = paxos_lease_leader_write(token, &leader);
	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader, sizeof(struct leader_record));
	return rv; /* DP_OK */
}

/* return < 0 on error, 1 on success */

int set_next_owner_self(struct token *token)
{
	struct leader_record leader;
	int rv;

	rv = paxos_lease_leader_read(token, &leader);
	if (rv < 0)
		return rv;

	if (leader.num_hosts < token->host_id) {
		log_errot(token, "set_next_owner_self num_hosts %llu host_id %llu",
			  (unsigned long long)leader.num_hosts,
			  (unsigned long long)token->host_id);
		return DP_BAD_NUMHOSTS;
	}

	leader.next_owner_id = token->host_id;

	rv = paxos_lease_leader_write(token, &leader);
	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader, sizeof(struct leader_record));
	return rv; /* DP_OK */
}

/*
 * migration destination verifies the migrate state sent from source,
 * which needs to be consisent with the source having successfully written
 * the next_owner itself, or having not tried or tried and failed.
 *
 * If we can't read the leader, return an error, and the migration
 * needs to be aborted.
 */

/* return < 0 on error, 1 on success */

int parse_incoming_state(struct token *token, char *str, int *migrate_result,
                         struct leader_record *leader);

int check_incoming_state(struct token *token, char *opt_str, int *migrate_result_out)
{
	struct leader_record leader_ret;
	struct leader_record leader_src;
	int migrate_result;
	int rv;

	rv = paxos_lease_leader_read(token, &leader_ret);
	if (rv < 0)
		return rv;

	rv = parse_incoming_state(token, opt_str, &migrate_result, &leader_src);
	if (rv < 0) {
		log_errot(token, "check_incoming_state parse error %d result %d len %zd",
			  rv, migrate_result, strlen(opt_str));
		return rv;
	}

	*migrate_result_out = migrate_result;

	/* source successfully wrote next_owner */

	if (migrate_result == DP_OK) {
		if (leader_src.next_owner_id == token->host_id &&
		    leader_ret.next_owner_id == token->host_id &&
		    leader_src.lver == leader_ret.lver &&
		    leader_src.timestamp == leader_ret.timestamp) {
			log_token(token, "check_incoming_state all match");
			return DP_OK;
		} else {
			log_errot(token, "check_incoming_state mismatch "
				  "next_owner %llu %llu %llu "
				  "lver %llu %llu "
				  "timestamp %llu %llu",
				  (unsigned long long)token->host_id,
				  (unsigned long long)leader_src.next_owner_id,
				  (unsigned long long)leader_ret.next_owner_id,
				  (unsigned long long)leader_src.lver,
				  (unsigned long long)leader_ret.lver,
				  (unsigned long long)leader_src.timestamp,
				  (unsigned long long)leader_ret.timestamp);
			return -1;
		}
	}

	/* migrate_result <= 0, source could not (or did not) write next_owner_id,
	   so it should still be 0 */

	if (leader_src.owner_id != leader_ret.owner_id ||
	    leader_src.timestamp != leader_ret.timestamp ||
	    leader_ret.next_owner_id != 0) {

		log_errot(token, "check_incoming_state mismatch migrate_result %d "
			  "next_owner %llu owner %llu %llu timestamp %llu %llu",
			  migrate_result,
			  (unsigned long long)leader_ret.next_owner_id,
			  (unsigned long long)leader_src.owner_id,
			  (unsigned long long)leader_ret.owner_id,
			  (unsigned long long)leader_src.timestamp,
			  (unsigned long long)leader_ret.timestamp);
		return -1;
	}

	return DP_OK;
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

