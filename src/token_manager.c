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
static pthread_mutex_t resource_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t resource_cond = PTHREAD_COND_INITIALIZER;
static pthread_t release_thread;
static int release_thread_stop;

struct resource {
	struct list_head list;
	char space_name[NAME_ID_SIZE+1];
	char resource_name[NAME_ID_SIZE+1];
	struct token *token;
	int pid;
};

static struct resource *find_resource(struct token *token,
				      struct list_head *head)
{
	struct resource *r;

	list_for_each_entry(r, head, list) {
		if (strncmp(r->space_name, token->r.lockspace_name, NAME_ID_SIZE))
			continue;
		if (strncmp(r->resource_name, token->r.name, NAME_ID_SIZE))
			continue;
		return r;
	}
	return NULL;
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

	r = malloc(sizeof(struct resource));
	if (!r) {
		rv = -ENOMEM;
		goto out;
	}

	memset(r, 0, sizeof(struct resource));
	strncpy(r->space_name, token->r.lockspace_name, NAME_ID_SIZE);
	strncpy(r->resource_name, token->r.name, NAME_ID_SIZE);
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

int acquire_token(struct token *token, uint64_t acquire_lver,
		  int new_num_hosts)
{
	struct leader_record leader_ret;
	int rv;

	rv = paxos_lease_acquire(&to, token, 0, &leader_ret, acquire_lver,
				 new_num_hosts);

	token->acquire_result = rv;

	log_token(token, "acquire rv %d lver %llu at %llu", rv,
		  (unsigned long long)token->leader.lver,
		  (unsigned long long)token->leader.timestamp);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	token->r.lver = token->leader.lver;
	return rv; /* SANLK_OK */
}

/* return < 0 on error, 1 on success */

int release_token(struct token *token)
{
	struct leader_record leader_ret;
	int rv;

	rv = paxos_lease_release(&to, token, &token->leader, &leader_ret);

	token->release_result = rv;

	log_token(token, "release rv %d", rv);

	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));
	return rv; /* SANLK_OK */
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

		close_disks(token->disks, token->r.num_disks);

		/* we don't want to remove r from dispose_list until after the
		   lease is released because we don't want a new token for
		   the same resource to be added and attempt to acquire
		   the lease until after it's been released */

		pthread_mutex_lock(&resource_mutex);
		_del_resource(r);
		pthread_mutex_unlock(&resource_mutex);
		free(token);
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

