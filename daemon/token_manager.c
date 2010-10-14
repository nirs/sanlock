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

#include "sm.h"
#include "sm_msg.h"
#include "disk_paxos.h"
#include "token_manager.h"
#include "watchdog.h"
#include "sm_options.h"
#include "lockfile.h"
#include "log.h"
#include "diskio.h"
#include "list.h"

struct sm_timeouts to;

static struct list_head resources;
static struct list_head dispose_resources;
static pthread_mutex_t resource_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t resource_cond = PTHREAD_COND_INITIALIZER;
static pthread_t release_thread;
static int release_thread_done;

struct resource {
	struct list_head list;
	char name[NAME_ID_SIZE+1];
	struct token *token;
	int client_idx;
	int pid;
};

/* return < 0 on error, 1 on success */

static int acquire_lease(struct token *token, struct leader_record *leader)
{
	struct leader_record leader_ret;
	int rv;

	rv = disk_paxos_acquire(token, 0, &leader_ret);
	if (rv < 0)
		return rv;

	memcpy(leader, &leader_ret, sizeof(struct leader_record));
	return 1;
}

/* return < 0 on error, 1 on success */

static int release_lease(struct token *token)
{
	struct leader_record leader_ret;
	int rv;

	rv = disk_paxos_release(token, &token->leader, &leader_ret);
	if (rv < 0)
		return rv;

	memcpy(&token->leader, &leader_ret, sizeof(struct leader_record));

	log_debug(token, "release token_id %d rv %d",
		  token->token_id, rv);

	return 1;
}

void *acquire_thread(void *arg)
{
	struct token *token = (struct token *)arg;
	struct leader_record leader;
	int rv, num_opened;

	num_opened = open_disks(token->disks, token->num_disks);
	if (!majority_disks(token, num_opened)) {
		log_error(token, "cannot open majority of disks");
		token->acquire_result = -ENODEV;
		return NULL;
	}

	log_debug(token, "lease_thread token_id %d acquire_lease...",
		  token->token_id);

	rv = acquire_lease(token, &leader);

	token->acquire_result = rv;
	memcpy(&token->leader, &leader, sizeof(struct leader_record));

	log_debug(token, "acquire token_id %d rv %d at %llu",
		  token->token_id, rv,
		  (unsigned long long)token->leader.timestamp);

	if (rv < 0)
		close_disks(token->disks, token->num_disks);
	return NULL;
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

static struct resource *find_resource(struct list_head *head, char *name)
{
	struct resource *r;

	list_for_each_entry(r, head, list) {
		if (!strncmp(r->name, name, NAME_ID_SIZE))
			return r;
	}
	return NULL;
}

int add_resource(struct token *token, int ci, int pid)
{
	struct resource *r, *r2;

	r = malloc(sizeof(struct resource));
	if (!r)
		return -ENOMEM;
	memset(r, 0, sizeof(struct resource));

	strncpy(r->name, token->resource_name, NAME_ID_SIZE);
	r->token = token;
	r->client_idx = ci;
	r->pid = pid;

	pthread_mutex_lock(&resource_mutex);
	r2 = find_resource(&resources, token->resource_name);
	if (!r2)
		r2 = find_resource(&dispose_resources, token->resource_name);
	if (r2) {
		free(r);
		pthread_mutex_unlock(&resource_mutex);
		return -EEXIST;
	}
	list_add_tail(&r->list, &resources);
	pthread_mutex_unlock(&resource_mutex);
	return 0;
}

void del_resource(struct token *token)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(&resources, token->resource_name);
	if (r) {
		list_del(&r->list);
		free(r);
	}
	pthread_mutex_unlock(&resource_mutex);
}

/* the caller can block on disk i/o */

void release_token_wait(struct token *token)
{
	if (token->acquire_result == 1)
		release_lease(token);

	del_resource(token);

	if (token->disks)
		free(token->disks);
	free(token);
}

static void *async_release_thread(void *arg GNUC_UNUSED)
{
	struct resource *r;

	while (1) {
		pthread_mutex_lock(&resource_mutex);
		while (list_empty(&dispose_resources)) {
			if (release_thread_done) {
				pthread_mutex_unlock(&resource_mutex);
				goto out;
			}
			pthread_cond_wait(&resource_cond, &resource_mutex);
		}

		r = list_first_entry(&dispose_resources, struct resource, list);
		pthread_mutex_unlock(&resource_mutex);

		if (r->token->acquire_result == 1)
			release_lease(r->token);

		/* we don't want to remove r from dispose_list until after the
		   lease is released because we don't want a new token for
		   the same resource to be added and attempt to acquire
		   the lease until after it's been released */

		pthread_mutex_lock(&resource_mutex);
		list_del(&r->list);
		pthread_mutex_unlock(&resource_mutex);

		if (r->token->disks)
			free(r->token->disks);
		free(r->token);
		free(r);
	}
 out:
	return NULL;
}

/* move resource struct from active list to delayed release list
   that release_thread will process; after release_thread calls
   release_lease, it calls del_token_resource */

void release_token_async(struct token *token)
{
	struct resource *r;

	pthread_mutex_lock(&resource_mutex);
	r = find_resource(&resources, token->resource_name);
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
	release_thread_done = 1;
	pthread_cond_signal(&resource_cond);
	pthread_mutex_unlock(&resource_mutex);
	pthread_join(release_thread, NULL);
}

