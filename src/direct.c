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
#include "token_manager.h"
#include "direct.h"
#include "paxos_lease.h"
#include "delta_lease.h"

/*
 * cli: sanlock direct init
 * cli: sanlock direct read_leader
 * cli: sanlock direct acquire
 * cli: sanlock direct release
 * lib: sanlock_direct_init()
 *
 *              direct.c:
 *              direct_init()
 *              direct_read_leader()
 *              direct_acquire()
 *              direct_release()
 * 	           do_paxos_action()
 * 	              paxos_lease.c:
 * 	              paxos_lease_init()
 * 	              paxos_lease_leader_read()
 * 	              paxos_lease_acquire()
 * 	              paxos_lease_release()
 *
 * cli: sanlock direct init
 * cli: sanlock direct read_leader
 * cli: sanlock direct acquire_id
 * cli: sanlock direct release_id
 * cli: sanlock direct renew_id
 * cli: sanlock direct read_id
 * cli: sanlock direct live_id
 * lib: sanlock_direct_read_id()
 * lib: sanlock_direct_live_id()
 * lib: sanlock_direct_init()
 *
 *              direct.c:
 *              direct_init()
 *              direct_read_leader()
 *              direct_acquire_id()
 *              direct_release_id()
 *              direct_renew_id()
 *              direct_read_id()
 *              direct_live_id()
 *                 do_delta_action()
 *                    delta_lease.c:
 *                    delta_lease_init()
 *                    delta_lease_leader_read()
 *                    delta_lease_acquire()
 *                    delta_lease_release()
 *                    delta_lease_renew()
 */

static int do_paxos_action(int action, struct task *task,
			   struct sanlk_resource *res,
			   int max_hosts, int num_hosts,
			   uint64_t local_host_id,
			   uint64_t local_host_generation,
			   struct leader_record *leader_ret)
{
	struct token *token;
	struct leader_record leader;
	int disks_len, token_len;
	int num_opened;
	int j, rv = 0;

	disks_len = res->num_disks * sizeof(struct sync_disk);
	token_len = sizeof(struct token) + disks_len;

	token = malloc(token_len);
	if (!token)
		return -ENOMEM;
	memset(token, 0, token_len);
	token->disks = (struct sync_disk *)&token->r.disks[0];
	token->r.num_disks = res->num_disks;
	memcpy(token->r.lockspace_name, res->lockspace_name, SANLK_NAME_LEN);
	memcpy(token->r.name, res->name, SANLK_NAME_LEN);

	/* WARNING sync_disk == sanlk_disk */

	memcpy(token->disks, &res->disks, disks_len);

	for (j = 0; j < token->r.num_disks; j++) {
		token->disks[j].sector_size = 0;
		token->disks[j].fd = -1;
	}

	num_opened = open_disks(token->disks, token->r.num_disks);
	if (!majority_disks(token, num_opened)) {
		free(token);
		return -ENODEV;
	}

	switch (action) {
	case ACT_INIT:
		rv = paxos_lease_init(task, token, num_hosts, max_hosts);
		break;

	case ACT_ACQUIRE:
		token->host_id = local_host_id;
		token->host_generation = local_host_generation;

		rv = paxos_lease_acquire(task, token, 0, leader_ret, 0, num_hosts);
		break;

	case ACT_RELEASE:
		rv = paxos_lease_leader_read(task, token, &leader, "direct_release");
		if (rv < 0)
			break;
		rv = paxos_lease_release(task, token, &leader, leader_ret);
		break;

	case ACT_READ_LEADER:
		rv = paxos_lease_leader_read(task, token, &leader, "direct_read_leader");
		break;
	}

	close_disks(token->disks, token->r.num_disks);
	free(token);

	if (rv == SANLK_OK)
		rv = 0;

	if (leader_ret)
		memcpy(leader_ret, &leader, sizeof(struct leader_record));

	return rv;
}

/*
 * sanlock direct acquire -i <local_host_id> -g <local_host_generation> -r RESOURCE
 * sanlock direct release -r RESOURCE
 */

int direct_acquire(struct task *task,
		   struct sanlk_resource *res,
		   int num_hosts,
		   uint64_t local_host_id,
		   uint64_t local_host_generation,
		   struct leader_record *leader_ret)
{
	return do_paxos_action(ACT_ACQUIRE, task, res,
			       -1, num_hosts,
			       local_host_id, local_host_generation,
			       leader_ret);
}

int direct_release(struct task *task,
		   struct sanlk_resource *res,
		   struct leader_record *leader_ret)
{
	return do_paxos_action(ACT_RELEASE, task, res,
			       -1, -1,
			       0, 0,
			       leader_ret);
}

static int do_delta_action(int action,
			   struct task *task,
			   struct sanlk_lockspace *ls,
			   int max_hosts,
			   struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct sync_disk sd;
	struct space space;
	int rv;

	/* for log_space in delta functions */
	memset(&space, 0, sizeof(space));

	if (!ls->host_id_disk.path[0])
		return -ENODEV;

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &ls->host_id_disk, sizeof(struct sanlk_disk));
	sd.fd = -1;

	rv = open_disks(&sd, 1);
	if (rv != 1)
		return -ENODEV;

	switch (action) {
	case ACT_INIT:
		rv = delta_lease_init(task, &sd, ls->name, max_hosts);
		break;

	case ACT_ACQUIRE_ID:
		rv = delta_lease_acquire(task, &space, &sd,
					 ls->name,
					 ls->host_id,
					 ls->host_id,
					 &leader);
		break;
	case ACT_RENEW_ID:
		rv = delta_lease_renew(task, &space, &sd,
				       ls->name,
				       ls->host_id,
				       ls->host_id,
				       &leader);
		break;
	case ACT_RELEASE_ID:
		rv = delta_lease_leader_read(task, &sd,
					     ls->name,
					     ls->host_id,
					     &leader,
					     "direct_release");
		if (rv < 0)
			return rv;
		rv = delta_lease_release(task, &space, &sd,
					 ls->name,
					 ls->host_id,
					 &leader, &leader);
		break;
	case ACT_READ_ID:
	case ACT_READ_LEADER:
		rv = delta_lease_leader_read(task, &sd,
					     ls->name,
					     ls->host_id,
					     &leader,
					     "direct_read");
		break;
	}

	close_disks(&sd, 1);

	if (rv == SANLK_OK)
		rv = 0;

	if (leader_ret)
		memcpy(leader_ret, &leader, sizeof(struct leader_record));

	return rv;
}

/* 
 * sanlock direct acquire_id|release_id|renew_id -s LOCKSPACE
 *
 * should be the equivalent of what the daemon would do for
 * sanlock client add_lockspace|rem_lockspace -s LOCKSPACE
 */

int direct_acquire_id(struct task *task, struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_ACQUIRE_ID, task, ls, -1, NULL);
}

int direct_release_id(struct task *task, struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RELEASE_ID, task, ls, -1, NULL);
}

int direct_renew_id(struct task *task, struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RENEW_ID, task, ls, -1, NULL);
}

int direct_read_id(struct task *task,
		   struct sanlk_lockspace *ls,
		   uint64_t *timestamp,
		   uint64_t *owner_id,
		   uint64_t *owner_generation)
{
	struct leader_record leader;
	int rv;

	memset(&leader, 0, sizeof(struct leader_record));

	rv = do_delta_action(ACT_READ_ID, task, ls, -1, &leader);

	*timestamp = leader.timestamp;
	*owner_id = leader.owner_id;
	*owner_generation = leader.owner_generation;

	return rv;
}

int direct_live_id(struct task *task,
		   struct sanlk_lockspace *ls,
		   uint64_t *timestamp,
		   uint64_t *owner_id,
		   uint64_t *owner_generation,
		   int *live)
{
	struct leader_record leader_begin;
	struct leader_record leader;
	time_t start;
	int rv;

	rv = do_delta_action(ACT_READ_ID, task, ls, -1, &leader_begin);
	if (rv < 0)
		return rv;

	start = time(NULL);

	while (1) {
		sleep(1);

		rv = do_delta_action(ACT_READ_ID, task, ls, -1, &leader);
		if (rv < 0)
			return rv;

		if (leader.timestamp != leader_begin.timestamp) {
			*live = 1;
			break;
		}

		if (leader.owner_id != leader_begin.owner_id) {
			*live = 2;
			break;
		}

		if (leader.owner_generation != leader_begin.owner_generation) {
			*live = 3;
			break;
		}

		if (time(NULL) - start > task->host_id_timeout_seconds) {
			*live = 0;
			break;
		}
	}

	*timestamp = leader.timestamp;
	*owner_id = leader.owner_id;
	*owner_generation = leader.owner_generation;
	return 0;
}

/*
 * sanlock direct init -n <num_hosts> [-s LOCKSPACE] [-r RESOURCE]
 *
 * Note: host_id not used for init, whatever is given in LOCKSPACE
 * is ignored
 */

int direct_init(struct task *task,
		struct sanlk_lockspace *ls,
		struct sanlk_resource *res,
		int max_hosts, int num_hosts)
{
	int rv = -1;

	if (ls && ls->host_id_disk.path[0]) {
		rv = do_delta_action(ACT_INIT, task, ls, max_hosts, NULL);

	} else if (res) {
		if (!num_hosts)
			return -EINVAL;

		if (num_hosts > max_hosts)
			return SANLK_LEADER_NUMHOSTS;

		if (!res->num_disks)
			return -ENODEV;

		if (!res->disks[0].path[0])
			return -ENODEV;

		rv = do_paxos_action(ACT_INIT, task, res,
				     max_hosts, num_hosts, 0, 0, NULL);
	}

	return rv;
}

int direct_read_leader(struct task *task,
		       struct sanlk_lockspace *ls,
		       struct sanlk_resource *res,
		       struct leader_record *leader_ret)
{
	int rv = -1;

	if (ls && ls->host_id_disk.path[0])
		rv = do_delta_action(ACT_READ_LEADER, task, ls, -1, leader_ret);

	else if (res)
		rv = do_paxos_action(ACT_READ_LEADER, task, res,
				     -1, -1, 0, 0, leader_ret);
	return rv;
}

int direct_dump(struct task *task, char *dump_path)
{
	char *data;
	char *colon, *off_str;
	struct leader_record *lr;
	struct sync_disk sd;
	char sname[NAME_ID_SIZE+1];
	char rname[NAME_ID_SIZE+1];
	int num_opened, rv;
	uint64_t sector_nr;

	memset(&sd, 0, sizeof(struct sync_disk));

	colon = strstr(dump_path, ":");
	if (colon) {
		off_str = colon + 1;
		*colon = '\0';
		sd.offset = atoll(off_str);
	}

	strncpy(sd.path, dump_path, SANLK_PATH_LEN);
	sd.fd = -1;

	num_opened = open_disks(&sd, 1);
	if (num_opened != 1)
		return -ENODEV;

	data = malloc(sd.sector_size);
	if (!data) {
		rv = -ENOMEM;
		goto out_close;
	}
	lr = (struct leader_record *)data;

	sector_nr = 0;

	printf("%8s %36s %36s %10s %4s %4s %s\n",
	       "offset",
	       "lockspace",
	       "resource",
	       "timestamp",
	       "own",
	       "gen",
	       "lver");

	while (1) {
		memset(sname, 0, sizeof(rname));
		memset(rname, 0, sizeof(rname));
		memset(data, 0, sd.sector_size);

		rv = read_sectors(&sd, sector_nr, 1, data, sd.sector_size,
				  task, "dump");

		if (lr->magic == DELTA_DISK_MAGIC) {
			strncpy(sname, lr->space_name, NAME_ID_SIZE);
			strncpy(rname, lr->resource_name, NAME_ID_SIZE);

			printf("%08llu %36s %36s %010llu %04llu %04llu\n",
			       (unsigned long long)(sector_nr * sd.sector_size),
			       sname, rname,
			       (unsigned long long)lr->timestamp,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation);

			sector_nr += 1;
		} else if (lr->magic == PAXOS_DISK_MAGIC) {
			strncpy(sname, lr->space_name, NAME_ID_SIZE);
			strncpy(rname, lr->resource_name, NAME_ID_SIZE);

			printf("%08llu %36s %36s %010llu %04llu %04llu %llu\n",
			       (unsigned long long)(sector_nr * sd.sector_size),
			       sname, rname,
			       (unsigned long long)lr->timestamp,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation,
			       (unsigned long long)lr->lver);

			sector_nr += lr->max_hosts + 2;
		} else {
			printf("%08llu %36s\n",
			       (unsigned long long)(sector_nr * sd.sector_size),
			       "uninitialized");
			break;
		}
	}

	rv = 0;
	free(data);
 out_close:
	close_disks(&sd, 1);
	return rv;
}

