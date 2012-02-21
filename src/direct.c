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
#include "log.h"
#include "resource.h"
#include "direct.h"
#include "paxos_lease.h"
#include "delta_lease.h"
#include "mode_block.h"

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

	rv = open_disks(token->disks, token->r.num_disks);
	if (rv < 0) {
		free(token);
		return rv;
	}

	switch (action) {
	case ACT_DIRECT_INIT:
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
			   char *our_host_name,
			   struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct sync_disk sd;
	struct space space;
	char bitmap[HOSTID_BITMAP_SIZE];
	int read_result, rv;

	memset(bitmap, 0, sizeof(bitmap));

	/* for log_space in delta functions */
	memset(&space, 0, sizeof(space));

	if (!ls->host_id_disk.path[0])
		return -ENODEV;

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &ls->host_id_disk, sizeof(struct sanlk_disk));
	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0)
		return -ENODEV;

	switch (action) {
	case ACT_DIRECT_INIT:
		rv = delta_lease_init(task, &sd, ls->name, max_hosts);
		break;

	case ACT_ACQUIRE_ID:
		rv = delta_lease_acquire(task, &space, &sd,
					 ls->name,
					 our_host_name,
					 ls->host_id,
					 &leader);
		break;
	case ACT_RENEW_ID:
		rv = delta_lease_leader_read(task, &sd,
					     ls->name,
					     ls->host_id,
					     &leader,
					     "direct_renew");
		if (rv < 0)
			return rv;
		rv = delta_lease_renew(task, &space, &sd,
				       ls->name,
				       bitmap,
				       -1,
				       &read_result,
				       &leader,
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
					 &leader,
					 &leader);
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

int direct_acquire_id(struct task *task, struct sanlk_lockspace *ls,
		      char *our_host_name)
{
	return do_delta_action(ACT_ACQUIRE_ID, task, ls, -1, our_host_name, NULL);
}

int direct_release_id(struct task *task, struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RELEASE_ID, task, ls, -1, NULL, NULL);
}

int direct_renew_id(struct task *task, struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RENEW_ID, task, ls, -1, NULL, NULL);
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

	rv = do_delta_action(ACT_READ_ID, task, ls, -1, NULL, &leader);

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

	rv = do_delta_action(ACT_READ_ID, task, ls, -1, NULL, &leader_begin);
	if (rv < 0)
		return rv;

	start = monotime();

	while (1) {
		sleep(1);

		rv = do_delta_action(ACT_READ_ID, task, ls, -1, NULL, &leader);
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

		if (monotime() - start > task->host_dead_seconds) {
			*live = 0;
			break;
		}
	}

	*timestamp = leader.timestamp;
	*owner_id = leader.owner_id;
	*owner_generation = leader.owner_generation;
	return 0;
}

int direct_align(struct sync_disk *disk)
{
	if (disk->sector_size == 512)
		return 1024 * 1024;
	else if (disk->sector_size == 4096)
		return 8 * 1024 * 1024;
	else
		return -EINVAL;
}

/*
 * sanlock direct init [-s LOCKSPACE] [-r RESOURCE]
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
		rv = do_delta_action(ACT_DIRECT_INIT, task, ls, max_hosts, NULL, NULL);

	} else if (res) {
		if (!res->num_disks)
			return -ENODEV;

		if (!res->disks[0].path[0])
			return -ENODEV;

		rv = do_paxos_action(ACT_DIRECT_INIT, task, res,
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
		rv = do_delta_action(ACT_READ_LEADER, task, ls, -1, NULL, leader_ret);

	else if (res)
		rv = do_paxos_action(ACT_READ_LEADER, task, res,
				     -1, -1, 0, 0, leader_ret);
	return rv;
}

int test_id_bit(int host_id, char *bitmap);

int direct_dump(struct task *task, char *dump_path, int force_mode)
{
	char *data, *bitmap;
	char *colon, *off_str;
	struct leader_record *lr;
	struct request_record *rr;
	struct sync_disk sd;
	char sname[NAME_ID_SIZE+1];
	char rname[NAME_ID_SIZE+1];
	uint64_t sector_nr;
	int sector_count, datalen, align_size;
	int i, rv, b;

	memset(&sd, 0, sizeof(struct sync_disk));

	colon = strstr(dump_path, ":");
	if (colon) {
		off_str = colon + 1;
		*colon = '\0';
		sd.offset = atoll(off_str);
	}

	strncpy(sd.path, dump_path, SANLK_PATH_LEN);
	sd.fd = -1;

	rv = open_disk(&sd);
	if (rv < 0)
		return -ENODEV;

	rv = direct_align(&sd);
	if (rv < 0)
		goto out_close;

	align_size = rv;
	datalen = align_size;
	sector_count = align_size / sd.sector_size;

	data = malloc(datalen);
	if (!data) {
		rv = -ENOMEM;
		goto out_close;
	}

	printf("%8s %36s %48s %10s %4s %4s %s",
	       "offset",
	       "lockspace",
	       "resource",
	       "timestamp",
	       "own",
	       "gen",
	       "lver");

	if (force_mode)
		printf("/req/mode");

	printf("\n");

	sector_nr = 0;

	while (1) {
		memset(sname, 0, sizeof(rname));
		memset(rname, 0, sizeof(rname));
		memset(data, 0, sd.sector_size);

		rv = read_sectors(&sd, sector_nr, sector_count, data, datalen,
				  task, "dump");

		lr = (struct leader_record *)data;

		if (lr->magic == DELTA_DISK_MAGIC) {
			for (i = 0; i < sector_count; i++) {
				lr = (struct leader_record *)(data + (i * sd.sector_size));

				if (!lr->magic)
					continue;

				/* has never been acquired, don't print */
				if (!lr->owner_id && !lr->owner_generation)
					continue;

				strncpy(sname, lr->space_name, NAME_ID_SIZE);
				strncpy(rname, lr->resource_name, NAME_ID_SIZE);

				printf("%08llu %36s %48s %010llu %04llu %04llu",
					(unsigned long long)((sector_nr + i) * sd.sector_size),
					sname, rname,
					(unsigned long long)lr->timestamp,
					(unsigned long long)lr->owner_id,
					(unsigned long long)lr->owner_generation);

				if (force_mode) {
					bitmap = (char *)lr + LEADER_RECORD_MAX;
					for (b = 0; b < DEFAULT_MAX_HOSTS; b++) {
						if (test_id_bit(b+1, bitmap))
							printf(" %d", b+1);
					}
				}
				printf("\n");
			}
		} else if (lr->magic == PAXOS_DISK_MAGIC) {
			strncpy(sname, lr->space_name, NAME_ID_SIZE);
			strncpy(rname, lr->resource_name, NAME_ID_SIZE);

			printf("%08llu %36s %48s %010llu %04llu %04llu %llu",
			       (unsigned long long)(sector_nr * sd.sector_size),
			       sname, rname,
			       (unsigned long long)lr->timestamp,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation,
			       (unsigned long long)lr->lver);

			if (force_mode) {
				rr = (struct request_record *)(data + sd.sector_size);
				printf("/%llu/%u",
				       (unsigned long long)rr->lver, rr->force_mode);
			}
			printf("\n");

			for (i = 0; i < lr->num_hosts; i++) {
				char *pd = data + ((2 + i) * sd.sector_size);
				struct mode_block *mb = (struct mode_block *)(pd + MBLOCK_OFFSET);

				if (!(mb->flags & MBLOCK_SHARED))
					continue;

				printf("                                                                                                          ");
				printf("%04u %04llu SH\n", i+1, (unsigned long long)mb->generation);
			}
		} else {
			break;
		}

		sector_nr += sector_count;
	}

	rv = 0;
	free(data);
 out_close:
	close_disks(&sd, 1);
	return rv;
}

