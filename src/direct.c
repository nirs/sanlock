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
#include "paxos_lease.h"
#include "delta_lease.h"
#include "sanlock_direct.h"

static int do_paxos_action(void)
{
	struct sanlk_resource *res;
	struct token *token;
	struct leader_record leader_read, leader_ret;
	int disks_len, token_len;
	int num_opened;
	int i, j, rv = 0;

	for (i = 0; i < com.res_count; i++) {
		res = com.res_args[i];

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
			token->disks[j].fd = 0;
		}

		/*
		 * TODO: verify all resources are in the same lockspace?
		 * a single local_host_id option isn't suited to multiple
		 * lockspaces where one host can have different host_ids
		 */

		token->host_id = com.local_host_id;
		token->host_generation = com.local_host_generation;

		num_opened = open_disks(token->disks, token->r.num_disks);
		if (!majority_disks(token, num_opened)) {
			log_tool("cannot open majority of disks");
			return -1;
		}

		switch (com.action) {
		case ACT_INIT:
			rv = paxos_lease_init(token, com.num_hosts, com.max_hosts);
			if (rv < 0) {
				log_tool("cannot initialize disks");
				return -1;
			}
			break;

		case ACT_ACQUIRE:
			rv = paxos_lease_acquire(token, 0, &leader_ret, 0, com.num_hosts);
			if (rv < 0) {
				log_tool("cannot acquire lease on %s", token->r.name);
				return -1;
			}
			break;

		case ACT_RELEASE:
			rv = paxos_lease_leader_read(token, &leader_read, "direct_release");
			if (rv < 0) {
				log_tool("cannot read lease on %s", token->r.name);
				return -1;
			}

			rv = paxos_lease_release(token, &leader_read, &leader_ret);
			if (rv < 0) {
				log_tool("cannot release lease on %s", token->r.name);
				return -1;
			}
			break;
		}

		free(token);
	}

	return 0;
}

/*
 * sanlock direct acquire -i <local_host_id> -g <local_host_generation> -r RESOURCE
 * sanlock direct release -r RESOURCE
 */

int sanlock_direct_acquire(void)
{
	return do_paxos_action();
}

int sanlock_direct_release(void)
{
	return do_paxos_action();
}

static int do_delta_action(int action, struct sanlk_lockspace *ls,
			   struct leader_record *leader_ret)
{
	struct leader_record leader;
	struct sync_disk sd;
	struct space space;
	int rv;

	if (!ls->name[0])
		return -1;

	if (!ls->host_id_disk.path[0])
		return -1;

	if (!ls->host_id)
		return -1;

	/* for log_space in delta functions */
	memset(&space, 0, sizeof(space));

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &ls->host_id_disk, sizeof(struct sanlk_disk));

	rv = open_disks(&sd, 1);
	if (rv != 1) {
		log_tool("open_disk failed %d %s", rv, sd.path);
		return -1;
	}

	switch (action) {
	case ACT_ACQUIRE_ID:
		rv = delta_lease_acquire(&space, &sd,
					 ls->name,
					 ls->host_id,
					 ls->host_id,
					 &leader);
		break;
	case ACT_RENEW_ID:
		rv = delta_lease_renew(&space, &sd,
				       ls->name,
				       ls->host_id,
				       ls->host_id,
				       &leader);
		break;
	case ACT_RELEASE_ID:
		rv = delta_lease_leader_read(&sd,
					     ls->name,
					     ls->host_id,
					     &leader);
		if (rv < 0)
			return rv;
		rv = delta_lease_release(&space, &sd,
					 ls->name,
					 ls->host_id,
					 &leader, &leader);
		break;
	case ACT_READ_ID:
		rv = delta_lease_leader_read(&sd,
					     ls->name,
					     ls->host_id,
					     &leader);
		break;
	}

	if (rv == DP_OK)
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

int sanlock_direct_acquire_id(struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_ACQUIRE_ID, ls, NULL);
}

int sanlock_direct_release_id(struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RELEASE_ID, ls, NULL);
}

int sanlock_direct_renew_id(struct sanlk_lockspace *ls)
{
	return do_delta_action(ACT_RENEW_ID, ls, NULL);
}

int sanlock_direct_read_id(struct sanlk_lockspace *ls,
			   uint64_t *timestamp,
			   uint64_t *owner_id,
			   uint64_t *owner_generation)
{
	struct leader_record leader;
	int rv;

	memset(&leader, 0, sizeof(struct leader_record));

	rv = do_delta_action(ACT_READ_ID, ls, &leader);

	*timestamp = leader.timestamp;
	*owner_id = leader.owner_id;
	*owner_generation = leader.owner_generation;

	return rv;
}

int sanlock_direct_live_id(struct sanlk_lockspace *ls,
			   uint64_t *timestamp,
			   uint64_t *owner_id,
			   uint64_t *owner_generation,
			   int *live)
{
	struct leader_record leader_begin;
	struct leader_record leader;
	time_t start;
	int rv;

	rv = do_delta_action(ACT_READ_ID, ls, &leader_begin);
	if (rv < 0)
		return rv;

	start = time(NULL);

	while (1) {
		sleep(1);

		rv = do_delta_action(ACT_READ_ID, ls, &leader);
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

		if (time(NULL) - start > to.host_id_timeout_seconds) {
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

int sanlock_direct_init(void)
{
	struct sync_disk sd;
	int num_opened;
	int rv;

	if (!com.lockspace.host_id_disk.path[0])
		goto tokens;

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &com.lockspace.host_id_disk, sizeof(struct sanlk_disk));

	num_opened = open_disks(&sd, 1);
	if (num_opened != 1) {
		log_tool("cannot open disk %s", sd.path);
		return -1;
	}

	rv = delta_lease_init(&sd, com.lockspace.name, com.max_hosts);
	if (rv < 0) {
		log_tool("cannot initialize host_id disk");
		return -1;
	}

 tokens:
	if (!com.res_count)
		return 0;

	if (!com.num_hosts) {
		log_tool("num_hosts option required for paxos lease init");
		return -1;
	}

	if (com.num_hosts > com.max_hosts) {
		log_tool("num_hosts cannot be greater than max_hosts");
		return -1;
	}

	return do_paxos_action();
}

/* TODO: if this and daemon use aio, running this will cause i/o errors
 * in the daemon renewals.  This was using a virtual device (/dev/vdb)
 * backed by a file in the host.  Try using a real sda on hosts.
 * Problem in guest didn't appear with -a 0 (to disable aio). */

int sanlock_direct_dump(void)
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

	colon = strstr(com.dump_path, ":");
	if (colon) {
		off_str = colon + 1;
		*colon = '\0';
		sd.offset = atoll(off_str);
	}

	strncpy(sd.path, com.dump_path, SANLK_PATH_LEN);

	num_opened = open_disks(&sd, 1);
	if (num_opened != 1) {
		log_tool("cannot open disk %s", sd.path);
		return -1;
	}

	data = malloc(sd.sector_size);
	if (!data)
		return -ENOMEM;
	lr = (struct leader_record *)data;

	sector_nr = 0;
	while (1) {
		memset(sname, 0, sizeof(rname));
		memset(rname, 0, sizeof(rname));
		memset(data, 0, sd.sector_size);

		rv = read_sectors(&sd, sector_nr, 1, data, sd.sector_size,
				  to.io_timeout_seconds, options.use_aio,
				  "dump");

		if (lr->magic == DELTA_DISK_MAGIC) {
			strncpy(sname, lr->space_name, NAME_ID_SIZE);
			strncpy(rname, lr->resource_name, NAME_ID_SIZE);

			printf("%08llu/%08llu lockspace %36s\n"
			       "                  resource  %36s\n"
			       "                  own %4llu gen %4llu time %010llu age %u\n",
			       (unsigned long long)(sector_nr * sd.sector_size),
			       (unsigned long long)sector_nr,
			       sname, rname,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation,
			       (unsigned long long)lr->timestamp,
			       !lr->timestamp ? 0 : (uint32_t)(time(NULL) - lr->timestamp));

			sector_nr += 1;
		} else if (lr->magic == PAXOS_DISK_MAGIC) {
			strncpy(sname, lr->space_name, NAME_ID_SIZE);
			strncpy(rname, lr->resource_name, NAME_ID_SIZE);

			printf("%08llu/%08llu lockspace %36s\n"
			       "                  resource  %36s\n"
			       "                  own %4llu gen %4llu ver %4llu time %010llu age %u\n",
			       (unsigned long long)(sector_nr * sd.sector_size),
			       (unsigned long long)sector_nr,
			       sname, rname,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation,
			       (unsigned long long)lr->lver,
			       (unsigned long long)lr->timestamp,
			       !lr->timestamp ? 0 : (uint32_t)(time(NULL) - lr->timestamp));

			sector_nr += lr->max_hosts + 2;
		} else {
			printf("%08llu/%08llu %36s\n",
			       (unsigned long long)(sector_nr * sd.sector_size),
			       (unsigned long long)sector_nr,
			       "uninitialized");
			break;
		}
	}

	free(data);
	return 0;
}

