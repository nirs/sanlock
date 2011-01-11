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
#include "leader.h"
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
	int num_opened;
	int i, j, rv = 0;

	for (i = 0; i < com.res_count; i++) {
		res = com.res_args[i];

		rv = create_token(res->num_disks, &token);
		if (rv < 0)
			return rv;

		strncpy(token->resource_name, res->name, NAME_ID_SIZE);

		/* see WARNING above about sync_disk == sanlk_disk */

		memcpy(token->disks, &res->disks,
		       token->num_disks * sizeof(struct sync_disk));

		/* zero out pad1 and pad2, see WARNING above */
		for (j = 0; j < token->num_disks; j++) {
			token->disks[j].sector_size = 0;
			token->disks[j].fd = 0;
		}

		num_opened = open_disks(token->disks, token->num_disks);
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
				log_tool("cannot acquire lease on %s",
				 	 token->resource_name);
				return -1;
			}
			break;

		case ACT_RELEASE:
			rv = paxos_lease_leader_read(token, &leader_read);
			if (rv < 0) {
				log_tool("cannot read lease on %s",
				 	 token->resource_name);
				return -1;
			}

			rv = paxos_lease_release(token, &leader_read, &leader_ret);
			if (rv < 0) {
				log_tool("cannot release lease on %s",
				 	 token->resource_name);
				return -1;
			}
			break;

		case ACT_MIGRATE:
			rv = paxos_lease_leader_read(token, &leader_read);
			if (rv < 0) {
				log_tool("cannot read lease on %s",
				 	 token->resource_name);
				return -1;
			}

			rv = paxos_lease_migrate(token, &leader_read, &leader_ret, com.host_id);
			if (rv < 0) {
				log_tool("cannot migrate lease on %s",
				 	 token->resource_name);
				return -1;
			}
			break;
		}

		free_token(token);
	}

	return 0;
}

int sanlock_direct_init(void)
{
	struct sync_disk sd;
	int num_opened;
	int rv = 0;

	if (!options.host_id_path[0])
		goto tokens;

	memset(&sd, 0, sizeof(struct sync_disk));
	strncpy(sd.path, options.host_id_path, DISK_PATH_LEN);
	sd.offset = options.host_id_offset;

	num_opened = open_disks(&sd, 1);
	if (num_opened != 1) {
		log_tool("cannot open disk %s", sd.path);
		return -1;
	}

	rv = delta_lease_init(&sd, com.max_hosts);
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

int sanlock_direct_acquire(void)
{
	return do_paxos_action();
}

int sanlock_direct_release(void)
{
	return do_paxos_action();
}

int sanlock_direct_migrate(void)
{
	return do_paxos_action();
}

static int do_delta_action(void)
{
	struct leader_record leader;
	struct sync_disk host_id_disk;
	int rv;

	memset(&host_id_disk, 0, sizeof(struct sync_disk));
	strncpy(host_id_disk.path, options.host_id_path, DISK_PATH_LEN);
	host_id_disk.offset = options.host_id_offset;

	rv = open_disks(&host_id_disk, 1);
	if (rv != 1) {
		log_tool("open_disk failed %d %s", rv, options.host_id_path);
		return -1;
	}

	switch (com.action) {
	case ACT_ACQUIRE_ID:
		rv = delta_lease_acquire(&host_id_disk, com.host_id, &leader);
		break;
	case ACT_RENEW_ID:
		rv = delta_lease_renew(&host_id_disk, com.host_id, &leader);
		break;
	case ACT_RELEASE_ID:
		rv = delta_lease_leader_read(&host_id_disk, com.host_id, &leader);
		if (rv < 0)
			return rv;
		rv = delta_lease_release(&host_id_disk, com.host_id, &leader, &leader);
		break;
	}

	return rv;
}

int sanlock_direct_acquire_id(void)
{
	return do_delta_action();
}

int sanlock_direct_release_id(void)
{
	return do_delta_action();
}

int sanlock_direct_renew_id(void)
{
	return do_delta_action();
}

/* TODO: if this and daemon use aio, running this will cause i/o errors
 * in the daemon renewals.  This was using a virtual device (/dev/vdb)
 * backed by a file in the host.  Try using a real sda on hosts.
 * Problem in guest didn't appear with -a 0 (to disable aio). */

int sanlock_direct_dump(void)
{
	char *data;
	struct leader_record *lr;
	struct sync_disk sd;
	int num_opened, rv;
	uint64_t sector_nr;

	memset(&sd, 0, sizeof(struct sync_disk));
	strncpy(sd.path, options.host_id_path, DISK_PATH_LEN);
	sd.offset = options.host_id_offset;

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
		memset(data, 0, sd.sector_size);

		rv = read_sectors(&sd, sector_nr, 1, data, sd.sector_size,
				  to.io_timeout_seconds, options.use_aio,
				  "dump");

		if (lr->magic == DELTA_DISK_MAGIC) {
			printf("%08llu %36s own %4llu gen %4llu",
			       (unsigned long long)sector_nr,
			       lr->resource_name,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation);
			if (options.debug)
				printf(" time %010llu age %u",
			      	       (unsigned long long)lr->timestamp,
				       !lr->timestamp ? 0 :
				       (uint32_t)(time(NULL) - lr->timestamp));
			printf("\n");

			sector_nr += 1;
		} else if (lr->magic == PAXOS_DISK_MAGIC) {
			printf("%08llu %36s own %4llu gen %4llu ver %4llu",
			       (unsigned long long)sector_nr,
			       lr->resource_name,
			       (unsigned long long)lr->owner_id,
			       (unsigned long long)lr->owner_generation,
			       (unsigned long long)lr->lver);
			if (options.debug)
				printf(" time %010llu age %u",
			      	       (unsigned long long)lr->timestamp,
				       !lr->timestamp ? 0 :
				       (uint32_t)(time(NULL) - lr->timestamp));
			printf("\n");

			sector_nr += lr->max_hosts + 2;
		} else {
			printf("%08llu %36s\n",
			       (unsigned long long)sector_nr,
			       "uninitialized");
			break;
		}
	}

	free(data);
	return 0;
}

