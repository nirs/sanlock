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
	int num_opened;
	int i, j, rv = 0;

	for (i = 0; i < com.res_count; i++) {
		res = com.res_args[i];

		rv = create_token(res->num_disks, &token);
		if (rv < 0)
			return rv;

		/*
		 * TODO: verify all resources are in the same lockspace?
		 * a single local_host_id option isn't suited to multiple
		 * lockspaces where one host can have different host_ids
		 */

		token->host_id = com.local_host_id;
		token->host_generation = com.local_host_generation;

		strncpy(token->space_name, res->lockspace_name, NAME_ID_SIZE);
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

			rv = paxos_lease_migrate(token, &leader_read, &leader_ret, com.target_host_id);
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

/*
 * sanlock direct acquire -i <local_host_id> -g <local_host_generation> -r RESOURCE
 * sanlock direct release -r RESOURCE
 * sanlock direct migrate -t <target_host_id> -r RESOURCE
 */

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
	struct sync_disk sd;
	struct space space;
	int rv;

	/* for log_space in delta functions */
	memset(&space, 0, sizeof(space));

	memset(&sd, 0, sizeof(struct sync_disk));
	memcpy(&sd, &com.lockspace.host_id_disk, sizeof(struct sanlk_disk));

	rv = open_disks(&sd, 1);
	if (rv != 1) {
		log_tool("open_disk failed %d %s", rv, sd.path);
		return -1;
	}

	switch (com.action) {
	case ACT_ACQUIRE_ID:
		rv = delta_lease_acquire(&space, &sd,
					 com.lockspace.name,
					 com.lockspace.host_id,
					 com.lockspace.host_id,
					 &leader);
		break;
	case ACT_RENEW_ID:
		rv = delta_lease_renew(&space, &sd,
				       com.lockspace.name,
				       com.lockspace.host_id,
				       com.lockspace.host_id,
				       &leader);
		break;
	case ACT_RELEASE_ID:
		rv = delta_lease_leader_read(&sd,
					     com.lockspace.name,
					     com.lockspace.host_id,
					     &leader);
		if (rv < 0)
			return rv;
		rv = delta_lease_release(&space, &sd,
					 com.lockspace.name,
					 com.lockspace.host_id,
					 &leader, &leader);
		break;
	}

	return rv;
}

/* 
 * sanlock direct acquire_id|release_id|renew_id -s LOCKSPACE
 *
 * should be the equivalent of what the daemon would do for
 * sanlock client add_lockspace|rem_lockspace -s LOCKSPACE
 */

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

